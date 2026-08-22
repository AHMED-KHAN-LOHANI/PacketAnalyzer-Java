# DPI Engine - Deep Packet Inspection System (Java Edition)

This document explains everything about this project - from basic networking concepts to the complete Java architecture. After reading this, you should understand exactly how packets flow through the system without needing to read the code.

## Table of Contents
1. [What is DPI?](#1-what-is-dpi)
2. [Networking Background](#2-networking-background)
3. [Project Overview](#3-project-overview)
4. [File Structure](#4-file-structure)
5. [The Journey of a Packet (Simple Version)](#5-the-journey-of-a-packet-simple-version)
6. [The Journey of a Packet (Multi-threaded Version)](#6-the-journey-of-a-packet-multi-threaded-version)
7. [Deep Dive: Each Component](#7-deep-dive-each-component)
8. [How SNI Extraction Works](#8-how-sni-extraction-works)
9. [How Blocking Works](#9-how-blocking-works)
10. [Building and Running](#10-building-and-running)
11. [Understanding the Output](#11-understanding-the-output)

## 1. What is DPI?
Deep Packet Inspection (DPI) is a technology used to examine the contents of network packets as they pass through a checkpoint. Unlike simple firewalls that only look at packet headers (source/destination IP), DPI looks *inside* the packet payload.

**Real-World Uses:**
*   **ISPs:** Throttle or block certain applications (e.g., BitTorrent)
*   **Enterprises:** Block social media on office networks
*   **Parental Controls:** Block inappropriate websites
*   **Security:** Detect malware or intrusion attempts

**What Our DPI Engine Does:**
User Traffic (PCAP) -> [DPI Engine] -> Filtered Traffic (PCAP)
- Identifies apps (YouTube, Facebook, Netflix, etc.)
- Blocks based on rules
- Generates categorized reports

## 2. Networking Background
### The Network Stack (Layers)
When you visit a website, data travels through multiple "layers":
`	ext
+---------------------------------------------------------+
¦ Layer 7: Application ¦ HTTP, TLS, DNS                   ¦
+---------------------------------------------------------¦
¦ Layer 4: Transport   ¦ TCP (reliable), UDP (fast)       ¦
+---------------------------------------------------------¦
¦ Layer 3: Network     ¦ IP addresses (routing)           ¦
+---------------------------------------------------------¦
¦ Layer 2: Data Link   ¦ MAC addresses (local network)    ¦
+---------------------------------------------------------+
`

### A Packet's Structure
Every network packet is like a Russian nesting doll - headers wrapped inside headers:
`	ext
+------------------------------------------------------------------+
¦ Ethernet Header (14 bytes)                                       ¦
¦ +--------------------------------------------------------------+ ¦
¦ ¦ IP Header (20 bytes)                                         ¦ ¦
¦ ¦ +----------------------------------------------------------+ ¦ ¦
¦ ¦ ¦ TCP Header (20 bytes)                                    ¦ ¦ ¦
¦ ¦ ¦ +------------------------------------------------------+ ¦ ¦ ¦
¦ ¦ ¦ ¦ Payload (Application Data)                           ¦ ¦ ¦ ¦
¦ ¦ ¦ ¦ e.g., TLS Client Hello with SNI                      ¦ ¦ ¦ ¦
¦ ¦ ¦ +------------------------------------------------------+ ¦ ¦ ¦
¦ ¦ +----------------------------------------------------------+ ¦ ¦
¦ +--------------------------------------------------------------+ ¦
+------------------------------------------------------------------+
`

### The Five-Tuple
A connection (or "flow") is uniquely identified by 5 values:
1. Source IP
2. Destination IP
3. Source Port
4. Destination Port
5. Protocol

*All packets with the same 5-tuple (regardless of direction) belong to the same connection!*

### What is SNI?
Server Name Indication (SNI) is part of the TLS/HTTPS handshake. When you visit https://www.youtube.com:
1. Your browser sends a "Client Hello" message
2. This message includes the domain name in plaintext (not encrypted yet!)
3. The server uses this to know which certificate to send

This is the key to DPI: **Even though HTTPS is encrypted, the domain name is visible in the first packet!**

## 3. Project Overview
**What This Project Does**
`	ext
+-------------+       +-------------+       +-------------+
¦  Wireshark  ¦       ¦  DPI Engine ¦       ¦   Output    ¦
¦   Capture   ¦ --?   ¦   - Parse   ¦ --?   ¦    PCAP     ¦
¦ (input.pcap)¦       ¦  - Classify ¦       ¦  (filtered) ¦
+-------------+       ¦   - Block   ¦       +-------------+
                      ¦  - Report   ¦
                      +-------------+
`

## 4. File Structure
`	ext
PacketAnalyzer-Java/
+-- src/main/java/com/dpi/engine/
¦   +-- Main.java               # Entry point
¦   +-- simple/                 # Single-threaded mode
¦   ¦   +-- SimpleDPI.java
¦   +-- engine/                 # Multi-threaded orchestrator
¦   ¦   +-- DPIEngine.java
¦   +-- concurrent/             # Concurrency / Threads
¦   ¦   +-- ThreadSafeQueue.java
¦   ¦   +-- LoadBalancer.java
¦   ¦   +-- FastPath.java
¦   +-- dpi/                    # Payload Inspection
¦   ¦   +-- SNIExtractor.java
¦   ¦   +-- HTTPHostExtractor.java
¦   +-- pcap/                   # Binary file I/O
¦   ¦   +-- PcapReader.java
¦   +-- model/                  # Data structures
¦       +-- FiveTuple.java
¦       +-- Packet.java
+-- pom.xml                     # Maven config (optional)
+-- generate_test_pcap.py       # Test data generator
`

## 5. The Journey of a Packet (Simple Version)
Let's trace a single packet through SimpleDPI.java:

**Step 1: Read PCAP File**
`java
PcapReader reader = new PcapReader("capture.pcap");
`
Opens the binary file, reads the 24-byte global header, and validates the magic number.

**Step 2: Parse Protocol Headers**
`java
Packet parsed = PacketParser.parse(rawPacket);
`
Reads the Ethernet (14 bytes), IP (20 bytes), and TCP (20 bytes) headers to extract IPs and ports.

**Step 3: Create Five-Tuple and Look Up Flow**
`java
FiveTuple tuple = new FiveTuple(srcIp, dstIp, srcPort, dstPort, protocol);
Flow flow = connectionTracker.getOrCreateFlow(tuple);
`
Creates a bidirectional connection tracker. All packets in the same conversation map to the same Flow object.

**Step 4: Extract SNI (Deep Packet Inspection)**
`java
if (parsed.getDestPort() == 443 && parsed.getPayloadLength() > 5) {
    String sni = SNIExtractor.extract(payload, payloadLen);
    if (sni != null) {
        flow.appType = AppType.fromSNI(sni); // Maps "youtube.com" to YOUTUBE
    }
}
`

**Step 5: Check Rules & Forward**
`java
if (rules.isBlocked(flow.appType)) {
    flow.blocked = true;
    dropped++;
} else {
    forwarded++;
    output.write(rawPacket);
}
`

## 6. The Journey of a Packet (Multi-threaded Version)
The multi-threaded version (DPIEngine.java) adds parallelism for high performance:

**Architecture Overview**
`	ext
                 +-----------------+
                 ¦  Reader Thread  ¦
                 ¦  (reads PCAP)   ¦
                 +-----------------+
             hash(5-tuple) % 2
                  ?               ?
        +-----------------+ +-----------------+
        ¦   LB0 Thread    ¦ ¦   LB1 Thread    ¦
        ¦ (Load Balancer) ¦ ¦ (Load Balancer) ¦
        +-----------------+ +-----------------+
             hash % 2           hash % 2
            ?        ?         ?        ?
       +--------++--------++--------++--------+
       ¦FP0     ¦¦FP1     ¦¦FP2     ¦¦FP3     ¦
       ¦(Fast)  ¦¦(Fast)  ¦¦(Fast)  ¦¦(Fast)  ¦
       +--------++--------++--------++--------+
            +-----------------------------+
                           ?
                 +-----------------+
                 ¦  Writer Thread  ¦
                 +-----------------+
`
**Why Consistent Hashing?**
The Load Balancers use hash(5-tuple) so that every packet from the *same connection* always goes to the *same Fast Path (FP)* thread. This ensures the Fast Path thread can track the state of the conversation safely.

**Thread-Safe Queue (Java)**
Instead of basic locks, we built a highly efficient ThreadSafeQueue.java using Java's ReentrantLock and Condition.
`java
public void push(T item) throws InterruptedException {
    lock.lock();
    try {
        while (queue.size() >= capacity) {
            notFull.await();
        }
        queue.add(item);
        notEmpty.signal(); // Wake up consumers!
    } finally {
        lock.unlock();
    }
}
`

## 7. Deep Dive: SNI Extraction (The Magic)
When you visit youtube.com, the TLS Client Hello structure looks like this:
`	ext
Byte 0: Content Type = 0x16 (Handshake)
Byte 5: Handshake Type = 0x01 (Client Hello)
... Skip 40+ bytes of Random Data and Ciphers ...
-- Extensions --
Extension Type: 0x0000 (SNI)
Extension Length: L
SNI Value: "www.youtube.com"  <- THE GOAL!
`

Our SNIExtractor.java manually navigates these raw bytes:
`java
public static String extract(byte[] payload, int length) {
    if (payload[0] != 22) return null; // Not handshake
    
    int offset = 43; // Skip header and Random
    // ... manually parsing byte offsets ...
    
    while (offset + 4 <= extensionsEnd) {
        int extType = readUint16BE(payload, offset);
        int extLen = readUint16BE(payload, offset + 2);
        
        if (extType == 0x0000) { // Found SNI!
            int sniLen = readUint16BE(payload, offset + 7);
            return new String(payload, offset + 9, sniLen);
        }
        offset += 4 + extLen;
    }
    return null;
}
`

## 8. Building and Running

**Running (Without Maven)**
If you have the compiled .jar file, you can run it directly using Java:
`ash
# Simple Mode
java -jar target/packet-analyzer-2.0.0.jar test_dpi.pcap output.pcap --block-app YOUTUBE

# Multi-Threaded Mode (2 LBs, 4 FPs)
java -jar target/packet-analyzer-2.0.0.jar test_dpi.pcap output.pcap --mt --lbs 2 --fps 4 --block-app YOUTUBE
`

**Compiling with Maven**
If you want to edit the code and recompile it:
`ash
mvn clean package
`

## Summary
This Java DPI engine demonstrates:
*   **Network Protocol Parsing:** Manipulating raw binary data at the byte level
*   **Deep Packet Inspection:** Looking inside encrypted connections (TLS/SNI)
*   **Flow Tracking:** Managing stateful TCP/UDP connections via 5-tuple
*   **Concurrency:** Scaling with Load Balancers, Fast Paths, and ReentrantLock Thread-Safe Queues
