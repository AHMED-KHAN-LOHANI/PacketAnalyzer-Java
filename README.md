# Packet Analyzer - DPI Engine

A high-performance Deep Packet Inspection (DPI) engine written in pure Java. Reads PCAP files, parses network packets at the wire level, classifies traffic by application, applies blocking rules, and outputs filtered PCAP — all with zero external dependencies.

Supports both **single-threaded** and **multi-threaded** (Reader → Load Balancers → Fast Paths → Writer) architectures.

## Features

- **PCAP Parsing** — Reads and writes standard PCAP files (libpcap format, magic `0xa1b2c3d4`)
- **Protocol Stack** — Full Ethernet → IPv4 → TCP/UDP parsing with variable-length header support
- **TLS SNI Extraction** — Byte-level parsing of TLS Client Hello to extract the Server Name Indication field
- **HTTP Host Extraction** — Case-insensitive HTTP Host header parsing
- **DNS Query Extraction** — Parses DNS queries to identify requested domains
- **Application Classification** — Maps 20+ services (YouTube, Facebook, Netflix, etc.) from SNI/domain
- **Flow Tracking** — Five-tuple (srcIP, dstIP, srcPort, dstPort, protocol) based flow identification
- **Blocking Rules** — Block by source IP, application type, or domain substring
- **Multi-threaded Pipeline** — Configurable Reader → LB → FP → Writer architecture with consistent hashing
- **Zero Dependencies** — Pure Java 17, no external libraries

## Architecture

### Single-Threaded Mode (default)

```
PCAP File → Read → Parse → Classify (SNI/HTTP/DNS) → Check Rules → Write/Drop → Output PCAP
```

### Multi-Threaded Mode (`--mt`)

```
                          ┌─────────────┐
                          │   Reader     │
                          └──────┬───────┘
                    ┌────────────┼────────────┐
                    ▼            ▼            ▼
              ┌──────────┐ ┌──────────┐      │
              │   LB-0   │ │   LB-1   │  ... │
              └────┬─────┘ └────┬─────┘      │
            ┌──────┼──────┐     └───┬────────┐│
            ▼      ▼      ▼         ▼        ▼▼
         ┌─────┐┌─────┐┌─────┐  ┌─────┐ ┌─────┐
         │FP-0 ││FP-1 ││FP-2 │  │FP-3 │ │FP-4 │  ...
         └──┬──┘└──┬──┘└──┬──┘  └──┬──┘ └──┬──┘
            └──────┼──────┘        └────────┘
                   ▼
          ┌────────────────┐
          │ Output Writer  │
          └────────────────┘
```

- **Reader** thread reads packets from the PCAP file and dispatches them via hash-based distribution
- **Load Balancers** parse five-tuples and route packets to Fast Paths using consistent hashing
- **Fast Paths** perform the actual DPI: SNI extraction, classification, rule matching, and forwarding/dropping
- **Output Writer** thread serializes forwarded packets into the output PCAP file

## Supported Applications

| Category        | Domains                                                                    |
|-----------------|----------------------------------------------------------------------------|
| Google          | google.com, gstatic.com, googleapis.com, ggpht.com                        |
| YouTube         | youtube.com, youtu.be, ytimg.com                                          |
| Facebook        | facebook.com, fbcdn.net, meta.com                                         |
| Instagram       | instagram.com, cdninstagram.com                                           |
| Twitter/X       | twitter.com, x.com, twimg.com, t.co                                       |
| WhatsApp        | whatsapp.com, wa.me                                                       |
| Netflix         | netflix.com, nflxvideo.net                                                |
| Amazon          | amazon.com, amazonaws.com, cloudfront.net                                 |
| Microsoft       | microsoft.com, office.com, azure.com, outlook.com, bing.com               |
| Apple           | apple.com, icloud.com, itunes.com                                         |
| Telegram        | telegram.org, t.me                                                        |
| TikTok          | tiktok.com, bytedance.com                                                 |
| Spotify         | spotify.com                                                               |
| Zoom            | zoom.us                                                                   |
| Discord         | discord.com                                                               |
| GitHub          | github.com, githubusercontent.com                                         |
| Cloudflare      | cloudflare.com                                                            |

## Building

Requires **Java 17** and **Maven 3.8+**.

```bash
mvn clean package
```

The fat JAR will be at `target/packet-analyzer.jar`.

## Usage

```
java -jar packet-analyzer.jar <input.pcap> <output.pcap> [options]
```

### Options

| Flag               | Description                                      |
|--------------------|--------------------------------------------------|
| `--block-ip <ip>`  | Block traffic from a specific source IP           |
| `--block-app <app>`| Block an application by name (e.g., YouTube)      |
| `--block-domain <d>`| Block traffic matching a domain substring        |
| `--mt`             | Enable multi-threaded mode                        |
| `--lbs <n>`        | Number of load balancer threads (default: 2)      |
| `--fps <n>`        | Fast Path threads per LB (default: 2)             |

### Examples

**Block all YouTube traffic:**
```bash
java -jar packet-analyzer.jar capture.pcap filtered.pcap --block-app YOUTUBE
```

**Block an IP and a domain:**
```bash
java -jar packet-analyzer.jar capture.pcap filtered.pcap --block-ip 192.168.1.50 --block-domain reddit.com
```

**Multi-threaded with custom thread counts:**
```bash
java -jar packet-analyzer.jar capture.pcap filtered.pcap --block-app FACEBOOK --mt --lbs 3 --fps 4
```

**Stack multiple rules:**
```bash
java -jar packet-analyzer.jar capture.pcap filtered.pcap \
  --block-app YOUTUBE \
  --block-app TIKTOK \
  --block-ip 10.0.0.5 \
  --block-domain reddit.com \
  --mt
```

## Project Structure

```
src/main/java/com/dpi/engine/
├── Main.java                  # CLI entry point & argument parsing
├── model/
│   ├── AppType.java           # Application enum (25 types) with SNI→App mapping
│   ├── FiveTuple.java         # Immutable 5-tuple (srcIP, dstIP, srcPort, dstPort, proto)
│   ├── Flow.java              # Per-flow state (app type, SNI, packet/byte counts)
│   ├── RawPacket.java         # Raw PCAP packet (timestamp + bytes)
│   ├── ParsedPacket.java      # Fully parsed packet with protocol fields
│   └── Packet.java            # Self-contained packet for MT pipeline
├── pcap/
│   ├── PcapReader.java        # PCAP file reader (magic validation, packet loop)
│   └── PcapWriter.java        # PCAP file writer
├── parser/
│   └── PacketParser.java      # Ethernet → IP → TCP/UDP → payload parser
├── dpi/
│   ├── SNIExtractor.java      # TLS Client Hello SNI extraction (byte-level)
│   ├── HTTPHostExtractor.java # HTTP Host header extraction
│   └── DNSExtractor.java      # DNS query name extraction
├── rules/
│   └── RuleManager.java       # Blocking rules (IP / App / Domain)
├── tracking/
│   └── ConnectionTracker.java # ConcurrentHashMap-based flow tracker
├── concurrent/
│   ├── ThreadSafeQueue.java   # Bounded blocking queue (ReentrantLock + Condition)
│   ├── LoadBalancer.java      # Hash-based packet distribution to Fast Paths
│   └── FastPath.java          # Per-thread DPI processing with own flow table
├── engine/
│   └── DPIEngine.java         # Multi-threaded pipeline orchestrator
├── simple/
│   └── SimpleDPI.java         # Single-threaded processing loop
└── report/
    └── ReportGenerator.java   # Boxed report with stats & app breakdown
```

## How It Works

1. **Read** — Opens the PCAP file, validates the magic number (`0xa1b2c3d4`), and reads the 24-byte global header
2. **Parse** — For each packet, parses the 14-byte Ethernet header, then the IPv4 header (IHL × 4 bytes), then TCP (data offset × 4) or UDP (8 bytes)
3. **Extract** — From the payload, attempts TLS SNI extraction (content type `0x16`, handshake type `0x01`, extension `0x0000`), HTTP Host extraction, or DNS query extraction
4. **Classify** — Maps extracted SNI/domain to an `AppType` using substring matching
5. **Track** — Maintains per-flow state using a five-tuple key; once a flow is classified, subsequent packets inherit the classification
6. **Block** — Checks IP blocklist, then app blocklist, then domain blocklist; drops matching packets and marks the entire flow as blocked
7. **Write** — Forwarded packets are written to the output PCAP with preserved timestamps

## Generating Test Data

A Python script is included to generate a test PCAP with synthetic traffic:

```bash
python3 generate_test_pcap.py
```

This creates `test_dpi.pcap` with packets for 18+ different applications.

## License

MIT
