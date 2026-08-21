# DPI Engine - Deep Packet Inspection System (Java Edition)

This is a complete Java port of the Deep Packet Inspection (DPI) system.

## Features
- **Network Protocol Parsing**: Parses Ethernet, IPv4, TCP, and UDP.
- **Deep Packet Inspection**: Extracts Server Name Indication (SNI) from TLS/HTTPS and Host headers from HTTP.
- **Flow Tracking**: Tracks and maintains state for network connections using 5-tuples.
- **Multi-threaded Architecture**: Scales using a Load Balancer and Fast Path threads with thread-safe queues.
- **Rules Engine**: Block traffic based on Source IP, Application Type, or Domain name.

## Architecture

**Multi-threaded Pipeline:**
[Reader Thread] --> [Load Balancers] --> [Fast Paths] --> [Writer Thread]

## Build and Run

### Build
mvn clean package

### Run Single-threaded
java -jar target/packet-analyzer-2.0.0.jar input.pcap output.pcap --block-app YouTube --block-ip 192.168.1.50

### Run Multi-threaded
java -jar target/packet-analyzer-2.0.0.jar input.pcap output.pcap --mt --lbs 2 --fps 4 --block-domain facebook
