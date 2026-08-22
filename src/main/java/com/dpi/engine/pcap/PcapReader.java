package com.dpi.engine.pcap;

import com.dpi.engine.model.RawPacket;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Reads packets from a PCAP file (libpcap format).
 * Handles both native (0xa1b2c3d4) and byte-swapped (0xd4c3b2a1) formats.
 * Ported from the C++ PcapReader.
 */
public class PcapReader implements Closeable {

    private static final int PCAP_MAGIC_NATIVE = 0xa1b2c3d4;
    private static final int PCAP_MAGIC_SWAPPED = 0xd4c3b2a1;
    private static final int GLOBAL_HEADER_SIZE = 24;
    private static final int PACKET_HEADER_SIZE = 16;

    private DataInputStream dis;
    private boolean needsByteSwap = false;
    private int versionMajor;
    private int versionMinor;
    private int snapLen;
    private int networkType; // 1 = Ethernet
    private long totalPackets = 0;
    private long totalBytes = 0;

    /** Raw global header bytes (needed to copy to output file). */
    private byte[] rawGlobalHeader;

    public PcapReader() {}

    /** Open a PCAP file and validate the global header. */
    public void open(String filename) throws IOException {
        FileInputStream fis = new FileInputStream(filename);
        this.dis = new DataInputStream(new BufferedInputStream(fis, 65536));

        // Read raw global header bytes
        rawGlobalHeader = new byte[GLOBAL_HEADER_SIZE];
        dis.readFully(rawGlobalHeader);

        // Read as little-endian first (native PCAP format)
        ByteBuffer bb = ByteBuffer.wrap(rawGlobalHeader).order(ByteOrder.LITTLE_ENDIAN);
        int magic = bb.getInt();

        if (magic == PCAP_MAGIC_NATIVE) {
            needsByteSwap = false;
        } else if (magic == PCAP_MAGIC_SWAPPED) {
            needsByteSwap = true;
            // Re-read as big-endian
            bb = ByteBuffer.wrap(rawGlobalHeader).order(ByteOrder.BIG_ENDIAN);
        } else {
            throw new IOException("Invalid PCAP magic: 0x" + Integer.toHexString(magic));
        }

        versionMajor = bb.getShort() & 0xFFFF;
        versionMinor = bb.getShort() & 0xFFFF;
        bb.getInt(); // thiszone
        bb.getInt(); // sigfigs
        this.snapLen = bb.getInt();
        this.networkType = bb.getInt();

        if (networkType != 1) {
            throw new IOException("Unsupported link type: " + networkType + ". Only Ethernet (1) is supported.");
        }

        System.out.println("Opened PCAP file: " + filename);
        System.out.println("  Version: " + versionMajor + "." + versionMinor);
        System.out.println("  Snaplen: " + snapLen + " bytes");
        System.out.println("  Link type: " + networkType + " (Ethernet)");
    }

    /** Read the next packet. Returns null at EOF. */
    public RawPacket readNextPacket() throws IOException {
        if (dis == null) return null;

        byte[] pktHdr = new byte[PACKET_HEADER_SIZE];
        int read = dis.read(pktHdr);
        if (read == -1) return null;
        if (read < PACKET_HEADER_SIZE) throw new IOException("Truncated packet header");

        ByteBuffer hb = ByteBuffer.wrap(pktHdr).order(
                needsByteSwap ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
        long tsSec = hb.getInt() & 0xFFFFFFFFL;
        long tsUsec = hb.getInt() & 0xFFFFFFFFL;
        int inclLen = hb.getInt();
        int origLen = hb.getInt();

        if (inclLen > snapLen || inclLen > 65535) {
            throw new IOException("Invalid captured length: " + inclLen);
        }

        byte[] data = new byte[inclLen];
        dis.readFully(data);

        totalPackets++;
        totalBytes += inclLen;

        return new RawPacket(tsSec, tsUsec, inclLen, origLen, data);
    }

    /** Return the raw 24-byte global header (for copying to output). */
    public byte[] getRawGlobalHeader() { return rawGlobalHeader; }
    public long getTotalPackets() { return totalPackets; }
    public long getTotalBytes() { return totalBytes; }
    public int getSnapLen() { return snapLen; }
    public int getNetworkType() { return networkType; }
    public boolean needsByteSwap() { return needsByteSwap; }

    @Override
    public void close() throws IOException {
        if (dis != null) dis.close();
    }
}
