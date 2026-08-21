/*
 * Decompiled with CFR 0.152.
 */
package com.dpi.engine.pcap;

import com.dpi.engine.model.RawPacket;
import java.io.BufferedInputStream;
import java.io.Closeable;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PcapReader
implements Closeable {
    private static final int PCAP_MAGIC_NATIVE = -1582119980;
    private static final int PCAP_MAGIC_SWAPPED = -725372255;
    private static final int GLOBAL_HEADER_SIZE = 24;
    private static final int PACKET_HEADER_SIZE = 16;
    private DataInputStream dis;
    private boolean needsByteSwap = false;
    private int versionMajor;
    private int versionMinor;
    private int snapLen;
    private int networkType;
    private long totalPackets = 0L;
    private long totalBytes = 0L;
    private byte[] rawGlobalHeader;

    public void open(String filename) throws IOException {
        FileInputStream fis = new FileInputStream(filename);
        this.dis = new DataInputStream(new BufferedInputStream(fis, 65536));
        this.rawGlobalHeader = new byte[24];
        this.dis.readFully(this.rawGlobalHeader);
        ByteBuffer bb = ByteBuffer.wrap(this.rawGlobalHeader).order(ByteOrder.LITTLE_ENDIAN);
        int magic = bb.getInt();
        if (magic == -1582119980) {
            this.needsByteSwap = false;
        } else if (magic == -725372255) {
            this.needsByteSwap = true;
            bb = ByteBuffer.wrap(this.rawGlobalHeader).order(ByteOrder.BIG_ENDIAN);
        } else {
            throw new IOException("Invalid PCAP magic: 0x" + Integer.toHexString(magic));
        }
        this.versionMajor = bb.getShort() & 0xFFFF;
        this.versionMinor = bb.getShort() & 0xFFFF;
        bb.getInt();
        bb.getInt();
        this.snapLen = bb.getInt();
        this.networkType = bb.getInt();
        if (this.networkType != 1) {
            throw new IOException("Unsupported link type: " + this.networkType + ". Only Ethernet (1) is supported.");
        }
        System.out.println("Opened PCAP file: " + filename);
        System.out.println("  Version: " + this.versionMajor + "." + this.versionMinor);
        System.out.println("  Snaplen: " + this.snapLen + " bytes");
        System.out.println("  Link type: " + this.networkType + " (Ethernet)");
    }

    public RawPacket readNextPacket() throws IOException {
        if (this.dis == null) {
            return null;
        }
        byte[] pktHdr = new byte[16];
        int read = this.dis.read(pktHdr);
        if (read == -1) {
            return null;
        }
        if (read < 16) {
            throw new IOException("Truncated packet header");
        }
        ByteBuffer hb = ByteBuffer.wrap(pktHdr).order(this.needsByteSwap ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
        long tsSec = (long)hb.getInt() & 0xFFFFFFFFL;
        long tsUsec = (long)hb.getInt() & 0xFFFFFFFFL;
        int inclLen = hb.getInt();
        int origLen = hb.getInt();
        if (inclLen > this.snapLen || inclLen > 65535) {
            throw new IOException("Invalid captured length: " + inclLen);
        }
        byte[] data = new byte[inclLen];
        this.dis.readFully(data);
        ++this.totalPackets;
        this.totalBytes += (long)inclLen;
        return new RawPacket(tsSec, tsUsec, inclLen, origLen, data);
    }

    public byte[] getRawGlobalHeader() {
        return this.rawGlobalHeader;
    }

    public long getTotalPackets() {
        return this.totalPackets;
    }

    public long getTotalBytes() {
        return this.totalBytes;
    }

    public int getSnapLen() {
        return this.snapLen;
    }

    public int getNetworkType() {
        return this.networkType;
    }

    public boolean needsByteSwap() {
        return this.needsByteSwap;
    }

    @Override
    public void close() throws IOException {
        if (this.dis != null) {
            this.dis.close();
        }
    }
}

