package com.dpi.engine.pcap;

import com.dpi.engine.model.RawPacket;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Writes packets in PCAP format.
 * Can copy the global header from a reader (to preserve byte order / format)
 * or generate a new one.
 */
public class PcapWriter implements Closeable {

    private static final int PACKET_HEADER_SIZE = 16;

    private DataOutputStream dos;
    private long packetsWritten = 0;

    /** Create writer copying the global header from a PcapReader. */
    public PcapWriter(String filename, PcapReader reader) throws IOException {
        FileOutputStream fos = new FileOutputStream(filename);
        this.dos = new DataOutputStream(new BufferedOutputStream(fos, 65536));
        // Copy global header from reader (preserves byte order)
        dos.write(reader.getRawGlobalHeader());
    }

    /** Create writer with a new global header (little-endian, link type Ethernet). */
    public PcapWriter(String filename, int snapLen) throws IOException {
        FileOutputStream fos = new FileOutputStream(filename);
        this.dos = new DataOutputStream(new BufferedOutputStream(fos, 65536));
        ByteBuffer bb = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        bb.putInt(0xa1b2c3d4);
        bb.putShort((short) 2);
        bb.putShort((short) 4);
        bb.putInt(0);      // thiszone
        bb.putInt(0);      // sigfigs
        bb.putInt(snapLen != 0 ? snapLen : 65535);
        bb.putInt(1);      // link type Ethernet
        dos.write(bb.array());
    }

    /** Write a packet using the same byte order as the input file. */
    public void writePacket(RawPacket pkt) throws IOException {
        writeRaw(pkt.getTimestampSec(), pkt.getTimestampUsec(), pkt.getInclLen(), pkt.getOrigLen(), pkt.getData());
        packetsWritten++;
    }

    /** Write raw bytes as a packet (convenience for simple version). */
    public void writeRaw(long tsSec, long tsUsec, int origLen, byte[] data) throws IOException {
        writeRaw(tsSec, tsUsec, data.length, origLen, data);
        packetsWritten++;
    }

    private void writeRaw(long tsSec, long tsUsec, int inclLen, int origLen, byte[] data) throws IOException {
        // Write in little-endian (standard PCAP)
        ByteBuffer hb = ByteBuffer.allocate(PACKET_HEADER_SIZE).order(ByteOrder.LITTLE_ENDIAN);
        hb.putInt((int) tsSec);
        hb.putInt((int) tsUsec);
        hb.putInt(inclLen);
        hb.putInt(origLen);
        dos.write(hb.array());
        dos.write(data);
    }

    public long getPacketsWritten() { return packetsWritten; }

    @Override
    public void close() throws IOException {
        if (dos != null) dos.close();
    }
}