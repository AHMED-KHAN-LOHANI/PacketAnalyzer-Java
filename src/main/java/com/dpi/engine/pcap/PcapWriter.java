/*
 * Decompiled with CFR 0.152.
 */
package com.dpi.engine.pcap;

import com.dpi.engine.model.RawPacket;
import com.dpi.engine.pcap.PcapReader;
import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PcapWriter
implements Closeable {
    private static final int PACKET_HEADER_SIZE = 16;
    private DataOutputStream dos;
    private long packetsWritten = 0L;

    public PcapWriter(String filename, PcapReader reader) throws IOException {
        FileOutputStream fos = new FileOutputStream(filename);
        this.dos = new DataOutputStream(new BufferedOutputStream(fos, 65536));
        this.dos.write(reader.getRawGlobalHeader());
    }

    public PcapWriter(String filename, int snapLen) throws IOException {
        FileOutputStream fos = new FileOutputStream(filename);
        this.dos = new DataOutputStream(new BufferedOutputStream(fos, 65536));
        ByteBuffer bb = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        bb.putInt(-1582119980);
        bb.putShort((short)2);
        bb.putShort((short)4);
        bb.putInt(0);
        bb.putInt(0);
        bb.putInt(snapLen != 0 ? snapLen : 65535);
        bb.putInt(1);
        this.dos.write(bb.array());
    }

    public void writePacket(RawPacket pkt) throws IOException {
        this.writeRaw(pkt.getTimestampSec(), pkt.getTimestampUsec(), pkt.getInclLen(), pkt.getOrigLen(), pkt.getData());
        ++this.packetsWritten;
    }

    public void writeRaw(long tsSec, long tsUsec, int origLen, byte[] data) throws IOException {
        this.writeRaw(tsSec, tsUsec, data.length, origLen, data);
        ++this.packetsWritten;
    }

    private void writeRaw(long tsSec, long tsUsec, int inclLen, int origLen, byte[] data) throws IOException {
        ByteBuffer hb = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        hb.putInt((int)tsSec);
        hb.putInt((int)tsUsec);
        hb.putInt(inclLen);
        hb.putInt(origLen);
        this.dos.write(hb.array());
        this.dos.write(data);
    }

    public long getPacketsWritten() {
        return this.packetsWritten;
    }

    @Override
    public void close() throws IOException {
        if (this.dos != null) {
            this.dos.close();
        }
    }
}

