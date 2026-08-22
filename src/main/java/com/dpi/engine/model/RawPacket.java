package com.dpi.engine.model;

/**
 * Raw packet read directly from a PCAP file.
 * Contains the timestamp, original/captured lengths, and raw byte data.
 */
public class RawPacket {

    private long timestampSec;
    private long timestampUsec;
    private int inclLen;   // captured length (bytes saved in file)
    private int origLen;   // original length on the wire
    private byte[] data;

    public RawPacket() {}

    public RawPacket(long timestampSec, long timestampUsec, int inclLen, int origLen, byte[] data) {
        this.timestampSec = timestampSec;
        this.timestampUsec = timestampUsec;
        this.inclLen = inclLen;
        this.origLen = origLen;
        this.data = data;
    }

    public long getTimestampSec() { return timestampSec; }
    public void setTimestampSec(long v) { this.timestampSec = v; }
    public long getTimestampUsec() { return timestampUsec; }
    public void setTimestampUsec(long v) { this.timestampUsec = v; }
    public int getInclLen() { return inclLen; }
    public void setInclLen(int v) { this.inclLen = v; }
    public int getOrigLen() { return origLen; }
    public void setOrigLen(int v) { this.origLen = v; }
    public byte[] getData() { return data; }
    public void setData(byte[] v) { this.data = v; }

    /** Combined timestamp in microseconds. */
    public long getTimestampUsecTotal() {
        return timestampSec * 1_000_000L + timestampUsec;
    }
}