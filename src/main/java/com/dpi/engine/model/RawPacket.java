/*
 * Decompiled with CFR 0.152.
 */
package com.dpi.engine.model;

public class RawPacket {
    private long timestampSec;
    private long timestampUsec;
    private int inclLen;
    private int origLen;
    private byte[] data;

    public RawPacket() {
    }

    public RawPacket(long timestampSec, long timestampUsec, int inclLen, int origLen, byte[] data) {
        this.timestampSec = timestampSec;
        this.timestampUsec = timestampUsec;
        this.inclLen = inclLen;
        this.origLen = origLen;
        this.data = data;
    }

    public long getTimestampSec() {
        return this.timestampSec;
    }

    public void setTimestampSec(long v) {
        this.timestampSec = v;
    }

    public long getTimestampUsec() {
        return this.timestampUsec;
    }

    public void setTimestampUsec(long v) {
        this.timestampUsec = v;
    }

    public int getInclLen() {
        return this.inclLen;
    }

    public void setInclLen(int v) {
        this.inclLen = v;
    }

    public int getOrigLen() {
        return this.origLen;
    }

    public void setOrigLen(int v) {
        this.origLen = v;
    }

    public byte[] getData() {
        return this.data;
    }

    public void setData(byte[] v) {
        this.data = v;
    }

    public long getTimestampUsecTotal() {
        return this.timestampSec * 1000000L + this.timestampUsec;
    }
}

