/*
 * Decompiled with CFR 0.152.
 */
package com.dpi.engine.model;

import com.dpi.engine.model.FiveTuple;

public class Packet {
    public int id;
    public int tsSec;
    public int tsUsec;
    public FiveTuple tuple = new FiveTuple(0, 0, 0, 0, 0);
    public byte[] data = new byte[0];
    public int tcpFlags;
    public int payloadOffset;
    public int payloadLength;
}

