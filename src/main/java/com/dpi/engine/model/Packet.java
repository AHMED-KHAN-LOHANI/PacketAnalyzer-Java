package com.dpi.engine.model;

/**
 * Self-contained packet for passing through the multi-threaded pipeline.
 * Mirrors the C++ Packet struct in dpi_mt.cpp.
 */
public class Packet {

    public int id;
    public int tsSec;
    public int tsUsec;
    public FiveTuple tuple;
    public byte[] data;
    public int tcpFlags;
    public int payloadOffset;
    public int payloadLength;

    public Packet() {
        tuple = new FiveTuple(0, 0, 0, 0, 0);
        data = new byte[0];
    }
}
