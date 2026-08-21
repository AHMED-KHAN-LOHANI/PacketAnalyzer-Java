/*
 * Decompiled with CFR 0.152.
 */
package com.dpi.engine.model;

import com.dpi.engine.model.FiveTuple;

public class ParsedPacket {
    private String srcMac;
    private String destMac;
    private int etherType;
    private boolean hasEthernet = false;
    private String srcIp;
    private String destIp;
    private int protocol;
    private int ttl;
    private int ipHeaderLength;
    private boolean hasIpv4 = false;
    private int srcPort;
    private int destPort;
    private long seqNumber;
    private long ackNumber;
    private int dataOffset;
    private boolean syn;
    private boolean ack;
    private boolean fin;
    private boolean rst;
    private boolean psh;
    private boolean hasTcp = false;
    private int udpLength;
    private boolean hasUdp = false;
    private byte[] payload;
    private int payloadOffset;
    private int payloadLength;
    private FiveTuple fiveTuple;

    public String getSrcMac() {
        return this.srcMac;
    }

    public void setSrcMac(String v) {
        this.srcMac = v;
    }

    public String getDestMac() {
        return this.destMac;
    }

    public void setDestMac(String v) {
        this.destMac = v;
    }

    public int getEtherType() {
        return this.etherType;
    }

    public void setEtherType(int v) {
        this.etherType = v;
    }

    public boolean hasEthernet() {
        return this.hasEthernet;
    }

    public void setHasEthernet(boolean v) {
        this.hasEthernet = v;
    }

    public String getSrcIp() {
        return this.srcIp;
    }

    public void setSrcIp(String v) {
        this.srcIp = v;
    }

    public String getDestIp() {
        return this.destIp;
    }

    public void setDestIp(String v) {
        this.destIp = v;
    }

    public int getProtocol() {
        return this.protocol;
    }

    public void setProtocol(int v) {
        this.protocol = v;
    }

    public int getTtl() {
        return this.ttl;
    }

    public void setTtl(int v) {
        this.ttl = v;
    }

    public int getIpHeaderLength() {
        return this.ipHeaderLength;
    }

    public void setIpHeaderLength(int v) {
        this.ipHeaderLength = v;
    }

    public boolean hasIpv4() {
        return this.hasIpv4;
    }

    public void setHasIpv4(boolean v) {
        this.hasIpv4 = v;
    }

    public int getSrcPort() {
        return this.srcPort;
    }

    public void setSrcPort(int v) {
        this.srcPort = v;
    }

    public int getDestPort() {
        return this.destPort;
    }

    public void setDestPort(int v) {
        this.destPort = v;
    }

    public long getSeqNumber() {
        return this.seqNumber;
    }

    public void setSeqNumber(long v) {
        this.seqNumber = v;
    }

    public long getAckNumber() {
        return this.ackNumber;
    }

    public void setAckNumber(long v) {
        this.ackNumber = v;
    }

    public int getDataOffset() {
        return this.dataOffset;
    }

    public void setDataOffset(int v) {
        this.dataOffset = v;
    }

    public boolean isSyn() {
        return this.syn;
    }

    public void setSyn(boolean v) {
        this.syn = v;
    }

    public boolean isAck() {
        return this.ack;
    }

    public void setAck(boolean v) {
        this.ack = v;
    }

    public boolean isFin() {
        return this.fin;
    }

    public void setFin(boolean v) {
        this.fin = v;
    }

    public boolean isRst() {
        return this.rst;
    }

    public void setRst(boolean v) {
        this.rst = v;
    }

    public boolean isPsh() {
        return this.psh;
    }

    public void setPsh(boolean v) {
        this.psh = v;
    }

    public boolean hasTcp() {
        return this.hasTcp;
    }

    public void setHasTcp(boolean v) {
        this.hasTcp = v;
    }

    public int getUdpLength() {
        return this.udpLength;
    }

    public void setUdpLength(int v) {
        this.udpLength = v;
    }

    public boolean hasUdp() {
        return this.hasUdp;
    }

    public void setHasUdp(boolean v) {
        this.hasUdp = v;
    }

    public byte[] getPayload() {
        return this.payload;
    }

    public void setPayload(byte[] v) {
        this.payload = v;
    }

    public int getPayloadOffset() {
        return this.payloadOffset;
    }

    public void setPayloadOffset(int v) {
        this.payloadOffset = v;
    }

    public int getPayloadLength() {
        return this.payloadLength;
    }

    public void setPayloadLength(int v) {
        this.payloadLength = v;
    }

    public FiveTuple getFiveTuple() {
        return this.fiveTuple;
    }

    public void setFiveTuple(FiveTuple v) {
        this.fiveTuple = v;
    }

    public FiveTuple buildFiveTuple() {
        FiveTuple ft;
        int srcIpInt = FiveTuple.ipFromString(this.srcIp);
        int dstIpInt = FiveTuple.ipFromString(this.destIp);
        this.fiveTuple = ft = new FiveTuple(srcIpInt, dstIpInt, this.srcPort, this.destPort, this.protocol);
        return ft;
    }
}

