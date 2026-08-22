package com.dpi.engine.model;

/**
 * Fully parsed packet with all protocol layer fields extracted.
 */
public class ParsedPacket {

    // Ethernet
    private String srcMac;
    private String destMac;
    private int etherType;
    private boolean hasEthernet = false;

    // IP
    private String srcIp;
    private String destIp;
    private int protocol;        // 6=TCP, 17=UDP
    private int ttl;
    private int ipHeaderLength;
    private boolean hasIpv4 = false;

    // TCP
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

    // UDP
    private int udpLength;
    private boolean hasUdp = false;

    // Payload
    private byte[] payload;
    private int payloadOffset;
    private int payloadLength;

    // Five-tuple convenience
    private FiveTuple fiveTuple;

    // Getters and setters
    public String getSrcMac() { return srcMac; }
    public void setSrcMac(String v) { this.srcMac = v; }
    public String getDestMac() { return destMac; }
    public void setDestMac(String v) { this.destMac = v; }
    public int getEtherType() { return etherType; }
    public void setEtherType(int v) { this.etherType = v; }
    public boolean hasEthernet() { return hasEthernet; }
    public void setHasEthernet(boolean v) { hasEthernet = v; }

    public String getSrcIp() { return srcIp; }
    public void setSrcIp(String v) { this.srcIp = v; }
    public String getDestIp() { return destIp; }
    public void setDestIp(String v) { this.destIp = v; }
    public int getProtocol() { return protocol; }
    public void setProtocol(int v) { this.protocol = v; }
    public int getTtl() { return ttl; }
    public void setTtl(int v) { this.ttl = v; }
    public int getIpHeaderLength() { return ipHeaderLength; }
    public void setIpHeaderLength(int v) { this.ipHeaderLength = v; }
    public boolean hasIpv4() { return hasIpv4; }
    public void setHasIpv4(boolean v) { hasIpv4 = v; }

    public int getSrcPort() { return srcPort; }
    public void setSrcPort(int v) { this.srcPort = v; }
    public int getDestPort() { return destPort; }
    public void setDestPort(int v) { this.destPort = v; }
    public long getSeqNumber() { return seqNumber; }
    public void setSeqNumber(long v) { this.seqNumber = v; }
    public long getAckNumber() { return ackNumber; }
    public void setAckNumber(long v) { this.ackNumber = v; }
    public int getDataOffset() { return dataOffset; }
    public void setDataOffset(int v) { this.dataOffset = v; }
    public boolean isSyn() { return syn; }
    public void setSyn(boolean v) { this.syn = v; }
    public boolean isAck() { return ack; }
    public void setAck(boolean v) { this.ack = v; }
    public boolean isFin() { return fin; }
    public void setFin(boolean v) { this.fin = v; }
    public boolean isRst() { return rst; }
    public void setRst(boolean v) { this.rst = v; }
    public boolean isPsh() { return psh; }
    public void setPsh(boolean v) { this.psh = v; }
    public boolean hasTcp() { return hasTcp; }
    public void setHasTcp(boolean v) { hasTcp = v; }

    public int getUdpLength() { return udpLength; }
    public void setUdpLength(int v) { this.udpLength = v; }
    public boolean hasUdp() { return hasUdp; }
    public void setHasUdp(boolean v) { hasUdp = v; }

    public byte[] getPayload() { return payload; }
    public void setPayload(byte[] v) { this.payload = v; }
    public int getPayloadOffset() { return payloadOffset; }
    public void setPayloadOffset(int v) { this.payloadOffset = v; }
    public int getPayloadLength() { return payloadLength; }
    public void setPayloadLength(int v) { this.payloadLength = v; }

    public FiveTuple getFiveTuple() { return fiveTuple; }
    public void setFiveTuple(FiveTuple v) { this.fiveTuple = v; }

    /** Build a FiveTuple from parsed fields. */
    public FiveTuple buildFiveTuple() {
        int srcIpInt = FiveTuple.ipFromString(srcIp);
        int dstIpInt = FiveTuple.ipFromString(destIp);
        FiveTuple ft = new FiveTuple(srcIpInt, dstIpInt, srcPort, destPort, protocol);
        this.fiveTuple = ft;
        return ft;
    }
}