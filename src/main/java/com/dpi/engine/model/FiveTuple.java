package com.dpi.engine.model;

import java.util.Objects;

/**
 * Identifies a network flow using the classic 5-tuple:
 * source IP, destination IP, source port, destination port, protocol.
 */
public class FiveTuple {

    private final int srcIp;      // stored as unsigned 32-bit
    private final int dstIp;
    private final int srcPort;    // stored as unsigned 16-bit
    private final int dstPort;
    private final int protocol;   // 6=TCP, 17=UDP

    public FiveTuple(int srcIp, int dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.protocol = protocol;
    }

    public int getSrcIp() { return srcIp; }
    public int getDstIp() { return dstIp; }
    public int getSrcPort() { return srcPort & 0xFFFF; }
    public int getDstPort() { return dstPort & 0xFFFF; }
    public int getProtocol() { return protocol; }

    /** Convert an integer IP to dotted-decimal string. */
    public static String ipToString(int ip) {
        long unsigned = ip & 0xFFFFFFFFL;
        return String.format("%d.%d.%d.%d",
                (unsigned >> 24) & 0xFF,
                (unsigned >> 16) & 0xFF,
                (unsigned >> 8) & 0xFF,
                unsigned & 0xFF);
    }

    /** Parse a dotted-decimal IP string to integer. */
    public static int ipFromString(String ip) {
        String[] parts = ip.split("\\.");
        int result = 0;
        for (String part : parts) {
            result = (result << 8) | (Integer.parseInt(part) & 0xFF);
        }
        return result;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof FiveTuple)) return false;
        FiveTuple that = (FiveTuple) o;
        return srcIp == that.srcIp && dstIp == that.dstIp
                && srcPort == that.srcPort && dstPort == that.dstPort
                && protocol == that.protocol;
    }

    @Override
    public int hashCode() {
        return Objects.hash(srcIp, dstIp, srcPort, dstPort, protocol);
    }

    @Override
    public String toString() {
        return String.format("%s:%d -> %s:%d [%s]",
                ipToString(srcIp), srcPort & 0xFFFF,
                ipToString(dstIp), dstPort & 0xFFFF,
                protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : String.valueOf(protocol));
    }
}
