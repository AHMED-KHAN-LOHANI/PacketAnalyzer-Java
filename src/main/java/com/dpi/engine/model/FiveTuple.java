/*
 * Decompiled with CFR 0.152.
 */
package com.dpi.engine.model;

import java.util.Objects;

public class FiveTuple {
    private final int srcIp;
    private final int dstIp;
    private final int srcPort;
    private final int dstPort;
    private final int protocol;

    public FiveTuple(int srcIp, int dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.protocol = protocol;
    }

    public int getSrcIp() {
        return this.srcIp;
    }

    public int getDstIp() {
        return this.dstIp;
    }

    public int getSrcPort() {
        return this.srcPort & 0xFFFF;
    }

    public int getDstPort() {
        return this.dstPort & 0xFFFF;
    }

    public int getProtocol() {
        return this.protocol;
    }

    public static String ipToString(int ip) {
        long unsigned = (long)ip & 0xFFFFFFFFL;
        return String.format("%d.%d.%d.%d", unsigned >> 24 & 0xFFL, unsigned >> 16 & 0xFFL, unsigned >> 8 & 0xFFL, unsigned & 0xFFL);
    }

    public static int ipFromString(String ip) {
        String[] parts = ip.split("\\.");
        int result = 0;
        for (String part : parts) {
            result = result << 8 | Integer.parseInt(part) & 0xFF;
        }
        return result;
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof FiveTuple)) {
            return false;
        }
        FiveTuple that = (FiveTuple)o;
        return this.srcIp == that.srcIp && this.dstIp == that.dstIp && this.srcPort == that.srcPort && this.dstPort == that.dstPort && this.protocol == that.protocol;
    }

    public int hashCode() {
        return Objects.hash(this.srcIp, this.dstIp, this.srcPort, this.dstPort, this.protocol);
    }

    public String toString() {
        return String.format("%s:%d -> %s:%d [%s]", FiveTuple.ipToString(this.srcIp), this.srcPort & 0xFFFF, FiveTuple.ipToString(this.dstIp), this.dstPort & 0xFFFF, this.protocol == 6 ? "TCP" : (this.protocol == 17 ? "UDP" : String.valueOf(this.protocol)));
    }
}

