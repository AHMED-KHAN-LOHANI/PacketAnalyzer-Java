/*
 * Decompiled with CFR 0.152.
 */
package com.dpi.engine.model;

import com.dpi.engine.model.AppType;
import com.dpi.engine.model.FiveTuple;
import java.util.ArrayList;
import java.util.List;

public class Flow {
    private final FiveTuple tuple;
    private AppType appType = AppType.UNKNOWN;
    private String sni = null;
    private String host = null;
    private boolean blocked = false;
    private long packetCount = 0L;
    private long byteCount = 0L;
    private final List<String> detectedDomains = new ArrayList<String>();
    private long firstSeenTimestamp = -1L;
    private long lastSeenTimestamp = -1L;
    private boolean isTcp = false;
    private boolean isUdp = false;
    private boolean hasSni = false;

    public Flow(FiveTuple tuple) {
        this.tuple = tuple;
    }

    public FiveTuple getTuple() {
        return this.tuple;
    }

    public AppType getAppType() {
        return this.appType;
    }

    public void setAppType(AppType appType) {
        this.appType = appType;
    }

    public String getSni() {
        return this.sni;
    }

    public void setSni(String sni) {
        this.sni = sni;
        this.hasSni = true;
    }

    public String getHost() {
        return this.host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public boolean isBlocked() {
        return this.blocked;
    }

    public void setBlocked(boolean blocked) {
        this.blocked = blocked;
    }

    public long getPacketCount() {
        return this.packetCount;
    }

    public long getByteCount() {
        return this.byteCount;
    }

    public boolean isTcp() {
        return this.isTcp;
    }

    public void setTcp(boolean tcp) {
        this.isTcp = tcp;
    }

    public boolean isUdp() {
        return this.isUdp;
    }

    public void setUdp(boolean udp) {
        this.isUdp = udp;
    }

    public boolean hasSni() {
        return this.hasSni;
    }

    public long getFirstSeenTimestamp() {
        return this.firstSeenTimestamp;
    }

    public long getLastSeenTimestamp() {
        return this.lastSeenTimestamp;
    }

    public void recordPacket(long timestamp, int length) {
        ++this.packetCount;
        this.byteCount += (long)length;
        if (this.firstSeenTimestamp < 0L) {
            this.firstSeenTimestamp = timestamp;
        }
        this.lastSeenTimestamp = timestamp;
    }

    public void addDetectedDomain(String domain) {
        if (!this.detectedDomains.contains(domain)) {
            this.detectedDomains.add(domain);
        }
    }

    public List<String> getDetectedDomains() {
        return this.detectedDomains;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Flow{").append(this.tuple).append("}");
        if (this.sni != null) {
            sb.append(" SNI=").append(this.sni);
        }
        if (this.host != null) {
            sb.append(" Host=").append(this.host);
        }
        sb.append(" app=").append(this.appType.getDisplayName());
        sb.append(" pkts=").append(this.packetCount);
        if (this.blocked) {
            sb.append(" [BLOCKED]");
        }
        return sb.toString();
    }
}

