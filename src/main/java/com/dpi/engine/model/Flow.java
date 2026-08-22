package com.dpi.engine.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Represents a tracked network flow identified by a five-tuple.
 * Accumulates state as packets are processed.
 */
public class Flow {

    private final FiveTuple tuple;
    private AppType appType = AppType.UNKNOWN;
    private String sni = null;
    private String host = null;
    private boolean blocked = false;
    private long packetCount = 0;
    private long byteCount = 0;
    private final List<String> detectedDomains = new ArrayList<>();
    private long firstSeenTimestamp = -1;
    private long lastSeenTimestamp = -1;
    private boolean isTcp = false;
    private boolean isUdp = false;
    private boolean hasSni = false;

    public Flow(FiveTuple tuple) {
        this.tuple = tuple;
    }

    public FiveTuple getTuple() { return tuple; }
    public AppType getAppType() { return appType; }
    public void setAppType(AppType appType) { this.appType = appType; }
    public String getSni() { return sni; }
    public void setSni(String sni) { this.sni = sni; this.hasSni = true; }
    public String getHost() { return host; }
    public void setHost(String host) { this.host = host; }
    public boolean isBlocked() { return blocked; }
    public void setBlocked(boolean blocked) { this.blocked = blocked; }
    public long getPacketCount() { return packetCount; }
    public long getByteCount() { return byteCount; }
    public boolean isTcp() { return isTcp; }
    public void setTcp(boolean tcp) { isTcp = tcp; }
    public boolean isUdp() { return isUdp; }
    public void setUdp(boolean udp) { isUdp = udp; }
    public boolean hasSni() { return hasSni; }
    public long getFirstSeenTimestamp() { return firstSeenTimestamp; }
    public long getLastSeenTimestamp() { return lastSeenTimestamp; }

    public void recordPacket(long timestamp, int length) {
        packetCount++;
        byteCount += length;
        if (firstSeenTimestamp < 0) firstSeenTimestamp = timestamp;
        lastSeenTimestamp = timestamp;
    }

    public void addDetectedDomain(String domain) {
        if (!detectedDomains.contains(domain)) {
            detectedDomains.add(domain);
        }
    }

    public List<String> getDetectedDomains() { return detectedDomains; }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Flow{").append(tuple).append("}");
        if (sni != null) sb.append(" SNI=").append(sni);
        if (host != null) sb.append(" Host=").append(host);
        sb.append(" app=").append(appType.getDisplayName());
        sb.append(" pkts=").append(packetCount);
        if (blocked) sb.append(" [BLOCKED]");
        return sb.toString();
    }
}
