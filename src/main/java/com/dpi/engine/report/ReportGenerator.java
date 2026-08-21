/*
 * Decompiled with CFR 0.152.
 */
package com.dpi.engine.report;

import com.dpi.engine.model.AppType;
import com.dpi.engine.model.FiveTuple;
import com.dpi.engine.model.Flow;
import java.util.ArrayList;
import java.util.Map;
import java.util.TreeMap;

public class ReportGenerator {
    private long totalPackets;
    private long totalBytes;
    private long tcpPackets;
    private long udpPackets;
    private long forwarded;
    private long dropped;
    private int numLbs;
    private int numFps;
    private final long[] lbDispatched;
    private final long[] fpProcessed;
    private final Map<AppType, Long> appStats = new TreeMap<AppType, Long>();
    private final Map<String, String> detectedDomains = new TreeMap<String, String>();

    public ReportGenerator(int numLbs, int numFps) {
        this.numLbs = numLbs;
        this.numFps = numFps;
        this.lbDispatched = new long[numLbs];
        this.fpProcessed = new long[numFps];
    }

    public void setTotalPackets(long v) {
        this.totalPackets = v;
    }

    public void setTotalBytes(long v) {
        this.totalBytes = v;
    }

    public void setTcpPackets(long v) {
        this.tcpPackets = v;
    }

    public void setUdpPackets(long v) {
        this.udpPackets = v;
    }

    public void setForwarded(long v) {
        this.forwarded = v;
    }

    public void setDropped(long v) {
        this.dropped = v;
    }

    public void setLbDispatched(int index, long count) {
        this.lbDispatched[index] = count;
    }

    public void setFpProcessed(int index, long count) {
        this.fpProcessed[index] = count;
    }

    public void addAppStats(Map<AppType, Long> stats) {
        stats.forEach((k, v) -> this.appStats.merge((AppType)((Object)k), (Long)v, Long::sum));
    }

    public void addDetectedDomains(Map<String, String> domains) {
        this.detectedDomains.putAll(domains);
    }

    public void buildFromFlows(Map<FiveTuple, Flow> allFlows) {
        for (Flow flow : allFlows.values()) {
            AppType app = flow.getAppType();
            this.appStats.merge(app, flow.getPacketCount(), Long::sum);
            if (flow.getSni() != null) {
                this.detectedDomains.put(flow.getSni(), app.getDisplayName());
            }
            if (flow.getHost() != null) {
                this.detectedDomains.put(flow.getHost(), app.getDisplayName());
            }
            if (flow.isBlocked()) {
                this.dropped += flow.getPacketCount();
            } else {
                this.forwarded += flow.getPacketCount();
            }
            if (flow.isTcp()) {
                this.tcpPackets += flow.getPacketCount();
            }
            if (!flow.isUdp()) continue;
            this.udpPackets += flow.getPacketCount();
        }
    }

    public void print() {
        int w = 62;
        String border = "\u2550".repeat(w);
        String pad = String.format("%%-%ds", w - 4);
        System.out.println("\u2554" + border + "\u2557");
        System.out.printf("\u2551" + pad + "\u2551%n", "                      PROCESSING REPORT");
        System.out.println("\u2560" + border + "\u2563");
        System.out.printf("\u2551" + pad + "\u2551%n", "Total Packets:                " + this.totalPackets);
        System.out.printf("\u2551" + pad + "\u2551%n", "Total Bytes:                " + this.totalBytes);
        System.out.printf("\u2551" + pad + "\u2551%n", "TCP Packets:                  " + this.tcpPackets);
        System.out.printf("\u2551" + pad + "\u2551%n", "UDP Packets:                   " + this.udpPackets);
        System.out.println("\u2560" + border + "\u2563");
        System.out.printf("\u2551" + pad + "\u2551%n", "Forwarded:                    " + this.forwarded);
        System.out.printf("\u2551" + pad + "\u2551%n", "Dropped:                       " + this.dropped);
        if (this.numLbs > 0) {
            int i;
            System.out.println("\u2560" + border + "\u2563");
            System.out.printf("\u2551" + pad + "\u2551%n", "THREAD STATISTICS");
            for (i = 0; i < this.numLbs; ++i) {
                System.out.printf("\u2551" + pad + "\u2551%n", "  LB" + i + " dispatched:             " + this.lbDispatched[i]);
            }
            for (i = 0; i < this.numFps; ++i) {
                System.out.printf("\u2551" + pad + "\u2551%n", "  FP" + i + " processed:              " + this.fpProcessed[i]);
            }
        }
        System.out.println("\u2560" + border + "\u2563");
        System.out.printf("\u2551" + pad + "\u2551%n", "                   APPLICATION BREAKDOWN");
        System.out.println("\u2560" + border + "\u2563");
        long totalForPercent = 0L;
        for (long count : this.appStats.values()) {
            totalForPercent += count;
        }
        ArrayList<Map.Entry<AppType, Long>> sorted = new ArrayList<Map.Entry<AppType, Long>>(this.appStats.entrySet());
        sorted.sort((a, b) -> Long.compare((Long)b.getValue(), (Long)a.getValue()));
        for (Map.Entry entry : sorted) {
            String name = ((AppType)((Object)entry.getKey())).getDisplayName();
            long count = (Long)entry.getValue();
            double pct = totalForPercent > 0L ? 100.0 * (double)count / (double)totalForPercent : 0.0;
            int barLen = (int)(pct / 5.0);
            String bar = "#".repeat(Math.max(1, barLen));
            String blockedTag = "";
            blockedTag = "";
            String line = String.format("%-20s %5d %5.1f%% %s", name, count, pct, bar);
            System.out.printf("\u2551 %-58s \u2551%n", line);
        }
        System.out.println("\u255a" + border + "\u255d");
        if (!this.detectedDomains.isEmpty()) {
            System.out.println();
            System.out.println("[Detected Domains/SNIs]");
            for (Map.Entry entry : this.detectedDomains.entrySet()) {
                System.out.println("  - " + (String)entry.getKey() + " -> " + (String)entry.getValue());
            }
        }
    }
}

