package com.dpi.engine.report;

import com.dpi.engine.model.AppType;
import com.dpi.engine.model.Flow;
import com.dpi.engine.model.FiveTuple;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Generates the processing report showing statistics, thread info,
 * application breakdown, and detected domains.
 */
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
    private final Map<AppType, Long> appStats = new TreeMap<>();
    private final Map<String, String> detectedDomains = new TreeMap<>();

    public ReportGenerator(int numLbs, int numFps) {
        this.numLbs = numLbs;
        this.numFps = numFps;
        this.lbDispatched = new long[numLbs];
        this.fpProcessed = new long[numFps];
    }

    public void setTotalPackets(long v) { this.totalPackets = v; }
    public void setTotalBytes(long v) { this.totalBytes = v; }
    public void setTcpPackets(long v) { this.tcpPackets = v; }
    public void setUdpPackets(long v) { this.udpPackets = v; }
    public void setForwarded(long v) { this.forwarded = v; }
    public void setDropped(long v) { this.dropped = v; }

    public void setLbDispatched(int index, long count) { lbDispatched[index] = count; }
    public void setFpProcessed(int index, long count) { fpProcessed[index] = count; }

    public void addAppStats(Map<AppType, Long> stats) {
        stats.forEach((k, v) -> appStats.merge(k, v, Long::sum));
    }

    public void addDetectedDomains(Map<String, String> domains) {
        detectedDomains.putAll(domains);
    }

    /** Build the report from a ConnectionTracker (simple version). */
    public void buildFromFlows(Map<FiveTuple, Flow> allFlows) {
        for (Flow flow : allFlows.values()) {
            AppType app = flow.getAppType();
            appStats.merge(app, flow.getPacketCount(), Long::sum);
            if (flow.getSni() != null) {
                detectedDomains.put(flow.getSni(), app.getDisplayName());
            }
            if (flow.getHost() != null) {
                detectedDomains.put(flow.getHost(), app.getDisplayName());
            }
            if (flow.isBlocked()) {
                dropped += flow.getPacketCount();
            } else {
                forwarded += flow.getPacketCount();
            }
            if (flow.isTcp()) tcpPackets += flow.getPacketCount();
            if (flow.isUdp()) udpPackets += flow.getPacketCount();
        }
    }

    public void print() {
        int w = 62;
        String border = "\u2550".repeat(w);
        String pad = String.format("%%-%ds", w - 4);

        System.out.println("\u2554" + border + "\u2557");
        System.out.printf("\u2551" + pad + "\u2551%n", "                      PROCESSING REPORT");
        System.out.println("\u2560" + border + "\u2563");
        System.out.printf("\u2551" + pad + "\u2551%n", "Total Packets:                " + totalPackets);
        System.out.printf("\u2551" + pad + "\u2551%n", "Total Bytes:                " + totalBytes);
        System.out.printf("\u2551" + pad + "\u2551%n", "TCP Packets:                  " + tcpPackets);
        System.out.printf("\u2551" + pad + "\u2551%n", "UDP Packets:                   " + udpPackets);
        System.out.println("\u2560" + border + "\u2563");
        System.out.printf("\u2551" + pad + "\u2551%n", "Forwarded:                    " + forwarded);
        System.out.printf("\u2551" + pad + "\u2551%n", "Dropped:                       " + dropped);

        // Thread stats (only for multi-threaded)
        if (numLbs > 0) {
            System.out.println("\u2560" + border + "\u2563");
            System.out.printf("\u2551" + pad + "\u2551%n", "THREAD STATISTICS");
            for (int i = 0; i < numLbs; i++) {
                System.out.printf("\u2551" + pad + "\u2551%n", "  LB" + i + " dispatched:             " + lbDispatched[i]);
            }
            for (int i = 0; i < numFps; i++) {
                System.out.printf("\u2551" + pad + "\u2551%n", "  FP" + i + " processed:              " + fpProcessed[i]);
            }
        }

        // Application breakdown
        System.out.println("\u2560" + border + "\u2563");
        System.out.printf("\u2551" + pad + "\u2551%n", "                   APPLICATION BREAKDOWN");
        System.out.println("\u2560" + border + "\u2563");

        long totalForPercent = 0;
        for (long count : appStats.values()) totalForPercent += count;

        List<Map.Entry<AppType, Long>> sorted = new ArrayList<>(appStats.entrySet());
        sorted.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));

        for (Map.Entry<AppType, Long> entry : sorted) {
            String name = entry.getKey().getDisplayName();
            long count = entry.getValue();
            double pct = totalForPercent > 0 ? (100.0 * count / totalForPercent) : 0;
            int barLen = (int) (pct / 5);
            String bar = "#".repeat(Math.max(1, barLen));
            String blockedTag = "";
            // Check if any flow with this app type was blocked
            blockedTag = ""; // We'd need to check rules for this
            String line = String.format("%-20s %5d %5.1f%% %s", name, count, pct, bar);
            System.out.printf("\u2551 %-58s \u2551%n", line);
        }

        System.out.println("\u255A" + border + "\u255D");

        // Detected domains
        if (!detectedDomains.isEmpty()) {
            System.out.println();
            System.out.println("[Detected Domains/SNIs]");
            for (Map.Entry<String, String> entry : detectedDomains.entrySet()) {
                System.out.println("  - " + entry.getKey() + " -> " + entry.getValue());
            }
        }
    }
}
