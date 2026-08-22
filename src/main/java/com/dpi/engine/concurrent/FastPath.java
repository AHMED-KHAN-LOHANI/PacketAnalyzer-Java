package com.dpi.engine.concurrent;

import com.dpi.engine.dpi.HTTPHostExtractor;
import com.dpi.engine.dpi.SNIExtractor;
import com.dpi.engine.model.*;
import com.dpi.engine.engine.DPIEngine;
import com.dpi.engine.rules.RuleManager;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Fast Path thread - performs the actual DPI processing.
 * Each FP has its own flow table so no synchronization is needed for flow lookups.
 * Consistent hashing ensures all packets of a flow arrive at the same FP.
 * Ported from the C++ FastPath class in dpi_mt.cpp.
 */
public class FastPath implements Runnable {

    private final ThreadSafeQueue<Packet> inputQueue;
    private final ThreadSafeQueue<Packet> outputQueue;
    private final RuleManager rules;
    private final DPIEngine.Stats stats;
    private final int fpIndex;
    private volatile boolean running = true;
    private final AtomicLong processed = new AtomicLong(0);

    // Each FP has its own flow table (no lock needed)
    private final Map<FiveTuple, FlowEntry> flows = new HashMap<>();

    // Stats shared with report
    private final Map<AppType, Long> appStats = new ConcurrentHashMap<>();
    private final Map<String, AppType> detectedDomains = new ConcurrentHashMap<>();

    public FastPath(ThreadSafeQueue<Packet> inputQueue,
                    ThreadSafeQueue<Packet> outputQueue,
                    RuleManager ruleManager,
                    int fpIndex,
                    DPIEngine.Stats stats) {
        this.inputQueue = inputQueue;
        this.outputQueue = outputQueue;
        this.rules = ruleManager;
        this.fpIndex = fpIndex;
        this.stats = stats;
    }

    public ThreadSafeQueue<Packet> getInputQueue() { return inputQueue; }
    public long getProcessed() { return processed.get(); }
    public int getFpIndex() { return fpIndex; }
    public Map<AppType, Long> getAppStats() { return appStats; }
    public Map<String, AppType> getDetectedDomains() { return detectedDomains; }

    @Override
    public void run() {
        while (running) {
            try {
                Packet pkt = inputQueue.pop(100);
                if (pkt == null) continue;

                processed.incrementAndGet();

                // Get or create flow
                FlowEntry flow = flows.computeIfAbsent(pkt.tuple, FlowEntry::new);
                flow.packets++;
                flow.bytes += pkt.data.length;

                // Try to classify if not done yet
                if (!flow.classified) {
                    classifyFlow(pkt, flow);
                }

                // Check blocking
                if (!flow.blocked) {
                    flow.blocked = rules.isBlocked(
                            FiveTuple.ipToString(pkt.tuple.getSrcIp()),
                            flow.appType, flow.sni);
                }

                // Record app stats
                synchronized (appStats) {
                    appStats.merge(flow.appType, 1L, Long::sum);
                    if (!flow.sni.isEmpty()) {
                        detectedDomains.put(flow.sni, flow.appType);
                    }
                }

                // Forward or drop
                if (flow.blocked) {
                    stats.dropped.incrementAndGet();
                } else {
                    stats.forwarded.incrementAndGet();
                    outputQueue.push(pkt);
                }

            } catch (InterruptedException e) {
                break;
            }
        }
    }

    private void classifyFlow(Packet pkt, FlowEntry flow) {
        // Try SNI extraction for HTTPS
        if (pkt.tuple.getDstPort() == 443 && pkt.payloadLength > 5) {
            byte[] payload = new byte[pkt.payloadLength];
            System.arraycopy(pkt.data, pkt.payloadOffset, payload, 0, pkt.payloadLength);
            String sni = SNIExtractor.extract(payload, pkt.payloadLength);
            if (sni != null) {
                flow.sni = sni;
                flow.appType = AppType.fromSNI(sni);
                flow.classified = true;
                return;
            }
        }

        // Try HTTP Host extraction
        if (pkt.tuple.getDstPort() == 80 && pkt.payloadLength > 10) {
            byte[] payload = new byte[pkt.payloadLength];
            System.arraycopy(pkt.data, pkt.payloadOffset, payload, 0, pkt.payloadLength);
            String host = HTTPHostExtractor.extract(payload, pkt.payloadLength);
            if (host != null) {
                flow.sni = host;
                flow.appType = AppType.fromSNI(host);
                flow.classified = true;
                return;
            }
        }

        // DNS
        if (pkt.tuple.getDstPort() == 53 || pkt.tuple.getSrcPort() == 53) {
            flow.appType = AppType.DNS;
            flow.classified = true;
            return;
        }

        // Port-based fallback (don't mark classified - might get SNI later)
        if (pkt.tuple.getDstPort() == 443) {
            flow.appType = AppType.HTTPS;
        } else if (pkt.tuple.getDstPort() == 80) {
            flow.appType = AppType.HTTP;
        }
    }

    public void shutdown() {
        running = false;
        inputQueue.shutdown();
    }

    /** Flow entry matching the C++ FlowEntry in dpi_mt.cpp. */
    public static class FlowEntry {
        FiveTuple tuple;
        AppType appType = AppType.UNKNOWN;
        String sni = "";
        long packets = 0;
        long bytes = 0;
        boolean blocked = false;
        boolean classified = false;

        FlowEntry(FiveTuple tuple) { this.tuple = tuple; }
    }
}
