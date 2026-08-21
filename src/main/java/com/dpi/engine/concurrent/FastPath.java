/*
 * Decompiled with CFR 0.152.
 */
package com.dpi.engine.concurrent;

import com.dpi.engine.concurrent.ThreadSafeQueue;
import com.dpi.engine.dpi.HTTPHostExtractor;
import com.dpi.engine.dpi.SNIExtractor;
import com.dpi.engine.engine.DPIEngine;
import com.dpi.engine.model.AppType;
import com.dpi.engine.model.FiveTuple;
import com.dpi.engine.model.Packet;
import com.dpi.engine.rules.RuleManager;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

public class FastPath
implements Runnable {
    private final ThreadSafeQueue<Packet> inputQueue;
    private final ThreadSafeQueue<Packet> outputQueue;
    private final RuleManager rules;
    private final DPIEngine.Stats stats;
    private final int fpIndex;
    private volatile boolean running = true;
    private final AtomicLong processed = new AtomicLong(0L);
    private final Map<FiveTuple, FlowEntry> flows = new HashMap<FiveTuple, FlowEntry>();
    private final Map<AppType, Long> appStats = new ConcurrentHashMap<AppType, Long>();
    private final Map<String, AppType> detectedDomains = new ConcurrentHashMap<String, AppType>();

    public FastPath(ThreadSafeQueue<Packet> inputQueue, ThreadSafeQueue<Packet> outputQueue, RuleManager ruleManager, int fpIndex, DPIEngine.Stats stats) {
        this.inputQueue = inputQueue;
        this.outputQueue = outputQueue;
        this.rules = ruleManager;
        this.fpIndex = fpIndex;
        this.stats = stats;
    }

    public ThreadSafeQueue<Packet> getInputQueue() {
        return this.inputQueue;
    }

    public long getProcessed() {
        return this.processed.get();
    }

    public int getFpIndex() {
        return this.fpIndex;
    }

    public Map<AppType, Long> getAppStats() {
        return this.appStats;
    }

    public Map<String, AppType> getDetectedDomains() {
        return this.detectedDomains;
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    @Override
    public void run() {
        while (this.running) {
            try {
                Packet pkt = this.inputQueue.pop(100);
                if (pkt == null) continue;
                this.processed.incrementAndGet();
                FlowEntry flow = this.flows.computeIfAbsent(pkt.tuple, FlowEntry::new);
                ++flow.packets;
                flow.bytes += (long)pkt.data.length;
                if (!flow.classified) {
                    this.classifyFlow(pkt, flow);
                }
                if (!flow.blocked) {
                    flow.blocked = this.rules.isBlocked(FiveTuple.ipToString(pkt.tuple.getSrcIp()), flow.appType, flow.sni);
                }
                Map<AppType, Long> map = this.appStats;
                synchronized (map) {
                    this.appStats.merge(flow.appType, 1L, Long::sum);
                    if (!flow.sni.isEmpty()) {
                        this.detectedDomains.put(flow.sni, flow.appType);
                    }
                }
                if (flow.blocked) {
                    this.stats.dropped.incrementAndGet();
                    continue;
                }
                this.stats.forwarded.incrementAndGet();
                this.outputQueue.push(pkt);
            }
            catch (InterruptedException e) {
                break;
            }
        }
    }

    private void classifyFlow(Packet pkt, FlowEntry flow) {
        byte[] payload;
        if (pkt.tuple.getDstPort() == 443 && pkt.payloadLength > 5) {
            payload = new byte[pkt.payloadLength];
            System.arraycopy(pkt.data, pkt.payloadOffset, payload, 0, pkt.payloadLength);
            String sni = SNIExtractor.extract(payload, pkt.payloadLength);
            if (sni != null) {
                flow.sni = sni;
                flow.appType = AppType.fromSNI(sni);
                flow.classified = true;
                return;
            }
        }
        if (pkt.tuple.getDstPort() == 80 && pkt.payloadLength > 10) {
            payload = new byte[pkt.payloadLength];
            System.arraycopy(pkt.data, pkt.payloadOffset, payload, 0, pkt.payloadLength);
            String host = HTTPHostExtractor.extract(payload, pkt.payloadLength);
            if (host != null) {
                flow.sni = host;
                flow.appType = AppType.fromSNI(host);
                flow.classified = true;
                return;
            }
        }
        if (pkt.tuple.getDstPort() == 53 || pkt.tuple.getSrcPort() == 53) {
            flow.appType = AppType.DNS;
            flow.classified = true;
            return;
        }
        if (pkt.tuple.getDstPort() == 443) {
            flow.appType = AppType.HTTPS;
        } else if (pkt.tuple.getDstPort() == 80) {
            flow.appType = AppType.HTTP;
        }
    }

    public void shutdown() {
        this.running = false;
        this.inputQueue.shutdown();
    }

    public static class FlowEntry {
        FiveTuple tuple;
        AppType appType = AppType.UNKNOWN;
        String sni = "";
        long packets = 0L;
        long bytes = 0L;
        boolean blocked = false;
        boolean classified = false;

        FlowEntry(FiveTuple tuple) {
            this.tuple = tuple;
        }
    }
}

