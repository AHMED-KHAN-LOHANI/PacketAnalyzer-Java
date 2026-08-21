/*
 * Decompiled with CFR 0.152.
 */
package com.dpi.engine.engine;

import com.dpi.engine.concurrent.FastPath;
import com.dpi.engine.concurrent.LoadBalancer;
import com.dpi.engine.concurrent.ThreadSafeQueue;
import com.dpi.engine.model.AppType;
import com.dpi.engine.model.FiveTuple;
import com.dpi.engine.model.Packet;
import com.dpi.engine.model.ParsedPacket;
import com.dpi.engine.model.RawPacket;
import com.dpi.engine.parser.PacketParser;
import com.dpi.engine.pcap.PcapReader;
import com.dpi.engine.rules.RuleManager;
import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

public class DPIEngine {
    private final Config config;
    private final RuleManager rules = new RuleManager();
    private final Stats stats = new Stats();
    private final ThreadSafeQueue<Packet> outputQueue = new ThreadSafeQueue();
    private final List<FastPath> fps = new ArrayList<FastPath>();
    private final List<LoadBalancer> lbs = new ArrayList<LoadBalancer>();

    public DPIEngine(Config cfg) {
        this.config = cfg;
        int totalFps = cfg.numLbs * cfg.fpsPerLb;
        System.out.println();
        System.out.println("\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557");
        System.out.printf("\u2551              DPI ENGINE v2.0 (Multi-threaded)                 \u2551%n", new Object[0]);
        System.out.println("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563");
        System.out.printf("\u2551 Load Balancers: %2d    FPs per LB: %2d    Total FPs: %2d     \u2551%n", cfg.numLbs, cfg.fpsPerLb, totalFps);
        System.out.println("\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d");
        System.out.println();
        for (int i = 0; i < totalFps; ++i) {
            this.fps.add(new FastPath(new ThreadSafeQueue<Packet>(), this.outputQueue, this.rules, i, this.stats));
        }
        for (int lb = 0; lb < cfg.numLbs; ++lb) {
            FastPath[] lbFps = new FastPath[cfg.fpsPerLb];
            int start = lb * cfg.fpsPerLb;
            for (int i = 0; i < cfg.fpsPerLb; ++i) {
                lbFps[i] = this.fps.get(start + i);
            }
            this.lbs.add(new LoadBalancer(new ThreadSafeQueue<Packet>(), lbFps, lb));
        }
    }

    public void blockIp(String ip) {
        this.rules.blockIp(ip);
    }

    public void blockApp(String app) {
        this.rules.blockApp(app);
    }

    public void blockDomain(String dom) {
        this.rules.blockDomain(dom);
    }

    public boolean process(String inputFile, String outputFile) throws Exception {
        RawPacket raw;
        PcapReader reader = new PcapReader();
        reader.open(inputFile);
        BufferedOutputStream output = new BufferedOutputStream(new FileOutputStream(outputFile), 65536);
        ((OutputStream)output).write(reader.getRawGlobalHeader());
        ArrayList<Thread> fpThreads = new ArrayList<Thread>();
        for (FastPath fastPath : this.fps) {
            Thread t = new Thread((Runnable)fastPath, "FP-" + fastPath.getFpIndex());
            t.start();
            fpThreads.add(t);
        }
        ArrayList<Thread> lbThreads = new ArrayList<Thread>();
        for (LoadBalancer lb : this.lbs) {
            Thread t = new Thread((Runnable)lb, "LB-" + lb.getLbIndex());
            t.start();
            lbThreads.add(t);
        }
        AtomicBoolean atomicBoolean = new AtomicBoolean(true);
        Thread outputThread = new Thread(() -> {
            while (outputRunning.get() || this.outputQueue.size() > 0) {
                try {
                    Packet pkt = this.outputQueue.tryPop();
                    if (pkt == null) {
                        Thread.sleep(50L);
                        continue;
                    }
                    ByteBuffer hb = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
                    hb.putInt(pkt.tsSec);
                    hb.putInt(pkt.tsUsec);
                    hb.putInt(pkt.data.length);
                    hb.putInt(pkt.data.length);
                    output.write(hb.array());
                    output.write(pkt.data);
                }
                catch (IOException | InterruptedException e) {
                    break;
                }
            }
        }, "OutputWriter");
        outputThread.start();
        System.out.println("[Reader] Processing packets...");
        int pktId = 0;
        while ((raw = reader.readNextPacket()) != null) {
            ParsedPacket parsed = new ParsedPacket();
            if (!PacketParser.parse(raw, parsed) || !parsed.hasIpv4() || !parsed.hasTcp() && !parsed.hasUdp()) continue;
            Packet pkt = new Packet();
            pkt.id = pktId++;
            pkt.tsSec = (int)raw.getTimestampSec();
            pkt.tsUsec = (int)raw.getTimestampUsec();
            pkt.data = raw.getData();
            FiveTuple tuple = parsed.buildFiveTuple();
            pkt.tuple = tuple != null ? tuple : new FiveTuple(0, 0, 0, 0, 0);
            byte[] rawData = pkt.data;
            pkt.payloadOffset = 14;
            if (rawData.length > 14) {
                int ipIhl = rawData[14] & 0xF;
                pkt.payloadOffset += ipIhl * 4;
                if (parsed.hasTcp() && pkt.payloadOffset + 12 < rawData.length) {
                    int tcpOff = rawData[pkt.payloadOffset + 12] >> 4 & 0xF;
                    pkt.payloadOffset += tcpOff * 4;
                } else if (parsed.hasUdp()) {
                    pkt.payloadOffset += 8;
                }
                pkt.payloadLength = pkt.payloadOffset < rawData.length ? rawData.length - pkt.payloadOffset : 0;
            }
            this.stats.totalPackets.incrementAndGet();
            this.stats.totalBytes.addAndGet(rawData.length);
            if (parsed.hasTcp()) {
                this.stats.tcpPackets.incrementAndGet();
            } else if (parsed.hasUdp()) {
                this.stats.udpPackets.incrementAndGet();
            }
            int lbIdx = Math.abs(tuple.hashCode() % this.lbs.size());
            try {
                this.lbs.get(lbIdx).getInputQueue().push(pkt);
            }
            catch (InterruptedException e) {
                break;
            }
        }
        System.out.println("[Reader] Done reading " + pktId + " packets");
        reader.close();
        Thread.sleep(500L);
        for (LoadBalancer lb : this.lbs) {
            lb.shutdown();
        }
        for (FastPath fp : this.fps) {
            fp.shutdown();
        }
        for (Thread t : lbThreads) {
            t.join(5000L);
        }
        for (Thread t : fpThreads) {
            t.join(5000L);
        }
        atomicBoolean.set(false);
        this.outputQueue.shutdown();
        outputThread.join(5000L);
        ((OutputStream)output).close();
        this.printReport(pktId);
        return true;
    }

    private void printReport(int totalPktId) {
        int i;
        System.out.println();
        System.out.println("\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557");
        System.out.println("\u2551                      PROCESSING REPORT                        \u2551");
        System.out.println("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563");
        System.out.printf("\u2551 Total Packets:      %12d                           \u2551%n", this.stats.totalPackets.get());
        System.out.printf("\u2551 Total Bytes:        %12d                           \u2551%n", this.stats.totalBytes.get());
        System.out.printf("\u2551 TCP Packets:        %12d                           \u2551%n", this.stats.tcpPackets.get());
        System.out.printf("\u2551 UDP Packets:        %12d                           \u2551%n", this.stats.udpPackets.get());
        System.out.println("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563");
        System.out.printf("\u2551 Forwarded:          %12d                           \u2551%n", this.stats.forwarded.get());
        System.out.printf("\u2551 Dropped:            %12d                           \u2551%n", this.stats.dropped.get());
        System.out.println("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563");
        System.out.println("\u2551 THREAD STATISTICS                                             \u2551");
        for (i = 0; i < this.lbs.size(); ++i) {
            System.out.printf("\u2551   LB%d dispatched:   %12d                           \u2551%n", i, this.lbs.get(i).getDispatched());
        }
        for (i = 0; i < this.fps.size(); ++i) {
            System.out.printf("\u2551   FP%d processed:    %12d                           \u2551%n", i, this.fps.get(i).getProcessed());
        }
        System.out.println("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563");
        System.out.println("\u2551                   APPLICATION BREAKDOWN                       \u2551");
        System.out.println("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563");
        HashMap appCounts = new HashMap();
        TreeMap<String, AppType> detectedSnis = new TreeMap<String, AppType>();
        for (FastPath fp : this.fps) {
            fp.getAppStats().forEach((k, v) -> appCounts.merge(k, v, Long::sum));
            detectedSnis.putAll(fp.getDetectedDomains());
        }
        ArrayList sorted = new ArrayList(appCounts.entrySet());
        sorted.sort((a, b) -> Long.compare((Long)b.getValue(), (Long)a.getValue()));
        long total = this.stats.totalPackets.get();
        for (Map.Entry entry : sorted) {
            double pct = total > 0L ? 100.0 * (double)((Long)entry.getValue()).longValue() / (double)total : 0.0;
            int bar = (int)(pct / 5.0);
            String barStr = "#".repeat(Math.max(bar, 0));
            System.out.printf("\u2551 %-15s %8d %5.1f%% %-20s  \u2551%n", ((AppType)((Object)entry.getKey())).getDisplayName(), entry.getValue(), pct, barStr);
        }
        System.out.println("\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d");
        if (!detectedSnis.isEmpty()) {
            System.out.println();
            System.out.println("[Detected Domains/SNIs]");
            for (Map.Entry entry : detectedSnis.entrySet()) {
                System.out.println("  - " + (String)entry.getKey() + " -> " + ((AppType)((Object)entry.getValue())).getDisplayName());
            }
        }
    }

    public static class Stats {
        public final AtomicLong totalPackets = new AtomicLong(0L);
        public final AtomicLong totalBytes = new AtomicLong(0L);
        public final AtomicLong forwarded = new AtomicLong(0L);
        public final AtomicLong dropped = new AtomicLong(0L);
        public final AtomicLong tcpPackets = new AtomicLong(0L);
        public final AtomicLong udpPackets = new AtomicLong(0L);
    }

    public static class Config {
        public int numLbs = 2;
        public int fpsPerLb = 2;
    }
}

