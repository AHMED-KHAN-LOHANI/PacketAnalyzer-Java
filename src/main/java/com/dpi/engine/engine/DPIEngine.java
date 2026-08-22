package com.dpi.engine.engine;

import com.dpi.engine.dpi.HTTPHostExtractor;
import com.dpi.engine.dpi.SNIExtractor;
import com.dpi.engine.concurrent.FastPath;
import com.dpi.engine.concurrent.LoadBalancer;
import com.dpi.engine.concurrent.ThreadSafeQueue;
import com.dpi.engine.model.*;
import com.dpi.engine.pcap.PcapReader;
import com.dpi.engine.pcap.PcapWriter;
import com.dpi.engine.parser.PacketParser;
import com.dpi.engine.rules.RuleManager;

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Multi-threaded DPI Engine.
 * Architecture: Reader -> LB threads -> FP threads -> Output Writer
 * Ported from dpi_mt.cpp.
 */
public class DPIEngine {

    public static class Config {
        public int numLbs = 2;
        public int fpsPerLb = 2;
    }

    private final Config config;
    private final RuleManager rules = new RuleManager();
    private final Stats stats = new Stats();
    private final ThreadSafeQueue<Packet> outputQueue = new ThreadSafeQueue<>();
    private final List<FastPath> fps = new ArrayList<>();
    private final List<LoadBalancer> lbs = new ArrayList<>();

    public DPIEngine(Config cfg) {
        this.config = cfg;
        int totalFps = cfg.numLbs * cfg.fpsPerLb;

        System.out.println();
        System.out.println("\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557");
        System.out.printf("\u2551              DPI ENGINE v2.0 (Multi-threaded)                 \u2551%n");
        System.out.println("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563");
        System.out.printf("\u2551 Load Balancers: %2d    FPs per LB: %2d    Total FPs: %2d     \u2551%n",
                cfg.numLbs, cfg.fpsPerLb, totalFps);
        System.out.println("\u255A\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255D");
        System.out.println();

        // Create FP threads
        for (int i = 0; i < totalFps; i++) {
            fps.add(new FastPath(new ThreadSafeQueue<>(), outputQueue, rules, i, stats));
        }

        // Create LB threads, each managing a subset of FPs
        for (int lb = 0; lb < cfg.numLbs; lb++) {
            FastPath[] lbFps = new FastPath[cfg.fpsPerLb];
            int start = lb * cfg.fpsPerLb;
            for (int i = 0; i < cfg.fpsPerLb; i++) {
                lbFps[i] = fps.get(start + i);
            }
            lbs.add(new LoadBalancer(new ThreadSafeQueue<>(), lbFps, lb));
        }
    }

    public void blockIp(String ip) { rules.blockIp(ip); }
    public void blockApp(String app) { rules.blockApp(app); }
    public void blockDomain(String dom) { rules.blockDomain(dom); }

    public boolean process(String inputFile, String outputFile) throws Exception {
        PcapReader reader = new PcapReader();
        reader.open(inputFile);

        OutputStream output = new BufferedOutputStream(new FileOutputStream(outputFile), 65536);
        // Copy global header
        output.write(reader.getRawGlobalHeader());

        // Start all threads
        List<Thread> fpThreads = new ArrayList<>();
        for (FastPath fp : fps) {
            Thread t = new Thread(fp, "FP-" + fp.getFpIndex());
            t.start();
            fpThreads.add(t);
        }
        List<Thread> lbThreads = new ArrayList<>();
        for (LoadBalancer lb : lbs) {
            Thread t = new Thread(lb, "LB-" + lb.getLbIndex());
            t.start();
            lbThreads.add(t);
        }

        // Start output writer thread
        AtomicBoolean outputRunning = new AtomicBoolean(true);
        Thread outputThread = new Thread(() -> {
            while (outputRunning.get() || outputQueue.size() > 0) {
                try {
                    Packet pkt = outputQueue.tryPop();
                    if (pkt == null) {
                        Thread.sleep(50);
                        continue;
                    }
                    // Write packet header (16 bytes, little-endian)
                    ByteBuffer hb = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
                    hb.putInt(pkt.tsSec);
                    hb.putInt(pkt.tsUsec);
                    hb.putInt(pkt.data.length);
                    hb.putInt(pkt.data.length);
                    output.write(hb.array());
                    output.write(pkt.data);
                } catch (InterruptedException | IOException e) {
                    break;
                }
            }
        }, "OutputWriter");
        outputThread.start();

        // Read and dispatch packets
        System.out.println("[Reader] Processing packets...");
        int pktId = 0;

        RawPacket raw;
        while ((raw = reader.readNextPacket()) != null) {
            ParsedPacket parsed = new ParsedPacket();
            if (!PacketParser.parse(raw, parsed)) continue;
            if (!parsed.hasIpv4() || (!parsed.hasTcp() && !parsed.hasUdp())) continue;

            // Create Packet (self-contained)
            Packet pkt = new Packet();
            pkt.id = pktId++;
            pkt.tsSec = (int) raw.getTimestampSec();
            pkt.tsUsec = (int) raw.getTimestampUsec();
            pkt.data = raw.getData();

            // Parse five-tuple
            FiveTuple tuple = parsed.buildFiveTuple();
            pkt.tuple = tuple != null ? tuple : new FiveTuple(0,0,0,0,0);

            // Calculate payload offset (same as C++)
            byte[] rawData = pkt.data;
            pkt.payloadOffset = 14; // Ethernet
            if (rawData.length > 14) {
                int ipIhl = rawData[14] & 0x0F;
                pkt.payloadOffset += ipIhl * 4;

                if (parsed.hasTcp() && pkt.payloadOffset + 12 < rawData.length) {
                    int tcpOff = (rawData[pkt.payloadOffset + 12] >> 4) & 0x0F;
                    pkt.payloadOffset += tcpOff * 4;
                } else if (parsed.hasUdp()) {
                    pkt.payloadOffset += 8;
                }

                if (pkt.payloadOffset < rawData.length) {
                    pkt.payloadLength = rawData.length - pkt.payloadOffset;
                } else {
                    pkt.payloadLength = 0;
                }
            }

            // Update stats
            stats.totalPackets.incrementAndGet();
            stats.totalBytes.addAndGet(rawData.length);
            if (parsed.hasTcp()) stats.tcpPackets.incrementAndGet();
            else if (parsed.hasUdp()) stats.udpPackets.incrementAndGet();

            // Dispatch to LB (hash-based)
            int lbIdx = Math.abs(tuple.hashCode() % lbs.size());
            try {
                lbs.get(lbIdx).getInputQueue().push(pkt);
            } catch (InterruptedException e) {
                break;
            }
        }

        System.out.println("[Reader] Done reading " + pktId + " packets");
        reader.close();

        // Wait for queues to drain
        Thread.sleep(500);

        // Stop all threads
        for (LoadBalancer lb : lbs) lb.shutdown();
        for (FastPath fp : fps) fp.shutdown();

        // Join LB threads
        for (Thread t : lbThreads) t.join(5000);
        // Join FP threads
        for (Thread t : fpThreads) t.join(5000);

        outputRunning.set(false);
        outputQueue.shutdown();
        outputThread.join(5000);

        output.close();

        printReport(pktId);
        return true;
    }

    private void printReport(int totalPktId) {
        System.out.println();
        System.out.println("\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557");
        System.out.println("\u2551                      PROCESSING REPORT                        \u2551");
        System.out.println("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563");
        System.out.printf("\u2551 Total Packets:      %12d                           \u2551%n", stats.totalPackets.get());
        System.out.printf("\u2551 Total Bytes:        %12d                           \u2551%n", stats.totalBytes.get());
        System.out.printf("\u2551 TCP Packets:        %12d                           \u2551%n", stats.tcpPackets.get());
        System.out.printf("\u2551 UDP Packets:        %12d                           \u2551%n", stats.udpPackets.get());
        System.out.println("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563");
        System.out.printf("\u2551 Forwarded:          %12d                           \u2551%n", stats.forwarded.get());
        System.out.printf("\u2551 Dropped:            %12d                           \u2551%n", stats.dropped.get());

        // Thread stats
        System.out.println("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563");
        System.out.println("\u2551 THREAD STATISTICS                                             \u2551");
        for (int i = 0; i < lbs.size(); i++) {
            System.out.printf("\u2551   LB%d dispatched:   %12d                           \u2551%n", i, lbs.get(i).getDispatched());
        }
        for (int i = 0; i < fps.size(); i++) {
            System.out.printf("\u2551   FP%d processed:    %12d                           \u2551%n", i, fps.get(i).getProcessed());
        }

        // App breakdown
        System.out.println("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563");
        System.out.println("\u2551                   APPLICATION BREAKDOWN                       \u2551");
        System.out.println("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563");

        // Aggregate app stats from all FPs
        Map<AppType, Long> appCounts = new HashMap<>();
        Map<String, AppType> detectedSnis = new TreeMap<>();
        for (FastPath fp : fps) {
            fp.getAppStats().forEach((k, v) -> appCounts.merge(k, v, Long::sum));
            detectedSnis.putAll(fp.getDetectedDomains());
        }

        List<Map.Entry<AppType, Long>> sorted = new ArrayList<>(appCounts.entrySet());
        sorted.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));

        long total = stats.totalPackets.get();
        for (Map.Entry<AppType, Long> entry : sorted) {
            double pct = total > 0 ? 100.0 * entry.getValue() / total : 0;
            int bar = (int) (pct / 5);
            String barStr = "#".repeat(Math.max(bar, 0));
            System.out.printf("\u2551 %-15s %8d %5.1f%% %-20s  \u2551%n",
                    entry.getKey().getDisplayName(), entry.getValue(), pct, barStr);
        }

        System.out.println("\u255A\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255D");

        if (!detectedSnis.isEmpty()) {
            System.out.println();
            System.out.println("[Detected Domains/SNIs]");
            for (Map.Entry<String, AppType> entry : detectedSnis.entrySet()) {
                System.out.println("  - " + entry.getKey() + " -> " + entry.getValue().getDisplayName());
            }
        }
    }

    /**
     * Thread-safe statistics accumulator.
     */
    public static class Stats {
        public final AtomicLong totalPackets = new AtomicLong(0);
        public final AtomicLong totalBytes = new AtomicLong(0);
        public final AtomicLong forwarded = new AtomicLong(0);
        public final AtomicLong dropped = new AtomicLong(0);
        public final AtomicLong tcpPackets = new AtomicLong(0);
        public final AtomicLong udpPackets = new AtomicLong(0);
    }
}
