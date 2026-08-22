package com.dpi.engine.simple;

import com.dpi.engine.dpi.HTTPHostExtractor;
import com.dpi.engine.dpi.SNIExtractor;
import com.dpi.engine.model.*;
import com.dpi.engine.pcap.PcapReader;
import com.dpi.engine.pcap.PcapWriter;
import com.dpi.engine.parser.PacketParser;
import com.dpi.engine.rules.RuleManager;

import java.util.*;

/**
 * Single-threaded DPI engine.
 * Ported from main_working.cpp - processes packets one at a time.
 */
public class SimpleDPI {

    public static void run(String inputFile, String outputFile, RuleManager rules) throws Exception {
        System.out.println();
        System.out.println("\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557");
        System.out.println("\u2551                    DPI ENGINE v1.0                            \u2551");
        System.out.println("\u255A\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255D");
        System.out.println();

        PcapReader reader = new PcapReader();
        reader.open(inputFile);

        PcapWriter writer = new PcapWriter(outputFile, reader);

        // Flow table: FiveTuple -> Flow
        Map<FiveTuple, FlowEntry> flows = new LinkedHashMap<>();

        long totalPackets = 0;
        long forwarded = 0;
        long dropped = 0;
        Map<AppType, Long> appStats = new HashMap<>();

        System.out.println("[DPI] Processing packets...");

        RawPacket raw;
        while ((raw = reader.readNextPacket()) != null) {
            totalPackets++;

            ParsedPacket parsed = new ParsedPacket();
            if (!PacketParser.parse(raw, parsed)) continue;
            if (!parsed.hasIpv4() || (!parsed.hasTcp() && !parsed.hasUdp())) continue;

            // Create five-tuple
            FiveTuple tuple = parsed.buildFiveTuple();
            if (tuple == null) continue;

            // Get or create flow
            FlowEntry flow = flows.computeIfAbsent(tuple, FlowEntry::new);
            flow.packets++;
            flow.bytes += raw.getData().length;

            byte[] rawData = raw.getData();

            // --- SNI extraction for HTTPS ---
            if ((flow.appType == AppType.UNKNOWN || flow.appType == AppType.HTTPS)
                    && flow.sni.isEmpty() && parsed.hasTcp() && parsed.getDestPort() == 443) {

                int payloadOffset = 14; // Ethernet
                int ipIhl = rawData[14] & 0x0F;
                payloadOffset += ipIhl * 4;

                if (payloadOffset + 12 < rawData.length) {
                    int tcpOff = (rawData[payloadOffset + 12] >> 4) & 0x0F;
                    payloadOffset += tcpOff * 4;

                    if (payloadOffset < rawData.length) {
                        int payloadLen = rawData.length - payloadOffset;
                        if (payloadLen > 5) {
                            String sni = SNIExtractor.extract(
                                    java.util.Arrays.copyOfRange(rawData, payloadOffset, rawData.length),
                                    payloadLen);
                            if (sni != null) {
                                flow.sni = sni;
                                flow.appType = AppType.fromSNI(sni);
                            }
                        }
                    }
                }
            }

            // --- HTTP Host extraction ---
            if ((flow.appType == AppType.UNKNOWN || flow.appType == AppType.HTTP)
                    && flow.sni.isEmpty() && parsed.hasTcp() && parsed.getDestPort() == 80) {

                int payloadOffset = 14;
                int ipIhl = rawData[14] & 0x0F;
                payloadOffset += ipIhl * 4;

                if (payloadOffset + 12 < rawData.length) {
                    int tcpOff = (rawData[payloadOffset + 12] >> 4) & 0x0F;
                    payloadOffset += tcpOff * 4;

                    if (payloadOffset < rawData.length) {
                        int payloadLen = rawData.length - payloadOffset;
                        String host = HTTPHostExtractor.extract(
                                java.util.Arrays.copyOfRange(rawData, payloadOffset, rawData.length),
                                payloadLen);
                        if (host != null) {
                            flow.sni = host;
                            flow.appType = AppType.fromSNI(host);
                        }
                    }
                }
            }

            // --- DNS classification ---
            if (flow.appType == AppType.UNKNOWN
                    && (parsed.getDestPort() == 53 || parsed.getSrcPort() == 53)) {
                flow.appType = AppType.DNS;
            }

            // --- Port-based fallback ---
            if (flow.appType == AppType.UNKNOWN) {
                if (parsed.getDestPort() == 443) flow.appType = AppType.HTTPS;
                else if (parsed.getDestPort() == 80) flow.appType = AppType.HTTP;
            }

            // --- Check blocking rules ---
            if (!flow.blocked) {
                flow.blocked = rules.isBlocked(
                        parsed.getSrcIp() != null ? parsed.getSrcIp() : "",
                        flow.appType, flow.sni);
                if (flow.blocked) {
                    System.out.println("[BLOCKED] " + parsed.getSrcIp() + " -> " + parsed.getDestIp()
                            + " (" + flow.appType.getDisplayName()
                            + (!flow.sni.isEmpty() ? ": " + flow.sni : "") + ")");
                }
            }

            // Update app stats
            appStats.merge(flow.appType, 1L, Long::sum);

            // Forward or drop
            if (flow.blocked) {
                dropped++;
            } else {
                forwarded++;
                writer.writeRaw(raw.getTimestampSec(), raw.getTimestampUsec(),
                        raw.getOrigLen(), raw.getData());
            }
        }

        reader.close();
        writer.close();

        // --- Print report (matches C++ output) ---
        System.out.println();
        System.out.println("\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557");
        System.out.println("\u2551                      PROCESSING REPORT                       \u2551");
        System.out.println("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563");
        System.out.printf("\u2551 Total Packets:      %10d                             \u2551%n", totalPackets);
        System.out.printf("\u2551 Forwarded:          %10d                             \u2551%n", forwarded);
        System.out.printf("\u2551 Dropped:            %10d                             \u2551%n", dropped);
        System.out.printf("\u2551 Active Flows:       %10d                             \u2551%n", flows.size());
        System.out.println("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563");
        System.out.println("\u2551                    APPLICATION BREAKDOWN                     \u2551");
        System.out.println("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563");

        // Sort by count descending
        List<Map.Entry<AppType, Long>> sorted = new ArrayList<>(appStats.entrySet());
        sorted.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));

        for (Map.Entry<AppType, Long> entry : sorted) {
            double pct = totalPackets > 0 ? 100.0 * entry.getValue() / totalPackets : 0;
            int barLen = (int) (pct / 5);
            String bar = "#".repeat(Math.max(barLen, 0));
            String name = String.format("%-15s", entry.getKey().getDisplayName());
            String count = String.format("%8d", entry.getValue());
            System.out.printf("\u2551 %s %s %5.1f%% %-20s  \u2551%n", name, count, pct, bar);
        }

        System.out.println("\u255A\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255D");

        // Unique SNIs
        System.out.println();
        System.out.println("[Detected Applications/Domains]");
        for (FlowEntry f : flows.values()) {
            if (!f.sni.isEmpty()) {
                System.out.println("  - " + f.sni + " -> " + f.appType.getDisplayName());
            }
        }

        System.out.println();
        System.out.println("Output written to: " + outputFile);
    }

    /**
     * Simple flow entry matching the C++ Flow struct in main_working.cpp.
     */
    public static class FlowEntry {
        FiveTuple tuple;
        AppType appType = AppType.UNKNOWN;
        String sni = "";
        long packets = 0;
        long bytes = 0;
        boolean blocked = false;

        FlowEntry(FiveTuple tuple) { this.tuple = tuple; }
    }
}
