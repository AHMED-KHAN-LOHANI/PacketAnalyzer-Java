/*
 * Decompiled with CFR 0.152.
 */
package com.dpi.engine.simple;

import com.dpi.engine.dpi.HTTPHostExtractor;
import com.dpi.engine.dpi.SNIExtractor;
import com.dpi.engine.model.AppType;
import com.dpi.engine.model.FiveTuple;
import com.dpi.engine.model.ParsedPacket;
import com.dpi.engine.model.RawPacket;
import com.dpi.engine.parser.PacketParser;
import com.dpi.engine.pcap.PcapReader;
import com.dpi.engine.pcap.PcapWriter;
import com.dpi.engine.rules.RuleManager;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

public class SimpleDPI {
    public static void run(String inputFile, String outputFile, RuleManager rules) throws Exception {
        RawPacket raw;
        System.out.println();
        System.out.println("\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557");
        System.out.println("\u2551                    DPI ENGINE v1.0                            \u2551");
        System.out.println("\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d");
        System.out.println();
        PcapReader reader = new PcapReader();
        reader.open(inputFile);
        PcapWriter writer = new PcapWriter(outputFile, reader);
        LinkedHashMap<FiveTuple, FlowEntry> flows = new LinkedHashMap<FiveTuple, FlowEntry>();
        long totalPackets = 0L;
        long forwarded = 0L;
        long dropped = 0L;
        HashMap<AppType, Long> appStats = new HashMap<AppType, Long>();
        System.out.println("[DPI] Processing packets...");
        while ((raw = reader.readNextPacket()) != null) {
            int payloadLen;
            int tcpOff;
            int ipIhl;
            int payloadOffset;
            FiveTuple tuple;
            ++totalPackets;
            ParsedPacket parsed = new ParsedPacket();
            if (!PacketParser.parse(raw, parsed) || !parsed.hasIpv4() || !parsed.hasTcp() && !parsed.hasUdp() || (tuple = parsed.buildFiveTuple()) == null) continue;
            FlowEntry flowEntry = flows.computeIfAbsent(tuple, FlowEntry::new);
            ++flowEntry.packets;
            flowEntry.bytes += (long)raw.getData().length;
            byte[] rawData = raw.getData();
            if ((flowEntry.appType == AppType.UNKNOWN || flowEntry.appType == AppType.HTTPS) && flowEntry.sni.isEmpty() && parsed.hasTcp() && parsed.getDestPort() == 443) {
                String sni;
                payloadOffset = 14;
                ipIhl = rawData[14] & 0xF;
                if ((payloadOffset += ipIhl * 4) + 12 < rawData.length && (payloadOffset += (tcpOff = rawData[payloadOffset + 12] >> 4 & 0xF) * 4) < rawData.length && (payloadLen = rawData.length - payloadOffset) > 5 && (sni = SNIExtractor.extract(Arrays.copyOfRange(rawData, payloadOffset, rawData.length), payloadLen)) != null) {
                    flowEntry.sni = sni;
                    flowEntry.appType = AppType.fromSNI(sni);
                }
            }
            if ((flowEntry.appType == AppType.UNKNOWN || flowEntry.appType == AppType.HTTP) && flowEntry.sni.isEmpty() && parsed.hasTcp() && parsed.getDestPort() == 80) {
                payloadOffset = 14;
                ipIhl = rawData[14] & 0xF;
                if ((payloadOffset += ipIhl * 4) + 12 < rawData.length && (payloadOffset += (tcpOff = rawData[payloadOffset + 12] >> 4 & 0xF) * 4) < rawData.length) {
                    payloadLen = rawData.length - payloadOffset;
                    String host = HTTPHostExtractor.extract(Arrays.copyOfRange(rawData, payloadOffset, rawData.length), payloadLen);
                    if (host != null) {
                        flowEntry.sni = host;
                        flowEntry.appType = AppType.fromSNI(host);
                    }
                }
            }
            if (flowEntry.appType == AppType.UNKNOWN && (parsed.getDestPort() == 53 || parsed.getSrcPort() == 53)) {
                flowEntry.appType = AppType.DNS;
            }
            if (flowEntry.appType == AppType.UNKNOWN) {
                if (parsed.getDestPort() == 443) {
                    flowEntry.appType = AppType.HTTPS;
                } else if (parsed.getDestPort() == 80) {
                    flowEntry.appType = AppType.HTTP;
                }
            }
            if (!flowEntry.blocked) {
                flowEntry.blocked = rules.isBlocked(parsed.getSrcIp() != null ? parsed.getSrcIp() : "", flowEntry.appType, flowEntry.sni);
                if (flowEntry.blocked) {
                    System.out.println("[BLOCKED] " + parsed.getSrcIp() + " -> " + parsed.getDestIp() + " (" + flowEntry.appType.getDisplayName() + (String)(!flowEntry.sni.isEmpty() ? ": " + flowEntry.sni : "") + ")");
                }
            }
            appStats.merge(flowEntry.appType, 1L, Long::sum);
            if (flowEntry.blocked) {
                ++dropped;
                continue;
            }
            ++forwarded;
            writer.writeRaw(raw.getTimestampSec(), raw.getTimestampUsec(), raw.getOrigLen(), raw.getData());
        }
        reader.close();
        writer.close();
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
        ArrayList<Map.Entry<AppType, Long>> sorted = new ArrayList<>(appStats.entrySet());
        sorted.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));
        for (Map.Entry<AppType, Long> entry : sorted) {
            double pct = totalPackets > 0L ? 100.0 * (double)((Long)entry.getValue()).longValue() / (double)totalPackets : 0.0;
            int barLen = (int)(pct / 5.0);
            String bar = "#".repeat(Math.max(barLen, 0));
            String name = String.format("%-15s", entry.getKey().getDisplayName());
            String count = String.format("%8d", entry.getValue());
            System.out.printf("\u2551 %s %s %5.1f%% %-20s  \u2551%n", name, count, pct, bar);
        }
        System.out.println("\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d");
        System.out.println();
        System.out.println("[Detected Applications/Domains]");
        for (FlowEntry flowEntry : flows.values()) {
            if (flowEntry.sni.isEmpty()) continue;
            System.out.println("  - " + flowEntry.sni + " -> " + flowEntry.appType.getDisplayName());
        }
        System.out.println();
        System.out.println("Output written to: " + outputFile);
    }

    public static class FlowEntry {
        FiveTuple tuple;
        AppType appType = AppType.UNKNOWN;
        String sni = "";
        long packets = 0L;
        long bytes = 0L;
        boolean blocked = false;

        FlowEntry(FiveTuple tuple) {
            this.tuple = tuple;
        }
    }
}

