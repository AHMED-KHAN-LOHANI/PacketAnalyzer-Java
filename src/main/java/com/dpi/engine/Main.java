/*
 * Decompiled with CFR 0.152.
 */
package com.dpi.engine;

import com.dpi.engine.engine.DPIEngine;
import com.dpi.engine.rules.RuleManager;
import com.dpi.engine.simple.SimpleDPI;
import java.util.ArrayList;

public class Main {
    private static void printUsage(String prog) {
        System.out.println();
        System.out.println("DPI Engine - Deep Packet Inspection System");
        System.out.println("==========================================");
        System.out.println();
        System.out.println("Usage: " + prog + " <input.pcap> <output.pcap> [options]");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  --block-ip <ip>        Block traffic from source IP");
        System.out.println("  --block-app <app>      Block application (YouTube, Facebook, etc.)");
        System.out.println("  --block-domain <dom>   Block domain (substring match)");
        System.out.println("  --mt                   Use multi-threaded mode");
        System.out.println("  --lbs <n>              Number of load balancer threads (default: 2)");
        System.out.println("  --fps <n>              FP threads per LB (default: 2)");
        System.out.println();
        System.out.println("Example:");
        System.out.println("  " + prog + " capture.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50");
        System.out.println();
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            Main.printUsage("java -jar packet-analyzer.jar");
            System.exit(1);
            return;
        }
        String inputFile = args[0];
        String outputFile = args[1];
        ArrayList<String> blockIps = new ArrayList<String>();
        ArrayList<String> blockApps = new ArrayList<String>();
        ArrayList<String> blockDomains = new ArrayList<String>();
        boolean multiThreaded = false;
        int numLbs = 2;
        int fpsPerLb = 2;
        block16: for (int i = 2; i < args.length; ++i) {
            String arg = args[i];
            switch (arg) {
                case "--block-ip": {
                    if (i + 1 >= args.length) continue block16;
                    blockIps.add(args[++i]);
                    continue block16;
                }
                case "--block-app": {
                    if (i + 1 >= args.length) continue block16;
                    blockApps.add(args[++i]);
                    continue block16;
                }
                case "--block-domain": {
                    if (i + 1 >= args.length) continue block16;
                    blockDomains.add(args[++i]);
                    continue block16;
                }
                case "--mt": {
                    multiThreaded = true;
                    continue block16;
                }
                case "--lbs": {
                    if (i + 1 >= args.length) continue block16;
                    numLbs = Integer.parseInt(args[++i]);
                    continue block16;
                }
                case "--fps": {
                    if (i + 1 >= args.length) continue block16;
                    fpsPerLb = Integer.parseInt(args[++i]);
                    continue block16;
                }
                default: {
                    System.err.println("Unknown option: " + arg);
                }
            }
        }
        if (multiThreaded) {
            DPIEngine.Config cfg = new DPIEngine.Config();
            cfg.numLbs = numLbs;
            cfg.fpsPerLb = fpsPerLb;
            DPIEngine engine = new DPIEngine(cfg);
            for (String ip : blockIps) {
                engine.blockIp(ip);
            }
            for (String app : blockApps) {
                engine.blockApp(app);
            }
            for (String dom : blockDomains) {
                engine.blockDomain(dom);
            }
            if (!engine.process(inputFile, outputFile)) {
                System.exit(1);
            }
        } else {
            RuleManager rules = new RuleManager();
            for (String ip : blockIps) {
                rules.blockIp(ip);
            }
            for (String app : blockApps) {
                rules.blockApp(app);
            }
            for (String dom : blockDomains) {
                rules.blockDomain(dom);
            }
            SimpleDPI.run(inputFile, outputFile, rules);
        }
        System.out.println();
        System.out.println("Output written to: " + outputFile);
    }
}

