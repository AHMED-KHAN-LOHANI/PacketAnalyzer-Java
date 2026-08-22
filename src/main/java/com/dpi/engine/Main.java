package com.dpi.engine;

import com.dpi.engine.engine.DPIEngine;
import com.dpi.engine.rules.RuleManager;
import com.dpi.engine.simple.SimpleDPI;

import java.util.ArrayList;
import java.util.List;

/**
 * Main entry point for the DPI Engine.
 * Supports both single-threaded and multi-threaded modes.
 *
 * Usage:
 *   java -jar packet-analyzer.jar <input.pcap> <output.pcap> [options]
 *
 * Options:
 *   --block-ip <ip>        Block source IP
 *   --block-app <app>      Block application (YouTube, Facebook, etc.)
 *   --block-domain <dom>   Block domain (substring match)
 *   --mt                   Use multi-threaded mode
 *   --lbs <n>              Number of load balancer threads (default: 2, MT only)
 *   --fps <n>              FP threads per LB (default: 2, MT only)
 */
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
            printUsage("java -jar packet-analyzer.jar");
            System.exit(1);
            return;
        }

        String inputFile = args[0];
        String outputFile = args[1];

        List<String> blockIps = new ArrayList<>();
        List<String> blockApps = new ArrayList<>();
        List<String> blockDomains = new ArrayList<>();
        boolean multiThreaded = false;
        int numLbs = 2;
        int fpsPerLb = 2;

        // Parse options
        for (int i = 2; i < args.length; i++) {
            String arg = args[i];
            switch (arg) {
                case "--block-ip":
                    if (i + 1 < args.length) blockIps.add(args[++i]);
                    break;
                case "--block-app":
                    if (i + 1 < args.length) blockApps.add(args[++i]);
                    break;
                case "--block-domain":
                    if (i + 1 < args.length) blockDomains.add(args[++i]);
                    break;
                case "--mt":
                    multiThreaded = true;
                    break;
                case "--lbs":
                    if (i + 1 < args.length) numLbs = Integer.parseInt(args[++i]);
                    break;
                case "--fps":
                    if (i + 1 < args.length) fpsPerLb = Integer.parseInt(args[++i]);
                    break;
                default:
                    System.err.println("Unknown option: " + arg);
                    break;
            }
        }

        if (multiThreaded) {
            // Multi-threaded mode
            DPIEngine.Config cfg = new DPIEngine.Config();
            cfg.numLbs = numLbs;
            cfg.fpsPerLb = fpsPerLb;

            DPIEngine engine = new DPIEngine(cfg);

            for (String ip : blockIps) engine.blockIp(ip);
            for (String app : blockApps) engine.blockApp(app);
            for (String dom : blockDomains) engine.blockDomain(dom);

            if (!engine.process(inputFile, outputFile)) {
                System.exit(1);
            }
        } else {
            // Single-threaded mode (default)
            RuleManager rules = new RuleManager();

            for (String ip : blockIps) rules.blockIp(ip);
            for (String app : blockApps) rules.blockApp(app);
            for (String dom : blockDomains) rules.blockDomain(dom);

            SimpleDPI.run(inputFile, outputFile, rules);
        }

        System.out.println();
        System.out.println("Output written to: " + outputFile);
    }
}
