package com.dpi.engine.rules;

import com.dpi.engine.model.AppType;

import java.util.*;

/**
 * Manages blocking rules for IP addresses, application types, and domain patterns.
 */
public class RuleManager {

    private final Set<Integer> blockedIps = new HashSet<>();
    private final Set<AppType> blockedApps = new HashSet<>();
    private final List<String> blockedDomains = new ArrayList<>(); // substring match

    /** Add an IP address to the block list (dotted-decimal). */
    public void blockIp(String ip) {
        blockedIps.add(com.dpi.engine.model.FiveTuple.ipFromString(ip));
    }

    /** Add an application type to the block list. */
    public void blockApp(String appName) {
        String upper = appName.toUpperCase().replace(" ", "_");
        for (AppType at : AppType.values()) {
            if (at.name().equals(upper) || at.getDisplayName().equalsIgnoreCase(appName)) {
                blockedApps.add(at);
                return;
            }
        }
        // If not found, still store for logging
        System.err.println("[Rules] Warning: unknown app type \"" + appName + "\"");
    }

    /** Add a domain pattern (substring match against SNI). */
    public void blockDomain(String domain) {
        blockedDomains.add(domain.toLowerCase());
    }

    /** Check if traffic should be blocked. */
    public boolean isBlocked(String srcIpStr, AppType appType, String sni) {
        // IP check
        if (!srcIpStr.isEmpty()) {
            int ip = com.dpi.engine.model.FiveTuple.ipFromString(srcIpStr);
            if (blockedIps.contains(ip)) return true;
        }

        // App check
        if (appType != AppType.UNKNOWN && blockedApps.contains(appType)) return true;

        // Domain check
        if (sni != null && !sni.isEmpty()) {
            String lowerSni = sni.toLowerCase();
            for (String dom : blockedDomains) {
                if (lowerSni.contains(dom)) return true;
            }
        }

        return false;
    }

    public Set<Integer> getBlockedIps() { return Collections.unmodifiableSet(blockedIps); }
    public Set<AppType> getBlockedApps() { return Collections.unmodifiableSet(blockedApps); }
    public List<String> getBlockedDomains() { return Collections.unmodifiableList(blockedDomains); }

    public void printRules() {
        for (AppType app : blockedApps) {
            System.out.println("[Rules] Blocked app: " + app.getDisplayName());
        }
        for (int ip : blockedIps) {
            System.out.println("[Rules] Blocked IP: " + com.dpi.engine.model.FiveTuple.ipToString(ip));
        }
        for (String dom : blockedDomains) {
            System.out.println("[Rules] Blocked domain: " + dom);
        }
    }
}