/*
 * Decompiled with CFR 0.152.
 */
package com.dpi.engine.rules;

import com.dpi.engine.model.AppType;
import com.dpi.engine.model.FiveTuple;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

public class RuleManager {
    private final Set<Integer> blockedIps = new HashSet<Integer>();
    private final Set<AppType> blockedApps = new HashSet<AppType>();
    private final List<String> blockedDomains = new ArrayList<String>();

    public void blockIp(String ip) {
        this.blockedIps.add(FiveTuple.ipFromString(ip));
    }

    public void blockApp(String appName) {
        String upper = appName.toUpperCase().replace(" ", "_");
        for (AppType at : AppType.values()) {
            if (!at.name().equals(upper) && !at.getDisplayName().equalsIgnoreCase(appName)) continue;
            this.blockedApps.add(at);
            return;
        }
        System.err.println("[Rules] Warning: unknown app type \"" + appName + "\"");
    }

    public void blockDomain(String domain) {
        this.blockedDomains.add(domain.toLowerCase());
    }

    public boolean isBlocked(String srcIpStr, AppType appType, String sni) {
        int ip;
        if (!srcIpStr.isEmpty() && this.blockedIps.contains(ip = FiveTuple.ipFromString(srcIpStr))) {
            return true;
        }
        if (appType != AppType.UNKNOWN && this.blockedApps.contains((Object)appType)) {
            return true;
        }
        if (sni != null && !sni.isEmpty()) {
            String lowerSni = sni.toLowerCase();
            for (String dom : this.blockedDomains) {
                if (!lowerSni.contains(dom)) continue;
                return true;
            }
        }
        return false;
    }

    public Set<Integer> getBlockedIps() {
        return Collections.unmodifiableSet(this.blockedIps);
    }

    public Set<AppType> getBlockedApps() {
        return Collections.unmodifiableSet(this.blockedApps);
    }

    public List<String> getBlockedDomains() {
        return Collections.unmodifiableList(this.blockedDomains);
    }

    public void printRules() {
        for (AppType app : this.blockedApps) {
            System.out.println("[Rules] Blocked app: " + app.getDisplayName());
        }
        Iterator<Integer> iterator = this.blockedIps.iterator();
        while (iterator.hasNext()) {
            int ip = iterator.next();
            System.out.println("[Rules] Blocked IP: " + FiveTuple.ipToString(ip));
        }
        for (String dom : this.blockedDomains) {
            System.out.println("[Rules] Blocked domain: " + dom);
        }
    }
}

