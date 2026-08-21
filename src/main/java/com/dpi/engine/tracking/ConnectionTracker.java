/*
 * Decompiled with CFR 0.152.
 */
package com.dpi.engine.tracking;

import com.dpi.engine.model.FiveTuple;
import com.dpi.engine.model.Flow;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class ConnectionTracker {
    private final Map<FiveTuple, Flow> flows = new ConcurrentHashMap<FiveTuple, Flow>();

    public Flow getOrCreateFlow(FiveTuple tuple) {
        return this.flows.computeIfAbsent(tuple, Flow::new);
    }

    public Flow getFlow(FiveTuple tuple) {
        return this.flows.get(tuple);
    }

    public Map<FiveTuple, Flow> getAllFlows() {
        return Collections.unmodifiableMap(this.flows);
    }

    public int getFlowCount() {
        return this.flows.size();
    }

    public void clear() {
        this.flows.clear();
    }
}

