package com.dpi.engine.tracking;

import com.dpi.engine.model.FiveTuple;
import com.dpi.engine.model.Flow;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe flow tracker that maps five-tuples to Flow objects.
 * Each flow accumulates packets, SNI, and classification data.
 */
public class ConnectionTracker {

    private final Map<FiveTuple, Flow> flows = new ConcurrentHashMap<>();

    /** Get or create a flow for the given five-tuple. */
    public Flow getOrCreateFlow(FiveTuple tuple) {
        return flows.computeIfAbsent(tuple, Flow::new);
    }

    /** Get existing flow without creating. */
    public Flow getFlow(FiveTuple tuple) {
        return flows.get(tuple);
    }

    /** Return all tracked flows. */
    public Map<FiveTuple, Flow> getAllFlows() {
        return Collections.unmodifiableMap(flows);
    }

    /** Return the number of unique flows. */
    public int getFlowCount() {
        return flows.size();
    }

    /** Clear all flows. */
    public void clear() {
        flows.clear();
    }
}
