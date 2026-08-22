package com.dpi.engine.concurrent;

import com.dpi.engine.model.FiveTuple;
import com.dpi.engine.model.Packet;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Load Balancer thread. Reads Packets from its input queue,
 * hashes the five-tuple, and dispatches to the appropriate FP.
 * Ported from the C++ LoadBalancer class in dpi_mt.cpp.
 */
public class LoadBalancer implements Runnable {

    private final ThreadSafeQueue<Packet> inputQueue;
    private final FastPath[] fastPaths;
    private final int numFps;
    private final int lbIndex;
    private volatile boolean running = true;
    private final AtomicLong dispatched = new AtomicLong(0);

    public LoadBalancer(ThreadSafeQueue<Packet> inputQueue, FastPath[] fastPaths, int lbIndex) {
        this.inputQueue = inputQueue;
        this.fastPaths = fastPaths;
        this.numFps = fastPaths.length;
        this.lbIndex = lbIndex;
    }

    public ThreadSafeQueue<Packet> getInputQueue() { return inputQueue; }
    public long getDispatched() { return dispatched.get(); }
    public int getLbIndex() { return lbIndex; }

    @Override
    public void run() {
        while (running) {
            try {
                Packet pkt = inputQueue.pop(100);
                if (pkt == null) continue; // timeout or shutdown

                // Hash to select FP
                FiveTupleHash hasher = new FiveTupleHash();
                int fpIdx = Math.abs(hasher.hash(pkt.tuple) % numFps);

                fastPaths[fpIdx].getInputQueue().push(pkt);
                dispatched.incrementAndGet();

            } catch (InterruptedException e) {
                break;
            }
        }
    }

    public void shutdown() {
        running = false;
        inputQueue.shutdown();
    }

    /**
     * FiveTuple hash function ported from the C++ FiveTupleHash.
     */
    public static class FiveTupleHash {
        public int hash(FiveTuple t) {
            int h = 0;
            h ^= hashInt(t.getSrcIp()) + 0x9e3779b9 + (h << 6) + (h >>> 2);
            h ^= hashInt(t.getDstIp()) + 0x9e3779b9 + (h << 6) + (h >>> 2);
            h ^= hashShort(t.getSrcPort()) + 0x9e3779b9 + (h << 6) + (h >>> 2);
            h ^= hashShort(t.getDstPort()) + 0x9e3779b9 + (h << 6) + (h >>> 2);
            h ^= hashByte(t.getProtocol()) + 0x9e3779b9 + (h << 6) + (h >>> 2);
            return h;
        }
        private int hashInt(int v) { return v;
        }
        private int hashShort(int v) { return v;
        }
        private int hashByte(int v) { return v & 0xFF;
        }
    }
}
