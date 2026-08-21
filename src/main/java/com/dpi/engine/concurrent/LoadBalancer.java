/*
 * Decompiled with CFR 0.152.
 */
package com.dpi.engine.concurrent;

import com.dpi.engine.concurrent.FastPath;
import com.dpi.engine.concurrent.ThreadSafeQueue;
import com.dpi.engine.model.FiveTuple;
import com.dpi.engine.model.Packet;
import java.util.concurrent.atomic.AtomicLong;

public class LoadBalancer
implements Runnable {
    private final ThreadSafeQueue<Packet> inputQueue;
    private final FastPath[] fastPaths;
    private final int numFps;
    private final int lbIndex;
    private volatile boolean running = true;
    private final AtomicLong dispatched = new AtomicLong(0L);

    public LoadBalancer(ThreadSafeQueue<Packet> inputQueue, FastPath[] fastPaths, int lbIndex) {
        this.inputQueue = inputQueue;
        this.fastPaths = fastPaths;
        this.numFps = fastPaths.length;
        this.lbIndex = lbIndex;
    }

    public ThreadSafeQueue<Packet> getInputQueue() {
        return this.inputQueue;
    }

    public long getDispatched() {
        return this.dispatched.get();
    }

    public int getLbIndex() {
        return this.lbIndex;
    }

    @Override
    public void run() {
        while (this.running) {
            try {
                Packet pkt = this.inputQueue.pop(100);
                if (pkt == null) continue;
                FiveTupleHash hasher = new FiveTupleHash();
                int fpIdx = Math.abs(hasher.hash(pkt.tuple) % this.numFps);
                this.fastPaths[fpIdx].getInputQueue().push(pkt);
                this.dispatched.incrementAndGet();
            }
            catch (InterruptedException e) {
                break;
            }
        }
    }

    public void shutdown() {
        this.running = false;
        this.inputQueue.shutdown();
    }

    public static class FiveTupleHash {
        public int hash(FiveTuple t) {
            int h = 0;
            h ^= this.hashInt(t.getSrcIp()) + -1640531527 + (h << 6) + (h >>> 2);
            h ^= this.hashInt(t.getDstIp()) + -1640531527 + (h << 6) + (h >>> 2);
            h ^= this.hashShort(t.getSrcPort()) + -1640531527 + (h << 6) + (h >>> 2);
            h ^= this.hashShort(t.getDstPort()) + -1640531527 + (h << 6) + (h >>> 2);
            h ^= this.hashByte(t.getProtocol()) + -1640531527 + (h << 6) + (h >>> 2);
            return h;
        }

        private int hashInt(int v) {
            return v;
        }

        private int hashShort(int v) {
            return v;
        }

        private int hashByte(int v) {
            return v & 0xFF;
        }
    }
}

