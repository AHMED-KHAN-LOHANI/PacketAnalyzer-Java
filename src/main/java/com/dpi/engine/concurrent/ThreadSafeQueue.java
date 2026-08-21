/*
 * Decompiled with CFR 0.152.
 */
package com.dpi.engine.concurrent;

import java.util.LinkedList;
import java.util.Queue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

public class ThreadSafeQueue<T> {
    private final Queue<T> queue = new LinkedList<T>();
    private final ReentrantLock lock = new ReentrantLock();
    private final Condition notEmpty = this.lock.newCondition();
    private final Condition notFull = this.lock.newCondition();
    private final int capacity;
    private boolean shutdown = false;

    public ThreadSafeQueue() {
        this(10000);
    }

    public ThreadSafeQueue(int capacity) {
        this.capacity = capacity;
    }

    public void push(T item) throws InterruptedException {
        this.lock.lock();
        try {
            while (this.queue.size() >= this.capacity && !this.shutdown) {
                this.notFull.await();
            }
            if (this.shutdown) {
                return;
            }
            this.queue.add(item);
            this.notEmpty.signal();
        }
        finally {
            this.lock.unlock();
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    public T pop(int timeoutMs) throws InterruptedException {
        this.lock.lock();
        try {
            while (this.queue.isEmpty() && !this.shutdown) {
                if (this.notEmpty.await(timeoutMs, TimeUnit.MILLISECONDS)) continue;
                T t = null;
                return t;
            }
            if (this.queue.isEmpty()) {
                T t = null;
                return t;
            }
            T item = this.queue.poll();
            this.notFull.signal();
            T t = item;
            return t;
        }
        finally {
            this.lock.unlock();
        }
    }

    public T pop() throws InterruptedException {
        this.lock.lock();
        try {
            while (this.queue.isEmpty() && !this.shutdown) {
                this.notEmpty.await();
            }
            if (this.queue.isEmpty()) {
                T t = null;
                return t;
            }
            T item = this.queue.poll();
            this.notFull.signal();
            T t = item;
            return t;
        }
        finally {
            this.lock.unlock();
        }
    }

    public T tryPop() {
        this.lock.lock();
        try {
            if (this.queue.isEmpty()) {
                T t = null;
                return t;
            }
            T t = this.queue.poll();
            return t;
        }
        finally {
            this.lock.unlock();
        }
    }

    public int size() {
        this.lock.lock();
        try {
            int n = this.queue.size();
            return n;
        }
        finally {
            this.lock.unlock();
        }
    }

    public boolean isEmpty() {
        this.lock.lock();
        try {
            boolean bl = this.queue.isEmpty();
            return bl;
        }
        finally {
            this.lock.unlock();
        }
    }

    public void shutdown() {
        this.lock.lock();
        try {
            this.shutdown = true;
            this.notEmpty.signalAll();
            this.notFull.signalAll();
        }
        finally {
            this.lock.unlock();
        }
    }
}

