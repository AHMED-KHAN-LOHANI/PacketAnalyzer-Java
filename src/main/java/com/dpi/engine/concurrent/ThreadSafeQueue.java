package com.dpi.engine.concurrent;

import java.util.LinkedList;
import java.util.Queue;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.TimeUnit;

/**
 * Bounded, thread-safe blocking queue.
 * Mirrors the C++ TSQueue with push(), pop(timeout), shutdown(), size().
 */
public class ThreadSafeQueue<T> {

    private final Queue<T> queue = new LinkedList<>();
    private final ReentrantLock lock = new ReentrantLock();
    private final Condition notEmpty = lock.newCondition();
    private final Condition notFull = lock.newCondition();
    private final int capacity;
    private boolean shutdown = false;

    public ThreadSafeQueue() {
        this(10000);
    }

    public ThreadSafeQueue(int capacity) {
        this.capacity = capacity;
    }

    /** Add an item. Blocks if full or shutdown. */
    public void push(T item) throws InterruptedException {
        lock.lock();
        try {
            while (queue.size() >= capacity && !shutdown) {
                notFull.await();
            }
            if (shutdown) return;
            queue.add(item);
            notEmpty.signal();
        } finally {
            lock.unlock();
        }
    }

    /** Blocking pop with timeout (ms). Returns null on timeout or shutdown. */
    public T pop(int timeoutMs) throws InterruptedException {
        lock.lock();
        try {
            while (queue.isEmpty() && !shutdown) {
                if (!notEmpty.await(timeoutMs, TimeUnit.MILLISECONDS)) {
                    return null; // timeout
                }
            }
            if (queue.isEmpty()) return null; // shutdown
            T item = queue.poll();
            notFull.signal();
            return item;
        } finally {
            lock.unlock();
        }
    }

    /** Blocking pop (no timeout). */
    public T pop() throws InterruptedException {
        lock.lock();
        try {
            while (queue.isEmpty() && !shutdown) {
                notEmpty.await();
            }
            if (queue.isEmpty()) return null;
            T item = queue.poll();
            notFull.signal();
            return item;
        } finally {
            lock.unlock();
        }
    }

    /** Non-blocking pop. Returns null if empty. */
    public T tryPop() {
        lock.lock();
        try {
            if (queue.isEmpty()) return null;
            return queue.poll();
        } finally {
            lock.unlock();
        }
    }

    public int size() {
        lock.lock();
        try { return queue.size(); } finally { lock.unlock(); }
    }

    public boolean isEmpty() {
        lock.lock();
        try { return queue.isEmpty(); } finally { lock.unlock(); }
    }

    public void shutdown() {
        lock.lock();
        try {
            shutdown = true;
            notEmpty.signalAll();
            notFull.signalAll();
        } finally {
            lock.unlock();
        }
    }
}
