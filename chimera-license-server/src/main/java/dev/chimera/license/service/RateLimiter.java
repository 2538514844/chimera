package dev.chimera.license.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Sliding-window failure limiter for activation attempts (per account + client IP). */
@Component
public class RateLimiter {

    private final Map<String, Deque<Long>> failures = new ConcurrentHashMap<>();
    private final int maxFailures;
    private final long windowMillis;

    public RateLimiter(@Value("${license.rate-limit.max-failures:5}") int maxFailures,
                       @Value("${license.rate-limit.window-seconds:900}") long windowSeconds) {
        this.maxFailures = Math.max(1, maxFailures);
        this.windowMillis = Math.max(1L, windowSeconds) * 1000L;
    }

    public boolean isBlocked(String key) {
        Deque<Long> timestamps = failures.get(key);
        if (timestamps == null) {
            return false;
        }
        synchronized (timestamps) {
            prune(timestamps);
            return timestamps.size() >= maxFailures;
        }
    }

    public void recordFailure(String key) {
        Deque<Long> timestamps = failures.computeIfAbsent(key, ignored -> new ArrayDeque<>());
        synchronized (timestamps) {
            prune(timestamps);
            timestamps.addLast(Long.valueOf(System.currentTimeMillis()));
        }
    }

    public void reset(String key) {
        failures.remove(key);
    }

    private void prune(Deque<Long> timestamps) {
        long cutoff = System.currentTimeMillis() - windowMillis;
        while (!timestamps.isEmpty() && timestamps.peekFirst().longValue() < cutoff) {
            timestamps.removeFirst();
        }
    }
}
