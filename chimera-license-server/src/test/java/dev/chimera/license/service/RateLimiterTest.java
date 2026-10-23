package dev.chimera.license.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RateLimiterTest {

    @Test
    void blocksAfterConfiguredFailuresAndResets() {
        RateLimiter limiter = new RateLimiter(3, 60);
        String key = "account|ip";
        assertFalse(limiter.isBlocked(key));
        limiter.recordFailure(key);
        limiter.recordFailure(key);
        assertFalse(limiter.isBlocked(key));
        limiter.recordFailure(key);
        assertTrue(limiter.isBlocked(key));
        limiter.reset(key);
        assertFalse(limiter.isBlocked(key));
    }
}
