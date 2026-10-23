package dev.chimera.auth;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

/** Deterministic test clock. */
final class MutableClock extends Clock {

    private Instant instant;

    MutableClock(long epochSeconds) {
        this.instant = Instant.ofEpochSecond(epochSeconds);
    }

    void set(long epochSeconds) {
        this.instant = Instant.ofEpochSecond(epochSeconds);
    }

    void advanceSeconds(long seconds) {
        this.instant = instant.plusSeconds(seconds);
    }

    @Override
    public ZoneId getZone() {
        return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
        return this;
    }

    @Override
    public Instant instant() {
        return instant;
    }
}
