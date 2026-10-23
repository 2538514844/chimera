package dev.chimera.license;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

/** Controllable UTC clock for v4 timestamp/replay tests. */
final class MutableClock extends Clock {

    private volatile Instant instant;

    MutableClock(long epochSecond) {
        this.instant = Instant.ofEpochSecond(epochSecond);
    }

    void setEpochSecond(long epochSecond) {
        this.instant = Instant.ofEpochSecond(epochSecond);
    }

    void advanceSeconds(long seconds) {
        this.instant = this.instant.plusSeconds(seconds);
    }

    @Override
    public Instant instant() {
        return instant;
    }

    @Override
    public ZoneId getZone() {
        return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
        return this;
    }
}
