package dev.chimera.license.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Deterministic unit tests for the 5-second rapid-HWID-switch detector (no sleeping). */
class RiskControlServiceTest {

    private static final Instant T0 = Instant.parse("2026-10-19T00:00:00Z");
    private static final long ACCOUNT = 42L;

    private RiskControlService risk;

    @BeforeEach
    void setUp() {
        risk = new RiskControlService(5, 60);
    }

    @Test
    void firstActivityIsNotSuspicious() {
        assertFalse(risk.recordActivity(ACCOUNT, "hwid-a", T0));
        assertFalse(risk.isPoisoned(ACCOUNT, "hwid-a", T0));
    }

    @Test
    void sameHwidWithinWindowIsNotSuspicious() {
        assertFalse(risk.recordActivity(ACCOUNT, "hwid-a", T0));
        assertFalse(risk.recordActivity(ACCOUNT, "hwid-a", T0.plusMillis(4_999)));
        assertFalse(risk.isPoisoned(ACCOUNT, "hwid-a", T0.plusMillis(4_999)));
    }

    @Test
    void differentHwidWithinWindowPoisonsOnlyTheCurrentDevice() {
        assertFalse(risk.recordActivity(ACCOUNT, "hwid-a", T0));
        assertTrue(risk.recordActivity(ACCOUNT, "hwid-b", T0.plusMillis(1_000)));
        assertTrue(risk.isPoisoned(ACCOUNT, "hwid-b", T0.plusMillis(1_000)));
        assertFalse(risk.isPoisoned(ACCOUNT, "hwid-a", T0.plusMillis(1_000)),
                "the previously active legitimate device must not be poisoned");
        assertFalse(risk.recordActivity(ACCOUNT, "hwid-b", T0.plusMillis(2_000)),
                "staying on the flagged device is not a new rapid switch");
        assertTrue(risk.isPoisoned(ACCOUNT, "hwid-b", T0.plusMillis(2_000)));
    }

    @Test
    void windowBoundaryIsInclusive() {
        assertFalse(risk.recordActivity(ACCOUNT, "hwid-a", T0));
        assertTrue(risk.recordActivity(ACCOUNT, "hwid-b", T0.plusMillis(5_000)));
        assertTrue(risk.isPoisoned(ACCOUNT, "hwid-b", T0.plusMillis(5_000)));

        RiskControlService after = new RiskControlService(5, 60);
        assertFalse(after.recordActivity(ACCOUNT, "hwid-a", T0));
        assertFalse(after.recordActivity(ACCOUNT, "hwid-b", T0.plusMillis(5_001)),
                "switching after the 5s window is not suspicious");
        assertFalse(after.isPoisoned(ACCOUNT, "hwid-b", T0.plusMillis(5_001)));
    }

    @Test
    void accountsAreIsolated() {
        assertFalse(risk.recordActivity(1L, "hwid-a", T0));
        assertFalse(risk.recordActivity(2L, "hwid-b", T0.plusMillis(10)));
        assertFalse(risk.isPoisoned(2L, "hwid-b", T0.plusMillis(10)));
    }

    @Test
    void poisonFlagExpiresAfterTtl() {
        assertFalse(risk.recordActivity(ACCOUNT, "hwid-a", T0));
        assertTrue(risk.recordActivity(ACCOUNT, "hwid-b", T0.plusMillis(1_000)));
        assertTrue(risk.isPoisoned(ACCOUNT, "hwid-b", T0.plusMillis(59_999)));
        assertFalse(risk.isPoisoned(ACCOUNT, "hwid-b", T0.plusMillis(61_000)));
        assertFalse(risk.isPoisoned(ACCOUNT, "hwid-b", T0.plusMillis(61_000)),
                "expired flag must be removed");
    }

    @Test
    void resetClearsAllState() {
        assertFalse(risk.recordActivity(ACCOUNT, "hwid-a", T0));
        assertTrue(risk.recordActivity(ACCOUNT, "hwid-b", T0.plusMillis(1_000)));
        risk.reset();
        assertFalse(risk.isPoisoned(ACCOUNT, "hwid-b", T0.plusMillis(1_000)));
        assertFalse(risk.recordActivity(ACCOUNT, "hwid-c", T0.plusMillis(2_000)));
    }
}
