package dev.chimera.license.service;

import dev.chimera.license.api.LicenseException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AuthV4ClockTest {

    @Test
    void acceptsExactlyThreeHundredSecondsOfSkew() {
        assertDoesNotThrow(() -> AuthV4Clock.requireWithinSkew(1_000L, 700L, 1_300L));
    }

    @Test
    void rejectsIssuedAtBeyondThreeHundredSeconds() {
        LicenseException error = assertThrows(LicenseException.class,
                () -> AuthV4Clock.requireWithinSkew(1_000L, 699L, 1_000L));
        assertEquals("E_CLOCK_SKEW", error.code());
        assertEquals(409, error.status());
    }

    @Test
    void rejectsServerTimeBeyondThreeHundredSeconds() {
        LicenseException error = assertThrows(LicenseException.class,
                () -> AuthV4Clock.requireWithinSkew(1_000L, 1_000L, 1_301L));
        assertEquals("E_CLOCK_SKEW", error.code());
    }

    @Test
    void rejectsBackwardsIssuedAtAndAcceptsEqualValue() {
        assertDoesNotThrow(() -> AuthV4Clock.requireNoRollback(1_000L, 1_000L));
        LicenseException error = assertThrows(LicenseException.class,
                () -> AuthV4Clock.requireNoRollback(999L, 1_000L));
        assertEquals("E_CLOCK_ROLLBACK", error.code());
        assertEquals(409, error.status());
    }
}
