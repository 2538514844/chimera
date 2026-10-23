package dev.chimera.license.service;

import dev.chimera.license.api.LicenseException;

/**
 * Timestamp rules for v4 responses.
 *
 * <p>The client rejects a response when {@code |now - issued_at|} or
 * {@code |now - server_time|} exceeds 300 seconds, and it rejects a heartbeat whose
 * {@code issued_at} went backwards. Expiry is checked before rollback so an already-expired
 * session is reported as {@code E_EXPIRED} rather than {@code E_CLOCK_ROLLBACK}.</p>
 */
public final class AuthV4Clock {

    public static final long TOLERANCE_SECONDS = 300L;

    private AuthV4Clock() {
    }

    /** @throws LicenseException E_CLOCK_SKEW when either timestamp is outside the 300s window */
    public static void requireWithinSkew(long now, long issuedAt, long serverTime) {
        if (issuedAt <= 0 || serverTime <= 0) {
            throw new LicenseException(400, "E_BAD_RESPONSE");
        }
        if (Math.abs(now - issuedAt) > TOLERANCE_SECONDS
                || Math.abs(now - serverTime) > TOLERANCE_SECONDS) {
            throw new LicenseException(409, "E_CLOCK_SKEW");
        }
    }

    /** @throws LicenseException E_CLOCK_ROLLBACK when a new issued_at would move backwards */
    public static void requireNoRollback(long now, long lastIssuedAt) {
        if (now < lastIssuedAt) {
            throw new LicenseException(409, "E_CLOCK_ROLLBACK");
        }
    }
}
