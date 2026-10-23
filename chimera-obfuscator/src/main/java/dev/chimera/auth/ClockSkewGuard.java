package dev.chimera.auth;

/**
 * Validates signed timestamps against the local clock.
 *
 * <ul>
 *   <li>issued_at / server_time must be within {@code clockSkewSeconds} of local time;</li>
 *   <li>expires_at must be after issued_at and in the future;</li>
 *   <li>heartbeat issued_at must not go backwards (rollback/replay).</li>
 * </ul>
 */
public final class ClockSkewGuard {

    private final long toleranceSeconds;

    public ClockSkewGuard(long toleranceSeconds) {
        if (toleranceSeconds < 0 || toleranceSeconds > 86_400L) {
            throw new IllegalArgumentException("clock skew tolerance out of range: " + toleranceSeconds);
        }
        this.toleranceSeconds = toleranceSeconds;
    }

    public void checkActivation(long nowEpochSeconds, long issuedAt, long expiresAt, long serverTime)
            throws AuthProtocolException {
        checkBase(nowEpochSeconds, issuedAt, expiresAt, serverTime);
        if (expiresAt <= nowEpochSeconds) {
            throw new AuthProtocolException(AuthFailure.EXPIRED, "activation response already expired");
        }
    }

    public void checkHeartbeat(long nowEpochSeconds, long issuedAt, long expiresAt, long serverTime,
                               long lastIssuedAt) throws AuthProtocolException {
        checkBase(nowEpochSeconds, issuedAt, expiresAt, serverTime);
        // Expiry takes priority over rollback: an already-expired response must be reported as
        // E_EXPIRED even when its issued_at also moved backwards (both indicate the same stale
        // session, but callers/clients act differently on 410 vs a clock-rollback signal).
        if (expiresAt <= nowEpochSeconds) {
            throw new AuthProtocolException(AuthFailure.EXPIRED, "heartbeat response already expired");
        }
        if (issuedAt < lastIssuedAt) {
            throw new AuthProtocolException(AuthFailure.CLOCK_ROLLBACK,
                    "heartbeat issued_at moved backwards");
        }
    }

    private void checkBase(long now, long issuedAt, long expiresAt, long serverTime)
            throws AuthProtocolException {
        if (now <= 0 || issuedAt <= 0 || expiresAt <= 0 || serverTime <= 0) {
            throw new AuthProtocolException(AuthFailure.BAD_RESPONSE, "timestamps must be positive");
        }
        if (expiresAt <= issuedAt) {
            throw new AuthProtocolException(AuthFailure.BAD_RESPONSE, "expires_at must be after issued_at");
        }
        if (Math.abs(now - issuedAt) > toleranceSeconds) {
            throw new AuthProtocolException(AuthFailure.CLOCK_SKEW, "issued_at outside clock skew tolerance");
        }
        if (Math.abs(now - serverTime) > toleranceSeconds) {
            throw new AuthProtocolException(AuthFailure.CLOCK_SKEW, "server_time outside clock skew tolerance");
        }
    }
}
