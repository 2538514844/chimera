package dev.chimera.auth;

import java.util.Objects;

/**
 * Accepted v4 session state. The token is a bearer credential; wiring should keep it in the
 * native handle / a minimal-lifetime buffer and never log it.
 */
public record AuthV4Session(String account, String hwid, String token, long sequence,
                            long issuedAt, long expiresAt, String serverNonce) {

    public AuthV4Session {
        Objects.requireNonNull(account, "account");
        Objects.requireNonNull(hwid, "hwid");
        Objects.requireNonNull(token, "token");
        Objects.requireNonNull(serverNonce, "serverNonce");
    }

    public AuthV4Session afterHeartbeat(String newToken, long newSequence, long newIssuedAt,
                                        long newExpiresAt, String newServerNonce) {
        return new AuthV4Session(account, hwid, newToken, newSequence, newIssuedAt, newExpiresAt,
                newServerNonce);
    }

    @Override
    public String toString() {
        return "AuthV4Session[account=" + account + ", sequence=" + sequence + ", expiresAt="
                + expiresAt + "]";
    }
}
