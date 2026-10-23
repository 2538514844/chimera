package dev.chimera.license.store;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Persistent v4 auth state: sessions, consumed client nonces, issued server nonces, token history
 * and consumed heartbeat sequences. All replay checks rely on database uniqueness so they stay
 * atomic across concurrent requests and server instances.
 */
@Repository
public class AuthV4Store {

    private final JdbcTemplate jdbc;

    public AuthV4Store(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /** {@code clientPub} is the X25519 key captured at activation; {@code null} only for legacy rows. */
    public record SessionRow(long id, String token, long accountId, String hwid, byte[] clientPub,
                             long sequence, long issuedAt, long expiresAt, boolean revoked) {
    }

    public void insertSession(String token, long accountId, String hwid, byte[] clientPub,
                              long sequence, long issuedAt, long expiresAt, Instant now) {
        jdbc.update("INSERT INTO auth_v4_sessions(token, account_id, hwid, client_pub, sequence, "
                        + "issued_at, expires_at, revoked, created_at) VALUES (?,?,?,?,?,?,?,FALSE,?)",
                token, Long.valueOf(accountId), hwid, clientPub, Long.valueOf(sequence),
                Long.valueOf(issuedAt), Long.valueOf(expiresAt), Timestamp.from(now));
    }

    public Optional<SessionRow> findSession(String token) {
        List<SessionRow> rows = jdbc.query(
                "SELECT id, token, account_id, hwid, client_pub, sequence, issued_at, expires_at, "
                        + "revoked FROM auth_v4_sessions WHERE token = ?",
                (rs, rowNum) -> new SessionRow(rs.getLong("id"), rs.getString("token"),
                        rs.getLong("account_id"), rs.getString("hwid"), rs.getBytes("client_pub"),
                        rs.getLong("sequence"), rs.getLong("issued_at"),
                        rs.getLong("expires_at"), rs.getBoolean("revoked")),
                token);
        return rows.stream().findFirst();
    }

    /**
     * Migration window: binds the client public key of a session created before the
     * {@code client_pub} column existed. Only applies while the column is still NULL.
     *
     * @return 0 when the key was already bound (no longer NULL)
     */
    public int bindClientPubIfAbsent(long id, byte[] clientPub) {
        return jdbc.update(
                "UPDATE auth_v4_sessions SET client_pub = ? WHERE id = ? AND client_pub IS NULL",
                clientPub, Long.valueOf(id));
    }

    /**
     * Atomically rotates the bearer token and advances the sequence. Returns 0 when the presented
     * token/sequence/issued_at tuple is stale (concurrent heartbeat or replay).
     */
    public int rotateSession(long id, String expectedToken, long expectedSequence,
                             long expectedIssuedAt, String newToken, long newSequence,
                             long newIssuedAt, long newExpiresAt) {
        return jdbc.update("UPDATE auth_v4_sessions SET token = ?, sequence = ?, issued_at = ?, "
                        + "expires_at = ? WHERE id = ? AND token = ? AND sequence = ? "
                        + "AND issued_at = ? AND revoked = FALSE",
                newToken, Long.valueOf(newSequence), Long.valueOf(newIssuedAt),
                Long.valueOf(newExpiresAt), Long.valueOf(id), expectedToken,
                Long.valueOf(expectedSequence), Long.valueOf(expectedIssuedAt));
    }

    public int revokeSession(long id) {
        return jdbc.update("UPDATE auth_v4_sessions SET revoked = TRUE WHERE id = ?",
                Long.valueOf(id));
    }

    /**
     * Records a consumed nonce (client nonce or issued server nonce).
     *
     * @return {@code false} when the hash was already present (replay)
     */
    public boolean recordNonce(String kind, String nonceHash) {
        try {
            jdbc.update("INSERT INTO auth_v4_nonces(kind, nonce_hash, created_at) VALUES (?,?,?)",
                    kind, nonceHash, Timestamp.from(Instant.now()));
            return true;
        } catch (DataIntegrityViolationException duplicate) {
            return false;
        }
    }

    /**
     * Records that one heartbeat request sequence was consumed for a session.
     *
     * @return {@code false} when the sequence was already consumed (replay)
     */
    public boolean recordSequence(long sessionId, long sequence) {
        try {
            jdbc.update("INSERT INTO auth_v4_sequences(session_id, sequence, created_at) "
                            + "VALUES (?,?,?)",
                    Long.valueOf(sessionId), Long.valueOf(sequence), Timestamp.from(Instant.now()));
            return true;
        } catch (DataIntegrityViolationException duplicate) {
            return false;
        }
    }

    /**
     * Adds a bearer token (by hash) to the never-reuse history.
     *
     * @return {@code false} when this token was issued before
     */
    public boolean recordToken(String tokenHash, long accountId) {
        try {
            jdbc.update("INSERT INTO auth_v4_tokens(token_hash, account_id, created_at) "
                            + "VALUES (?,?,?)",
                    tokenHash, Long.valueOf(accountId), Timestamp.from(Instant.now()));
            return true;
        } catch (DataIntegrityViolationException duplicate) {
            return false;
        }
    }
}
