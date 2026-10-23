package dev.chimera.license.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * Retention sweep for the v4 replay tables.
 *
 * <p>Red team round 4 (source audit): {@code auth_v4_nonces}, {@code auth_v4_sequences},
 * {@code auth_v4_tokens} and {@code audit_logs} were append-only. A single client writes roughly
 * 4300 rows per day (two nonces, one sequence, one token and one audit row per minute of play), and
 * the H2 file database has no other reaper - so the file grows forever and the replay lookups get
 * slower as the tables grow.</p>
 *
 * <p>Retention is deliberately generous: replay protection only needs to outlive a session, and
 * sessions expire in 24h by default. Seven days leaves a comfortable margin for clock skew and for
 * investigating an incident without keeping months of noise.</p>
 *
 * <p>Every delete is bounded and idempotent; failures are logged and never propagate (a full disk or
 * a locked table must not take the licence server down).</p>
 */
@Component
public class SessionReaper {

    private static final Logger LOG = LoggerFactory.getLogger(SessionReaper.class);

    private final JdbcTemplate jdbc;
    private final int replayRetentionDays;
    private final int auditRetentionDays;
    private final long expiredSessionGraceHours;

    public SessionReaper(JdbcTemplate jdbc,
                         @Value("${license.retention.replay-days:7}") int replayRetentionDays,
                         @Value("${license.retention.audit-days:30}") int auditRetentionDays,
                         @Value("${license.retention.expired-session-grace-hours:24}")
                         long expiredSessionGraceHours) {
        this.jdbc = jdbc;
        this.replayRetentionDays = Math.max(1, replayRetentionDays);
        this.auditRetentionDays = Math.max(1, auditRetentionDays);
        this.expiredSessionGraceHours = Math.max(1, expiredSessionGraceHours);
    }

    @Scheduled(initialDelayString = "${license.retention.initial-delay-ms:60000}",
            fixedDelayString = "${license.retention.sweep-ms:3600000}")
    public void sweep() {
        Instant now = Instant.now();
        try {
            // Sequences belong to sessions: drop them together, otherwise the foreign rows outlive
            // the session that made them meaningful.
            Timestamp sessionCutoff = Timestamp.from(
                    now.minus(expiredSessionGraceHours, ChronoUnit.HOURS));
            int sequences = jdbc.update(
                    "DELETE FROM auth_v4_sequences WHERE session_id IN "
                            + "(SELECT id FROM auth_v4_sessions WHERE expires_at < ?)",
                    sessionCutoff.getTime() / 1000L);
            int sessions = jdbc.update(
                    "DELETE FROM auth_v4_sessions WHERE expires_at < ?",
                    sessionCutoff.getTime() / 1000L);

            Timestamp replayCutoff = Timestamp.from(now.minus(replayRetentionDays, ChronoUnit.DAYS));
            int nonces = jdbc.update("DELETE FROM auth_v4_nonces WHERE created_at < ?", replayCutoff);
            int tokens = jdbc.update("DELETE FROM auth_v4_tokens WHERE created_at < ?", replayCutoff);

            Timestamp auditCutoff = Timestamp.from(now.minus(auditRetentionDays, ChronoUnit.DAYS));
            int audits = jdbc.update("DELETE FROM audit_logs WHERE created_at < ?", auditCutoff);

            if (sequences + sessions + nonces + tokens + audits > 0) {
                LOG.info("retention sweep: sessions={} sequences={} nonces={} tokens={} audits={}",
                        sessions, sequences, nonces, tokens, audits);
            }
        } catch (RuntimeException failure) {
            // Never let housekeeping affect licensing.
            LOG.warn("retention sweep failed (will retry on the next tick): {}", failure.toString());
        }
    }
}
