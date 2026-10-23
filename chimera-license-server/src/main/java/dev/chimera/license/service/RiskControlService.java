package dev.chimera.license.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory risk control for the B-Full lite UserContentKey delivery.
 *
 * <p>Rule: when the <b>same account</b> is observed with a <b>different HWID</b> within
 * {@code license.risk-control.window-seconds} (default 5s), the new HWID is considered anomalous.
 * The anomalous (current) HWID is flagged for {@code license.risk-control.poison-ttl-seconds}
 * (default 300s); activation responses for a flagged HWID carry a signed but byte-rotated
 * UserContentKey so the client silently fails to decrypt paid content.</p>
 *
 * <p>Both activation and heartbeat feed this detector. Heartbeat responses carry no key material
 * in the v3 wire format, so an anomaly seen on heartbeat only arms poisoning for that HWID's next
 * activation; see README "风险控制" and docs/known-issues.md KI-28.</p>
 *
 * <p>This is deliberately lightweight: state is in-memory (lost on restart, per-instance under a
 * multi-node deployment) and keyed by numeric account id.</p>
 */
@Component
public class RiskControlService {

    private final long windowMillis;
    private final long poisonTtlMillis;

    private final Map<Long, Activity> lastActivity = new ConcurrentHashMap<>();
    private final Map<DeviceKey, Long> poisonUntil = new ConcurrentHashMap<>();

    public RiskControlService(@Value("${license.risk-control.window-seconds:5}") long windowSeconds,
                              @Value("${license.risk-control.poison-ttl-seconds:300}") long poisonTtlSeconds) {
        this.windowMillis = Math.max(1L, windowSeconds) * 1000L;
        this.poisonTtlMillis = Math.max(1L, poisonTtlSeconds) * 1000L;
    }

    /** Identity of a bound device: the numeric account id plus the raw HWID string. */
    public record DeviceKey(long accountId, String hwid) {
    }

    private record Activity(String hwid, long atMillis) {
    }

    /**
     * Records an activation/heartbeat event and detects a rapid HWID switch for the account.
     *
     * @return {@code true} when the account used a different HWID within the configured window;
     *         the current HWID is poison-flagged in that case
     */
    public boolean recordActivity(long accountId, String hwid, Instant now) {
        long nowMillis = now.toEpochMilli();
        boolean[] suspicious = {false};
        lastActivity.compute(accountId, (id, previous) -> {
            if (previous != null
                    && !previous.hwid().equals(hwid)
                    && nowMillis >= previous.atMillis()
                    && nowMillis - previous.atMillis() <= windowMillis) {
                suspicious[0] = true;
                poisonUntil.put(new DeviceKey(accountId, hwid), nowMillis + poisonTtlMillis);
            }
            return new Activity(hwid, nowMillis);
        });
        return suspicious[0];
    }

    /** @return true while the (account, hwid) pair must receive a poisoned UserContentKey */
    public boolean isPoisoned(long accountId, String hwid, Instant now) {
        DeviceKey key = new DeviceKey(accountId, hwid);
        Long until = poisonUntil.get(key);
        if (until == null) {
            return false;
        }
        if (now.toEpochMilli() >= until.longValue()) {
            poisonUntil.remove(key, until);
            return false;
        }
        return true;
    }

    /** Test/support helper: forget all in-memory risk state. */
    public void reset() {
        lastActivity.clear();
        poisonUntil.clear();
    }
}
