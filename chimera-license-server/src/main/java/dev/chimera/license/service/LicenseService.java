package dev.chimera.license.service;

import dev.chimera.license.api.ApiModels;
import dev.chimera.license.api.LicenseException;
import dev.chimera.license.config.KeyStoreService;
import dev.chimera.license.config.ResourceKeyService;
import dev.chimera.license.crypto.CryptoUtils;
import dev.chimera.license.store.LicenseStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;

/**
 * Implements activation and heartbeat (docs/AUTH-V2-PROTOCOL.md v3).
 *
 * <p>B-Full lite: {@code wrapped_ck} no longer carries the product-level content key. For every
 * (account id, HWID) the server derives {@code UserContentKey = HKDF-SHA256(MasterKey,
 * salt="chimera/uck/v1", info=BE64(account_id)||UTF8(hwid), L=32)} and wraps that value. A rapid
 * HWID switch (same account, different HWID within {@code license.risk-control.window-seconds})
 * flags the anomalous HWID for {@code license.risk-control.poison-ttl-seconds}; its activation
 * then receives the byte-rotated key inside a normally signed response.</p>
 *
 * <p>KI-28 envelope: activation additionally returns {@code resource_ck}, the long-lived
 * {@code ResourceKey} encrypted under the delivered UserContentKey
 * ({@code HKDF-SHA256(UserContentKey, zeros32, "chimera/resource-wrap/v1")}, AES-256-GCM,
 * AAD {@code "chimera-resource/v1|account|hwid"}). The ResourceKey is what the build pipeline uses
 * to encrypt paid resources; the MasterKey is never delivered. Poisoned devices receive a rotated
 * ResourceKey, so they cannot decrypt released content.</p>
 */
@Service
public class LicenseService {

    private static final Logger LOG = LoggerFactory.getLogger(LicenseService.class);
    private static final byte[] WRAP_INFO = "chimera/wrap/v1".getBytes(StandardCharsets.UTF_8);

    private final LicenseStore store;
    private final KeyStoreService keys;
    private final RateLimiter rateLimiter;
    private final RiskControlService riskControl;
    private final ResourceKeyService resourceKeys;
    private final long sessionTtlSeconds;
    private final int maxDevicesPerAccount;
    private final boolean autoBindFirstDevice;

    public LicenseService(LicenseStore store,
                          KeyStoreService keys,
                          RateLimiter rateLimiter,
                          RiskControlService riskControl,
                          ResourceKeyService resourceKeys,
                          @Value("${license.session-ttl-seconds:86400}") long sessionTtlSeconds,
                          @Value("${license.max-devices-per-account:1}") int maxDevicesPerAccount,
                          @Value("${license.auto-bind-first-device:true}") boolean autoBindFirstDevice) {
        this.store = store;
        this.keys = keys;
        this.rateLimiter = rateLimiter;
        this.riskControl = riskControl;
        this.resourceKeys = resourceKeys;
        this.sessionTtlSeconds = Math.max(60L, sessionTtlSeconds);
        this.maxDevicesPerAccount = Math.max(1, maxDevicesPerAccount);
        this.autoBindFirstDevice = autoBindFirstDevice;
    }

    /** Admin/build-pipeline account provisioning (token guarded by the controller). */
    public void registerAccount(String account, String password) {
        if (account == null || account.isBlank() || password == null || password.length() < 6) {
            throw new LicenseException(400, "E_BAD_REQUEST");
        }
        if (store.findAccount(account.trim()).isPresent()) {
            throw new LicenseException(409, "E_ACCOUNT_EXISTS");
        }
        store.insertAccount(account.trim(), CryptoUtils.hashPassword(password), "ACTIVE");
    }

    /**
     * Self-service onboarding against a pre-registered hardware slot (2026-10-22).
     *
     * <p>Flow the operator asked for: the customer sends their HWID, the operator adds it with
     * {@code POST /admin/reserve-hwid}, then the customer registers an account of their own from
     * that machine and is bound to exactly that HWID - no account is created by the operator and no
     * invite code changes hands.</p>
     *
     * <p>Why exposing registration is safe: a reservation can be claimed exactly once
     * ({@code WHERE claimed_account_id IS NULL}), and the request must present the HWID that was
     * reserved. An attacker would have to know a specific customer's 64-hex hardware id before that
     * customer registers. Failures are rate limited per client address, and the whole operation runs
     * in one transaction so the loser of a race leaves no orphan account.</p>
     */
    @org.springframework.transaction.annotation.Transactional
    public void registerWithReservedHwid(String account, String password, String hwid,
                                         String clientIp) {
        String normalizedAccount = account == null ? "" : account.trim();
        String normalizedHwid = hwid == null ? "" : hwid.trim().toLowerCase(java.util.Locale.ROOT);
        if (normalizedAccount.isEmpty() || password == null || password.length() < 6
                || !normalizedHwid.matches("[0-9a-f]{64}")) {
            throw new LicenseException(400, "E_BAD_REQUEST");
        }
        String limitKey = "register|" + (clientIp == null ? "-" : clientIp);
        if (rateLimiter.isBlocked(limitKey)) {
            throw new LicenseException(429, "E_RATE_LIMIT");
        }
        if (store.findAccount(normalizedAccount).isPresent()) {
            throw new LicenseException(409, "E_ACCOUNT_EXISTS");
        }
        LicenseStore.ReservationRow reservation = store.findReservation(normalizedHwid)
                .orElseThrow(() -> {
                    rateLimiter.recordFailure(limitKey);
                    return new LicenseException(403, "E_HWID_NOT_RESERVED");
                });
        if (reservation.claimedAccountId() != null) {
            throw new LicenseException(409, "E_HWID_CLAIMED");
        }
        // The account insert and the claim run in one transaction; if the claim loses the race the
        // rollback removes the account, so no orphan is left behind.
        store.insertAccount(normalizedAccount, CryptoUtils.hashPassword(password), "ACTIVE");
        LicenseStore.AccountRow created = store.findAccount(normalizedAccount)
                .orElseThrow(() -> new IllegalStateException("account vanished after insert"));
        if (store.claimReservation(normalizedHwid, created.id(), Instant.now()) == 0) {
            throw new LicenseException(409, "E_HWID_CLAIMED");
        }
        // Red team round 4 (source audit): this used to create the device row here, with
        // device_pub left NULL because registration has no handshake yet. The next activation then
        // adopted whatever public key it was presented with, so the "same hwid must present the same
        // device key" rule was unenforced for exactly the accounts that had just been onboarded.
        // Registration now only claims the reservation; the device row is created by the first
        // activation, which always has the client's X25519 key in hand.
        store.audit(created.id(), "REGISTER_RESERVED_HWID", hashHwid(normalizedHwid), null);
        rateLimiter.reset(limitKey);
        LOG.info("self-registration ok account={} hwidHash={}", normalizedAccount,
                hashHwid(normalizedHwid).substring(0, 12));
    }

    // SECURITY (2026-10-22): v3 activate/heartbeat removed - v3 heartbeat authenticated with
    // a bearer token only (no HWID, no client key, no signature), so a leaked token could be
    // renewed indefinitely. v4 is the only auth path now.
    /**
     * First device of an account is auto-bound when configured; additional devices are only bound
     * when {@code license.max-devices-per-account > 1} and a slot is free (needed for the
     * multi-device risk-control deployment). With the default 1:1 policy a different HWID is
     * rejected with E_HWID_MISMATCH.
     */
    private void bindNewDevice(long accountId, String hwid, int activeDevices, Instant now) {
        if (activeDevices == 0) {
            if (!autoBindFirstDevice) {
                throw new LicenseException(403, "E_HWID_MISMATCH");
            }
            store.bindDevice(accountId, hwid, now);
            return;
        }
        if (maxDevicesPerAccount <= 1) {
            // 1:1 accounts: the account is bound to another device; rebind is a support action.
            throw new LicenseException(403, "E_HWID_MISMATCH");
        }
        if (activeDevices >= maxDevicesPerAccount || store.deviceCount(accountId) >= maxDevicesPerAccount) {
            throw new LicenseException(403, "E_DEVICE_LIMIT");
        }
        store.bindDevice(accountId, hwid, now);
    }

    private static String hashHwid(String hwid) {
        return CryptoUtils.hex(CryptoUtils.sha256(hwid.getBytes(StandardCharsets.UTF_8)));
    }

    private static String hashIp(String clientIp) {
        return CryptoUtils.hex(CryptoUtils.sha256(String.valueOf(clientIp).getBytes(StandardCharsets.UTF_8)));
    }

    private static boolean isAllZero(byte[] data) {
        for (byte value : data) {
            if (value != 0) {
                return false;
            }
        }
        return true;
    }

    private static void wipe(byte[] data) {
        if (data != null) {
            Arrays.fill(data, (byte) 0);
        }
    }

    private static String trim(String value) {
        return value == null ? "" : value.trim();
    }
}
