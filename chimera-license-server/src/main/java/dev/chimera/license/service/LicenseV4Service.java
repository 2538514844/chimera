package dev.chimera.license.service;

import dev.chimera.license.api.ApiModels;
import dev.chimera.license.api.LicenseException;
import dev.chimera.license.config.KeyStoreService;
import dev.chimera.license.config.ResourceKeyService;
import dev.chimera.license.crypto.AuthTranscriptV4;
import dev.chimera.license.crypto.CryptoUtils;
import dev.chimera.license.store.AuthV4Store;
import dev.chimera.license.store.LicenseStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * v4 activation / heartbeat.
 *
 * <p>The signed transcript is the binary canonical form implemented by
 * {@link AuthTranscriptV4}: {@code u32be(len) || UTF-8} fields, domain first, decimal version
 * second. It is byte-identical to the client component's {@code AuthTranscriptV4}.</p>
 *
 * <p>Security invariants enforced here:</p>
 * <ul>
 *   <li>activation always starts at {@code sequence = 1};</li>
 *   <li>heartbeat returns {@code request.sequence + 1} and rejects stale sequences;</li>
 *   <li>every heartbeat rotates the bearer token; old tokens stop resolving and a token hash
 *       history makes re-issuing any previous token impossible;</li>
 *   <li>server nonces are unique across all v4 responses;</li>
 *   <li>an expired session is reported as {@code E_EXPIRED} before clock-rollback is considered;
 *       a non-expired heartbeat whose {@code issued_at} would move backwards is rejected with
 *       {@code E_CLOCK_ROLLBACK};</li>
 *   <li>issued_at/server_time stay within 300s of the server clock;</li>
 *   <li>client nonces and consumed heartbeat sequences are recorded in replay tables backed by
 *       database uniqueness constraints;</li>
 *   <li>the X25519 client public key presented at activation is stored on the session and every
 *       heartbeat must present exactly the same key ({@code E_KEY_MISMATCH} otherwise), so a
 *       stolen token cannot be used to wrap the ResourceKey to an attacker-controlled key;</li>
 *   <li>responses echo the request binding fields covered by the canonical transcript.</li>
 * </ul>
 */
@Service
public class LicenseV4Service {

    private static final Logger LOG = LoggerFactory.getLogger(LicenseV4Service.class);
    private static final int VERSION = 4;
    private static final int NONCE_MAX_ATTEMPTS = 8;

    private final AuthV4Store v4Store;
    private final LicenseStore store;
    private final KeyStoreService keys;
    private final ResourceKeyService resourceKeys;
    private final RateLimiter rateLimiter;
    private final RiskControlService riskControl;
    private final Clock clock;
    private final long sessionTtlSeconds;
    private final int maxDevicesPerAccount;
    private final boolean autoBindFirstDevice;

    /**
     * Serialises "count the account's devices, then bind" across concurrent activations.
     *
     * <p>Red team round 4 (source audit): the check was a plain read-then-write, so N machines
     * activating the same account at the same moment all observed zero devices and all inserted -
     * the per-account device limit was bypassable by a customer with a shell and {@code &}, no
     * support involvement required. A JVM-wide lock is sufficient for the single-node deployment
     * this server targets; a clustered deployment would need a database constraint instead
     * ({@code UNIQUE(account_id)} when the limit is 1, or a serialisable transaction).</p>
     */
    private final Object deviceBindLock = new Object();

    public LicenseV4Service(AuthV4Store v4Store,
                            LicenseStore store,
                            KeyStoreService keys,
                            ResourceKeyService resourceKeys,
                            RateLimiter rateLimiter,
                            RiskControlService riskControl,
                            Clock clock,
                            @Value("${license.session-ttl-seconds:86400}") long sessionTtlSeconds,
                            @Value("${license.max-devices-per-account:1}") int maxDevicesPerAccount,
                            @Value("${license.auto-bind-first-device:true}") boolean autoBindFirstDevice) {
        this.v4Store = v4Store;
        this.store = store;
        this.keys = keys;
        this.resourceKeys = resourceKeys;
        this.rateLimiter = rateLimiter;
        this.riskControl = riskControl;
        this.clock = clock;
        this.sessionTtlSeconds = Math.max(60L, sessionTtlSeconds);
        this.maxDevicesPerAccount = Math.max(1, maxDevicesPerAccount);
        this.autoBindFirstDevice = autoBindFirstDevice;
    }

    public ApiModels.ActivateV4Response activate(ApiModels.ActivateV4Request request, String clientIp) {
        if (request == null) {
            throw new LicenseException(400, "E_BAD_REQUEST");
        }
        if (request.v() != VERSION) {
            throw new LicenseException(400, "E_VERSION");
        }
        String account = trim(request.account());
        String password = request.password();
        String hwid = trim(request.hwid());
        String clientEphemeral = trim(request.client_ephemeral_pub());
        String clientNonce = trim(request.client_nonce());
        if (account.isEmpty() || password == null || password.isEmpty() || hwid.isEmpty()
                || clientEphemeral.isEmpty() || clientNonce.isEmpty()) {
            throw new LicenseException(400, "E_BAD_REQUEST");
        }
        requireClientNonce(clientNonce);

        byte[] clientPublic;
        try {
            clientPublic = CryptoUtils.unb64(clientEphemeral);
        } catch (RuntimeException e) {
            throw new LicenseException(400, "E_BAD_PUBKEY");
        }
        if (clientPublic.length != 32) {
            throw new LicenseException(400, "E_BAD_PUBKEY");
        }

        String limitKey = account + "|" + (clientIp == null ? "-" : clientIp);
        if (rateLimiter.isBlocked(limitKey)) {
            throw new LicenseException(429, "E_RATE_LIMIT");
        }
        LicenseStore.AccountRow accountRow = store.findAccount(account).orElse(null);
        if (accountRow == null || !CryptoUtils.verifyPassword(password, accountRow.passwordHash())) {
            rateLimiter.recordFailure(limitKey);
            throw new LicenseException(401, "E_AUTH");
        }
        if (!"ACTIVE".equals(accountRow.status())) {
            throw new LicenseException(403, "E_REVOKED");
        }

        Instant now = Instant.ofEpochSecond(clock.instant().getEpochSecond());
        // Everything below is one critical section: the device count that decides whether a bind is
        // allowed must not change between the read and the insert.
        synchronized (deviceBindLock) {
            List<String> devices = store.devices(accountRow.id());
            if (!devices.contains(hwid)) {
                bindNewDevice(accountRow.id(), hwid, devices.size(), now, clientPublic);
            } else {
                requireDeviceKey(accountRow.id(), hwid, clientPublic);
                store.touchDevice(accountRow.id(), hwid, now);
            }
        }
        rateLimiter.reset(limitKey);

        boolean rapidSwitch = riskControl.recordActivity(accountRow.id(), hwid, now);
        boolean poisoned = rapidSwitch || riskControl.isPoisoned(accountRow.id(), hwid, now);
        // #17: the stable licence id (generated on first use) and the address the server actually
        // saw. Both are signed into the response, so the client can embed a trustworthy licence id
        // in the per-licence watermark and the IP cannot be rewritten in transit.
        String licenseId = store.ensureLicenseId(accountRow.id());
        String ipWire = wireIp(clientIp);

        // X25519 shared secret authenticates the resource-key envelope (v4 ECDH wrap).
        KeyPair serverEphemeral = CryptoUtils.x25519KeyPair();
        byte[] serverEphemeralRaw = CryptoUtils.rawX25519(serverEphemeral.getPublic());
        byte[] shared;
        try {
            shared = CryptoUtils.x25519(serverEphemeral.getPrivate(), clientPublic);
            if (isAllZero(shared)) {
                throw new LicenseException(400, "E_BAD_PUBKEY");
            }
        } catch (LicenseException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new LicenseException(400, "E_BAD_PUBKEY");
        }

        // Replay table: one client_nonce may be used at most once across activate/heartbeat.
        if (!v4Store.recordNonce("client_nonce", nonceHash(clientNonce))) {
            throw new LicenseException(409, "E_REPLAY");
        }

        String serverNonce = newUniqueServerNonce();
        String token = newUniqueToken(accountRow.id(), null);
        long nowEpoch = now.getEpochSecond();
        long expiresEpoch = nowEpoch + sessionTtlSeconds;
        AuthV4Clock.requireWithinSkew(nowEpoch, nowEpoch, nowEpoch);

        byte[] ckPlain = resourceKeys.resourceKey();
        byte[] ckDelivered = poisoned ? CryptoUtils.poisonResourceKey(ckPlain) : ckPlain;
        byte[] ckWrapKey = CryptoUtils.hkdf(shared, clientNonce.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                "chimera/v1/v4/ck".getBytes(java.nio.charset.StandardCharsets.UTF_8), 32);
        byte[] ckNonce = CryptoUtils.random(12);
        byte[] ckAad = ("chimera/v1/v4/ck|" + account + "|" + hwid)
                .getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] ckSealed = CryptoUtils.aesGcmEncrypt(ckWrapKey, ckNonce, ckDelivered, ckAad);
        byte[] ckEnvelope = new byte[ckNonce.length + ckSealed.length];
        System.arraycopy(ckNonce, 0, ckEnvelope, 0, ckNonce.length);
        System.arraycopy(ckSealed, 0, ckEnvelope, ckNonce.length, ckSealed.length);
        String resourceCk = CryptoUtils.b64(ckEnvelope);
        wipe(shared);
        wipe(ckPlain);
        if (ckDelivered != ckPlain) {
            wipe(ckDelivered);
        }
        wipe(ckWrapKey);
        v4Store.insertSession(token, accountRow.id(), hwid, clientPublic, 1L, nowEpoch,
                expiresEpoch, now);

        byte[] canonical = AuthTranscriptV4.activateResponse(VERSION, account, hwid,
                clientEphemeral, clientNonce, CryptoUtils.b64(serverEphemeralRaw), serverNonce,
                token, 1L, nowEpoch, expiresEpoch, nowEpoch, resourceCk,
                licenseId, ipWire);
        String signature = CryptoUtils.b64(keys.sign(canonical));
        // #19b: self-authenticating watermark signature. Covers the two fields the watermark
        // claims (licence id + account), so a payload naming somebody else's licence cannot carry a
        // valid signature. Not part of the transcript: it needs no second signature of its own.
        String wmSig = CryptoUtils.b64(keys.sign(("chimera-wm-v1|" + licenseId + "|" + account)
                .getBytes(StandardCharsets.UTF_8)));

        String hwidHash = hashHwid(hwid);
        store.audit(accountRow.id(), poisoned ? "ACTIVATE_V4_POISONED" : "ACTIVATE_V4",
                hwidHash, hashIp(clientIp));
        LOG.info("v4 activation ok account={} licenseId={} hwidHash={} ip={} poisoned={}", account,
                licenseId, hwidHash.substring(0, 12), ipWire, poisoned);

        return new ApiModels.ActivateV4Response(VERSION, account, hwid, clientEphemeral,
                clientNonce, CryptoUtils.b64(serverEphemeralRaw), serverNonce, token, 1L,
                nowEpoch, expiresEpoch, nowEpoch, resourceCk, licenseId, ipWire, wmSig, signature);
    }

    public ApiModels.HeartbeatV4Response heartbeat(ApiModels.HeartbeatV4Request request,
                                                   String clientIp) {
        if (request == null) {
            throw new LicenseException(400, "E_BAD_REQUEST");
        }
        if (request.v() != VERSION) {
            throw new LicenseException(400, "E_VERSION");
        }
        String hwid = trim(request.hwid());
        String presentedToken = trim(request.token());
        String clientNonce = trim(request.client_nonce());
        if (hwid.isEmpty() || presentedToken.isEmpty() || clientNonce.isEmpty()
                || request.sequence() < 1L) {
            throw new LicenseException(400, "E_BAD_REQUEST");
        }
        requireClientNonce(clientNonce);

        String clientPubB64 = trim(request.client_ephemeral_pub());
        byte[] clientPublic;
        try {
            clientPublic = CryptoUtils.unb64(clientPubB64);
        } catch (RuntimeException invalid) {
            throw new LicenseException(400, "E_BAD_PUBKEY");
        }
        if (clientPublic.length != 32) {
            throw new LicenseException(400, "E_BAD_PUBKEY");
        }

        AuthV4Store.SessionRow session = v4Store.findSession(presentedToken)
                .orElseThrow(() -> new LicenseException(403, "E_REVOKED"));
        if (session.revoked()) {
            throw new LicenseException(403, "E_REVOKED");
        }
        // Red team round 4 (source audit): heartbeat used to validate the session row only. It
        // never looked at the account status or at the devices table, and every renewal slides
        // expires_at forward - so a banned account, or a machine whose binding had just been
        // cleared by /admin/rebind, kept renewing its session indefinitely. The "hardware change is
        // a support action" policy was therefore unenforceable: support could clear the binding and
        // the old machine would simply stay online.
        LicenseStore.AccountRow liveAccount = store.findAccountById(session.accountId())
                .orElseThrow(() -> new LicenseException(403, "E_REVOKED"));
        if (!"ACTIVE".equals(liveAccount.status())) {
            throw new LicenseException(403, "E_REVOKED");
        }
        if (!store.devices(liveAccount.id()).contains(session.hwid())) {
            throw new LicenseException(403, "E_BINDING");
        }
        long now = clock.instant().getEpochSecond();

        // Expiry takes priority over rollback: an already-expired session must be E_EXPIRED even
        // when issued_at also moved backwards.
        if (now >= session.expiresAt()) {
            throw new LicenseException(410, "E_EXPIRED");
        }
        if (!session.hwid().equals(hwid)) {
            throw new LicenseException(409, "E_BINDING");
        }
        // NOTE: heartbeat deliberately does not feed RiskControlService.recordActivity. A heartbeat
        // is not a device change, and recording it re-enters the rapid-switch window every minute,
        // which measurably poisoned the account's *other* devices (RiskControlIntegrationTest
        // heartbeatHonoursPoisonFlagAndKeepsOtherDeviceClean). HWID changes are rejected outright
        // above, which is strictly stronger than poisoning. The detector stays activation-driven.
        // The session is bound to the activation-time client key: HWID and key are immutable, and
        // re-binding requires admin/revoke followed by a fresh activation.
        byte[] boundPublic = session.clientPub();
        if (boundPublic == null) {
            // Fail closed: a session without a bound key is a legacy row. Adopting whatever key the
            // caller presents would let a stolen legacy token bind an attacker-controlled key and
            // defeat the whole binding. Legacy sessions must re-activate (they expire quickly).
            throw new LicenseException(403, "E_KEY_MISMATCH");
        } else if (!MessageDigest.isEqual(boundPublic, clientPublic)) {
            throw new LicenseException(403, "E_KEY_MISMATCH");
        }
        if (!v4Store.recordNonce("client_nonce", nonceHash(clientNonce))) {
            throw new LicenseException(409, "E_REPLAY");
        }
        AuthV4Clock.requireNoRollback(now, session.issuedAt());
        if (request.sequence() != session.sequence()) {
            throw new LicenseException(409, "E_SEQUENCE");
        }
        // Sequence replay table: each request sequence is consumed exactly once per session.
        // Red team round 4 (source audit): this used to run *before* rotateSession(), so a rotate
        // that lost a race burned the sequence permanently - the client could only retry with the
        // same number, which then always failed E_REPLAY, and two consecutive failures halt the
        // process. The sequence is now consumed only after the rotation actually happened;
        // rotateSession()'s compare-and-set on session.sequence() is what makes concurrent reuse
        // impossible in the first place.

        // Per-launch key delivery: the client re-presents its activation-time ephemeral public key
        // (already verified above) so the ResourceKey can be re-wrapped for a restart.
        KeyPair serverEphemeral = CryptoUtils.x25519KeyPair();
        byte[] serverEphemeralRaw = CryptoUtils.rawX25519(serverEphemeral.getPublic());
        byte[] shared = CryptoUtils.x25519(serverEphemeral.getPrivate(), clientPublic);
        if (isAllZero(shared)) {
            wipe(shared);
            throw new LicenseException(400, "E_BAD_PUBKEY");
        }
        LicenseStore.AccountRow accountRow = store.findAccountById(session.accountId())
                .orElseThrow(() -> new LicenseException(403, "E_REVOKED"));
        boolean poisoned = riskControl.isPoisoned(session.accountId(), hwid, clock.instant());
        byte[] resourcePlain = resourceKeys.resourceKey();
        byte[] delivered = poisoned ? CryptoUtils.poisonResourceKey(resourcePlain) : resourcePlain;
        byte[] hbWrapKey = CryptoUtils.hkdf(shared,
                clientNonce.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                "chimera/v1/v4/ck".getBytes(java.nio.charset.StandardCharsets.UTF_8), 32);
        byte[] hbNonce = CryptoUtils.random(12);
        byte[] hbAad = ("chimera/v1/v4/ck|" + accountRow.account() + "|" + hwid)
                .getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] hbSealed = CryptoUtils.aesGcmEncrypt(hbWrapKey, hbNonce, delivered, hbAad);
        byte[] hbEnvelope = new byte[hbNonce.length + hbSealed.length];
        System.arraycopy(hbNonce, 0, hbEnvelope, 0, hbNonce.length);
        System.arraycopy(hbSealed, 0, hbEnvelope, hbNonce.length, hbSealed.length);
        String resourceCk = CryptoUtils.b64(hbEnvelope);
        byte[] serverEphemeralForWire = serverEphemeralRaw;
        wipe(shared);
        wipe(resourcePlain);
        if (delivered != resourcePlain) {
            wipe(delivered);
        }
        wipe(hbWrapKey);

        String serverNonce = newUniqueServerNonce();
        String newToken = newUniqueToken(session.accountId(), presentedToken);
        long nextSequence = request.sequence() + 1L;
        long expiresAt = now + sessionTtlSeconds;
        // (The former requireWithinSkew(now, now, now) call was a no-op: all three arguments were
        // the server's own clock, so the skew was always zero. Skew is enforced where it can be
        // observed - AuthV4Clock.requireNoRollback against the stored issued_at, above.)

        int rotated = v4Store.rotateSession(session.id(), presentedToken, session.sequence(),
                session.issuedAt(), newToken, nextSequence, now, expiresAt);
        if (rotated == 0) {
            throw new LicenseException(409, "E_REPLAY");
        }
        // Consumed only now that the rotation is durable, so a lost race does not burn the number.
        v4Store.recordSequence(session.id(), request.sequence());

        String serverPubWire = CryptoUtils.b64(serverEphemeralForWire);
        String licenseId = store.ensureLicenseId(session.accountId());
        String ipWire = wireIp(clientIp);
        byte[] canonical = AuthTranscriptV4.heartbeatResponse(VERSION, hwid, clientNonce,
                presentedToken, newToken, nextSequence, serverNonce, now, expiresAt, now,
                resourceCk, serverPubWire, licenseId, ipWire);
        String signature = CryptoUtils.b64(keys.sign(canonical));
        // #19b: refreshed every heartbeat so an upgraded client gets a verifiable watermark without
        // having to re-activate (the signature is self-authenticating and stays out of the transcript).
        String wmSig = CryptoUtils.b64(keys.sign(("chimera-wm-v1|" + licenseId + "|" + accountRow.account())
                .getBytes(StandardCharsets.UTF_8)));

        store.audit(session.accountId(), "HEARTBEAT_V4", hashHwid(hwid), hashIp(clientIp));
        LOG.info("v4 heartbeat ok accountId={} licenseId={} sequence={} ip={}",
                session.accountId(), licenseId, nextSequence, ipWire);

        return new ApiModels.HeartbeatV4Response(VERSION, hwid, clientNonce, newToken,
                nextSequence, serverNonce, now, expiresAt, now, resourceCk, serverPubWire,
                licenseId, ipWire, wmSig, signature);
    }

    /**
     * Builds the signed resource envelope exactly like v3 (KI-28). v4 responses do not carry
     * {@code wrapped_ck}, so this envelope is only useful to consumers that obtain the
     * UserContentKey through the v3 activation path; it is still signed and bound to account/hwid.
     */
    private String resourceEnvelope(long accountId, String account, String hwid, boolean poisoned) {
        byte[] userContentKey = null;
        byte[] deliveredKey = null;
        byte[] resourceKey = null;
        byte[] resourcePlaintext = null;
        byte[] resourceWrapKey = null;
        try {
            userContentKey = keys.deriveUserContentKey(accountId, hwid);
            deliveredKey = poisoned
                    ? CryptoUtils.poisonUserContentKey(userContentKey) : userContentKey;
            resourceKey = resourceKeys.resourceKey();
            resourcePlaintext = poisoned
                    ? CryptoUtils.poisonResourceKey(resourceKey) : resourceKey;
            resourceWrapKey = CryptoUtils.resourceWrapKey(deliveredKey);
            byte[] gcmNonce = CryptoUtils.random(12);
            byte[] sealed = CryptoUtils.aesGcmEncrypt(resourceWrapKey, gcmNonce,
                    resourcePlaintext, CryptoUtils.resourceAad(account, hwid));
            byte[] envelope = new byte[gcmNonce.length + sealed.length];
            System.arraycopy(gcmNonce, 0, envelope, 0, gcmNonce.length);
            System.arraycopy(sealed, 0, envelope, gcmNonce.length, sealed.length);
            return CryptoUtils.b64(envelope);
        } finally {
            wipe(userContentKey);
            if (deliveredKey != userContentKey) {
                wipe(deliveredKey);
            }
            wipe(resourceKey);
            if (resourcePlaintext != resourceKey) {
                wipe(resourcePlaintext);
            }
            wipe(resourceWrapKey);
        }
    }

    private String newUniqueServerNonce() {
        for (int attempt = 0; attempt < NONCE_MAX_ATTEMPTS; attempt++) {
            String nonce = CryptoUtils.b64(CryptoUtils.random(16));
            if (v4Store.recordNonce("server_nonce", nonceHash(nonce))) {
                return nonce;
            }
        }
        throw new IllegalStateException("cannot allocate a fresh server_nonce");
    }

    private String newUniqueToken(long accountId, String forbiddenToken) {
        for (int attempt = 0; attempt < NONCE_MAX_ATTEMPTS; attempt++) {
            String token = CryptoUtils.b64(CryptoUtils.random(32));
            if (forbiddenToken != null && token.equals(forbiddenToken)) {
                continue;
            }
            if (v4Store.recordToken(AuthTranscriptV4.tokenHashHex(token), accountId)) {
                return token;
            }
        }
        throw new IllegalStateException("cannot allocate a fresh bearer token");
    }

    private static void requireClientNonce(String clientNonce) {
        try {
            byte[] raw = Base64.getDecoder().decode(clientNonce);
            if (raw.length < 16 || raw.length > 64) {
                throw new LicenseException(400, "E_BAD_REQUEST");
            }
        } catch (IllegalArgumentException e) {
            throw new LicenseException(400, "E_BAD_REQUEST");
        }
    }

    private static String nonceHash(String nonce) {
        return CryptoUtils.hex(CryptoUtils.sha256(nonce.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * Red team round 3, finding 3: {@code hwid} is a string the client writes, so binding an account
     * on it alone means anyone who learns a customer's 64 hex can activate on another machine.
     *
     * <p>The account is now bound to the public half of the client's DPAPI-sealed X25519 key. That
     * key never leaves the machine in usable form (the sealed private half is bound to the Windows
     * user by {@code CryptProtectData}), so a stolen {@code hwid} string without the matching key
     * cannot activate. {@code hwid} stays as the human-readable label and as the device limit key.</p>
     *
     * <p>Rows created before this column existed adopt the first key presented, so an upgrade does
     * not lock out already-bound customers; enforcement starts from the following activation.</p>
     */
    private void requireDeviceKey(long accountId, String hwid, byte[] presented) {
        byte[] bound = store.devicePub(accountId, hwid);
        if (bound == null) {
            store.adoptDevicePub(accountId, hwid, presented);
            return;
        }
        if (!MessageDigest.isEqual(bound, presented)) {
            // Same HWID, different device key: the string was copied, or the machine was reinstalled
            // (which regenerates the sealed key). Both are a support action, never self-service.
            throw new LicenseException(403, "E_DEVICE_KEY_MISMATCH");
        }
    }

    private void bindNewDevice(long accountId, String hwid, int activeDevices, Instant now,
                               byte[] devicePub) {
        if (activeDevices == 0) {
            if (!autoBindFirstDevice) {
                throw new LicenseException(403, "E_HWID_MISMATCH");
            }
            store.bindDevice(accountId, hwid, devicePub, now);
            return;
        }
        if (maxDevicesPerAccount <= 1) {
            throw new LicenseException(403, "E_HWID_MISMATCH");
        }
        if (activeDevices >= maxDevicesPerAccount
                || store.deviceCount(accountId) >= maxDevicesPerAccount) {
            throw new LicenseException(403, "E_DEVICE_LIMIT");
        }
        store.bindDevice(accountId, hwid, devicePub, now);
    }

    private static String hashHwid(String hwid) {
        return CryptoUtils.hex(CryptoUtils.sha256(hwid.getBytes(StandardCharsets.UTF_8)));
    }

    private static String hashIp(String clientIp) {
        return CryptoUtils.hex(CryptoUtils.sha256(String.valueOf(clientIp)
                .getBytes(StandardCharsets.UTF_8)));
    }

    /** Wire form of the observed client address: never null, so the signed field is unambiguous. */
    private static String wireIp(String clientIp) {
        return clientIp == null ? "" : clientIp.trim();
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
