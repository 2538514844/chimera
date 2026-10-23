package dev.chimera.auth;

import dev.chimera.crypto.Crypto;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.Optional;

/**
 * Client-side v4 protocol state machine: client_nonce generation, request/response binding,
 * response signature verification, token rotation, monotonic sequence persistence, replay
 * detection and clock-skew checks.
 *
 * <p>This class performs no I/O. Wiring is responsible for HTTP, JSON field extraction
 * ({@link ActivationResponseV4#fromFields(java.util.Map)} / {@link HeartbeatResponseV4#fromFields}),
 * X25519/AES-GCM protected-key unwrapping, and installing accepted keys/nonces into the runtime.</p>
 *
 * <p>All mutating entry points are synchronized: one activation/heartbeat session per instance.
 * Every verification clears the pending request (single use), so a caller must request a fresh
 * nonce for each attempt.</p>
 */
public final class AuthProtocolV4 {

    private final AuthV4Config config;
    private final byte[] serverPublicKeyRaw;
    private final ClockSkewGuard clockGuard;
    private final BoundedDigestHistory nonceHistory;
    private final BoundedDigestHistory tokenHistory;

    private ActivationRequestV4 pendingActivation;
    private HeartbeatRequestV4 pendingHeartbeat;

    public AuthProtocolV4(AuthV4Config config, byte[] serverEd25519PublicKeyRaw) {
        this.config = Objects.requireNonNull(config, "config");
        if (serverEd25519PublicKeyRaw == null || serverEd25519PublicKeyRaw.length != 32) {
            throw new IllegalArgumentException("pinned Ed25519 public key must be 32 raw bytes");
        }
        this.serverPublicKeyRaw = serverEd25519PublicKeyRaw.clone();
        this.clockGuard = new ClockSkewGuard(config.clockSkewSeconds());
        this.nonceHistory = new BoundedDigestHistory(config.historyLimit());
        this.tokenHistory = new BoundedDigestHistory(config.historyLimit());
    }

    /**
     * Creates an activation request with a fresh 32B client_nonce.
     *
     * @param clientEphemeralPubB64 base64 of the client's ephemeral X25519 public key (32B raw)
     */
    public synchronized ActivationRequestV4 newActivation(String account, String hwid,
                                                          String clientEphemeralPubB64)
            throws AuthProtocolException {
        String safeAccount = requireInput("account", account, 254);
        String safeHwid = requireInput("hwid", hwid, 512);
        String safePublicKey = requireInput("client_ephemeral_pub", clientEphemeralPubB64, 128);
        decodeBase64("client_ephemeral_pub", safePublicKey, 32, AuthFailure.INPUT);
        ActivationRequestV4 request = new ActivationRequestV4(ActivationRequestV4.VERSION,
                safeAccount, safeHwid, safePublicKey, newClientNonce());
        this.pendingActivation = request;
        this.pendingHeartbeat = null;
        return request;
    }

    /**
     * Verifies and accepts the activation response. The response must echo account/hwid/
     * client_ephemeral_pub/client_nonce, start at sequence 1, carry a valid signature and sane
     * timestamps. On success the initial sequence/token state is persisted before returning.
     */
    public synchronized AuthV4Session verifyActivate(ActivationRequestV4 request,
                                                     ActivationResponseV4 response)
            throws AuthProtocolException {
        ActivationRequestV4 pending = pendingActivation;
        pendingActivation = null;
        if (pending == null) {
            throw new AuthProtocolException(AuthFailure.STATE, "no pending activation request");
        }
        if (request == null || response == null) {
            throw new AuthProtocolException(AuthFailure.BAD_RESPONSE, "activation request/response missing");
        }
        if (!sameActivationRequest(pending, request)) {
            throw new AuthProtocolException(AuthFailure.BINDING, "activation request does not match pending nonce");
        }
        if (response.version() != ActivationRequestV4.VERSION) {
            throw new AuthProtocolException(AuthFailure.VERSION, "unsupported activation response version");
        }
        if (!same(pending.account(), response.account())
                || !same(pending.hwid(), response.hwid())
                || !same(pending.clientEphemeralPub(), response.clientEphemeralPub())
                || !same(pending.clientNonce(), response.clientNonce())) {
            throw new AuthProtocolException(AuthFailure.BINDING,
                    "activation response is not bound to the request fields");
        }
        if (response.sequence() != 1L) {
            throw new AuthProtocolException(AuthFailure.SEQUENCE, "activation sequence must start at 1");
        }
        if (!verifySignature(AuthTranscriptV4.activateResponse(response), response.signature())) {
            throw new AuthProtocolException(AuthFailure.SIGNATURE, "activation signature verification failed");
        }
        clockGuard.checkActivation(nowEpochSeconds(), response.issuedAt(), response.expiresAt(),
                response.serverTime());

        byte[] token = decodeBase64("token", response.token(), 32, AuthFailure.BAD_RESPONSE);
        byte[] serverNonce = decodeBase64("server_nonce", response.serverNonce(), 16, AuthFailure.BAD_RESPONSE);
        decodeBase64("server_ephemeral_pub", response.serverEphemeralPub(), 32, AuthFailure.BAD_RESPONSE);

        byte[] tokenHash = sha256(token);
        byte[] nonceHash = sha256(serverNonce);
        if (!tokenHistory.add(tokenHash)) {
            throw new AuthProtocolException(AuthFailure.TOKEN_REPLAY, "activation token already used");
        }
        if (!nonceHistory.add(nonceHash)) {
            throw new AuthProtocolException(AuthFailure.NONCE_REPLAY, "activation server_nonce already used");
        }
        saveState(new SequenceState(SequenceState.VERSION, response.account(), response.hwid(),
                1L, response.issuedAt(), tokenHash, nonceHash));

        return new AuthV4Session(response.account(), response.hwid(), response.token(), 1L,
                response.issuedAt(), response.expiresAt(), response.serverNonce());
    }

    /** Creates a heartbeat request with a fresh client_nonce bound to the current session sequence. */
    public synchronized HeartbeatRequestV4 newHeartbeat(AuthV4Session session)
            throws AuthProtocolException {
        if (session == null) {
            throw new AuthProtocolException(AuthFailure.STATE, "session is required");
        }
        requireInput("hwid", session.hwid(), 512);
        requireInput("token", session.token(), 128);
        if (session.sequence() < 1L) {
            throw new AuthProtocolException(AuthFailure.STATE, "session sequence must be >= 1");
        }
        HeartbeatRequestV4 request = new HeartbeatRequestV4(HeartbeatRequestV4.VERSION,
                session.hwid(), session.token(), newClientNonce(), session.sequence());
        this.pendingHeartbeat = request;
        this.pendingActivation = null;
        return request;
    }

    /**
     * Verifies a heartbeat response, rotates the token, advances and persists the sequence, and
     * returns the updated session. Replayed responses are rejected by the persisted sequence and
     * the nonce/token histories.
     */
    public synchronized AuthV4Session verifyHeartbeat(AuthV4Session session,
                                                      HeartbeatRequestV4 request,
                                                      HeartbeatResponseV4 response)
            throws AuthProtocolException {
        HeartbeatRequestV4 pending = pendingHeartbeat;
        pendingHeartbeat = null;
        if (pending == null) {
            throw new AuthProtocolException(AuthFailure.STATE, "no pending heartbeat request");
        }
        if (session == null || request == null || response == null) {
            throw new AuthProtocolException(AuthFailure.BAD_RESPONSE, "heartbeat request/response/session missing");
        }
        if (!sameHeartbeatRequest(pending, request)) {
            throw new AuthProtocolException(AuthFailure.BINDING, "heartbeat request does not match pending nonce");
        }
        if (!same(request.hwid(), session.hwid()) || request.sequence() != session.sequence()) {
            throw new AuthProtocolException(AuthFailure.SEQUENCE, "heartbeat request does not match session sequence");
        }
        if (!same(request.token(), session.token())) {
            throw new AuthProtocolException(AuthFailure.TOKEN, "heartbeat token does not match the active session");
        }
        if (response.version() != ActivationRequestV4.VERSION) {
            throw new AuthProtocolException(AuthFailure.VERSION, "unsupported heartbeat response version");
        }
        if (!same(response.hwid(), request.hwid())
                || !same(response.clientNonce(), request.clientNonce())) {
            throw new AuthProtocolException(AuthFailure.BINDING,
                    "heartbeat response is not bound to the request fields");
        }
        if (response.sequence() != request.sequence() + 1L) {
            throw new AuthProtocolException(AuthFailure.SEQUENCE, "heartbeat sequence must increment by exactly 1");
        }
        if (!verifySignature(AuthTranscriptV4.heartbeatResponse(response, request.token()),
                response.signature())) {
            throw new AuthProtocolException(AuthFailure.SIGNATURE, "heartbeat signature verification failed");
        }
        clockGuard.checkHeartbeat(nowEpochSeconds(), response.issuedAt(), response.expiresAt(),
                response.serverTime(), session.issuedAt());

        byte[] oldToken = decodeBase64("token", request.token(), 32, AuthFailure.TOKEN);
        byte[] newToken = decodeBase64("token", response.token(), 32, AuthFailure.BAD_RESPONSE);
        byte[] serverNonce = decodeBase64("server_nonce", response.serverNonce(), 16,
                AuthFailure.BAD_RESPONSE);
        if (MessageDigest.isEqual(oldToken, newToken)) {
            throw new AuthProtocolException(AuthFailure.TOKEN_ROTATION,
                    "heartbeat must rotate the bearer token");
        }
        byte[] oldTokenHash = sha256(oldToken);
        byte[] newTokenHash = sha256(newToken);
        byte[] nonceHash = sha256(serverNonce);
        if (tokenHistory.contains(newTokenHash)) {
            throw new AuthProtocolException(AuthFailure.TOKEN_REPLAY, "rotated token was already used");
        }

        SequenceState state = loadState().orElseThrow(() -> new AuthProtocolException(
                AuthFailure.STATE, "missing persisted auth state; re-activation required"));
        if (!same(state.account(), session.account()) || !same(state.hwid(), session.hwid())
                || state.sequence() != request.sequence()
                || state.issuedAt() != session.issuedAt()
                || !MessageDigest.isEqual(state.tokenHash(), oldTokenHash)) {
            throw new AuthProtocolException(AuthFailure.STATE,
                    "persisted auth state does not match the presented session (replay/rollback?)");
        }
        if (!nonceHistory.add(nonceHash)) {
            throw new AuthProtocolException(AuthFailure.NONCE_REPLAY, "heartbeat server_nonce already used");
        }
        saveState(new SequenceState(SequenceState.VERSION, session.account(), session.hwid(),
                response.sequence(), response.issuedAt(), newTokenHash, nonceHash));
        tokenHistory.add(newTokenHash);

        return session.afterHeartbeat(response.token(), response.sequence(), response.issuedAt(),
                response.expiresAt(), response.serverNonce());
    }

    /** Loads the persisted monotonic state for wiring/diagnostics; validates account/hwid binding. */
    public synchronized Optional<SequenceState> loadPersistedState(String account, String hwid)
            throws AuthProtocolException {
        Optional<SequenceState> loaded = loadState();
        if (loaded.isPresent()) {
            SequenceState state = loaded.get();
            if (!same(state.account(), account) || !same(state.hwid(), hwid)) {
                throw new AuthProtocolException(AuthFailure.STATE,
                        "persisted auth state belongs to a different account/hwid");
            }
        }
        return loaded;
    }

    /** Logout/rebind: removes persisted sequence state and in-memory replay histories. */
    public synchronized void clearPersistedState() throws AuthProtocolException {
        try {
            config.sequenceStore().clear();
        } catch (IOException e) {
            throw new AuthProtocolException(AuthFailure.STATE, "cannot clear persisted auth state", e);
        }
        nonceHistory.clear();
        tokenHistory.clear();
        pendingActivation = null;
        pendingHeartbeat = null;
    }

    /** Drops pending requests and in-memory histories without touching persisted state (tests). */
    public synchronized void reset() {
        pendingActivation = null;
        pendingHeartbeat = null;
        nonceHistory.clear();
        tokenHistory.clear();
    }

    private String newClientNonce() throws AuthProtocolException {
        byte[] nonce = config.nonceSource().nextBytes(config.nonceBytes());
        if (nonce == null || nonce.length != config.nonceBytes()) {
            throw new AuthProtocolException(AuthFailure.STATE, "nonce source returned an invalid nonce");
        }
        return Base64.getEncoder().encodeToString(nonce);
    }

    private long nowEpochSeconds() {
        return config.clock().instant().getEpochSecond();
    }

    private boolean verifySignature(byte[] canonical, String signatureBase64) {
        if (canonical == null || signatureBase64 == null) {
            return false;
        }
        byte[] signature;
        try {
            signature = Base64.getDecoder().decode(signatureBase64);
        } catch (IllegalArgumentException e) {
            return false;
        }
        return config.signatureVerifier().verify(canonical, signature, serverPublicKeyRaw);
    }

    private Optional<SequenceState> loadState() throws AuthProtocolException {
        try {
            return config.sequenceStore().load();
        } catch (IOException e) {
            throw new AuthProtocolException(AuthFailure.STATE, "cannot load persisted auth state", e);
        }
    }

    private void saveState(SequenceState state) throws AuthProtocolException {
        try {
            config.sequenceStore().save(state);
        } catch (IOException e) {
            throw new AuthProtocolException(AuthFailure.STATE, "cannot persist auth state", e);
        }
    }

    private static boolean sameActivationRequest(ActivationRequestV4 left, ActivationRequestV4 right) {
        return left.version() == right.version()
                && same(left.account(), right.account())
                && same(left.hwid(), right.hwid())
                && same(left.clientEphemeralPub(), right.clientEphemeralPub())
                && same(left.clientNonce(), right.clientNonce());
    }

    private static boolean sameHeartbeatRequest(HeartbeatRequestV4 left, HeartbeatRequestV4 right) {
        return left.version() == right.version()
                && left.sequence() == right.sequence()
                && same(left.hwid(), right.hwid())
                && same(left.token(), right.token())
                && same(left.clientNonce(), right.clientNonce());
    }

    private static boolean same(String left, String right) {
        if (left == null || right == null) {
            return false;
        }
        return MessageDigest.isEqual(left.getBytes(StandardCharsets.UTF_8),
                right.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] decodeBase64(String field, String value, int expectedLength,
                                       AuthFailure failure) throws AuthProtocolException {
        if (value == null || value.isEmpty()) {
            throw new AuthProtocolException(failure, field + " is missing");
        }
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw new AuthProtocolException(failure, field + " is not valid base64");
        }
        if (decoded.length != expectedLength) {
            throw new AuthProtocolException(failure, field + " has wrong length");
        }
        return decoded;
    }

    private static String requireInput(String field, String value, int maxLength)
            throws AuthProtocolException {
        if (value == null || value.isEmpty() || value.length() > maxLength) {
            throw new AuthProtocolException(AuthFailure.INPUT, "invalid " + field);
        }
        return value;
    }

    private static byte[] sha256(byte[] value) {
        return Crypto.sha256(value);
    }
}
