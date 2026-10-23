package dev.chimera.auth;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Base64;

/**
 * Pure-logic v4 license server double. Emits typed response records (no HTTP/JSON) and can produce
 * both "binding" faults (validly signed but wrong request fields) and "tamper" faults (field changed
 * after signing) for negative tests.
 */
final class MockLicenseServerV4 {

    static final String ACCOUNT = "player@example.com";
    static final String PASSWORD = "correct horse battery staple";
    static final String HWID = "hwid-0123456789abcdef";

    enum ActivateMutation {
        ACCOUNT, HWID, CLIENT_EPHEMERAL_PUB, CLIENT_NONCE, SERVER_EPHEMERAL_PUB, SERVER_NONCE,
        TOKEN, SEQUENCE, ISSUED_AT, EXPIRES_AT, SERVER_TIME, RESOURCE_CK
    }

    enum HeartbeatMutation {
        HWID, CLIENT_NONCE, TOKEN, SEQUENCE, SERVER_NONCE, ISSUED_AT, EXPIRES_AT, SERVER_TIME
    }

    private final KeyPair signing;
    private final SecureRandom random = new SecureRandom();
    private final byte[] resourceCk = randomBytes(32);

    private long now = 1_760_000_000L;
    private String currentToken;
    private long currentSequence;
    private byte[] lastServerNonce;
    private HeartbeatResponseV4 lastHeartbeatResponse;
    private int activations;

    int version = 4;
    boolean tamperSignature;
    boolean mutateBeforeSigning;
    boolean activationSequenceNotOne;
    boolean activationExpired;
    long activationIssuedOffset;
    long activationServerTimeOffset;
    ActivateMutation activateMutation;
    boolean heartbeatSameToken;
    boolean heartbeatStaleSequence;
    boolean heartbeatReuseNonce;
    boolean heartbeatOldIssuedAt;
    boolean heartbeatExpired;
    HeartbeatMutation heartbeatMutation;

    MockLicenseServerV4() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
        this.signing = generator.generateKeyPair();
    }

    byte[] publicKeyRaw() {
        byte[] encoded = signing.getPublic().getEncoded();
        byte[] raw = new byte[32];
        System.arraycopy(encoded, encoded.length - 32, raw, 0, 32);
        return raw;
    }

    long now() {
        return now;
    }

    void advance(long seconds) {
        now += seconds;
    }

    int activations() {
        return activations;
    }

    String currentToken() {
        return currentToken;
    }

    long currentSequence() {
        return currentSequence;
    }

    byte[] lastServerNonce() {
        return lastServerNonce == null ? null : lastServerNonce.clone();
    }

    HeartbeatResponseV4 lastHeartbeatResponse() {
        return lastHeartbeatResponse;
    }

    ActivationResponseV4 activate(ActivationRequestV4 request, long nowSeconds) throws Exception {
        long issued = activationExpired ? nowSeconds - 2 : nowSeconds - activationIssuedOffset;
        long expires = activationExpired ? nowSeconds - 1 : nowSeconds + 3600;
        long serverTime = nowSeconds + activationServerTimeOffset;
        long sequence = activationSequenceNotOne ? 2 : 1;
        String token = base64(randomBytes(32));
        String nonce = base64(randomBytes(16));
        ActivationResponseV4 response = new ActivationResponseV4(version, request.account(),
                request.hwid(), request.clientEphemeralPub(), request.clientNonce(),
                base64(randomBytes(32)), nonce, token, sequence, issued, expires, serverTime,
                base64(resourceCk), "");
        if (mutateBeforeSigning && activateMutation != null) {
            response = mutateActivate(response);
        }
        String signature = sign(AuthTranscriptV4.activateResponse(response));
        if (tamperSignature) {
            signature = tampered(signature);
        }
        response = withActivateSignature(response, signature);
        if (!mutateBeforeSigning && activateMutation != null) {
            response = mutateActivate(response);
        }
        this.currentToken = token;
        this.currentSequence = sequence;
        this.lastServerNonce = Base64.getDecoder().decode(nonce);
        this.activations++;
        return response;
    }

    HeartbeatResponseV4 heartbeat(HeartbeatRequestV4 request, long nowSeconds) throws Exception {
        if (!request.token().equals(currentToken)) {
            throw new IllegalStateException("mock: heartbeat token mismatch");
        }
        if (request.sequence() != currentSequence) {
            throw new IllegalStateException("mock: heartbeat sequence mismatch");
        }
        long nextSequence = heartbeatStaleSequence ? request.sequence() : request.sequence() + 1;
        String newToken = heartbeatSameToken ? request.token() : base64(randomBytes(32));
        byte[] nonce = heartbeatReuseNonce && lastServerNonce != null
                ? lastServerNonce : randomBytes(16);
        long issued = heartbeatExpired ? nowSeconds - 2 : (heartbeatOldIssuedAt ? nowSeconds - 1 : nowSeconds);
        long expires = heartbeatExpired ? nowSeconds - 1 : nowSeconds + 3600;
        HeartbeatResponseV4 response = new HeartbeatResponseV4(version, request.hwid(),
                request.clientNonce(), newToken, nextSequence, base64(nonce), issued, expires,
                nowSeconds, "");
        if (mutateBeforeSigning && heartbeatMutation != null) {
            response = mutateHeartbeat(response);
        }
        String signature = sign(AuthTranscriptV4.heartbeatResponse(response, request.token()));
        if (tamperSignature) {
            signature = tampered(signature);
        }
        response = withHeartbeatSignature(response, signature);
        if (!mutateBeforeSigning && heartbeatMutation != null) {
            response = mutateHeartbeat(response);
        }
        if (!heartbeatStaleSequence) {
            currentSequence = nextSequence;
            currentToken = newToken;
        }
        lastServerNonce = nonce;
        lastHeartbeatResponse = response;
        return response;
    }

    private ActivationResponseV4 withActivateSignature(ActivationResponseV4 r, String signature) {
        return new ActivationResponseV4(r.version(), r.account(), r.hwid(), r.clientEphemeralPub(),
                r.clientNonce(), r.serverEphemeralPub(), r.serverNonce(), r.token(), r.sequence(),
                r.issuedAt(), r.expiresAt(), r.serverTime(), r.resourceCk(), signature);
    }

    private HeartbeatResponseV4 withHeartbeatSignature(HeartbeatResponseV4 r, String signature) {
        return new HeartbeatResponseV4(r.version(), r.hwid(), r.clientNonce(), r.token(),
                r.sequence(), r.serverNonce(), r.issuedAt(), r.expiresAt(), r.serverTime(), signature);
    }

    private ActivationResponseV4 mutateActivate(ActivationResponseV4 r) {
        return switch (activateMutation) {
            case ACCOUNT -> withActivateSignature(new ActivationResponseV4(r.version(),
                    "evil@example.com", r.hwid(), r.clientEphemeralPub(), r.clientNonce(),
                    r.serverEphemeralPub(), r.serverNonce(), r.token(), r.sequence(), r.issuedAt(),
                    r.expiresAt(), r.serverTime(), r.resourceCk(), r.signature()), r.signature());
            case HWID -> withActivateSignature(new ActivationResponseV4(r.version(), r.account(),
                    "evil-hwid", r.clientEphemeralPub(), r.clientNonce(), r.serverEphemeralPub(),
                    r.serverNonce(), r.token(), r.sequence(), r.issuedAt(), r.expiresAt(),
                    r.serverTime(), r.resourceCk(), r.signature()), r.signature());
            case CLIENT_EPHEMERAL_PUB -> withActivateSignature(new ActivationResponseV4(r.version(),
                    r.account(), r.hwid(), base64(randomBytes(32)), r.clientNonce(),
                    r.serverEphemeralPub(), r.serverNonce(), r.token(), r.sequence(), r.issuedAt(),
                    r.expiresAt(), r.serverTime(), r.resourceCk(), r.signature()), r.signature());
            case CLIENT_NONCE -> withActivateSignature(new ActivationResponseV4(r.version(),
                    r.account(), r.hwid(), r.clientEphemeralPub(), base64(randomBytes(32)),
                    r.serverEphemeralPub(), r.serverNonce(), r.token(), r.sequence(), r.issuedAt(),
                    r.expiresAt(), r.serverTime(), r.resourceCk(), r.signature()), r.signature());
            case SERVER_EPHEMERAL_PUB -> withActivateSignature(new ActivationResponseV4(r.version(),
                    r.account(), r.hwid(), r.clientEphemeralPub(), r.clientNonce(),
                    base64(randomBytes(32)), r.serverNonce(), r.token(), r.sequence(), r.issuedAt(),
                    r.expiresAt(), r.serverTime(), r.resourceCk(), r.signature()), r.signature());
            case SERVER_NONCE -> withActivateSignature(new ActivationResponseV4(r.version(),
                    r.account(), r.hwid(), r.clientEphemeralPub(), r.clientNonce(),
                    r.serverEphemeralPub(), base64(randomBytes(16)), r.token(), r.sequence(),
                    r.issuedAt(), r.expiresAt(), r.serverTime(), r.resourceCk(), r.signature()),
                    r.signature());
            case TOKEN -> withActivateSignature(new ActivationResponseV4(r.version(),
                    r.account(), r.hwid(), r.clientEphemeralPub(), r.clientNonce(),
                    r.serverEphemeralPub(), r.serverNonce(), base64(randomBytes(32)), r.sequence(),
                    r.issuedAt(), r.expiresAt(), r.serverTime(), r.resourceCk(), r.signature()),
                    r.signature());
            case SEQUENCE -> withActivateSignature(new ActivationResponseV4(r.version(),
                    r.account(), r.hwid(), r.clientEphemeralPub(), r.clientNonce(),
                    r.serverEphemeralPub(), r.serverNonce(), r.token(), r.sequence() + 1,
                    r.issuedAt(), r.expiresAt(), r.serverTime(), r.resourceCk(), r.signature()),
                    r.signature());
            case ISSUED_AT -> withActivateSignature(new ActivationResponseV4(r.version(),
                    r.account(), r.hwid(), r.clientEphemeralPub(), r.clientNonce(),
                    r.serverEphemeralPub(), r.serverNonce(), r.token(), r.sequence(),
                    r.issuedAt() + 1, r.expiresAt(), r.serverTime(), r.resourceCk(),
                    r.signature()), r.signature());
            case EXPIRES_AT -> withActivateSignature(new ActivationResponseV4(r.version(),
                    r.account(), r.hwid(), r.clientEphemeralPub(), r.clientNonce(),
                    r.serverEphemeralPub(), r.serverNonce(), r.token(), r.sequence(), r.issuedAt(),
                    r.expiresAt() + 1, r.serverTime(), r.resourceCk(), r.signature()),
                    r.signature());
            case SERVER_TIME -> withActivateSignature(new ActivationResponseV4(r.version(),
                    r.account(), r.hwid(), r.clientEphemeralPub(), r.clientNonce(),
                    r.serverEphemeralPub(), r.serverNonce(), r.token(), r.sequence(), r.issuedAt(),
                    r.expiresAt(), r.serverTime() + 1, r.resourceCk(), r.signature()),
                    r.signature());
            case RESOURCE_CK -> withActivateSignature(new ActivationResponseV4(r.version(),
                    r.account(), r.hwid(), r.clientEphemeralPub(), r.clientNonce(),
                    r.serverEphemeralPub(), r.serverNonce(), r.token(), r.sequence(), r.issuedAt(),
                    r.expiresAt(), r.serverTime(), base64(randomBytes(32)), r.signature()),
                    r.signature());
        };
    }

    private HeartbeatResponseV4 mutateHeartbeat(HeartbeatResponseV4 r) {
        return switch (heartbeatMutation) {
            case HWID -> withHeartbeatSignature(new HeartbeatResponseV4(r.version(), "evil-hwid",
                    r.clientNonce(), r.token(), r.sequence(), r.serverNonce(), r.issuedAt(),
                    r.expiresAt(), r.serverTime(), r.signature()), r.signature());
            case CLIENT_NONCE -> withHeartbeatSignature(new HeartbeatResponseV4(r.version(),
                    r.hwid(), base64(randomBytes(32)), r.token(), r.sequence(), r.serverNonce(),
                    r.issuedAt(), r.expiresAt(), r.serverTime(), r.signature()), r.signature());
            case TOKEN -> withHeartbeatSignature(new HeartbeatResponseV4(r.version(), r.hwid(),
                    r.clientNonce(), base64(randomBytes(32)), r.sequence(), r.serverNonce(),
                    r.issuedAt(), r.expiresAt(), r.serverTime(), r.signature()), r.signature());
            case SEQUENCE -> withHeartbeatSignature(new HeartbeatResponseV4(r.version(), r.hwid(),
                    r.clientNonce(), r.token(), r.sequence() + 1, r.serverNonce(), r.issuedAt(),
                    r.expiresAt(), r.serverTime(), r.signature()), r.signature());
            case SERVER_NONCE -> withHeartbeatSignature(new HeartbeatResponseV4(r.version(),
                    r.hwid(), r.clientNonce(), r.token(), r.sequence(), base64(randomBytes(16)),
                    r.issuedAt(), r.expiresAt(), r.serverTime(), r.signature()), r.signature());
            case ISSUED_AT -> withHeartbeatSignature(new HeartbeatResponseV4(r.version(),
                    r.hwid(), r.clientNonce(), r.token(), r.sequence(), r.serverNonce(),
                    r.issuedAt() + 1, r.expiresAt(), r.serverTime(), r.signature()),
                    r.signature());
            case EXPIRES_AT -> withHeartbeatSignature(new HeartbeatResponseV4(r.version(),
                    r.hwid(), r.clientNonce(), r.token(), r.sequence(), r.serverNonce(),
                    r.issuedAt(), r.expiresAt() + 1, r.serverTime(), r.signature()),
                    r.signature());
            case SERVER_TIME -> withHeartbeatSignature(new HeartbeatResponseV4(r.version(),
                    r.hwid(), r.clientNonce(), r.token(), r.sequence(), r.serverNonce(),
                    r.issuedAt(), r.expiresAt(), r.serverTime() + 1, r.signature()),
                    r.signature());
        };
    }

    private String sign(byte[] message) throws Exception {
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(signing.getPrivate());
        signature.update(message);
        return base64(signature.sign());
    }

    private static String tampered(String signatureBase64) {
        byte[] raw = Base64.getDecoder().decode(signatureBase64);
        raw[raw.length - 1] ^= 0x01;
        return base64(raw);
    }

    private byte[] randomBytes(int length) {
        byte[] out = new byte[length];
        random.nextBytes(out);
        return out;
    }

    private static String base64(byte[] value) {
        return Base64.getEncoder().encodeToString(value);
    }
}