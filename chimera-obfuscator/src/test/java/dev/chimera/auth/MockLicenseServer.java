package dev.chimera.auth;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Test-only license server implementing docs/AUTH-V2-PROTOCOL.md with JDK crypto only.
 * Used by the client handshake tests and by the end-to-end auth test. Not production code.
 */
public final class MockLicenseServer implements AutoCloseable {

    public static final String ACCOUNT = "player@example.com";
    public static final String PASSWORD = "correct horse battery staple";
    public static final String HWID = "hwid-0123456789abcdef";

    private static final byte[] ED25519_SPKI_PREFIX = {
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
    };
    private static final byte[] X25519_SPKI_PREFIX = {
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00
    };

    private final HttpServer server;
    private final KeyPair signing;
    private final byte[] contentKey = new byte[32];
    /**
     * KI-28: long-lived product ResourceKey delivered inside {@code resource_ck}. Test-only value;
     * production obtains the same key through {@code CHIMERA_RESOURCE_KEY_HEX} / the license API.
     */
    private final byte[] resourceKey = new byte[32];
    private final SecureRandom random = new SecureRandom();

    private volatile String expectedToken;
    private volatile boolean tamperSignature;
    private volatile boolean rejectCredentials;
    private volatile boolean replayOldHeartbeat;
    private volatile int activations;
    private volatile long sequence;
    private volatile String lastHeartbeatResponse;
    private volatile byte[] lastNonce;

    public MockLicenseServer() throws Exception {
        KeyPairGenerator ed = KeyPairGenerator.getInstance("Ed25519");
        this.signing = ed.generateKeyPair();
        random.nextBytes(contentKey);
        random.nextBytes(resourceKey);
        this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/v1/license/activate", this::handleActivate);
        server.createContext("/api/v1/license/heartbeat", this::handleHeartbeat);
        server.setExecutor(null);
        server.start();
    }

    public String baseUrl() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    public String publicKeyBase64() {
        byte[] encoded = signing.getPublic().getEncoded();
        byte[] raw = new byte[32];
        System.arraycopy(encoded, encoded.length - 32, raw, 0, 32);
        return Base64.getEncoder().encodeToString(raw);
    }

    public byte[] contentKey() {
        return contentKey.clone();
    }

    /** KI-28: the build pipeline must encrypt resources with exactly this key. */
    public byte[] resourceKey() {
        return resourceKey.clone();
    }

    public void setTamperSignature(boolean tamperSignature) {
        this.tamperSignature = tamperSignature;
    }

    public void setRejectCredentials(boolean rejectCredentials) {
        this.rejectCredentials = rejectCredentials;
    }

    /** When true, the next heartbeat returns the previous (validly signed but stale) response. */
    public void setReplayOldHeartbeat(boolean replayOldHeartbeat) {
        this.replayOldHeartbeat = replayOldHeartbeat;
    }

    public long currentSequence() {
        return sequence;
    }

    public int activations() {
        return activations;
    }

    public byte[] lastNonce() {
        byte[] value = lastNonce;
        return value == null ? null : value.clone();
    }

    private void handleActivate(HttpExchange exchange) {
        try {
            String request = readBody(exchange);
            String account = jsonString(request, "account");
            String password = jsonString(request, "password");
            String hwid = jsonString(request, "hwid");
            String clientEphemeral = jsonString(request, "client_ephemeral_pub");
            if (rejectCredentials || account == null || !account.equals(ACCOUNT)
                    || password == null || !password.equals(PASSWORD)
                    || hwid == null || !hwid.equals(HWID)
                    || clientEphemeral == null) {
                send(exchange, 401, "{\"error\":\"E_AUTH\"}");
                return;
            }
            byte[] clientRaw = Base64.getDecoder().decode(clientEphemeral);
            if (clientRaw.length != 32) {
                send(exchange, 400, "{\"error\":\"E_BAD_PUBKEY\"}");
                return;
            }
            KeyPairGenerator x = KeyPairGenerator.getInstance("X25519");
            KeyPair serverEphemeral = x.generateKeyPair();
            byte[] serverEphemeralRaw = tail32(serverEphemeral.getPublic().getEncoded());
            byte[] shared = x25519(serverEphemeral, clientRaw);
            byte[] nonce = new byte[16];
            random.nextBytes(nonce);
            lastNonce = nonce.clone();
            byte[] wrapKey = hkdf(shared, nonce,
                    "chimera/wrap/v1".getBytes(StandardCharsets.UTF_8), 32);
            byte[] aesNonce = new byte[12];
            random.nextBytes(aesNonce);
            byte[] aad = ("chimera-wrap/v1|" + account + "|" + hwid).getBytes(StandardCharsets.UTF_8);
            byte[] ciphertext = aesGcmEncrypt(wrapKey, aesNonce, contentKey, aad);
            byte[] wrapped = new byte[aesNonce.length + ciphertext.length];
            System.arraycopy(aesNonce, 0, wrapped, 0, aesNonce.length);
            System.arraycopy(ciphertext, 0, wrapped, aesNonce.length, ciphertext.length);

            // KI-28 resource_ck: UserContentKey wraps the product ResourceKey.
            // NOTE: the frozen client DLL derives this key with
            // HKDF(ikm=UserContentKey, salt=UTF8("chimera/resource-wrap/v1"), info=empty)
            // (see chimera_auth.cpp), which differs from the license-server README's
            // salt=zeros/info=label form; this mock follows the frozen client contract so the
            // end-to-end activation test exercises the real op9 path.
            byte[] resourceWrapKey = hkdf(contentKey,
                    "chimera/resource-wrap/v1".getBytes(StandardCharsets.UTF_8),
                    new byte[0], 32);
            byte[] resourceNonce = new byte[12];
            random.nextBytes(resourceNonce);
            byte[] resourceAad = ("chimera-resource/v1|" + account + "|" + hwid)
                    .getBytes(StandardCharsets.UTF_8);
            byte[] resourceCiphertext = aesGcmEncrypt(resourceWrapKey, resourceNonce, resourceKey,
                    resourceAad);
            byte[] resourceEnvelope = new byte[resourceNonce.length + resourceCiphertext.length];
            System.arraycopy(resourceNonce, 0, resourceEnvelope, 0, resourceNonce.length);
            System.arraycopy(resourceCiphertext, 0, resourceEnvelope, resourceNonce.length,
                    resourceCiphertext.length);

            String nonceText = Base64.getEncoder().encodeToString(nonce);
            String ephemeralText = Base64.getEncoder().encodeToString(serverEphemeralRaw);
            String wrappedText = Base64.getEncoder().encodeToString(wrapped);
            String resourceCkText = Base64.getEncoder().encodeToString(resourceEnvelope);
            long now = System.currentTimeMillis() / 1000L;
            long expires = now + 3600L;
            byte[] tokenBytes = new byte[32];
            random.nextBytes(tokenBytes);
            String token = Base64.getEncoder().encodeToString(tokenBytes);
            expectedToken = token;
            sequence = 1L;
            String canonical = "{\"expires_at\":" + expires
                    + ",\"issued_at\":" + now
                    + ",\"sequence\":" + sequence
                    + ",\"server_ephemeral_pub\":\"" + ephemeralText
                    + "\",\"server_nonce\":\"" + nonceText
                    + "\",\"token\":\"" + token
                    + "\",\"wrapped_ck\":\"" + wrappedText + "\"}";
            String signature = sign(canonical);
            activations++;
            // resource_ck is sent in the response but deliberately excluded from the canonical
            // signature: the frozen C++ client rebuilds the canonical transcript without it.
            send(exchange, 200, "{\"server_nonce\":\"" + nonceText
                    + "\",\"server_ephemeral_pub\":\"" + ephemeralText
                    + "\",\"wrapped_ck\":\"" + wrappedText
                    + "\",\"resource_ck\":\"" + resourceCkText
                    + "\",\"expires_at\":" + expires
                    + ",\"sequence\":" + sequence
                    + ",\"issued_at\":" + now
                    + ",\"token\":\"" + token
                    + "\",\"account\":\"" + account
                    + "\",\"server_time\":" + now
                    + ",\"signature\":\"" + signature + "\"}");
        } catch (Throwable t) {
            try {
                send(exchange, 500, "{\"error\":\"E_INTERNAL\"}");
            } catch (Throwable ignored) {
                // nothing else to do in a test double
            }
        }
    }

    private void handleHeartbeat(HttpExchange exchange) {
        try {
            String request = readBody(exchange);
            String token = jsonString(request, "token");
            if (token == null || !token.equals(expectedToken)) {
                send(exchange, 410, "{\"error\":\"E_EXPIRED\"}");
                return;
            }
            if (replayOldHeartbeat && lastHeartbeatResponse != null) {
                send(exchange, 200, lastHeartbeatResponse);
                return;
            }
            byte[] nonce = new byte[16];
            random.nextBytes(nonce);
            lastNonce = nonce.clone();
            String nonceText = Base64.getEncoder().encodeToString(nonce);
            long now = System.currentTimeMillis() / 1000L;
            long expires = now + 3600L;
            sequence++;
            String canonical = "{\"expires_at\":" + expires
                    + ",\"issued_at\":" + now
                    + ",\"sequence\":" + sequence
                    + ",\"server_nonce\":\"" + nonceText
                    + "\",\"token\":\"" + token + "\"}";
            String signature = sign(canonical);
            String response = "{\"server_nonce\":\"" + nonceText
                    + "\",\"expires_at\":" + expires
                    + ",\"sequence\":" + sequence
                    + ",\"issued_at\":" + now
                    + ",\"server_time\":" + now
                    + ",\"signature\":\"" + signature + "\"}";
            lastHeartbeatResponse = response;
            send(exchange, 200, response);
        } catch (Throwable t) {
            try {
                send(exchange, 500, "{\"error\":\"E_INTERNAL\"}");
            } catch (Throwable ignored) {
                // nothing else to do in a test double
            }
        }
    }

    private String sign(String canonical) throws Exception {
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(signing.getPrivate());
        signature.update(canonical.getBytes(StandardCharsets.UTF_8));
        byte[] signed = signature.sign();
        if (tamperSignature) {
            signed[0] ^= 0x01;
        }
        return Base64.getEncoder().encodeToString(signed);
    }

    private static byte[] tail32(byte[] encoded) {
        byte[] raw = new byte[32];
        System.arraycopy(encoded, encoded.length - 32, raw, 0, 32);
        return raw;
    }

    private static byte[] x25519(KeyPair serverEphemeral, byte[] clientRaw) throws Exception {
        PublicKey client = KeyFactory.getInstance("X25519")
                .generatePublic(new X509EncodedKeySpec(concat(X25519_SPKI_PREFIX, clientRaw)));
        KeyAgreement agreement = KeyAgreement.getInstance("X25519");
        agreement.init(serverEphemeral.getPrivate());
        agreement.doPhase(client, true);
        return agreement.generateSecret();
    }

    private static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int length) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(salt.length == 0 ? new byte[32] : salt, "HmacSHA256"));
        byte[] prk = mac.doFinal(ikm);
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        ByteArrayOutputStream out = new ByteArrayOutputStream(length);
        byte[] previous = new byte[0];
        int counter = 1;
        while (out.size() < length) {
            mac.update(previous);
            mac.update(info);
            mac.update((byte) counter);
            previous = mac.doFinal();
            out.write(previous, 0, Math.min(previous.length, length - out.size()));
            counter++;
        }
        return out.toByteArray();
    }

    private static byte[] aesGcmEncrypt(byte[] key, byte[] nonce, byte[] plaintext, byte[] aad) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        cipher.updateAAD(aad);
        return cipher.doFinal(plaintext);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static String readBody(HttpExchange exchange) throws Exception {
        try (InputStream in = exchange.getRequestBody()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static void send(HttpExchange exchange, int status, String body) throws Exception {
        byte[] payload = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(status, payload.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(payload);
        }
    }

    /** Extracts a string field from a flat JSON object (test helper only). */
    static String jsonString(String json, String key) {
        if (json == null) {
            return null;
        }
        int at = json.indexOf("\"" + key + "\"");
        if (at < 0) {
            return null;
        }
        int colon = json.indexOf(':', at);
        if (colon < 0) {
            return null;
        }
        int start = json.indexOf('"', colon + 1);
        if (start < 0) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (int i = start + 1; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '\\' && i + 1 < json.length()) {
                sb.append(json.charAt(++i));
            } else if (c == '"') {
                return sb.toString();
            } else {
                sb.append(c);
            }
        }
        return null;
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
