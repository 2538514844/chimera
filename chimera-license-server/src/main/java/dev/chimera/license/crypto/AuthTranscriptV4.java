package dev.chimera.license.crypto;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Server-side v4 canonical transcripts.
 *
 * <p>Wire contract (must stay byte-identical to the client's
 * {@code dev.chimera.auth.AuthTranscriptV4}): every field is encoded as
 * {@code u32be(byte length) || UTF-8 bytes}. The first field is the per-message domain, the second
 * is the decimal protocol version. Numbers use their minimal decimal ASCII representation, exactly
 * as they appear in the JSON response. {@code null} text fields are encoded as the empty string.</p>
 */
public final class AuthTranscriptV4 {

    public static final int VERSION = 4;
    public static final String ACTIVATE_RESPONSE_DOMAIN = "chimera-auth-v4/activate-response";
    public static final String HEARTBEAT_RESPONSE_DOMAIN = "chimera-auth-v4/heartbeat-response";

    private AuthTranscriptV4() {
    }

    /**
     * Activation response transcript, in this exact order:
     * {@code v, account, hwid, client_ephemeral_pub, client_nonce, server_ephemeral_pub,
     * server_nonce, token, sequence, issued_at, expires_at, server_time, resource_ck,
     * license_id, client_ip}.
     *
     * <p>{@code license_id} and {@code client_ip} were appended on 2026-10-22 (task #17). They are
     * signed so the client can trust the licence id it embeds in the per-licence watermark and so
     * the observed IP cannot be rewritten in transit. Appending (rather than inserting) keeps every
     * earlier field at its old offset; a client built before this change still fails closed on the
     * signature, which is the intended behaviour for a protocol the server and client ship
     * together.</p>
     */
    public static byte[] activateResponse(int version, String account, String hwid,
                                          String clientEphemeralPub, String clientNonce,
                                          String serverEphemeralPub, String serverNonce,
                                          String token, long sequence, long issuedAt,
                                          long expiresAt, long serverTime, String resourceCk,
                                          String licenseId, String clientIp) {
        return encode(ACTIVATE_RESPONSE_DOMAIN,
                Integer.toString(version),
                account,
                hwid,
                clientEphemeralPub,
                clientNonce,
                serverEphemeralPub,
                serverNonce,
                token,
                Long.toString(sequence),
                Long.toString(issuedAt),
                Long.toString(expiresAt),
                Long.toString(serverTime),
                resourceCk == null ? "" : resourceCk,
                licenseId == null ? "" : licenseId,
                clientIp == null ? "" : clientIp);
    }

    /**
     * Heartbeat response transcript, in this exact order:
     * {@code v, hwid, client_nonce, SHA256hex(presented token), token(new), sequence,
     * server_nonce, issued_at, expires_at, server_time, resource_ck, server_ephemeral_pub,
     * license_id, client_ip}.
     */
    public static byte[] heartbeatResponse(int version, String hwid, String clientNonce,
                                           String presentedToken, String newToken, long sequence,
                                           String serverNonce, long issuedAt, long expiresAt,
                                           long serverTime, String resourceCk,
                                           String serverEphemeralPub, String licenseId,
                                           String clientIp) {
        return encode(HEARTBEAT_RESPONSE_DOMAIN,
                Integer.toString(version),
                hwid,
                clientNonce,
                tokenHashHex(presentedToken),
                newToken,
                Long.toString(sequence),
                serverNonce,
                Long.toString(issuedAt),
                Long.toString(expiresAt),
                Long.toString(serverTime),
                resourceCk == null ? "" : resourceCk,
                serverEphemeralPub == null ? "" : serverEphemeralPub,
                licenseId == null ? "" : licenseId,
                clientIp == null ? "" : clientIp);
    }

    /** Generic length-prefixed encoder shared with the client contract. */
    public static byte[] encode(String domain, String... fields) {
        if (domain == null || fields == null) {
            throw new IllegalArgumentException("domain/fields must not be null");
        }
        ByteArrayOutputStream buffer = new ByteArrayOutputStream(256);
        try (DataOutputStream out = new DataOutputStream(buffer)) {
            writeField(out, domain);
            for (String field : fields) {
                writeField(out, field == null ? "" : field);
            }
        } catch (IOException e) {
            throw new IllegalStateException("cannot encode v4 canonical transcript", e);
        }
        return buffer.toByteArray();
    }

    /** Lowercase hex SHA-256 of the UTF-8 token (raw bearer tokens are never signed). */
    public static String tokenHashHex(String token) {
        if (token == null) {
            throw new IllegalArgumentException("token must not be null");
        }
        return CryptoUtils.hex(CryptoUtils.sha256(token.getBytes(StandardCharsets.UTF_8)));
    }

    private static void writeField(DataOutputStream out, String value) throws IOException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        out.writeInt(bytes.length);
        out.write(bytes);
    }
}
