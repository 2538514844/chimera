package dev.chimera.auth;

import dev.chimera.crypto.Crypto;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * <b>TEST-ONLY / LEGACY.</b> This 12-field transcript predates #17 (license_id + client_ip) and is
 * no longer what the shipped client uses - {@code dev.chimera.runtime.ChimeraV4Session} builds the
 * 14-field transcript itself, and the server's {@code dev.chimera.license.crypto.AuthTranscriptV4}
 * is the reference implementation.
 *
 * <p>It survives because {@code AuthProtocolV4} and its tests use it against an in-process fake
 * server. Do not wire it into the product: a build that verified responses with this class would
 * fail every signature check with {@code -7}.</p>
 *
 * <p>Encoding: for every text field, {@code u32be(byte length) || utf8 bytes}. The first field is a
 * per-message domain string; the second field is the decimal protocol version. Numbers are encoded
 * as their minimal decimal ASCII representation (same as the wire JSON).</p>
 */

public final class AuthTranscriptV4 {

    public static final String ACTIVATE_REQUEST_DOMAIN = "chimera-auth-v4/activate-request";
    public static final String ACTIVATE_RESPONSE_DOMAIN = "chimera-auth-v4/activate-response";
    public static final String HEARTBEAT_REQUEST_DOMAIN = "chimera-auth-v4/heartbeat-request";
    public static final String HEARTBEAT_RESPONSE_DOMAIN = "chimera-auth-v4/heartbeat-response";

    private AuthTranscriptV4() {
    }

    /** Server-side canonical activation transcript (request fields + response fields). */
    public static byte[] activateResponse(ActivationResponseV4 response) {
        return encode(ACTIVATE_RESPONSE_DOMAIN,
                Integer.toString(response.version()),
                response.account(),
                response.hwid(),
                response.clientEphemeralPub(),
                response.clientNonce(),
                response.serverEphemeralPub(),
                response.serverNonce(),
                response.token(),
                Long.toString(response.sequence()),
                Long.toString(response.issuedAt()),
                Long.toString(response.expiresAt()),
                Long.toString(response.serverTime()),
                response.resourceCk());
    }

    /** Request-binding canonical (client proof / server audit; not currently signed by the client). */
    public static byte[] activateRequest(ActivationRequestV4 request) {
        return encode(ACTIVATE_REQUEST_DOMAIN,
                Integer.toString(request.version()),
                request.account(),
                request.hwid(),
                request.clientEphemeralPub(),
                request.clientNonce());
    }

    /** Server-side canonical heartbeat transcript, binding the presented (old) token by hash. */
    public static byte[] heartbeatResponse(HeartbeatResponseV4 response, String presentedToken) {
        return encode(HEARTBEAT_RESPONSE_DOMAIN,
                Integer.toString(response.version()),
                response.hwid(),
                response.clientNonce(),
                tokenHashHex(presentedToken),
                response.token(),
                Long.toString(response.sequence()),
                response.serverNonce(),
                Long.toString(response.issuedAt()),
                Long.toString(response.expiresAt()),
                Long.toString(response.serverTime()));
    }

    public static byte[] heartbeatRequest(HeartbeatRequestV4 request) {
        return encode(HEARTBEAT_REQUEST_DOMAIN,
                Integer.toString(request.version()),
                request.hwid(),
                request.token(),
                request.clientNonce(),
                Long.toString(request.sequence()));
    }

    /** Lowercase hex SHA-256 of the UTF-8 token (never signs the raw token). */
    public static String tokenHashHex(String token) {
        if (token == null) {
            throw new IllegalArgumentException("token must not be null");
        }
        return Crypto.hex(Crypto.sha256(token.getBytes(StandardCharsets.UTF_8)));
    }

    /** Generic length-prefixed encoder, exposed so server implementations can share a test vector. */
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
            throw new IllegalStateException("cannot encode canonical transcript", e);
        }
        return buffer.toByteArray();
    }

    private static void writeField(DataOutputStream out, String value) throws IOException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        out.writeInt(bytes.length);
        out.write(bytes);
    }
}
