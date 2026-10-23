package dev.chimera.auth;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * v4 heartbeat response. {@code token} is the NEW rotated token; the response signature binds the
 * old/presented token via its SHA-256 (see {@link AuthTranscriptV4}).
 */
public record HeartbeatResponseV4(int version, String hwid, String clientNonce, String token,
                                  long sequence, String serverNonce, long issuedAt, long expiresAt,
                                  long serverTime, String signature) {

    public static final int VERSION = 4;

    public HeartbeatResponseV4 {
        Objects.requireNonNull(hwid, "hwid");
        Objects.requireNonNull(clientNonce, "clientNonce");
        Objects.requireNonNull(token, "token");
        Objects.requireNonNull(serverNonce, "serverNonce");
        Objects.requireNonNull(signature, "signature");
    }

    public Map<String, String> toFields() {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("v", Integer.toString(version));
        fields.put("hwid", hwid);
        fields.put("client_nonce", clientNonce);
        fields.put("token", token);
        fields.put("sequence", Long.toString(sequence));
        fields.put("server_nonce", serverNonce);
        fields.put("issued_at", Long.toString(issuedAt));
        fields.put("expires_at", Long.toString(expiresAt));
        fields.put("server_time", Long.toString(serverTime));
        fields.put("signature", signature);
        return fields;
    }

    public static HeartbeatResponseV4 fromFields(Map<String, String> fields) throws AuthProtocolException {
        return new HeartbeatResponseV4(
                WireFields.integer(fields, "v"),
                WireFields.text(fields, "hwid"),
                WireFields.text(fields, "client_nonce"),
                WireFields.text(fields, "token"),
                WireFields.number(fields, "sequence"),
                WireFields.text(fields, "server_nonce"),
                WireFields.number(fields, "issued_at"),
                WireFields.number(fields, "expires_at"),
                WireFields.number(fields, "server_time"),
                WireFields.text(fields, "signature"));
    }
}
