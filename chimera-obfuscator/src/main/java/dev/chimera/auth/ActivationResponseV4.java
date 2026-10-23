package dev.chimera.auth;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/** Parsed v4 activation response; {@code signature} is over {@link AuthTranscriptV4}. */
public record ActivationResponseV4(int version, String account, String hwid,
                                   String clientEphemeralPub, String clientNonce,
                                   String serverEphemeralPub, String serverNonce, String token,
                                   long sequence, long issuedAt, long expiresAt, long serverTime,
                                   String resourceCk, String signature) {

    public static final int VERSION = 4;

    public ActivationResponseV4 {
        Objects.requireNonNull(account, "account");
        Objects.requireNonNull(hwid, "hwid");
        Objects.requireNonNull(clientEphemeralPub, "clientEphemeralPub");
        Objects.requireNonNull(clientNonce, "clientNonce");
        Objects.requireNonNull(serverEphemeralPub, "serverEphemeralPub");
        Objects.requireNonNull(serverNonce, "serverNonce");
        Objects.requireNonNull(token, "token");
        Objects.requireNonNull(signature, "signature");
        // resource_ck is optional for pure v4 tests but the server signs an empty string when absent.
        resourceCk = resourceCk == null ? "" : resourceCk;
    }

    public Map<String, String> toFields() {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("v", Integer.toString(version));
        fields.put("account", account);
        fields.put("hwid", hwid);
        fields.put("client_ephemeral_pub", clientEphemeralPub);
        fields.put("client_nonce", clientNonce);
        fields.put("server_ephemeral_pub", serverEphemeralPub);
        fields.put("server_nonce", serverNonce);
        fields.put("token", token);
        fields.put("sequence", Long.toString(sequence));
        fields.put("issued_at", Long.toString(issuedAt));
        fields.put("expires_at", Long.toString(expiresAt));
        fields.put("server_time", Long.toString(serverTime));
        fields.put("resource_ck", resourceCk);
        fields.put("signature", signature);
        return fields;
    }

    public static ActivationResponseV4 fromFields(Map<String, String> fields) throws AuthProtocolException {
        return new ActivationResponseV4(
                WireFields.integer(fields, "v"),
                WireFields.text(fields, "account"),
                WireFields.text(fields, "hwid"),
                WireFields.text(fields, "client_ephemeral_pub"),
                WireFields.text(fields, "client_nonce"),
                WireFields.text(fields, "server_ephemeral_pub"),
                WireFields.text(fields, "server_nonce"),
                WireFields.text(fields, "token"),
                WireFields.number(fields, "sequence"),
                WireFields.number(fields, "issued_at"),
                WireFields.number(fields, "expires_at"),
                WireFields.number(fields, "server_time"),
                fields.getOrDefault("resource_ck", ""),
                WireFields.text(fields, "signature"));
    }
}
