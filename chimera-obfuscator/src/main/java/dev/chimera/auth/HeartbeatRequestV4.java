package dev.chimera.auth;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/** v4 heartbeat request fields (password-free, no key material). */
public record HeartbeatRequestV4(int version, String hwid, String token, String clientNonce,
                                 long sequence) {

    public static final int VERSION = 4;

    public HeartbeatRequestV4 {
        Objects.requireNonNull(hwid, "hwid");
        Objects.requireNonNull(token, "token");
        Objects.requireNonNull(clientNonce, "clientNonce");
    }

    public Map<String, String> toFields() {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("v", Integer.toString(version));
        fields.put("hwid", hwid);
        fields.put("token", token);
        fields.put("client_nonce", clientNonce);
        fields.put("sequence", Long.toString(sequence));
        return fields;
    }

    public static HeartbeatRequestV4 fromFields(Map<String, String> fields) throws AuthProtocolException {
        return new HeartbeatRequestV4(
                WireFields.integer(fields, "v"),
                WireFields.text(fields, "hwid"),
                WireFields.text(fields, "token"),
                WireFields.text(fields, "client_nonce"),
                WireFields.number(fields, "sequence"));
    }
}
