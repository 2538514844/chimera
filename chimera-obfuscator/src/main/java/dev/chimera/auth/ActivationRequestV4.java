package dev.chimera.auth;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Signature-relevant activation request fields. The password is intentionally NOT part of this
 * record or of any canonical bytes; wiring adds it to the JSON body over TLS only.
 */
public record ActivationRequestV4(int version, String account, String hwid,
                                  String clientEphemeralPub, String clientNonce) {

    public static final int VERSION = 4;

    public ActivationRequestV4 {
        Objects.requireNonNull(account, "account");
        Objects.requireNonNull(hwid, "hwid");
        Objects.requireNonNull(clientEphemeralPub, "clientEphemeralPub");
        Objects.requireNonNull(clientNonce, "clientNonce");
    }

    public Map<String, String> toFields() {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("v", Integer.toString(version));
        fields.put("account", account);
        fields.put("hwid", hwid);
        fields.put("client_ephemeral_pub", clientEphemeralPub);
        fields.put("client_nonce", clientNonce);
        return fields;
    }

    public static ActivationRequestV4 fromFields(Map<String, String> fields) throws AuthProtocolException {
        return new ActivationRequestV4(
                WireFields.integer(fields, "v"),
                WireFields.text(fields, "account"),
                WireFields.text(fields, "hwid"),
                WireFields.text(fields, "client_ephemeral_pub"),
                WireFields.text(fields, "client_nonce"));
    }
}
