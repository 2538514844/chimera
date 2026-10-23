package dev.chimera.auth;

/** Machine-readable failure reasons for the v4 client protocol. */
public enum AuthFailure {
    BAD_RESPONSE("E_BAD_RESPONSE"),
    VERSION("E_VERSION"),
    BINDING("E_BINDING"),
    SIGNATURE("E_SIGNATURE"),
    NONCE("E_NONCE"),
    NONCE_REPLAY("E_NONCE_REPLAY"),
    SEQUENCE("E_SEQUENCE"),
    TOKEN("E_TOKEN"),
    TOKEN_REPLAY("E_TOKEN_REPLAY"),
    TOKEN_ROTATION("E_TOKEN_ROTATION"),
    CLOCK_SKEW("E_CLOCK_SKEW"),
    CLOCK_ROLLBACK("E_CLOCK_ROLLBACK"),
    EXPIRED("E_EXPIRED"),
    STATE("E_STATE"),
    INPUT("E_INPUT");

    private final String code;

    AuthFailure(String code) {
        this.code = code;
    }

    public String code() {
        return code;
    }
}
