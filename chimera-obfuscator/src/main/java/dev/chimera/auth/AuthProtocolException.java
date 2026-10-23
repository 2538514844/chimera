package dev.chimera.auth;

/** Checked failure of the v4 client protocol. Never contains tokens, nonces or key material. */
public class AuthProtocolException extends Exception {

    private final AuthFailure failure;

    public AuthProtocolException(AuthFailure failure, String message) {
        super(message);
        this.failure = failure;
    }

    public AuthProtocolException(AuthFailure failure, String message, Throwable cause) {
        super(message, cause);
        this.failure = failure;
    }

    public AuthFailure failure() {
        return failure;
    }

    /** Wire-style error code (e.g. E_BINDING); suitable for logging/telemetry. */
    public String code() {
        return failure.code();
    }
}
