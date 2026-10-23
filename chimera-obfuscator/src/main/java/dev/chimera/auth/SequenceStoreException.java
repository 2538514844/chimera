package dev.chimera.auth;

import java.io.IOException;

/** Sequence state could not be authenticated/parsed; callers must fail closed. */
public class SequenceStoreException extends IOException {

    public SequenceStoreException(String message) {
        super(message);
    }

    public SequenceStoreException(String message, Throwable cause) {
        super(message, cause);
    }
}
