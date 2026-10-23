package dev.chimera.auth;

import java.util.Arrays;

/** Stable 32-byte device fingerprint derived by {@link HwidDerivation}. */
public record Hwid(byte[] raw, String base64, String hex) {

    public Hwid {
        if (raw == null || raw.length != 32) {
            throw new IllegalArgumentException("hwid raw must be 32 bytes");
        }
        if (base64 == null || hex == null) {
            throw new IllegalArgumentException("hwid encodings must not be null");
        }
        raw = raw.clone();
    }

    @Override
    public byte[] raw() {
        return raw.clone();
    }

    @Override
    public String toString() {
        return "Hwid[hex=" + hex + "]";
    }

    public boolean sameAs(Hwid other) {
        return other != null && Arrays.equals(raw, other.raw);
    }
}
