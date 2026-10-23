package dev.chimera.core;

import dev.chimera.crypto.Crypto;

import java.nio.charset.StandardCharsets;

/**
 * P1-1: build-side replica of the native CHENC1 key derivation.
 *
 * <p>At runtime the key is produced by {@code nativeDeriveClassKey} from the ResourceKey that only
 * an authorized SessionHandle holds, so the shipped jar never contains it. The build has no handle
 * to ask, so it reproduces the exact same HKDF-SHA256 expansion here:
 * {@code HKDF-SHA256(ikm = ResourceKey, salt = "chimera-classenc-v1", info = "class-key", 32)}.
 * {@code ClassKeyAlignmentTest} asserts the two agree byte for byte, which is what keeps
 * build-time encryption and runtime decryption from drifting apart.</p>
 */
public final class ClassKeyDerivation {

    /** HKDF salt, identical to the {@code salt[]} literal in chimera_auth.cpp. */
    public static final byte[] SALT = "chimera-classenc-v1".getBytes(StandardCharsets.UTF_8);
    /** HKDF info, identical to the {@code info[]} literal in chimera_auth.cpp. */
    public static final byte[] INFO = "class-key".getBytes(StandardCharsets.UTF_8);
    public static final int KEY_LENGTH = 32;

    private ClassKeyDerivation() {
    }

    /**
     * Derives the 32-byte class-body key from the product ResourceKey.
     *
     * <p>The ResourceKey must be exactly 32 bytes: native always expands a 32-byte ResourceKey, and
     * a shorter or longer input would silently produce a key the runtime can never reproduce.</p>
     */
    public static byte[] derive(byte[] resourceKey) {
        if (resourceKey == null || resourceKey.length != 32) {
            throw new IllegalArgumentException(
                    "class-body key derivation needs the 32-byte ResourceKey (got "
                            + (resourceKey == null ? "null" : resourceKey.length + " bytes") + ")");
        }
        return Crypto.hkdf(resourceKey, SALT, INFO, KEY_LENGTH);
    }
}
