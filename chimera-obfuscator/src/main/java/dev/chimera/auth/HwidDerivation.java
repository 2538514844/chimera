package dev.chimera.auth;

import dev.chimera.crypto.Crypto;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;

/**
 * Derives a stable, versioned HWID from a per-install salt and named machine identifiers.
 *
 * <pre>
 * raw = SHA-256( LP("chimera/hwid/v1") || LP(install_salt) ||
 *               for each identifier key in lexicographic order: LP(key) || LP(value) )
 * hwid = Base64(raw)          // standard Base64 with padding, 44 chars (server accepts this form)
 * hex  = lowercase hex(raw)   // 64 chars
 * </pre>
 *
 * LP(x) = u32be(len(x)) || x. Length prefixing removes ambiguity between identifier boundaries.
 * The salt must be generated once per installation ({@link #newInstallSalt()}) and persisted; the
 * raw identifier values never leave the device (only the derived HWID is sent to the server).
 */
public final class HwidDerivation {

    public static final int SALT_BYTES = 16;
    private static final byte[] DOMAIN = "chimera/hwid/v1".getBytes(StandardCharsets.UTF_8);

    private HwidDerivation() {
    }

    public static Hwid derive(byte[] installSalt, Map<String, String> identifiers) {
        if (installSalt == null || installSalt.length < 16 || installSalt.length > 32) {
            throw new IllegalArgumentException("install salt must be 16..32 bytes");
        }
        if (identifiers == null || identifiers.isEmpty()) {
            throw new IllegalArgumentException("identifiers must not be empty");
        }
        ByteArrayOutputStream buffer = new ByteArrayOutputStream(128);
        try (DataOutputStream out = new DataOutputStream(buffer)) {
            write(out, DOMAIN);
            write(out, installSalt);
            identifiers.keySet().stream().sorted().forEach(key -> {
                String value = identifiers.get(key);
                Objects.requireNonNull(key, "identifier key");
                Objects.requireNonNull(value, "identifier value for " + key);
                try {
                    write(out, key.getBytes(StandardCharsets.UTF_8));
                    write(out, value.getBytes(StandardCharsets.UTF_8));
                } catch (IOException e) {
                    throw new IllegalStateException("cannot encode hwid identifiers", e);
                }
            });
        } catch (IOException e) {
            throw new IllegalStateException("cannot encode hwid identifiers", e);
        }
        byte[] raw = Crypto.sha256(buffer.toByteArray());
        return new Hwid(raw, Base64.getEncoder().encodeToString(raw), Crypto.hex(raw));
    }

    public static byte[] newInstallSalt() {
        return Crypto.random(SALT_BYTES);
    }

    private static void write(DataOutputStream out, byte[] value) throws IOException {
        out.writeInt(value.length);
        out.write(value);
    }
}
