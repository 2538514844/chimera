package dev.chimera.integrity;

import dev.chimera.crypto.Crypto;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Builds {@code manifest.dat} + {@code manifest.mac} (+ {@code manifest.hmac}) consumed by
 * {@code ChimeraRuntime}.
 *
 * <p>Manifest text (UTF-8, LF line endings):</p>
 * <pre>
 * CHM1 | CHM2
 * &lt;sha256hex&gt;  &lt;path&gt;
 * &lt;sha256hex&gt;  &lt;path&gt;
 * </pre>
 * <p>Entries are sorted by path so the output is deterministic. The two spaces between hash and
 * path are part of the format parsed by the runtime.</p>
 *
 * <p><b>#9 (audit 2026-10-22):</b> {@code CHM1} only ever listed classes, so every {@code chimera/**}
 * resource ({@code auth.dat}, {@code env.dat}, {@code attach/agent.jar}, {@code res/native.dat},
 * {@code strings.dat}, {@code wm/*}, ...) shipped with no integrity coverage at all. {@code CHM2}
 * is the full-coverage format: it additionally lists every non-reserved {@code chimera/**} entry, so
 * the runtime can detect a missing, extra or rewritten resource. The header distinguishes the two
 * so a legacy artifact is never held to the stricter "no unlisted resource" rule.</p>
 */
public final class ManifestBuilder {

    /** Legacy class-only header. */
    public static final String HEADER_V1 = "CHM1";
    /** Full-coverage header: classes + every {@code chimera/**} resource. */
    public static final String HEADER_V2 = "CHM2";

    public static final String MANIFEST_RESOURCE = "chimera/manifest.dat";
    public static final String MAC_RESOURCE = "chimera/manifest.mac";
    /**
     * HMAC-SHA256(manifest) under a key baked into the native library
     * ({@code -DCHIMERA_MANIFEST_KEY_HEX}). This is the record the runtime authenticates; the
     * sealed {@code manifest.mac} alone is not enough, because its key is derived from build
     * material that lives in the same jar the manifest is supposed to protect.
     */
    public static final String HMAC_RESOURCE = "chimera/manifest.hmac";
    public static final int HMAC_BYTES = 32;

    private static final String SEPARATOR = "  ";

    /**
     * True for the three records that can never be listed inside the manifest (they would have to
     * hash themselves). The runtime exempts exactly these names from the "unlisted resource" rule.
     */
    public static boolean isReservedEntry(String path) {
        return MANIFEST_RESOURCE.equals(path) || MAC_RESOURCE.equals(path)
                || HMAC_RESOURCE.equals(path);
    }

    /**
     * Entries that carry their own authenticated encryption and are deliberately excluded from the
     * manifest: every S5 fragment chunk ({@code chimera/chunks/chunk_<id>.bin} + its sealed
     * {@code .hash} record) and every encrypted class payload ({@code chimera/classes/...}) is
     * AES-GCM sealed with an AAD that binds the id, index, length and chunk count, and the digest
     * record is itself sealed under the ResourceKey. Their failure mode is intentionally local
     * (that one fragment/class fails closed), so listing them here would turn a single corrupted
     * fragment into a whole-process halt without adding any detection the per-chunk seals do not
     * already provide.
     */
    public static boolean isPerChunkEncryptedEntry(String path) {
        return path.startsWith("chimera/chunks/") || path.startsWith("chimera/classes/");
    }

    /**
     * KI-28: manifest authentication is sealed with the ResourceKey-derived item key
     * {@code HKDF(kek, envSalt, "chimera/v1/manifest/0")}. Runtime op9 can decrypt it without any
     * key ever entering Java. File layout: {@code nonce[12] || AES-GCM(sha256(manifest))[48]}.
     */
    public static final int SEALED_NONCE_BYTES = 12;
    public static final int SEALED_MAC_BYTES = SEALED_NONCE_BYTES + 32 + 16;
    public static final String MANIFEST_KIND = "manifest";
    public static final int MANIFEST_ID = 0;
    public static final String MANIFEST_AAD = "manifest/0";

    /** C-06: sealed digest of the string-table ciphertext ({@code chimera/strings.mac}). */
    public static final String STRINGS_KIND = "strings";
    public static final int STRINGS_ID = 0;
    public static final String STRINGS_AAD = "strings/0";

    public byte[] build(Map<String, String> classHashes) {
        return build(HEADER_V1, classHashes);
    }

    /**
     * #9: full-coverage manifest ({@code CHM2}). Same line format as {@link #build(Map)}, but the
     * runtime treats it as authoritative for the whole {@code chimera/**} namespace: every entry in
     * the artifact must be listed, and every listed entry must match.
     */
    public byte[] buildFull(Map<String, String> hashes) {
        return build(HEADER_V2, hashes);
    }

    private byte[] build(String header, Map<String, String> hashes) {
        if (hashes == null) throw new IllegalArgumentException("classHashes is required");

        List<String> paths = new ArrayList<>(hashes.keySet());
        Collections.sort(paths);

        StringBuilder text = new StringBuilder(header).append('\n');
        for (String path : paths) {
            if (path == null) throw new IllegalArgumentException("null manifest path");
            String hash = hashes.get(path);
            if (hash == null) throw new IllegalArgumentException("missing hash for " + path);
            text.append(hash).append(SEPARATOR).append(path).append('\n');
        }
        return text.toString().getBytes(StandardCharsets.UTF_8);
    }

    /** Legacy HMAC (kept for compatibility); new builds use {@link #sealedMac}. */
    public byte[] mac(byte[] manifest, byte[] kek) {
        if (manifest == null || kek == null) {
            throw new IllegalArgumentException("manifest and kek are required");
        }
        return Crypto.hmacSha256(kek, manifest);
    }

    /**
     * KI-28: seals {@code sha256(manifest)} with the ResourceKey-derived item key so the runtime can
     * authenticate the manifest through native DECRYPT_DATA (op 9) or the Java fallback without
     * materialising the key outside the native handle.
     */
    public byte[] sealedMac(byte[] manifest, byte[] itemKey) {
        return sealedMac(manifest, itemKey, MANIFEST_AAD);
    }

    /**
     * Seals {@code sha256(payload)} with an explicit AAD. Used for artefacts other than the
     * manifest, e.g. the C-06 string-table digest ({@code "strings/0"}).
     */
    public byte[] sealedMac(byte[] payload, byte[] itemKey, String aad) {
        if (payload == null || itemKey == null || aad == null) {
            throw new IllegalArgumentException("payload, itemKey and aad are required");
        }
        byte[] nonce = Crypto.random(SEALED_NONCE_BYTES);
        byte[] ciphertext = Crypto.aesGcmEncrypt(itemKey, nonce, Crypto.sha256(payload),
                aad.getBytes(StandardCharsets.UTF_8));
        byte[] out = new byte[nonce.length + ciphertext.length];
        System.arraycopy(nonce, 0, out, 0, nonce.length);
        System.arraycopy(ciphertext, 0, out, nonce.length, ciphertext.length);
        return out;
    }

    /**
     * #9: authenticates the manifest with a key that never enters the artifact.
     *
     * <p>The sealed {@link #sealedMac} is derived from build material ({@code kek}/{@code envSalt})
     * that a rebuild of the jar can reproduce, so on its own it proves nothing against an attacker
     * who edits a resource and re-seals it. This record is a plain HMAC-SHA256 over the manifest
     * bytes under a key that is a compile-time constant of the native library
     * ({@code -DCHIMERA_MANIFEST_KEY_HEX}). The jar carries only the tag; verifying it requires the
     * shipped DLL, which is the artifact's root of trust.</p>
     */
    public byte[] manifestHmac(byte[] manifest, byte[] key) {
        if (manifest == null || key == null || key.length == 0) {
            throw new IllegalArgumentException("manifest and key are required");
        }
        return Crypto.hmacSha256(key, manifest);
    }

    /** Java-side counterpart of {@link #sealedMac}: opens the sealed digest. */
    public byte[] openSealedDigest(byte[] sealedMac, byte[] itemKey) {
        if (sealedMac == null || sealedMac.length != SEALED_MAC_BYTES || itemKey == null) {
            throw new IllegalArgumentException("sealed manifest mac must be " + SEALED_MAC_BYTES + " bytes");
        }
        byte[] nonce = new byte[SEALED_NONCE_BYTES];
        System.arraycopy(sealedMac, 0, nonce, 0, nonce.length);
        byte[] ciphertext = new byte[sealedMac.length - nonce.length];
        System.arraycopy(sealedMac, nonce.length, ciphertext, 0, ciphertext.length);
        return Crypto.aesGcmDecrypt(itemKey, nonce, ciphertext,
                MANIFEST_AAD.getBytes(StandardCharsets.UTF_8));
    }
}
