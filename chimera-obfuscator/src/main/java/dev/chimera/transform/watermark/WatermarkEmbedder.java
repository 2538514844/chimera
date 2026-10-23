package dev.chimera.transform.watermark;

import dev.chimera.crypto.Crypto;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.ClassNode;

import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Build-time watermark embedder.
 *
 * <p>Inputs: build id, license tag ({@code HMAC(licenseId, salt)}), the product ResourceKey and
 * the build environment salt. Outputs:</p>
 * <ol>
 *   <li>five independently AES-GCM-sealed shard resources
 *       {@code chimera/wm/wm0.bin .. wm4.bin}, threshold 3-of-5;</li>
 *   <li>{@link WatermarkPlan#variantBits()}: k equivalent variant slots per class
 *       (opaque-predicate shape);</li>
 *   <li>{@link WatermarkPlan#structureOrderBits()}: one member-order bit per class.</li>
 * </ol>
 *
 * <p>Key schedule matches the project convention:
 * {@code kek = HKDF(ResourceKey, "chimera-kek-v1", "kek")} and every shard item key is
 * {@code HKDF(kek, envSalt, "chimera/v1/wm/shard/<index>")}. When the engine already exposes
 * {@code ctx.kek}, use {@link #usingKek(byte[], byte[])} to avoid re-deriving it.</p>
 */
public final class WatermarkEmbedder {

    public static final int SHARD_COUNT = WatermarkShardCodec.SHARD_COUNT;
    public static final int RECOVERY_THRESHOLD = WatermarkShardCodec.THRESHOLD;
    public static final int DEFAULT_VARIANT_BITS_PER_CLASS = 8;
    public static final int MAX_VARIANT_BITS_PER_CLASS = WatermarkPayload.MAX_VARIANT_BITS;
    public static final String SHARD_DIRECTORY = "chimera/wm/";

    private static final byte[] KEK_SALT = "chimera-kek-v1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] KEK_INFO = "kek".getBytes(StandardCharsets.UTF_8);
    private static final int MAX_BUILD_ID_BYTES = WatermarkPayload.MAX_BUILD_ID_BYTES;
    private static final int MAX_LICENSE_TAG_BYTES = WatermarkPayload.MAX_LICENSE_TAG_BYTES;
    private static final int MAX_CLASSES = WatermarkPayload.MAX_CLASSES;

    private final byte[] kek;
    private final byte[] envSalt;

    /** @param resourceKey 32-byte product ResourceKey */
    public WatermarkEmbedder(byte[] resourceKey, byte[] envSalt) {
        validateResourceKey(resourceKey);
        validateEnvSalt(envSalt);
        this.kek = Crypto.hkdf(resourceKey, KEK_SALT, KEK_INFO, 32);
        this.envSalt = envSalt.clone();
    }

    private WatermarkEmbedder(byte[] kek, byte[] envSalt, boolean preDerived) {
        validateKek(kek);
        validateEnvSalt(envSalt);
        this.kek = kek.clone();
        this.envSalt = envSalt.clone();
    }

    /** Uses an already-derived KEK (e.g. {@code TransformContext.kek}). */
    public static WatermarkEmbedder usingKek(byte[] kek, byte[] envSalt) {
        return new WatermarkEmbedder(kek, envSalt, true);
    }

    public static int shardCount() {
        return SHARD_COUNT;
    }

    public static int recoveryThreshold() {
        return RECOVERY_THRESHOLD;
    }

    public static String shardResource(int index) {
        if (index < 0 || index >= SHARD_COUNT) {
            throw new IllegalArgumentException("shard index out of range: " + index);
        }
        return SHARD_DIRECTORY + "wm" + index + ".bin";
    }

    /**
     * License tag helper: {@code HMAC-SHA256(key=licenseId, message=salt)}.
     * Either the tag or a longer license binding may be archived; the extractor only treats it
     * as opaque bytes.
     */
    public static byte[] deriveLicenseTag(String licenseId, byte[] salt) {
        if (licenseId == null || licenseId.isEmpty()) {
            throw new IllegalArgumentException("licenseId is required");
        }
        return deriveLicenseTag(licenseId.getBytes(StandardCharsets.UTF_8), salt);
    }

    public static byte[] deriveLicenseTag(byte[] licenseId, byte[] salt) {
        if (licenseId == null || licenseId.length == 0) {
            throw new IllegalArgumentException("licenseId is required");
        }
        return Crypto.hmacSha256(licenseId, salt == null ? new byte[0] : salt);
    }

    /**
     * Allocates carriers for the supplied internal names without parsing class bytes.
     * Mixin/interface/enum filtering still happens in {@link WatermarkCarrier}; prefer
     * {@link #embed(String, byte[], Map, int)} to keep metadata and carriers aligned.
     */
    public WatermarkPlan embed(String buildId, byte[] licenseTag, Collection<String> classNames) {
        return embed(buildId, licenseTag, classNames, DEFAULT_VARIANT_BITS_PER_CLASS);
    }

    public WatermarkPlan embed(String buildId, byte[] licenseTag, Collection<String> classNames,
                               int variantBitsPerClass) {
        Map<String, Boolean> structureSupported = new LinkedHashMap<>();
        Set<String> names = new LinkedHashSet<>();
        if (classNames != null) {
            for (String candidate : classNames) {
                String name = normalizeName(candidate);
                if (name.isEmpty()) {
                    continue;
                }
                names.add(name);
            }
        }
        for (String name : names) {
            structureSupported.put(name, Boolean.TRUE);
        }
        return build(buildId, licenseTag, structureSupported, variantBitsPerClass);
    }

    /**
     * Preferred integration entry point: parses class headers, keeps only classes that the
     * carrier can actually modify (never Mixin/interface/enum/record/annotation), and records a
     * structure bit only when at least two sortable members exist.
     *
     * @param classes entry name (with or without {@code .class}) -&gt; class bytes
     */
    public WatermarkPlan embed(String buildId, byte[] licenseTag, Map<String, byte[]> classes) {
        return embed(buildId, licenseTag, classes, DEFAULT_VARIANT_BITS_PER_CLASS);
    }

    public WatermarkPlan embed(String buildId, byte[] licenseTag, Map<String, byte[]> classes,
                               int variantBitsPerClass) {
        Map<String, Boolean> structureSupported = new LinkedHashMap<>();
        if (classes != null) {
            for (Map.Entry<String, byte[]> entry : classes.entrySet()) {
                if (entry.getValue() == null || entry.getValue().length == 0) {
                    continue;
                }
                ClassNode node = readHeader(entry.getValue());
                if (node == null || node.name == null) {
                    continue;
                }
                if (!WatermarkCarrier.isEligible(node.name, node)) {
                    continue;
                }
                if (structureSupported.containsKey(node.name)) {
                    continue;
                }
                structureSupported.put(node.name,
                        WatermarkCarrier.canEncodeStructure(node, node.name));
            }
        }
        return build(buildId, licenseTag, structureSupported, variantBitsPerClass);
    }

    private WatermarkPlan build(String buildId, byte[] licenseTag,
                                Map<String, Boolean> structureSupported,
                                int variantBitsPerClass) {
        validateBuildId(buildId);
        validateLicenseTag(licenseTag);
        if (variantBitsPerClass < 0 || variantBitsPerClass > MAX_VARIANT_BITS_PER_CLASS) {
            throw new IllegalArgumentException("variantBitsPerClass must be 0.."
                    + MAX_VARIANT_BITS_PER_CLASS + ": " + variantBitsPerClass);
        }
        if (structureSupported.size() > MAX_CLASSES) {
            throw new IllegalArgumentException("too many watermark classes");
        }
        byte[] tag = licenseTag.clone();
        byte[] variantSeed = Crypto.hmacSha256(tag,
                ("chimera/wm/variant/" + buildId).getBytes(StandardCharsets.UTF_8));
        byte[] orderSeed = Crypto.hmacSha256(tag,
                ("chimera/wm/order/" + buildId).getBytes(StandardCharsets.UTF_8));
        Map<String, int[]> variants = new LinkedHashMap<>();
        Map<String, Integer> structures = new LinkedHashMap<>();
        try {
            for (Map.Entry<String, Boolean> entry : structureSupported.entrySet()) {
                String name = entry.getKey();
                if (variantBitsPerClass > 0) {
                    int[] bits = new int[variantBitsPerClass];
                    for (int slot = 0; slot < bits.length; slot++) {
                        byte[] digest = Crypto.hmacSha256(variantSeed,
                                (name + "#" + slot).getBytes(StandardCharsets.UTF_8));
                        bits[slot] = digest[0] & 1;
                    }
                    variants.put(name, bits);
                }
                if (Boolean.TRUE.equals(entry.getValue())) {
                    byte[] digest = Crypto.hmacSha256(orderSeed,
                            name.getBytes(StandardCharsets.UTF_8));
                    structures.put(name, digest[0] & 1);
                }
            }
            byte[] payload = WatermarkPayload.encode(buildId, tag, variants, structures);
            byte[] orderKey = WatermarkCarrier.deriveOrderKey(kek, envSalt);
            Map<String, byte[]> resources;
            try {
                resources = sealShards(payload);
            } finally {
                WatermarkShardCodec.wipe(payload);
            }
            return new WatermarkPlan(buildId, tag, variants, structures, resources, orderKey);
        } finally {
            WatermarkShardCodec.wipe(variantSeed);
            WatermarkShardCodec.wipe(orderSeed);
            WatermarkShardCodec.wipe(tag);
        }
    }

    private Map<String, byte[]> sealShards(byte[] payload) {
        byte[][] shares = WatermarkShardCodec.split(payload);
        Map<String, byte[]> resources = new LinkedHashMap<>();
        try {
            for (int index = 0; index < SHARD_COUNT; index++) {
                byte[] itemKey = WatermarkShardCodec.shardKey(kek, envSalt, index);
                try {
                    resources.put(shardResource(index),
                            WatermarkShardCodec.seal(index, shares[index], itemKey));
                } finally {
                    WatermarkShardCodec.wipe(itemKey);
                }
            }
            return resources;
        } finally {
            for (byte[] share : shares) {
                WatermarkShardCodec.wipe(share);
            }
        }
    }

    private static ClassNode readHeader(byte[] bytes) {
        try {
            ClassNode node = new ClassNode();
            new ClassReader(bytes).accept(node,
                    ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
            return node;
        } catch (RuntimeException ex) {
            return null;
        }
    }

    private static String normalizeName(String candidate) {
        if (candidate == null) {
            return "";
        }
        String name = candidate.trim().replace('\\', '/');
        while (name.startsWith("/")) {
            name = name.substring(1);
        }
        if (name.endsWith(".class")) {
            name = name.substring(0, name.length() - ".class".length());
        }
        return name;
    }

    private static void validateResourceKey(byte[] resourceKey) {
        if (resourceKey == null || resourceKey.length != 32) {
            throw new IllegalArgumentException("resourceKey must be exactly 32 bytes");
        }
    }

    private static void validateKek(byte[] kek) {
        if (kek == null || kek.length != 32) {
            throw new IllegalArgumentException("kek must be exactly 32 bytes");
        }
    }

    private static void validateEnvSalt(byte[] envSalt) {
        if (envSalt == null || envSalt.length > 64) {
            throw new IllegalArgumentException("envSalt must be 0..64 bytes");
        }
    }

    private static void validateBuildId(String buildId) {
        if (buildId == null || buildId.isEmpty()) {
            throw new IllegalArgumentException("buildId is required");
        }
        if (buildId.getBytes(StandardCharsets.UTF_8).length > MAX_BUILD_ID_BYTES) {
            throw new IllegalArgumentException("buildId too long");
        }
    }

    private static void validateLicenseTag(byte[] licenseTag) {
        if (licenseTag == null || licenseTag.length < 16 || licenseTag.length > MAX_LICENSE_TAG_BYTES) {
            throw new IllegalArgumentException(
                    "licenseTag must be 16.." + MAX_LICENSE_TAG_BYTES + " bytes");
        }
    }
}
