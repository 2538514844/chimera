package dev.chimera.transform.watermark;

import dev.chimera.crypto.Crypto;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.ClassNode;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class WatermarkTest {

    private static final byte[] RESOURCE_KEY =
            Crypto.sha256("watermark-resource-key".getBytes(StandardCharsets.UTF_8));
    private static final byte[] ENV_SALT =
            Crypto.sha256("watermark-env-salt".getBytes(StandardCharsets.UTF_8));
    private static final byte[] LICENSE_TAG = WatermarkEmbedder.deriveLicenseTag(
            "license-42", Crypto.sha256("license-salt".getBytes(StandardCharsets.UTF_8)));
    private static final String BUILD_ID = "build-2026-10-20-watermark";

    @TempDir
    Path temp;

    @Test
    void roundTripRecoversBuildIdLicenseTagAndAllLayers() {
        Bundle bundle = embed(6);
        WatermarkExtraction extraction = extract(bundle);

        assertTrue(extraction.recovered(), extraction::failureReason);
        assertEquals(BUILD_ID, extraction.buildId());
        assertArrayEquals(LICENSE_TAG, extraction.licenseTag());
        assertVariantBitsEqual(bundle.plan.variantBits(), extraction.variantBits());
        assertEquals(bundle.plan.structureOrderBits(), extraction.structureOrderBits());
        assertTrue(extraction.hasLayer(WatermarkExtraction.Layer.SHARDS));
        assertTrue(extraction.hasLayer(WatermarkExtraction.Layer.VARIANT_BITS));
        assertTrue(extraction.hasLayer(WatermarkExtraction.Layer.STRUCTURE_BITS));
        assertEquals(5, extraction.shardsPresent());
        assertEquals(5, extraction.shardsValid());
        assertEquals(10, extraction.shardCombinations());
        assertEquals(10, extraction.shardVotes());
        assertEquals(extraction.variantClassesExpected(), extraction.variantClassesMatched());
        assertEquals(extraction.structureClassesExpected(), extraction.structureClassesMatched());
        assertTrue(extraction.confidence() >= 0.99, extraction.toString());
        assertTrue(bundle.plan.variantBits().containsKey(WatermarkFixture.ALPHA));
        assertTrue(bundle.plan.variantBits().containsKey(WatermarkFixture.BETA));
        assertFalse(bundle.plan.variantBits().containsKey(WatermarkFixture.MIXIN_TARGET));
    }

    @Test
    void roundTripThroughJar() throws IOException {
        Bundle bundle = embed(5);
        Path jar = writeJar(bundle.entries);
        WatermarkExtraction extraction = new WatermarkExtractor(RESOURCE_KEY, ENV_SALT).extract(jar);
        assertTrue(extraction.recovered(), extraction::failureReason);
        assertEquals(BUILD_ID, extraction.buildId());
        assertArrayEquals(LICENSE_TAG, extraction.licenseTag());
        assertVariantBitsEqual(bundle.plan.variantBits(), extraction.variantBits());
        assertEquals(bundle.plan.structureOrderBits(), extraction.structureOrderBits());
        assertTrue(extraction.confidence() >= 0.99, extraction.toString());

        WatermarkExtraction viaKek = WatermarkExtractor.usingKek(kek(), ENV_SALT).extract(jar);
        assertTrue(viaKek.recovered(), viaKek::failureReason);
        assertEquals(BUILD_ID, viaKek.buildId());
    }

    @Test
    void deletingOneShardStillRecovers() {
        Bundle bundle = embed(5);
        Map<String, byte[]> entries = new LinkedHashMap<>(bundle.entries);
        entries.remove(WatermarkEmbedder.shardResource(2));

        WatermarkExtraction extraction = new WatermarkExtractor(RESOURCE_KEY, ENV_SALT)
                .extract(entries);
        assertTrue(extraction.recovered(), extraction::failureReason);
        assertEquals(BUILD_ID, extraction.buildId());
        assertArrayEquals(LICENSE_TAG, extraction.licenseTag());
        assertEquals(4, extraction.shardsPresent());
        assertEquals(4, extraction.shardsValid());
        assertEquals(4, extraction.shardCombinations());
        assertEquals(4, extraction.shardVotes());
        assertTrue(extraction.hasLayer(WatermarkExtraction.Layer.VARIANT_BITS));
        assertTrue(extraction.confidence() >= 0.94, extraction.toString());
    }

    @Test
    void deletingTwoShardsStillRecoversAtThreshold() {
        Bundle bundle = embed(5);
        Map<String, byte[]> entries = new LinkedHashMap<>(bundle.entries);
        entries.remove(WatermarkEmbedder.shardResource(0));
        entries.remove(WatermarkEmbedder.shardResource(3));

        WatermarkExtraction extraction = new WatermarkExtractor(RESOURCE_KEY, ENV_SALT)
                .extract(entries);
        assertTrue(extraction.recovered(), extraction::failureReason);
        assertEquals(3, extraction.shardsPresent());
        assertEquals(3, extraction.shardsValid());
        assertEquals(1, extraction.shardCombinations());
        assertEquals(1, extraction.shardVotes());
        assertEquals(BUILD_ID, extraction.buildId());
        assertTrue(extraction.confidence() >= 0.89, extraction.toString());
    }

    @Test
    void deletingThreeShardsFailsClosed() {
        Bundle bundle = embed(4);
        Map<String, byte[]> entries = new LinkedHashMap<>(bundle.entries);
        entries.remove(WatermarkEmbedder.shardResource(0));
        entries.remove(WatermarkEmbedder.shardResource(1));
        entries.remove(WatermarkEmbedder.shardResource(2));

        WatermarkExtraction extraction = new WatermarkExtractor(RESOURCE_KEY, ENV_SALT)
                .extract(entries);
        assertFalse(extraction.recovered());
        assertNull(extraction.buildId());
        assertNull(extraction.licenseTag());
        assertEquals(0.0, extraction.confidence());
        assertTrue(extraction.hitLayers().isEmpty());
        assertEquals(2, extraction.shardsPresent());
        assertEquals(2, extraction.shardsValid());
        assertNotNull(extraction.failureReason());
        assertTrue(extraction.failureReason().contains("insufficient"));
    }

    @Test
    void flippingOneBitInOneShardStillRecovers() {
        Bundle bundle = embed(5);
        Map<String, byte[]> entries = new LinkedHashMap<>(bundle.entries);
        byte[] shard = entries.get(WatermarkEmbedder.shardResource(1)).clone();
        // Near the end (inside ciphertext/GCM tag): exactly one bit flipped.
        shard[shard.length - 20] ^= 0x01;
        entries.put(WatermarkEmbedder.shardResource(1), shard);

        WatermarkExtraction extraction = new WatermarkExtractor(RESOURCE_KEY, ENV_SALT)
                .extract(entries);
        assertTrue(extraction.recovered(), extraction::failureReason);
        assertEquals(5, extraction.shardsPresent());
        assertEquals(4, extraction.shardsValid());
        assertEquals(BUILD_ID, extraction.buildId());
        assertArrayEquals(LICENSE_TAG, extraction.licenseTag());
        assertTrue(extraction.confidence() >= 0.94, extraction.toString());
    }

    @Test
    void deletedShardPlusFlippedBitStillRecovers() {
        Bundle bundle = embed(5);
        Map<String, byte[]> entries = new LinkedHashMap<>(bundle.entries);
        entries.remove(WatermarkEmbedder.shardResource(0));
        byte[] shard = entries.get(WatermarkEmbedder.shardResource(1)).clone();
        shard[shard.length - 20] ^= 0x01;
        entries.put(WatermarkEmbedder.shardResource(1), shard);

        WatermarkExtraction extraction = new WatermarkExtractor(RESOURCE_KEY, ENV_SALT)
                .extract(entries);
        assertTrue(extraction.recovered(), extraction::failureReason);
        assertEquals(4, extraction.shardsPresent());
        assertEquals(3, extraction.shardsValid());
        assertEquals(BUILD_ID, extraction.buildId());
        assertArrayEquals(LICENSE_TAG, extraction.licenseTag());
        assertTrue(extraction.confidence() >= 0.89, extraction.toString());
    }

    @Test
    void missingOrWrongResourceKeyFailsClosed() {
        Bundle bundle = embed(4);

        assertThrows(IllegalArgumentException.class,
                () -> new WatermarkExtractor(null, ENV_SALT));
        assertThrows(IllegalArgumentException.class,
                () -> new WatermarkExtractor(new byte[0], ENV_SALT));
        assertThrows(IllegalArgumentException.class,
                () -> WatermarkExtractor.fromEntries(bundle.entries, null, ENV_SALT));

        WatermarkExtraction wrongKey = new WatermarkExtractor(new byte[32], ENV_SALT)
                .extract(bundle.entries);
        assertFalse(wrongKey.recovered());
        assertNull(wrongKey.buildId());
        assertNull(wrongKey.licenseTag());
        assertEquals(0.0, wrongKey.confidence());
        assertTrue(wrongKey.hitLayers().isEmpty());
        assertEquals(5, wrongKey.shardsPresent());
        assertEquals(0, wrongKey.shardsValid());
        assertNotNull(wrongKey.failureReason());
    }

    @Test
    void encryptedShardsDoNotLeakPlaintext() {
        Bundle bundle = embed(4);
        byte[] buildId = BUILD_ID.getBytes(StandardCharsets.UTF_8);
        byte[] payloadMagic = "CHW1".getBytes(StandardCharsets.US_ASCII);
        byte[] classMarker = WatermarkFixture.ALPHA.getBytes(StandardCharsets.UTF_8);
        byte[] tagHex = Crypto.hex(LICENSE_TAG).getBytes(StandardCharsets.US_ASCII);
        for (int index = 0; index < WatermarkEmbedder.shardCount(); index++) {
            byte[] shard = bundle.entries.get(WatermarkEmbedder.shardResource(index));
            assertNotNull(shard);
            assertFalse(contains(shard, buildId), "buildId leaked into shard " + index);
            assertFalse(contains(shard, LICENSE_TAG), "licenseTag leaked into shard " + index);
            assertFalse(contains(shard, payloadMagic), "payload magic leaked into shard " + index);
            assertFalse(contains(shard, classMarker), "class name leaked into shard " + index);
            assertFalse(contains(shard, tagHex), "license tag hex leaked into shard " + index);
        }
    }

    @Test
    void mixinBytesAndDebugAttributesStayUntouched() {
        Bundle bundle = embed(4);
        assertFalse(bundle.plan.variantBits().containsKey(WatermarkFixture.MIXIN_TARGET));
        assertFalse(bundle.plan.structureOrderBits().containsKey(WatermarkFixture.MIXIN_TARGET));

        byte[] original = bundle.originalClasses.get(WatermarkFixture.MIXIN_TARGET + ".class");
        byte[] carried = bundle.plan.applyCarrier(original, WatermarkFixture.MIXIN_TARGET);
        assertSame(original, carried, "Mixin bytes must keep the original array identity");

        ClassNode node = read(original);
        int methodCount = node.methods.size();
        String signature = node.signature;
        String sourceFile = node.sourceFile;
        assertFalse(bundle.plan.applyCarrier(WatermarkFixture.MIXIN_TARGET, node));
        assertEquals(methodCount, node.methods.size());
        assertEquals(signature, node.signature);
        assertEquals(sourceFile, node.sourceFile);
        assertNotNull(node.visibleAnnotations);
        assertTrue(node.visibleAnnotations.stream()
                .anyMatch(annotation -> annotation.desc != null
                        && annotation.desc.contains("spongepowered/asm/mixin/Mixin")));
        assertTrue(node.methods.stream()
                .noneMatch(method -> method.name.startsWith(WatermarkCarrier.VARIANT_METHOD_PREFIX)));
    }

    @Test
    void variantAndStructureBitsAreReadableDirectlyFromBytecode() {
        Bundle bundle = embed(7);
        ClassNode node = read(bundle.entries.get(WatermarkFixture.ALPHA + ".class"));

        int[] expected = bundle.plan.variantBits(WatermarkFixture.ALPHA);
        int[] recovered = WatermarkCarrier.readVariantBits(node, expected.length);
        assertArrayEquals(expected, recovered);
        assertEquals(expected.length, WatermarkCarrier.carrierMethodCount(node));

        byte[] orderKey = WatermarkCarrier.deriveOrderKey(kek(), ENV_SALT);
        Integer order = WatermarkCarrier.readStructureBit(node, WatermarkFixture.ALPHA, orderKey);
        assertEquals(bundle.plan.structureBit(WatermarkFixture.ALPHA), order);
    }

    @Test
    void transformedClassPassesJvmVerificationAndKeepsBehaviour() throws Exception {
        Bundle bundle = embed(7);
        byte[] bytes = bundle.entries.get(WatermarkFixture.ALPHA + ".class");
        Class<?> type = new ClassLoader() {
            Class<?> define(byte[] data) {
                return defineClass(null, data, 0, data.length);
            }
        }.define(bytes);
        Object instance = type.getDeclaredConstructor().newInstance();
        assertEquals(7, type.getMethod("zeta").invoke(instance));
        assertEquals(3, type.getMethod("alpha").invoke(instance));
        assertEquals(4, type.getMethod("middle", int.class).invoke(instance, 3));
        assertEquals("payload", type.getMethod("compute", String.class)
                .invoke(instance, "payload"));
    }

    @Test
    void licenseTagIsHmacOfLicenseIdAndSalt() {
        byte[] salt = "license-salt".getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(
                Crypto.hmacSha256("license-42".getBytes(StandardCharsets.UTF_8), salt),
                WatermarkEmbedder.deriveLicenseTag("license-42", salt));
    }

    private Bundle embed(int variantBits) {
        Map<String, byte[]> classes = WatermarkFixture.classes();
        WatermarkPlan plan = new WatermarkEmbedder(RESOURCE_KEY, ENV_SALT)
                .embed(BUILD_ID, LICENSE_TAG, classes, variantBits);
        Map<String, byte[]> entries = new LinkedHashMap<>(plan.resources());
        for (Map.Entry<String, byte[]> entry : classes.entrySet()) {
            String internalName = entry.getKey().substring(
                    0, entry.getKey().length() - ".class".length());
            entries.put(entry.getKey(), plan.applyCarrier(entry.getValue(), internalName));
        }
        return new Bundle(plan, classes, entries);
    }

    private WatermarkExtraction extract(Bundle bundle) {
        return new WatermarkExtractor(RESOURCE_KEY, ENV_SALT).extract(bundle.entries);
    }

    private Path writeJar(Map<String, byte[]> entries) throws IOException {
        Path jar = temp.resolve("watermark-" + UUID.randomUUID() + ".jar");
        try (ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(jar))) {
            for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                out.putNextEntry(new ZipEntry(entry.getKey()));
                out.write(entry.getValue());
                out.closeEntry();
            }
        }
        return jar;
    }

    private static byte[] kek() {
        return Crypto.hkdf(RESOURCE_KEY,
                "chimera-kek-v1".getBytes(StandardCharsets.UTF_8),
                "kek".getBytes(StandardCharsets.UTF_8), 32);
    }

    private static ClassNode read(byte[] bytes) {
        ClassNode node = new ClassNode();
        new ClassReader(bytes).accept(node, 0);
        return node;
    }

    private static void assertVariantBitsEqual(Map<String, int[]> expected,
                                               Map<String, int[]> actual) {
        assertEquals(expected.keySet(), actual.keySet());
        for (String name : expected.keySet()) {
            assertArrayEquals(expected.get(name), actual.get(name), name);
        }
    }

    private static boolean contains(byte[] haystack, byte[] needle) {
        if (needle.length == 0) {
            return true;
        }
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    private static final class Bundle {
        final WatermarkPlan plan;
        final Map<String, byte[]> originalClasses;
        final Map<String, byte[]> entries;

        Bundle(WatermarkPlan plan, Map<String, byte[]> originalClasses,
               Map<String, byte[]> entries) {
            this.plan = plan;
            this.originalClasses = originalClasses;
            this.entries = entries;
        }
    }
}
