package dev.chimera.transform.watermark;

import dev.chimera.crypto.Crypto;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.ClassNode;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Extracts the watermark from a protected jar (or an in-memory entry map).
 *
 * <p>Algorithm:</p>
 * <ol>
 *   <li>read {@code chimera/wm/wm0.bin .. wm4.bin}; a missing or GCM-rejected shard is treated
 *       as erased (this is how one corrupted shard or one flipped bit is tolerated);</li>
 *   <li>enumerate all 3-of-5 combinations, reconstruct the payload, verify its SHA-256 checksum
 *       and parse it; identical payloads vote, the majority wins;</li>
 *   <li>scan the class entries referenced by the shard metadata and recover the variant bits
 *       and member-order bits from the bytecode carriers;</li>
 *   <li>report confidence and hit layers. Missing ResourceKey is rejected at construction
 *       (fail-closed); a wrong key yields a failed extraction, never a partial result.</li>
 * </ol>
 */
public final class WatermarkExtractor {

    private static final byte[] KEK_SALT = "chimera-kek-v1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] KEK_INFO = "kek".getBytes(StandardCharsets.UTF_8);

    private final byte[] kek;
    private final byte[] envSalt;
    private final byte[] orderKey;

    /** @param resourceKey 32-byte product ResourceKey; null/empty is rejected fail-closed */
    public WatermarkExtractor(byte[] resourceKey, byte[] envSalt) {
        validateResourceKey(resourceKey);
        validateEnvSalt(envSalt);
        this.kek = Crypto.hkdf(resourceKey, KEK_SALT, KEK_INFO, 32);
        this.envSalt = envSalt.clone();
        this.orderKey = WatermarkCarrier.deriveOrderKey(kek, envSalt);
    }

    private WatermarkExtractor(byte[] kek, byte[] envSalt, boolean preDerived) {
        validateKek(kek);
        validateEnvSalt(envSalt);
        this.kek = kek.clone();
        this.envSalt = envSalt.clone();
        this.orderKey = WatermarkCarrier.deriveOrderKey(kek, envSalt);
    }

    /** Uses an already-derived KEK (e.g. {@code TransformContext.kek}). */
    public static WatermarkExtractor usingKek(byte[] kek, byte[] envSalt) {
        return new WatermarkExtractor(kek, envSalt, true);
    }

    public static WatermarkExtraction fromJar(Path jar, byte[] resourceKey, byte[] envSalt)
            throws IOException {
        return new WatermarkExtractor(resourceKey, envSalt).extract(jar);
    }

    public static WatermarkExtraction fromEntries(Map<String, byte[]> entries,
                                                  byte[] resourceKey, byte[] envSalt) {
        return new WatermarkExtractor(resourceKey, envSalt).extract(entries);
    }

    /** Extracts from an in-memory map of jar entry name -&gt; bytes. */
    public WatermarkExtraction extract(Map<String, byte[]> entries) {
        if (entries == null) {
            throw new IllegalArgumentException("entries are required");
        }
        Map<Integer, byte[]> shards = new LinkedHashMap<>();
        for (int index = 0; index < WatermarkEmbedder.SHARD_COUNT; index++) {
            byte[] data = entries.get(WatermarkEmbedder.shardResource(index));
            if (data != null) {
                shards.put(index, data);
            }
        }
        ShardRecovery recovery = recover(shards);
        if (recovery.payload == null) {
            return WatermarkExtraction.failure(recovery.failureReason,
                    recovery.presentShards, recovery.validShards);
        }
        Set<String> expected = expectedClassNames(recovery.payload);
        Map<String, byte[]> classes = new HashMap<>();
        for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
            String name = normalizeClassName(entry.getKey());
            if (expected.contains(name) && entry.getValue() != null) {
                classes.put(name, entry.getValue());
            }
        }
        return finish(recovery, classes);
    }

    /** Extracts from a jar file (zip entries, not a directory). */
    public WatermarkExtraction extract(Path jar) throws IOException {
        if (jar == null) {
            throw new IllegalArgumentException("jar path is required");
        }
        Map<Integer, byte[]> shards = new LinkedHashMap<>();
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            Enumeration<? extends ZipEntry> enumeration = zip.entries();
            while (enumeration.hasMoreElements()) {
                ZipEntry entry = enumeration.nextElement();
                if (entry.isDirectory()) {
                    continue;
                }
                int index = shardIndex(entry.getName());
                if (index >= 0) {
                    shards.put(index, readAll(zip.getInputStream(entry)));
                }
            }
        }
        ShardRecovery recovery = recover(shards);
        if (recovery.payload == null) {
            return WatermarkExtraction.failure(recovery.failureReason,
                    recovery.presentShards, recovery.validShards);
        }
        Set<String> expected = expectedClassNames(recovery.payload);
        Map<String, byte[]> classes = new HashMap<>();
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            Enumeration<? extends ZipEntry> enumeration = zip.entries();
            while (enumeration.hasMoreElements()) {
                ZipEntry entry = enumeration.nextElement();
                if (entry.isDirectory() || !entry.getName().endsWith(".class")) {
                    continue;
                }
                String name = normalizeClassName(entry.getName());
                if (expected.contains(name)) {
                    classes.put(name, readAll(zip.getInputStream(entry)));
                }
            }
        }
        return finish(recovery, classes);
    }

    private ShardRecovery recover(Map<Integer, byte[]> shardFiles) {
        int present = shardFiles.size();
        if (present == 0) {
            return ShardRecovery.failure("no watermark shards found", 0, 0);
        }
        List<WatermarkShardCodec.Share> valid = new ArrayList<>();
        try {
            for (int index = 0; index < WatermarkEmbedder.SHARD_COUNT; index++) {
                byte[] file = shardFiles.get(index);
                if (file == null) {
                    continue;
                }
                byte[] itemKey = WatermarkShardCodec.shardKey(kek, envSalt, index);
                byte[] share;
                try {
                    share = WatermarkShardCodec.open(file, index, itemKey);
                } finally {
                    WatermarkShardCodec.wipe(itemKey);
                }
                if (share != null) {
                    valid.add(new WatermarkShardCodec.Share(index, share));
                }
            }
            if (valid.size() < WatermarkEmbedder.RECOVERY_THRESHOLD) {
                return ShardRecovery.failure("insufficient watermark shards: "
                        + valid.size() + " valid of " + present
                        + " (threshold " + WatermarkEmbedder.RECOVERY_THRESHOLD + ")",
                        present, valid.size());
            }
            int length = valid.get(0).data.length;
            if (length <= 0) {
                return ShardRecovery.failure("empty watermark share", present, valid.size());
            }
            List<WatermarkShardCodec.Share> consistent = new ArrayList<>();
            for (WatermarkShardCodec.Share share : valid) {
                if (share.data.length == length) {
                    consistent.add(share);
                }
            }
            if (consistent.size() < WatermarkEmbedder.RECOVERY_THRESHOLD) {
                return ShardRecovery.failure("inconsistent watermark shard lengths",
                        present, consistent.size());
            }
            List<int[]> combinations = WatermarkShardCodec.combinations(
                    consistent.size(), WatermarkEmbedder.RECOVERY_THRESHOLD);
            Map<String, Candidate> candidates = new LinkedHashMap<>();
            for (int[] combination : combinations) {
                List<WatermarkShardCodec.Share> selected = new ArrayList<>(
                        WatermarkEmbedder.RECOVERY_THRESHOLD);
                for (int position : combination) {
                    selected.add(consistent.get(position));
                }
                byte[] payload = null;
                try {
                    payload = WatermarkShardCodec.combine(selected, length);
                    WatermarkPayload.Decoded decoded = WatermarkPayload.decode(payload);
                    if (decoded == null) {
                        continue;
                    }
                    String digest = Crypto.hex(Crypto.sha256(payload));
                    Candidate candidate = candidates.get(digest);
                    if (candidate == null) {
                        candidate = new Candidate(decoded);
                        candidates.put(digest, candidate);
                    }
                    candidate.votes++;
                } catch (RuntimeException ex) {
                    // A malformed share is simply a failed candidate.
                } finally {
                    WatermarkShardCodec.wipe(payload);
                }
            }
            if (candidates.isEmpty()) {
                return ShardRecovery.failure(
                        "no 3-of-5 combination passed shard authentication and payload integrity",
                        present, consistent.size());
            }
            Candidate winner = null;
            int maxVotes = 0;
            int ties = 0;
            for (Candidate candidate : candidates.values()) {
                if (candidate.votes > maxVotes) {
                    winner = candidate;
                    maxVotes = candidate.votes;
                    ties = 1;
                } else if (candidate.votes == maxVotes) {
                    ties++;
                }
            }
            if (winner == null || ties != 1) {
                return ShardRecovery.failure(
                        "ambiguous watermark payload: no majority among shard combinations",
                        present, consistent.size());
            }
            return new ShardRecovery(winner.decoded, present, consistent.size(), maxVotes,
                    combinations.size(), null);
        } finally {
            for (WatermarkShardCodec.Share share : valid) {
                WatermarkShardCodec.wipe(share.data);
            }
        }
    }

    private WatermarkExtraction finish(ShardRecovery recovery, Map<String, byte[]> classes) {
        WatermarkPayload.Decoded metadata = recovery.payload;
        Set<String> expected = expectedClassNames(metadata);
        Map<String, int[]> recoveredVariants = new LinkedHashMap<>();
        Map<String, Integer> recoveredStructure = new LinkedHashMap<>();
        int variantRecovered = 0;
        int variantMatched = 0;
        int structureRecovered = 0;
        int structureMatched = 0;
        for (String name : expected) {
            byte[] bytes = classes.get(name);
            if (bytes == null) {
                continue;
            }
            ClassNode node;
            try {
                node = new ClassNode();
                new ClassReader(bytes).accept(node, ClassReader.SKIP_FRAMES);
            } catch (RuntimeException ex) {
                continue;
            }
            int[] expectedBits = metadata.variantBits.get(name);
            if (expectedBits != null && expectedBits.length > 0) {
                int[] carrier = WatermarkCarrier.readVariantBits(node, expectedBits.length);
                boolean complete = true;
                for (int bit : carrier) {
                    if (bit < 0) {
                        complete = false;
                        break;
                    }
                }
                if (complete) {
                    recoveredVariants.put(name, carrier);
                    variantRecovered++;
                    if (Arrays.equals(carrier, expectedBits)) {
                        variantMatched++;
                    }
                }
            }
            Integer expectedOrder = metadata.structureOrderBits.get(name);
            if (expectedOrder != null) {
                Integer carrierOrder = WatermarkCarrier.readStructureBit(node, name, orderKey);
                if (carrierOrder != null) {
                    recoveredStructure.put(name, carrierOrder);
                    structureRecovered++;
                    if (carrierOrder.equals(expectedOrder)) {
                        structureMatched++;
                    }
                }
            }
        }

        Map<String, int[]> outputVariants = new LinkedHashMap<>();
        for (Map.Entry<String, int[]> entry : metadata.variantBits.entrySet()) {
            outputVariants.put(entry.getKey(), entry.getValue().clone());
        }
        outputVariants.putAll(recoveredVariants);
        Map<String, Integer> outputStructure = new LinkedHashMap<>(metadata.structureOrderBits);
        outputStructure.putAll(recoveredStructure);

        Set<WatermarkExtraction.Layer> layers = new LinkedHashSet<>();
        layers.add(WatermarkExtraction.Layer.SHARDS);
        if (variantRecovered > 0) {
            layers.add(WatermarkExtraction.Layer.VARIANT_BITS);
        }
        if (structureRecovered > 0) {
            layers.add(WatermarkExtraction.Layer.STRUCTURE_BITS);
        }

        int variantExpected = metadata.variantBits.size();
        int structureExpected = metadata.structureOrderBits.size();
        double base = 0.60 + 0.05 * Math.max(0, recovery.validShards - 3);
        double vote = recovery.combinations == 0 ? 0.0
                : (double) recovery.votes / recovery.combinations;
        double variantAgreement = variantExpected == 0 ? 0.0
                : (double) variantMatched / variantExpected;
        double structureAgreement = structureExpected == 0 ? 0.0
                : (double) structureMatched / structureExpected;
        double confidence = base + 0.10 * vote + 0.10 * variantAgreement
                + 0.10 * structureAgreement;

        return WatermarkExtraction.recovered(metadata.buildId, metadata.licenseTag,
                outputVariants, outputStructure, confidence, layers,
                recovery.presentShards, recovery.validShards, recovery.votes,
                recovery.combinations,
                variantExpected, variantRecovered, variantMatched,
                structureExpected, structureRecovered, structureMatched);
    }

    private static Set<String> expectedClassNames(WatermarkPayload.Decoded payload) {
        Set<String> names = new LinkedHashSet<>(payload.variantBits.keySet());
        names.addAll(payload.structureOrderBits.keySet());
        return names;
    }

    private static int shardIndex(String entryName) {
        for (int index = 0; index < WatermarkEmbedder.SHARD_COUNT; index++) {
            if (WatermarkEmbedder.shardResource(index).equals(entryName)) {
                return index;
            }
        }
        return -1;
    }

    private static String normalizeClassName(String entryName) {
        if (entryName == null) {
            return "";
        }
        String name = entryName.replace('\\', '/');
        while (name.startsWith("/")) {
            name = name.substring(1);
        }
        if (name.endsWith(".class")) {
            name = name.substring(0, name.length() - ".class".length());
        }
        return name;
    }

    private static byte[] readAll(InputStream in) throws IOException {
        try (InputStream input = in) {
            return input.readAllBytes();
        }
    }

    private static void validateResourceKey(byte[] resourceKey) {
        if (resourceKey == null || resourceKey.length != 32) {
            throw new IllegalArgumentException(
                    "ResourceKey is required and must be exactly 32 bytes (fail-closed)");
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

    private static final class Candidate {
        final WatermarkPayload.Decoded decoded;
        int votes;

        Candidate(WatermarkPayload.Decoded decoded) {
            this.decoded = decoded;
        }
    }

    private static final class ShardRecovery {
        final WatermarkPayload.Decoded payload;
        final int presentShards;
        final int validShards;
        final int votes;
        final int combinations;
        final String failureReason;

        ShardRecovery(WatermarkPayload.Decoded payload, int presentShards, int validShards,
                      int votes, int combinations, String failureReason) {
            this.payload = payload;
            this.presentShards = presentShards;
            this.validShards = validShards;
            this.votes = votes;
            this.combinations = combinations;
            this.failureReason = failureReason;
        }

        static ShardRecovery failure(String reason, int presentShards, int validShards) {
            return new ShardRecovery(null, presentShards, validShards, 0, 0, reason);
        }
    }
}
