package dev.chimera.transform.watermark;

import dev.chimera.crypto.Crypto;

import java.util.Collections;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Result of {@link WatermarkExtractor}.
 *
 * <p>{@link #hitLayers()} reports which independent layers were actually observed in the jar:
 * the threshold shards, the per-class variant carriers and the member-order carriers. A
 * recovered result always contains {@link Layer#SHARDS}; mismatching carrier layers reduce
 * {@link #confidence()} even when the shards still authenticate.</p>
 */
public final class WatermarkExtraction {

    /** Independent watermark layers reported by the extractor. */
    public enum Layer {
        SHARDS,
        VARIANT_BITS,
        STRUCTURE_BITS
    }

    private final boolean recovered;
    private final String buildId;
    private final byte[] licenseTag;
    private final Map<String, int[]> variantBits;
    private final Map<String, Integer> structureOrderBits;
    private final double confidence;
    private final Set<Layer> hitLayers;
    private final int shardsPresent;
    private final int shardsValid;
    private final int shardVotes;
    private final int shardCombinations;
    private final int variantClassesExpected;
    private final int variantClassesRecovered;
    private final int variantClassesMatched;
    private final int structureClassesExpected;
    private final int structureClassesRecovered;
    private final int structureClassesMatched;
    private final String failureReason;

    private WatermarkExtraction(boolean recovered, String buildId, byte[] licenseTag,
                                Map<String, int[]> variantBits,
                                Map<String, Integer> structureOrderBits,
                                double confidence, Set<Layer> hitLayers,
                                int shardsPresent, int shardsValid, int shardVotes,
                                int shardCombinations,
                                int variantClassesExpected, int variantClassesRecovered,
                                int variantClassesMatched,
                                int structureClassesExpected, int structureClassesRecovered,
                                int structureClassesMatched, String failureReason) {
        this.recovered = recovered;
        this.buildId = buildId;
        this.licenseTag = licenseTag == null ? null : licenseTag.clone();
        this.variantBits = deepCopyBits(variantBits);
        this.structureOrderBits = structureOrderBits == null
                ? Collections.emptyMap()
                : Collections.unmodifiableMap(new LinkedHashMap<>(structureOrderBits));
        this.confidence = clamp(confidence);
        EnumSet<Layer> layers = hitLayers == null || hitLayers.isEmpty()
                ? EnumSet.noneOf(Layer.class) : EnumSet.copyOf(hitLayers);
        this.hitLayers = Collections.unmodifiableSet(layers);
        this.shardsPresent = shardsPresent;
        this.shardsValid = shardsValid;
        this.shardVotes = shardVotes;
        this.shardCombinations = shardCombinations;
        this.variantClassesExpected = variantClassesExpected;
        this.variantClassesRecovered = variantClassesRecovered;
        this.variantClassesMatched = variantClassesMatched;
        this.structureClassesExpected = structureClassesExpected;
        this.structureClassesRecovered = structureClassesRecovered;
        this.structureClassesMatched = structureClassesMatched;
        this.failureReason = failureReason;
    }

    static WatermarkExtraction recovered(String buildId, byte[] licenseTag,
                                         Map<String, int[]> variantBits,
                                         Map<String, Integer> structureOrderBits,
                                         double confidence, Set<Layer> hitLayers,
                                         int shardsPresent, int shardsValid, int shardVotes,
                                         int shardCombinations,
                                         int variantClassesExpected, int variantClassesRecovered,
                                         int variantClassesMatched,
                                         int structureClassesExpected, int structureClassesRecovered,
                                         int structureClassesMatched) {
        return new WatermarkExtraction(true, buildId, licenseTag, variantBits, structureOrderBits,
                confidence, hitLayers, shardsPresent, shardsValid, shardVotes, shardCombinations,
                variantClassesExpected, variantClassesRecovered, variantClassesMatched,
                structureClassesExpected, structureClassesRecovered, structureClassesMatched, null);
    }

    static WatermarkExtraction failure(String reason, int shardsPresent, int shardsValid) {
        return new WatermarkExtraction(false, null, null,
                Collections.emptyMap(), Collections.emptyMap(), 0.0,
                EnumSet.noneOf(Layer.class), shardsPresent, shardsValid, 0, 0,
                0, 0, 0, 0, 0, 0,
                reason == null ? "watermark not recovered" : reason);
    }

    public boolean recovered() {
        return recovered;
    }

    public String buildId() {
        return buildId;
    }

    public byte[] licenseTag() {
        return licenseTag == null ? null : licenseTag.clone();
    }

    public String licenseTagHex() {
        return licenseTag == null ? null : Crypto.hex(licenseTag);
    }

    /** Recovered variant bits, falling back to shard metadata for classes without carriers. */
    public Map<String, int[]> variantBits() {
        return deepCopyBits(variantBits);
    }

    /** Recovered member-order bits, falling back to shard metadata. */
    public Map<String, Integer> structureOrderBits() {
        return new LinkedHashMap<>(structureOrderBits);
    }

    public double confidence() {
        return confidence;
    }

    public Set<Layer> hitLayers() {
        return hitLayers;
    }

    public boolean hasLayer(Layer layer) {
        return layer != null && hitLayers.contains(layer);
    }

    public int shardsPresent() {
        return shardsPresent;
    }

    public int shardsValid() {
        return shardsValid;
    }

    /** Number of 3-subsets that produced the winning payload. */
    public int shardVotes() {
        return shardVotes;
    }

    /** Total 3-subsets considered; votes/combinations is the agreement ratio. */
    public int shardCombinations() {
        return shardCombinations;
    }

    public int variantClassesExpected() {
        return variantClassesExpected;
    }

    public int variantClassesRecovered() {
        return variantClassesRecovered;
    }

    public int variantClassesMatched() {
        return variantClassesMatched;
    }

    public int structureClassesExpected() {
        return structureClassesExpected;
    }

    public int structureClassesRecovered() {
        return structureClassesRecovered;
    }

    public int structureClassesMatched() {
        return structureClassesMatched;
    }

    public String failureReason() {
        return failureReason;
    }

    @Override
    public String toString() {
        if (!recovered) {
            return "WatermarkExtraction{failed=" + failureReason
                    + ", shards=" + shardsValid + "/" + shardsPresent + "}";
        }
        return "WatermarkExtraction{buildId=" + buildId
                + ", licenseTag=" + licenseTagHex()
                + ", confidence=" + String.format(java.util.Locale.ROOT, "%.3f", confidence)
                + ", layers=" + hitLayers
                + ", shards=" + shardsValid + "/" + shardsPresent
                + ", votes=" + shardVotes + "/" + shardCombinations
                + ", variants=" + variantClassesMatched + "/" + variantClassesExpected
                + ", structure=" + structureClassesMatched + "/" + structureClassesExpected
                + "}";
    }

    private static Map<String, int[]> deepCopyBits(Map<String, int[]> source) {
        Map<String, int[]> copy = new LinkedHashMap<>();
        if (source != null) {
            for (Map.Entry<String, int[]> entry : source.entrySet()) {
                copy.put(entry.getKey(), entry.getValue().clone());
            }
        }
        return Collections.unmodifiableMap(copy);
    }

    private static double clamp(double value) {
        if (Double.isNaN(value)) {
            return 0.0;
        }
        return Math.max(0.0, Math.min(1.0, value));
    }
}
