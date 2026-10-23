package dev.chimera.transform.watermark;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.tree.ClassNode;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.BiConsumer;

/**
 * Output of {@link WatermarkEmbedder}: the five sealed shard resources plus the concrete
 * variant/order assignments that must be applied to the classes.
 *
 * <p>Wiring contract (Lead):</p>
 * <pre>
 * WatermarkPlan plan = new WatermarkEmbedder(resourceKey, envSalt)
 *         .embed(buildId, licenseTag, classes);          // classes: entryName -&gt; bytes
 * plan.writeResources(ctx.sink::put);                     // chimera/wm/wm0..4.bin
 * for each class: plan.applyCarrier(internalName, classNode) before ClassWriter
 * </pre>
 * <p>Alternatively use {@link #applyCarrier(byte[], String)} as a whole-jar pre-pass.</p>
 */
public final class WatermarkPlan {

    private final String buildId;
    private final byte[] licenseTag;
    private final Map<String, int[]> variantBits;
    private final Map<String, Integer> structureOrderBits;
    private final Map<String, byte[]> resources;
    private final byte[] orderKey;

    WatermarkPlan(String buildId, byte[] licenseTag,
                  Map<String, int[]> variantBits,
                  Map<String, Integer> structureOrderBits,
                  Map<String, byte[]> resources,
                  byte[] orderKey) {
        this.buildId = buildId;
        this.licenseTag = licenseTag.clone();
        this.variantBits = deepCopyBits(variantBits);
        this.structureOrderBits = Collections.unmodifiableMap(
                new LinkedHashMap<>(structureOrderBits));
        this.resources = deepCopyResources(resources);
        this.orderKey = orderKey.clone();
    }

    public String buildId() {
        return buildId;
    }

    public byte[] licenseTag() {
        return licenseTag.clone();
    }

    /** Class internal name -&gt; k variant bits (each 0/1). */
    public Map<String, int[]> variantBits() {
        return deepCopyBits(variantBits);
    }

    /** Class internal name -&gt; member-order bit (0 ascending, 1 descending). */
    public Map<String, Integer> structureOrderBits() {
        return new LinkedHashMap<>(structureOrderBits);
    }

    /** Exactly {@code chimera/wm/wm0.bin .. wm4.bin}. */
    public Map<String, byte[]> resources() {
        return deepCopyResources(resources);
    }

    public byte[] resource(String name) {
        byte[] data = resources.get(name);
        return data == null ? null : data.clone();
    }

    /** Streams the shards into the engine's {@code ResourceSink}-compatible consumer. */
    public void writeResources(BiConsumer<String, byte[]> sink) {
        if (sink == null) {
            throw new IllegalArgumentException("sink is required");
        }
        for (Map.Entry<String, byte[]> entry : resources.entrySet()) {
            sink.accept(entry.getKey(), entry.getValue().clone());
        }
    }

    public Set<String> classNames() {
        Set<String> names = new LinkedHashSet<>(variantBits.keySet());
        names.addAll(structureOrderBits.keySet());
        return Collections.unmodifiableSet(names);
    }

    /** Number of classes carrying variant bits (Stats: watermarkVariantClasses). */
    public int variantClassCount() {
        return variantBits.size();
    }

    /** Total synthetic variant methods (Stats: watermarkVariantMethods). */
    public int variantMethodCount() {
        int count = 0;
        for (int[] bits : variantBits.values()) {
            count += bits.length;
        }
        return count;
    }

    /** Number of classes carrying a member-order bit (Stats: watermarkStructureClasses). */
    public int structureClassCount() {
        return structureOrderBits.size();
    }

    /** Number of shard resources (always 5). */
    public int shardCount() {
        return resources.size();
    }

    public int[] variantBits(String internalName) {
        int[] bits = variantBits.get(normalize(internalName));
        return bits == null ? null : bits.clone();
    }

    public Integer structureBit(String internalName) {
        return structureOrderBits.get(normalize(internalName));
    }

    /**
     * Applies both carrier layers to an ASM node. Returns false when the class is not part of
     * the plan or is ineligible (Mixin/interface/enum/record/annotation/...).
     */
    public boolean applyCarrier(String internalName, ClassNode node) {
        if (node == null) {
            return false;
        }
        String name = internalName == null ? node.name : normalize(internalName);
        int[] bits = variantBits.get(name);
        Integer order = structureOrderBits.get(name);
        if (bits == null && order == null) {
            return false;
        }
        return WatermarkCarrier.embed(node, name, bits, order, orderKey);
    }

    /**
     * Byte-level variant of {@link #applyCarrier(String, ClassNode)}.
     *
     * <p>For classes outside the plan and for every Mixin/interface/enum/record class the
     * <em>same byte array instance</em> is returned, so "Mixin bytes must not change" is
     * enforced structurally rather than by convention.</p>
     */
    public byte[] applyCarrier(byte[] classBytes, String internalName) {
        if (classBytes == null) {
            throw new IllegalArgumentException("classBytes is required");
        }
        String name = normalize(internalName);
        int[] bits = variantBits.get(name);
        Integer order = structureOrderBits.get(name);
        if (bits == null && order == null) {
            return classBytes;
        }
        ClassNode node;
        try {
            node = new ClassNode();
            new ClassReader(classBytes).accept(node, ClassReader.EXPAND_FRAMES);
        } catch (RuntimeException ex) {
            return classBytes;
        }
        if (!WatermarkCarrier.isEligible(name, node)) {
            return classBytes;
        }
        if (!WatermarkCarrier.embed(node, name, bits, order, orderKey)) {
            return classBytes;
        }
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        node.accept(writer);
        return writer.toByteArray();
    }

    byte[] orderKeyInternal() {
        return orderKey;
    }

    private static String normalize(String internalName) {
        if (internalName == null) {
            return "";
        }
        String name = internalName.trim().replace('\\', '/');
        while (name.startsWith("/")) {
            name = name.substring(1);
        }
        if (name.endsWith(".class")) {
            name = name.substring(0, name.length() - ".class".length());
        }
        return name;
    }

    private static Map<String, int[]> deepCopyBits(Map<String, int[]> source) {
        Map<String, int[]> copy = new LinkedHashMap<>();
        for (Map.Entry<String, int[]> entry : source.entrySet()) {
            copy.put(entry.getKey(), entry.getValue().clone());
        }
        return Collections.unmodifiableMap(copy);
    }

    private static Map<String, byte[]> deepCopyResources(Map<String, byte[]> source) {
        Map<String, byte[]> copy = new LinkedHashMap<>();
        for (Map.Entry<String, byte[]> entry : source.entrySet()) {
            copy.put(entry.getKey(), entry.getValue().clone());
        }
        return Collections.unmodifiableMap(copy);
    }
}
