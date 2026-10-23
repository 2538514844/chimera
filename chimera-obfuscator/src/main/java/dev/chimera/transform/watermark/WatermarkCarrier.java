package dev.chimera.transform.watermark;

import dev.chimera.crypto.Crypto;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * Bytecode carrier for the watermark layers.
 *
 * <p><b>Variant bits.</b> Every class owns {@code k} synthetic methods
 * {@code $chimera$wm$0 .. $chimera$wm$(k-1)}. Each method returns zero through one of two
 * equivalent opaque-predicate shapes:</p>
 * <pre>
 * bit 0: iconst_0; ireturn
 * bit 1: iconst_1; iconst_1; ixor; ireturn   // 1 ^ 1 == 0
 * </pre>
 * <p>Both are behaviourally dead and verifier-safe. The method name selects the bit slot;
 * the body selects the value, so extraction only needs the class file.</p>
 *
 * <p><b>Structure bit.</b> All non-special, non-synthetic fields and methods are sorted by
 * {@code HMAC-SHA256(orderKey, className || kind || name || descriptor)}. Bit 0 uses ascending
 * key order, bit 1 descending. The key is derived from the build KEK + envSalt, so the order
 * looks random without the key but is perfectly checkable with it.</p>
 *
 * <p><b>Mixin safety.</b> Classes carrying a Mixin (or MixinExtras) annotation, interfaces,
 * annotations, enums, records and module/package-info classes are never touched. Callers that
 * use the byte-array API receive the original array identity, guaranteeing byte-for-byte
 * preservation of Mixin classes.</p>
 */
public final class WatermarkCarrier {

    /** Prefix of the synthetic variant carrier methods. */
    public static final String VARIANT_METHOD_PREFIX = "$chimera$wm$";

    private static final String[] MIXIN_ANNOTATION_PREFIXES = {
            "Lorg/spongepowered/asm/mixin/",
            "Lcom/llamalad7/mixinextras/"
    };

    private WatermarkCarrier() {
    }

    /** Derives the member-order key used by both carriers and the extractor. */
    public static byte[] deriveOrderKey(byte[] kek, byte[] envSalt) {
        return Crypto.hkdf(kek, envSalt,
                "chimera/v1/wm/order".getBytes(StandardCharsets.UTF_8), 32);
    }

    /**
     * True when this class may receive watermark carriers. Mixin classes are always rejected:
     * their Signature/debug attributes and byte layout must stay untouched.
     */
    public static boolean isEligible(String internalName, ClassNode node) {
        if (node == null) {
            return false;
        }
        String name = internalName == null ? node.name : internalName;
        if (name == null || name.isEmpty()) {
            return false;
        }
        if (name.startsWith("dev/chimera/")
                || name.endsWith("module-info")
                || name.endsWith("package-info")
                || name.contains("$chimera$")) {
            return false;
        }
        int access = node.access;
        if ((access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION | Opcodes.ACC_ENUM
                | Opcodes.ACC_RECORD | Opcodes.ACC_MODULE)) != 0) {
            return false;
        }
        return !hasMixinAnnotation(node);
    }

    /** True when the class has at least two sortable members, i.e. a structure bit fits. */
    public static boolean canEncodeStructure(ClassNode node, String internalName) {
        if (!isEligible(internalName, node)) {
            return false;
        }
        return eligibleFields(node).size() >= 2 || eligibleMethods(node).size() >= 2;
    }

    /**
     * Embeds both layers into one class node.
     *
     * @param variantBits  per-slot 0/1 values, or null for no variant layer
     * @param structureBit 0 (ascending) / 1 (descending), or null for no member order
     * @param orderKey     32-byte key from {@link #deriveOrderKey(byte[], byte[])}
     * @return true when at least one layer modified the class
     */
    public static boolean embed(ClassNode node, String internalName, int[] variantBits,
                                Integer structureBit, byte[] orderKey) {
        if (node == null || !isEligible(internalName, node)) {
            return false;
        }
        String name = internalName == null ? node.name : internalName;
        boolean modified = false;
        if (variantBits != null && variantBits.length > 0) {
            if (variantBits.length > WatermarkPayload.MAX_VARIANT_BITS) {
                throw new IllegalArgumentException("too many variant bits: " + variantBits.length);
            }
            for (int bit : variantBits) {
                if (bit != 0 && bit != 1) {
                    throw new IllegalArgumentException("variant bit must be 0/1: " + bit);
                }
            }
            if (!hasCarrierCollision(node, variantBits.length)) {
                if (node.methods == null) {
                    node.methods = new ArrayList<>();
                }
                for (int slot = 0; slot < variantBits.length; slot++) {
                    node.methods.add(newCarrierMethod(slot, variantBits[slot]));
                }
                modified = true;
            }
        }
        if (structureBit != null) {
            if (structureBit != 0 && structureBit != 1) {
                throw new IllegalArgumentException("structure bit must be 0/1: " + structureBit);
            }
            if (orderKey == null || orderKey.length != 32) {
                throw new IllegalArgumentException("a 32-byte orderKey is required for structure bits");
            }
            modified |= sortMembers(node, name, structureBit, orderKey);
        }
        return modified;
    }

    /** Reads every complete variant slot; missing or ambiguous slots stay {@code -1}. */
    public static int[] readVariantBits(ClassNode node, int expectedBits) {
        int[] bits = new int[Math.max(expectedBits, 0)];
        Arrays.fill(bits, -1);
        if (node == null || node.methods == null || expectedBits <= 0) {
            return bits;
        }
        boolean[] seen = new boolean[bits.length];
        boolean[] conflict = new boolean[bits.length];
        for (MethodNode method : node.methods) {
            if (method == null || method.name == null
                    || !method.name.startsWith(VARIANT_METHOD_PREFIX)
                    || !"()I".equals(method.desc)) {
                continue;
            }
            int slot;
            try {
                slot = Integer.parseInt(method.name.substring(VARIANT_METHOD_PREFIX.length()));
            } catch (NumberFormatException ex) {
                continue;
            }
            if (slot < 0 || slot >= bits.length) {
                continue;
            }
            int bit = classifyCarrierBody(method);
            if (bit < 0) {
                continue;
            }
            if (seen[slot] && bits[slot] != bit) {
                conflict[slot] = true;
            }
            seen[slot] = true;
            bits[slot] = bit;
        }
        for (int i = 0; i < bits.length; i++) {
            if (conflict[i]) {
                bits[i] = -1;
            }
        }
        return bits;
    }

    /**
     * Reads the member-order bit, or {@code null} when the class has fewer than two sortable
     * members or its order is not a strict ascending/descending key sequence.
     */
    public static Integer readStructureBit(ClassNode node, String internalName, byte[] orderKey) {
        if (node == null || orderKey == null || orderKey.length != 32
                || !isEligible(internalName, node)) {
            return null;
        }
        String name = internalName == null ? node.name : internalName;
        Integer fields = detectOrder(eligibleFieldKeys(node, name, orderKey));
        Integer methods = detectOrder(eligibleMethodKeys(node, name, orderKey));
        if (fields != null && methods != null) {
            return fields.equals(methods) ? fields : null;
        }
        return fields != null ? fields : methods;
    }

    /** Number of structurally complete carrier methods in a class (tests/introspection). */
    public static int carrierMethodCount(ClassNode node) {
        if (node == null || node.methods == null) {
            return 0;
        }
        int count = 0;
        for (MethodNode method : node.methods) {
            if (method != null && method.name != null
                    && method.name.startsWith(VARIANT_METHOD_PREFIX)
                    && "()I".equals(method.desc)
                    && classifyCarrierBody(method) >= 0) {
                count++;
            }
        }
        return count;
    }

    private static MethodNode newCarrierMethod(int slot, int bit) {
        MethodNode method = new MethodNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                VARIANT_METHOD_PREFIX + slot, "()I", null, null);
        InsnList instructions = new InsnList();
        if (bit == 0) {
            instructions.add(new InsnNode(Opcodes.ICONST_0));
        } else {
            instructions.add(new InsnNode(Opcodes.ICONST_1));
            instructions.add(new InsnNode(Opcodes.ICONST_1));
            instructions.add(new InsnNode(Opcodes.IXOR));
        }
        instructions.add(new InsnNode(Opcodes.IRETURN));
        method.instructions = instructions;
        method.maxStack = 2;
        method.maxLocals = 0;
        return method;
    }

    private static int classifyCarrierBody(MethodNode method) {
        if (method.instructions == null) {
            return -1;
        }
        int[] opcodes = new int[method.instructions.size()];
        int count = 0;
        for (AbstractInsnNode instruction : method.instructions) {
            int opcode = instruction.getOpcode();
            if (opcode >= 0) {
                if (count >= opcodes.length) {
                    return -1;
                }
                opcodes[count++] = opcode;
            }
        }
        if (count == 2 && opcodes[0] == Opcodes.ICONST_0 && opcodes[1] == Opcodes.IRETURN) {
            return 0;
        }
        if (count == 4 && opcodes[0] == Opcodes.ICONST_1 && opcodes[1] == Opcodes.ICONST_1
                && opcodes[2] == Opcodes.IXOR && opcodes[3] == Opcodes.IRETURN) {
            return 1;
        }
        return -1;
    }

    private static boolean hasCarrierCollision(ClassNode node, int slots) {
        if (node.methods == null) {
            return false;
        }
        for (MethodNode method : node.methods) {
            if (method == null || method.name == null || !method.name.startsWith(VARIANT_METHOD_PREFIX)) {
                continue;
            }
            try {
                int slot = Integer.parseInt(method.name.substring(VARIANT_METHOD_PREFIX.length()));
                if (slot >= 0 && slot < slots) {
                    return true;
                }
            } catch (NumberFormatException ignored) {
                // A non-numeric user method with our prefix is not a collision.
            }
        }
        return false;
    }

    private static boolean sortMembers(ClassNode node, String className, int bit, byte[] orderKey) {
        boolean moved = false;
        List<FieldNode> fields = eligibleFields(node);
        if (fields.size() >= 2) {
            List<KeyedField> keyed = new ArrayList<>(fields.size());
            for (FieldNode field : fields) {
                keyed.add(new KeyedField(field,
                        memberKey(orderKey, className, "F", field.name, field.desc)));
            }
            keyed.sort(Comparator.comparing(item -> item.key, WatermarkCarrier::compareUnsigned));
            if (bit == 1) {
                Collections.reverse(keyed);
            }
            List<Integer> slots = fieldSlots(node);
            for (int i = 0; i < slots.size(); i++) {
                FieldNode replacement = keyed.get(i).node;
                if (node.fields.get(slots.get(i)) != replacement) {
                    moved = true;
                }
                node.fields.set(slots.get(i), replacement);
            }
        }
        List<MethodNode> methods = eligibleMethods(node);
        if (methods.size() >= 2) {
            List<KeyedMethod> keyed = new ArrayList<>(methods.size());
            for (MethodNode method : methods) {
                keyed.add(new KeyedMethod(method,
                        memberKey(orderKey, className, "M", method.name, method.desc)));
            }
            keyed.sort(Comparator.comparing(item -> item.key, WatermarkCarrier::compareUnsigned));
            if (bit == 1) {
                Collections.reverse(keyed);
            }
            List<Integer> slots = methodSlots(node);
            for (int i = 0; i < slots.size(); i++) {
                MethodNode replacement = keyed.get(i).node;
                if (node.methods.get(slots.get(i)) != replacement) {
                    moved = true;
                }
                node.methods.set(slots.get(i), replacement);
            }
        }
        return moved;
    }

    private static List<Integer> fieldSlots(ClassNode node) {
        List<Integer> slots = new ArrayList<>();
        if (node.fields == null) {
            return slots;
        }
        for (int i = 0; i < node.fields.size(); i++) {
            if (isEligibleField(node.fields.get(i))) {
                slots.add(i);
            }
        }
        return slots;
    }

    private static List<Integer> methodSlots(ClassNode node) {
        List<Integer> slots = new ArrayList<>();
        if (node.methods == null) {
            return slots;
        }
        for (int i = 0; i < node.methods.size(); i++) {
            if (isEligibleMethod(node.methods.get(i))) {
                slots.add(i);
            }
        }
        return slots;
    }

    private static List<FieldNode> eligibleFields(ClassNode node) {
        List<FieldNode> result = new ArrayList<>();
        if (node == null || node.fields == null) {
            return result;
        }
        for (FieldNode field : node.fields) {
            if (isEligibleField(field)) {
                result.add(field);
            }
        }
        return result;
    }

    private static List<MethodNode> eligibleMethods(ClassNode node) {
        List<MethodNode> result = new ArrayList<>();
        if (node == null || node.methods == null) {
            return result;
        }
        for (MethodNode method : node.methods) {
            if (isEligibleMethod(method)) {
                result.add(method);
            }
        }
        return result;
    }

    private static boolean isEligibleField(FieldNode field) {
        if (field == null || field.name == null
                || (field.access & Opcodes.ACC_SYNTHETIC) != 0) {
            return false;
        }
        return !field.name.startsWith("$chimera$") && !field.name.startsWith("chimera$");
    }

    private static boolean isEligibleMethod(MethodNode method) {
        if (method == null || method.name == null) {
            return false;
        }
        if ("<init>".equals(method.name) || "<clinit>".equals(method.name)) {
            return false;
        }
        if ((method.access & (Opcodes.ACC_SYNTHETIC | Opcodes.ACC_BRIDGE)) != 0) {
            return false;
        }
        if (method.name.startsWith("$chimera$") || method.name.startsWith("chimera$")) {
            return false;
        }
        return !method.name.startsWith("lambda$");
    }

    private static List<byte[]> eligibleFieldKeys(ClassNode node, String className, byte[] orderKey) {
        List<byte[]> keys = new ArrayList<>();
        for (FieldNode field : eligibleFields(node)) {
            keys.add(memberKey(orderKey, className, "F", field.name, field.desc));
        }
        return keys;
    }

    private static List<byte[]> eligibleMethodKeys(ClassNode node, String className, byte[] orderKey) {
        List<byte[]> keys = new ArrayList<>();
        for (MethodNode method : eligibleMethods(node)) {
            keys.add(memberKey(orderKey, className, "M", method.name, method.desc));
        }
        return keys;
    }

    private static Integer detectOrder(List<byte[]> keys) {
        if (keys == null || keys.size() < 2) {
            return null;
        }
        boolean ascending = true;
        boolean descending = true;
        for (int i = 1; i < keys.size(); i++) {
            int cmp = compareUnsigned(keys.get(i - 1), keys.get(i));
            if (cmp >= 0) {
                ascending = false;
            }
            if (cmp <= 0) {
                descending = false;
            }
        }
        if (ascending && !descending) {
            return 0;
        }
        if (descending && !ascending) {
            return 1;
        }
        return null;
    }

    private static byte[] memberKey(byte[] orderKey, String className, String kind,
                                    String name, String descriptor) {
        String material = className + '\0' + kind + '\0' + name + '\0'
                + (descriptor == null ? "" : descriptor);
        return Crypto.hmacSha256(orderKey, material.getBytes(StandardCharsets.UTF_8));
    }

    private static int compareUnsigned(byte[] a, byte[] b) {
        int length = Math.min(a.length, b.length);
        for (int i = 0; i < length; i++) {
            int left = a[i] & 0xff;
            int right = b[i] & 0xff;
            if (left != right) {
                return left - right;
            }
        }
        return a.length - b.length;
    }

    static boolean hasMixinAnnotation(ClassNode node) {
        return hasAnnotation(node == null ? null : node.visibleAnnotations)
                || hasAnnotation(node == null ? null : node.invisibleAnnotations);
    }

    private static boolean hasAnnotation(List<AnnotationNode> annotations) {
        if (annotations == null) {
            return false;
        }
        for (AnnotationNode annotation : annotations) {
            if (annotation == null || annotation.desc == null) {
                continue;
            }
            for (String prefix : MIXIN_ANNOTATION_PREFIXES) {
                if (annotation.desc.startsWith(prefix)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static final class KeyedField {
        final FieldNode node;
        final byte[] key;

        KeyedField(FieldNode node, byte[] key) {
            this.node = node;
            this.key = key;
        }
    }

    private static final class KeyedMethod {
        final MethodNode node;
        final byte[] key;

        KeyedMethod(MethodNode node, byte[] key) {
            this.node = node;
            this.key = key;
        }
    }
}
