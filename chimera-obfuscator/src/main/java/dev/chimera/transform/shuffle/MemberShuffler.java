package dev.chimera.transform.shuffle;

import dev.chimera.core.TransformContext;
import dev.chimera.core.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

/**
 * A10: shuffles the declaration order of fields and methods so tools that rely on member order
 * (diffing, signature matching, manual navigation) lose another stable signal.
 *
 * <p>Safety rules: Mixin classes, interfaces, enums, records and annotation types are skipped
 * entirely. Constructors and class initializers keep their relative positions: only the other
 * members are shuffled into the remaining slots, so initialization semantics never change. The
 * permutation is derived from a per-class seed, which keeps builds reproducible.</p>
 */
public final class MemberShuffler implements Transformer {

    private static final String MIXIN_PREFIX = "Lorg/spongepowered/asm/mixin/";
    private static final String MIXIN_EXTRAS_PREFIX = "Lcom/llamalad7/mixinextras/";

    private final boolean shuffleFields;
    private final boolean shuffleMethods;

    private int classesShuffled;
    private int fieldsMoved;
    private int methodsMoved;
    private int classesSkipped;

    public MemberShuffler(boolean shuffleFields, boolean shuffleMethods) {
        this.shuffleFields = shuffleFields;
        this.shuffleMethods = shuffleMethods;
    }

    public int classesShuffled() {
        return classesShuffled;
    }

    public int fieldsMoved() {
        return fieldsMoved;
    }

    public int methodsMoved() {
        return methodsMoved;
    }

    public int classesSkipped() {
        return classesSkipped;
    }

    @Override
    public void transform(String internalName, ClassNode node, TransformContext ctx) {
        if (isSkipped(internalName, node)) {
            classesSkipped++;
            return;
        }
        Random random = new Random(seed(internalName));
        if (shuffleFields && node.fields != null) {
            List<FieldNode> order = new ArrayList<>(node.fields);
            List<Integer> slots = new ArrayList<>();
            for (int i = 0; i < order.size(); i++) {
                FieldNode field = order.get(i);
                if (!mustStayInPlace(field.access, field.name)) {
                    slots.add(i);
                }
            }
            List<FieldNode> movable = new ArrayList<>();
            for (int slot : slots) {
                movable.add(order.get(slot));
            }
            Collections.shuffle(movable, random);
            for (int i = 0; i < slots.size(); i++) {
                FieldNode previous = order.get(slots.get(i));
                FieldNode replacement = movable.get(i);
                if (previous != replacement) {
                    fieldsMoved++;
                }
                order.set(slots.get(i), replacement);
            }
            node.fields = order;
        }
        if (shuffleMethods && node.methods != null) {
            List<MethodNode> order = new ArrayList<>(node.methods);
            List<Integer> slots = new ArrayList<>();
            for (int i = 0; i < order.size(); i++) {
                MethodNode method = order.get(i);
                if (!mustStayInPlace(method.access, method.name)) {
                    slots.add(i);
                }
            }
            List<MethodNode> movable = new ArrayList<>();
            for (int slot : slots) {
                movable.add(order.get(slot));
            }
            Collections.shuffle(movable, random);
            for (int i = 0; i < slots.size(); i++) {
                MethodNode previous = order.get(slots.get(i));
                MethodNode replacement = movable.get(i);
                if (previous != replacement) {
                    methodsMoved++;
                }
                order.set(slots.get(i), replacement);
            }
            node.methods = order;
        }
        classesShuffled++;
    }

    private static boolean mustStayInPlace(int access, String name) {
        if ("<init>".equals(name) || "<clinit>".equals(name)) {
            return true;
        }
        // Synthetic/bridge members are referenced by exact position in some frameworks and in
        // lambda/record bootstraps; leave them untouched.
        return (access & (Opcodes.ACC_SYNTHETIC | Opcodes.ACC_BRIDGE)) != 0;
    }

    private static boolean isSkipped(String internalName, ClassNode node) {
        if (internalName == null || internalName.startsWith("dev/chimera/")
                || internalName.contains("$chimera$")) {
            return true;
        }
        int access = node.access;
        if ((access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ENUM | Opcodes.ACC_ANNOTATION
                | Opcodes.ACC_RECORD)) != 0) {
            return true;
        }
        return hasAnnotation(node.visibleAnnotations, MIXIN_PREFIX)
                || hasAnnotation(node.invisibleAnnotations, MIXIN_PREFIX)
                || hasAnnotation(node.visibleAnnotations, MIXIN_EXTRAS_PREFIX)
                || hasAnnotation(node.invisibleAnnotations, MIXIN_EXTRAS_PREFIX);
    }

    private static boolean hasAnnotation(List<AnnotationNode> annotations, String prefix) {
        if (annotations == null) {
            return false;
        }
        for (AnnotationNode annotation : annotations) {
            if (annotation.desc != null && annotation.desc.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private static long seed(String internalName) {
        long hash = 0xcbf29ce484222325L;
        for (int i = 0; i < internalName.length(); i++) {
            hash ^= internalName.charAt(i);
            hash *= 0x100000001b3L;
        }
        return hash;
    }
}
