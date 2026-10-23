package dev.chimera.transform.debug;

import dev.chimera.core.TransformContext;
import dev.chimera.core.Transformer;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.List;

/**
 * A9: removes debug metadata (SourceFile, LineNumberTable, LocalVariableTable, MethodParameters,
 * local-variable annotations) so decompiled output loses line numbers and local names.
 *
 * <p>Fabric red line: Mixin classes keep every attribute byte for byte, because Mixin resolves
 * {@code @Shadow}/{@code @Inject} targets by name and its transformers are debug-sensitive.
 * Runtime/hidden-fragment classes and {@code dev/chimera/**} are skipped for the same reason.</p>
 */
public final class DebugInformationRemover implements Transformer {

    private static final String MIXIN_PREFIX = "Lorg/spongepowered/asm/mixin/";
    private static final String MIXIN_EXTRAS_PREFIX = "Lcom/llamalad7/mixinextras/";

    private final boolean stripSignatures;
    private int classesStripped;
    private int lineNumbersRemoved;
    private int localVariablesRemoved;
    private int classesSkipped;

    public DebugInformationRemover(boolean stripSignatures) {
        this.stripSignatures = stripSignatures;
    }

    public int classesStripped() {
        return classesStripped;
    }

    public int lineNumbersRemoved() {
        return lineNumbersRemoved;
    }

    public int localVariablesRemoved() {
        return localVariablesRemoved;
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
        // Keep a constant non-null SourceFile: Minecraft's stack-trace walker dereferences
        // StackTraceElement.getFileName() and would NPE on null, while the real file name is
        // exactly what we want to hide.
        node.sourceFile = "x";
        node.sourceDebug = null;
        for (FieldNode field : node.fields) {
            if (stripSignatures) {
                field.signature = null;
            }
        }
        for (MethodNode method : node.methods) {
            if (method.localVariables != null) {
                localVariablesRemoved += method.localVariables.size();
                method.localVariables = null;
            }
            method.visibleLocalVariableAnnotations = null;
            method.invisibleLocalVariableAnnotations = null;
            method.parameters = null;
            if (stripSignatures) {
                method.signature = null;
            }
            if (method.instructions == null) {
                continue;
            }
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; ) {
                AbstractInsnNode next = insn.getNext();
                if (insn instanceof LineNumberNode) {
                    method.instructions.remove(insn);
                    lineNumbersRemoved++;
                }
                insn = next;
            }
        }
        if (stripSignatures) {
            node.signature = null;
        }
        classesStripped++;
    }

    private static boolean isSkipped(String internalName, ClassNode node) {
        if (internalName == null || internalName.startsWith("dev/chimera/")
                || internalName.contains("$chimera$") || internalName.startsWith("META-INF/")) {
            return true;
        }
        if (isMixin(node)) {
            return true;
        }
        return false;
    }

    private static boolean isMixin(ClassNode node) {
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
}
