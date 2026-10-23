package dev.chimera.transform.cfg;

import dev.chimera.transform.indy.IndyDispatchTransformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.List;

/** Shared eligibility rules for the S6 control-flow transforms. */
final class CfgSupport {

    static final int DEFAULT_MAX_INSTRUCTIONS = 2000;
    private static final String CHIMERA_ANNOTATION_PREFIX = "Ldev/chimera/annotations/";
    private static final String MIXIN_ANNOTATION_PREFIX = "Lorg/spongepowered/asm/mixin";
    private static final String MIXIN_EXTRAS_PREFIX = "Lcom/llamalad7/mixinextras/";

    enum Skip {
        CONSTRUCTOR,
        CLASS_INIT,
        ABSTRACT_NATIVE,
        TRY_CATCH,
        MONITOR,
        JSR_RET,
        ANNOTATED,
        TOO_LARGE,
        EMPTY
    }

    private CfgSupport() {
    }

    /**
     * Mixin classes are skipped as a whole: Mixin merges/rewrites bodies at runtime and is very
     * sensitive to Signature/debug attributes, which this transform never touches for them.
     */
    static boolean isMixinClass(ClassNode node) {
        return IndyDispatchTransformer.isMixinClass(node);
    }

    static Skip skipReason(MethodNode method, int maxInstructions) {
        if ("<init>".equals(method.name)) return Skip.CONSTRUCTOR;
        if ("<clinit>".equals(method.name)) return Skip.CLASS_INIT;
        if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) {
            return Skip.ABSTRACT_NATIVE;
        }
        if (method.instructions == null || method.instructions.size() == 0) return Skip.EMPTY;
        if (method.tryCatchBlocks != null && !method.tryCatchBlocks.isEmpty()) return Skip.TRY_CATCH;
        if (hasChimeraAnnotation(method.visibleAnnotations) || hasChimeraAnnotation(method.invisibleAnnotations)
                || hasMixinMemberAnnotation(method.visibleAnnotations)
                || hasMixinMemberAnnotation(method.invisibleAnnotations)) {
            return Skip.ANNOTATED;
        }
        int count = 0;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            int opcode = insn.getOpcode();
            if (opcode == Opcodes.MONITORENTER || opcode == Opcodes.MONITOREXIT) return Skip.MONITOR;
            if (opcode == Opcodes.JSR || opcode == Opcodes.RET) return Skip.JSR_RET;
            if (++count > maxInstructions) return Skip.TOO_LARGE;
        }
        return null;
    }

    static void count(CfgStats stats, Skip reason) {
        switch (reason) {
            case CONSTRUCTOR -> stats.skippedConstructor++;
            case CLASS_INIT -> stats.skippedClassInit++;
            case TRY_CATCH -> stats.skippedTryCatch++;
            case ANNOTATED -> stats.skippedAnnotated++;
            case TOO_LARGE -> stats.skippedTooLarge++;
            default -> stats.skippedUnsupported++;
        }
    }

    private static boolean hasChimeraAnnotation(List<AnnotationNode> annotations) {
        if (annotations == null) return false;
        for (AnnotationNode annotation : annotations) {
            if (annotation.desc != null && annotation.desc.startsWith(CHIMERA_ANNOTATION_PREFIX)) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasMixinMemberAnnotation(List<AnnotationNode> annotations) {
        if (annotations == null) return false;
        for (AnnotationNode annotation : annotations) {
            String desc = annotation.desc;
            if (desc != null && (desc.startsWith(MIXIN_ANNOTATION_PREFIX)
                    || desc.startsWith(MIXIN_EXTRAS_PREFIX))) {
                return true;
            }
        }
        return false;
    }
}
