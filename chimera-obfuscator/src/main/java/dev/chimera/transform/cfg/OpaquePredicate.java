package dev.chimera.transform.cfg;

import dev.chimera.core.TransformContext;
import dev.chimera.core.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FrameNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.MethodNode;

/**
 * S6: injects opaque predicates at method entry.
 *
 * <p>Two branches are added: an always-true predicate guarding a dead {@code athrow} block, and
 * an always-false predicate guarding a dead continuation block. The live path is exactly the
 * original method body, so behaviour is preserved. Mixin/constructor/class-initializer/try-catch
 * methods are skipped untouched.</p>
 */
public final class OpaquePredicate implements Transformer {

    private final boolean enabled;
    private final int maxInstructions;
    private final CfgStats stats = new CfgStats();

    public OpaquePredicate(boolean enabled) {
        this(enabled, CfgSupport.DEFAULT_MAX_INSTRUCTIONS);
    }

    public OpaquePredicate(boolean enabled, int maxInstructions) {
        this.enabled = enabled;
        this.maxInstructions = Math.max(1, maxInstructions);
    }

    public CfgStats stats() {
        return stats;
    }

    @Override
    public void transform(String internalName, ClassNode node, TransformContext ctx) {
        if (!enabled || node == null || node.methods == null) return;
        stats.classesVisited++;
        if (CfgSupport.isMixinClass(node)) {
            stats.classesSkippedMixin++;
            return;
        }
        if ((node.access & Opcodes.ACC_INTERFACE) != 0) {
            stats.classesSkippedInterface++;
            return;
        }
        for (MethodNode method : node.methods) {
            stats.methodsVisited++;
            CfgSupport.Skip skip = CfgSupport.skipReason(method, maxInstructions);
            if (skip != null) {
                CfgSupport.count(stats, skip);
                continue;
            }
            inject(method);
        }
    }

    private void inject(MethodNode method) {
        LabelNode live = new LabelNode();
        LabelNode deadAlwaysTrue = new LabelNode();
        LabelNode deadAlwaysFalse = new LabelNode();
        LabelNode afterFalse = new LabelNode();

        InsnList prologue = new InsnList();
        // Always-true: (7 * 7) & 1 == 1. The unreachable throw block keeps the branch real.
        prologue.add(new IntInsnNode(Opcodes.BIPUSH, 7));
        prologue.add(new IntInsnNode(Opcodes.BIPUSH, 7));
        prologue.add(new InsnNode(Opcodes.IMUL));
        prologue.add(new InsnNode(Opcodes.ICONST_1));
        prologue.add(new InsnNode(Opcodes.IAND));
        prologue.add(new InsnNode(Opcodes.ICONST_1));
        prologue.add(new JumpInsnNode(Opcodes.IF_ICMPEQ, live));
        prologue.add(deadAlwaysTrue);
        prologue.add(new InsnNode(Opcodes.ACONST_NULL));
        prologue.add(new InsnNode(Opcodes.ATHROW));
        prologue.add(live);
        // Always-false: (4 & 2) != 0 is false; the branch target is dead, the live path skips it.
        prologue.add(new InsnNode(Opcodes.ICONST_4));
        prologue.add(new InsnNode(Opcodes.ICONST_2));
        prologue.add(new InsnNode(Opcodes.IAND));
        prologue.add(new JumpInsnNode(Opcodes.IFNE, deadAlwaysFalse));
        prologue.add(new JumpInsnNode(Opcodes.GOTO, afterFalse));
        prologue.add(deadAlwaysFalse);
        prologue.add(new InsnNode(Opcodes.NOP));
        prologue.add(afterFalse);

        removeFrames(method);
        method.instructions.insert(prologue);
        stats.methodsPredicated++;
        stats.opaqueBranches += 2;
    }

    private static void removeFrames(MethodNode method) {
        AbstractInsnNode insn = method.instructions.getFirst();
        while (insn != null) {
            AbstractInsnNode next = insn.getNext();
            if (insn instanceof FrameNode) method.instructions.remove(insn);
            insn = next;
        }
    }
}
