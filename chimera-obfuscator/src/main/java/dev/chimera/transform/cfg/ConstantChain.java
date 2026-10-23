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
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.ArrayList;
import java.util.List;

/**
 * S6: splits int/long constants into equivalent arithmetic chains ({@code value == a ^ mask}).
 *
 * <p>Only integer and long constants are rewritten: floating point/string/type constants keep
 * their exact representation. Methods containing try-catch, monitors or JSR/RET are skipped
 * conservatively; Mixin classes are skipped untouched.</p>
 */
public final class ConstantChain implements Transformer {

    private static final int INT_MASK = 0x5A5A5A5A;
    private static final long LONG_MASK = 0x5A5A5A5A5A5A5A5AL;

    private final boolean enabled;
    private final int maxInstructions;
    private final CfgStats stats = new CfgStats();

    public ConstantChain(boolean enabled) {
        this(enabled, CfgSupport.DEFAULT_MAX_INSTRUCTIONS);
    }

    public ConstantChain(boolean enabled, int maxInstructions) {
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
            if (rewriteConstants(method)) {
                removeFrames(method);
            }
        }
    }

    private boolean rewriteConstants(MethodNode method) {
        List<AbstractInsnNode> constants = new ArrayList<>();
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (constantValue(insn) != null) constants.add(insn);
        }
        for (AbstractInsnNode insn : constants) {
            Object value = constantValue(insn);
            if (value instanceof Integer integer) {
                int original = integer;
                InsnList chain = new InsnList();
                chain.add(pushInt(original ^ INT_MASK));
                chain.add(pushInt(INT_MASK));
                chain.add(new InsnNode(Opcodes.IXOR));
                method.instructions.insertBefore(insn, chain);
                method.instructions.remove(insn);
                stats.constantChains++;
            } else if (value instanceof Long longValue) {
                long original = longValue;
                InsnList chain = new InsnList();
                chain.add(pushLong(original ^ LONG_MASK));
                chain.add(pushLong(LONG_MASK));
                chain.add(new InsnNode(Opcodes.LXOR));
                method.instructions.insertBefore(insn, chain);
                method.instructions.remove(insn);
                stats.constantChains++;
            }
        }
        return !constants.isEmpty();
    }

    private static Object constantValue(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        if (opcode >= Opcodes.ICONST_M1 && opcode <= Opcodes.ICONST_5) {
            return Integer.valueOf(opcode - Opcodes.ICONST_0);
        }
        if (opcode == Opcodes.LCONST_0 || opcode == Opcodes.LCONST_1) {
            return Long.valueOf(opcode - Opcodes.LCONST_0);
        }
        if (insn instanceof IntInsnNode intInsn
                && (opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH)) {
            return Integer.valueOf(intInsn.operand);
        }
        if (insn instanceof LdcInsnNode ldc) {
            if (ldc.cst instanceof Integer) return ldc.cst;
            if (ldc.cst instanceof Long) return ldc.cst;
        }
        return null;
    }

    private static AbstractInsnNode pushInt(int value) {
        if (value >= -1 && value <= 5) {
            return new InsnNode(Opcodes.ICONST_0 + value);
        }
        return new LdcInsnNode(Integer.valueOf(value));
    }

    private static AbstractInsnNode pushLong(long value) {
        if (value == 0L || value == 1L) {
            return new InsnNode(Opcodes.LCONST_0 + (int) value);
        }
        return new LdcInsnNode(Long.valueOf(value));
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
