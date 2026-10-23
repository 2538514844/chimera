package dev.chimera.transform.cfg;

import dev.chimera.core.ClassPool;
import dev.chimera.core.TransformContext;
import dev.chimera.core.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FrameNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.AnalyzerException;
import org.objectweb.asm.tree.analysis.BasicInterpreter;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.objectweb.asm.tree.analysis.Frame;

import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * S6: control-flow flattening.
 *
 * <p>The original method body is split into basic blocks. Every block gets a state id, ends with
 * a state assignment and a jump to a single {@code TABLESWITCH} dispatcher; the entry block jumps
 * to the dispatcher first. Original branches/switches are replaced by small state-selection
 * trampolines, so behaviour is preserved for straight-line code, branches, loops and explicit
 * throws.</p>
 *
 * <p>Conservative red lines: Mixin classes, constructors, class initializers, any method with a
 * try-catch block, monitors, JSR/RET, Chimera-annotated methods and very large/small methods are
 * skipped and counted. Frame computation is left to the caller's {@code COMPUTE_FRAMES} writer
 * with the injected {@code ClassPool}; existing FrameNodes are removed.</p>
 */
public final class ControlFlowFlattening implements Transformer {

    public static final int DEFAULT_MIN_BLOCKS = 3;
    public static final int DEFAULT_MAX_BLOCKS = 512;
    public static final int DEFAULT_MAX_INSTRUCTIONS = 2000;

    private final boolean enabled;
    private final int minBlocks;
    private final int maxBlocks;
    private final int maxInstructions;
    private final CfgStats stats = new CfgStats();

    public ControlFlowFlattening(boolean enabled) {
        this(enabled, DEFAULT_MIN_BLOCKS, DEFAULT_MAX_BLOCKS, DEFAULT_MAX_INSTRUCTIONS);
    }

    public ControlFlowFlattening(boolean enabled, int minBlocks, int maxBlocks, int maxInstructions) {
        this.enabled = enabled;
        this.minBlocks = Math.max(2, minBlocks);
        this.maxBlocks = Math.max(this.minBlocks, maxBlocks);
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
            // Mixin merges at runtime and is sensitive to Signature/debug info: never touch it.
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
            if (flatten(internalName, method, ctx.pool)) {
                stats.methodsFlattened++;
            } else {
                // flatten() only fails for conservative safety reasons (stack merge, conflicting
                // local types, Object reference locals, block bounds); report them as unsupported
                // so the skip statistics stay meaningful.
                stats.skippedUnsupported++;
            }
        }
    }

    // ------------------------------------------------------------------ flattening

    private boolean flatten(String owner, MethodNode method, ClassPool pool) {
        int stateSlot = method.maxLocals;
        LabelNode dispatch = new LabelNode();

        // Basic-block stack discipline: a dispatcher needs an empty operand stack at every block
        // entry. Javac often shares a single return block and leaves the return value on the stack;
        // such methods are conservatively skipped instead of being miscompiled.
        java.util.IdentityHashMap<AbstractInsnNode, Integer> instructionIndex = new java.util.IdentityHashMap<>();
        int index = 0;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            instructionIndex.put(insn, index++);
        }
        Frame<BasicValue>[] frames;
        try {
            frames = new Analyzer<>(new PoolInterpreter(pool)).analyze(owner, method);
        } catch (AnalyzerException | RuntimeException ignored) {
            if (Boolean.getBoolean("chimera.cfg.debug")) ignored.printStackTrace();
            debug(method, "analyzer: " + ignored);
            return false;
        }
        // The dispatcher is a merge point for every state. Primitive locals that are uninitialized
        // on the entry path but initialized on a loop-back path would merge to TOP, so each
        // non-argument primitive slot with a stable type is initialized to zero before entering
        // it. Reference locals are handled separately: Object-typed slots (the real-world MC-type
        // degradation source) skip the method; exact non-Object slots merge safely with null.
        int firstFree = 0;
        if ((method.access & Opcodes.ACC_STATIC) == 0) firstFree = 1;
        for (Type argument : Type.getArgumentTypes(method.desc)) firstFree += argument.getSize();
        Type[] localTypes = new Type[method.maxLocals];
        for (Frame<BasicValue> frame : frames) {
            if (frame == null) continue;
            for (int slot = 0; slot < method.maxLocals; slot++) {
                BasicValue value = frame.getLocal(slot);
                if (value == null) continue;
                Type type = value.getType();
                if (type == null || type.getSort() == Type.VOID) continue;
                Type previous = localTypes[slot];
                if (previous == null) {
                    localTypes[slot] = type;
                } else if (!previous.equals(type)) {
                    // The dispatcher merges every state: a slot with different precise types on
                    // different paths would degrade to a common super type (often Object) and
                    // break real subtype uses. Skip such methods instead of emitting wrong frames.
                    debug(method, "slot " + slot + " type conflict " + previous + " vs " + type);
                    return false;
                }
            }
        }

        List<AbstractInsnNode> body = new ArrayList<>();
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (!(insn instanceof FrameNode)) body.add(insn);
        }
        if (body.isEmpty()) return false;

        Set<LabelNode> targets = Collections.newSetFromMap(new IdentityHashMap<>());
        for (AbstractInsnNode insn : body) {
            collectTargets(insn, targets);
        }

        List<Block> blocks = new ArrayList<>();
        Block current = null;
        AbstractInsnNode previous = null;
        for (AbstractInsnNode insn : body) {
            // Metadata (line numbers, non-target local-variable end labels) after a terminal
            // instruction stays with the previous block; only executable instructions or real
            // jump-target labels start a new block.
            boolean startsBlock = current == null
                    || (insn instanceof LabelNode label && targets.contains(label))
                    || (previous != null && endsBlock(previous) && insn.getOpcode() >= 0);
            if (startsBlock) {
                current = new Block(blocks.size());
                blocks.add(current);
            }
            current.instructions.add(insn);
            previous = insn;
        }
        if (blocks.size() < minBlocks) {
            debug(method, "blocks " + blocks.size());
            stats.skippedSmall++;
            return false;
        }
        if (blocks.size() > maxBlocks) {
            debug(method, "blocks " + blocks.size());
            stats.skippedTooLarge++;
            return false;
        }

        Map<LabelNode, Integer> labelToBlock = new IdentityHashMap<>();
        for (Block block : blocks) {
            for (AbstractInsnNode insn : block.instructions) {
                if (insn instanceof LabelNode label) labelToBlock.put(label, block.index);
            }
        }
        for (LabelNode target : targets) {
            if (!labelToBlock.containsKey(target)) {
                debug(method, "missing target");
                return false;
            }
        }
        for (Block block : blocks) {
            AbstractInsnNode first = firstExecutable(block.instructions);
            if (first == null) return false;
            Integer frameIndex = instructionIndex.get(first);
            if (frameIndex == null || frameIndex >= frames.length || frames[frameIndex] == null) {
                debug(method, "no frame for block " + block.index);
                return false;
            }
            if (frames[frameIndex].getStackSize() != 0) {
                debug(method, "stack at block " + block.index + " = " + frames[frameIndex].getStackSize());
                return false;
            }
        }
        for (int i = 0; i < blocks.size(); i++) {
            Block block = blocks.get(i);
            int executable = lastExecutable(block.instructions);
            if (executable < 0) {
                debug(method, "no executable in block");
                return false;
            }
            AbstractInsnNode last = block.instructions.get(executable);
            if (!endsBlock(last) && i + 1 >= blocks.size()) {
                debug(method, "last block not terminal");
                return false;
            }
            // A conditional branch in the last block has no fall-through target.
            if (i + 1 >= blocks.size() && last instanceof JumpInsnNode jump
                    && jump.getOpcode() != Opcodes.GOTO) {
                debug(method, "last conditional");
                return false;
            }
        }

        for (int slot = firstFree; slot < method.maxLocals; slot++) {
            Type type = localTypes[slot];
            if (type != null && type.getSort() == Type.OBJECT
                    && "java/lang/Object".equals(type.getInternalName())) {
                // Object-typed locals are where real-world MC types degrade (the same slot is
                // reused for different class_2338/class_1297 values), so skip those methods.
                // Exact non-Object references are safe: the dispatcher merges entry null with
                // the same type, and the precise-type conflict check above rejects mixed slots.
                debug(method, "Object reference local in non-arg slot " + slot + " type " + type);
                return false;
            }
        }

        InsnList output = new InsnList();
        output.add(pushInt(0));
        output.add(new VarInsnNode(Opcodes.ISTORE, stateSlot));
        for (int slot = firstFree; slot < method.maxLocals; slot++) {
            Type type = localTypes[slot];
            if (type == null) continue;
            switch (type.getSort()) {
                case Type.BOOLEAN:
                case Type.BYTE:
                case Type.CHAR:
                case Type.SHORT:
                case Type.INT:
                    output.add(new InsnNode(Opcodes.ICONST_0));
                    output.add(new VarInsnNode(Opcodes.ISTORE, slot));
                    break;
                case Type.LONG:
                    output.add(new InsnNode(Opcodes.LCONST_0));
                    output.add(new VarInsnNode(Opcodes.LSTORE, slot));
                    break;
                case Type.FLOAT:
                    output.add(new InsnNode(Opcodes.FCONST_0));
                    output.add(new VarInsnNode(Opcodes.FSTORE, slot));
                    break;
                case Type.DOUBLE:
                    output.add(new InsnNode(Opcodes.DCONST_0));
                    output.add(new VarInsnNode(Opcodes.DSTORE, slot));
                    break;
                default:
                    break;
            }
        }
        output.add(new JumpInsnNode(Opcodes.GOTO, dispatch));

        for (int i = 0; i < blocks.size(); i++) {
            Block block = blocks.get(i);
            output.add(block.label);
            int executable = lastExecutable(block.instructions);
            AbstractInsnNode last = block.instructions.get(executable);
            if (!endsBlock(last)) {
                appendAll(output, block.instructions, block.instructions.size());
                appendStateJump(output, stateSlot, i + 1, dispatch);
                continue;
            }
            appendAll(output, block.instructions, executable);
            if (last instanceof JumpInsnNode jump) {
                int targetBlock = labelToBlock.get(jump.label);
                if (jump.getOpcode() == Opcodes.GOTO) {
                    appendStateJump(output, stateSlot, targetBlock, dispatch);
                } else {
                    LabelNode trampoline = new LabelNode();
                    output.add(new JumpInsnNode(jump.getOpcode(), trampoline));
                    appendStateJump(output, stateSlot, i + 1, dispatch);
                    output.add(trampoline);
                    appendStateJump(output, stateSlot, targetBlock, dispatch);
                }
            } else if (last instanceof TableSwitchInsnNode tableSwitch) {
                appendTableSwitch(output, stateSlot, dispatch, labelToBlock, tableSwitch);
            } else if (last instanceof LookupSwitchInsnNode lookupSwitch) {
                appendLookupSwitch(output, stateSlot, dispatch, labelToBlock, lookupSwitch);
            } else {
                // return / athrow: keep the terminal instruction as-is.
                output.add(last);
            }
            // Trailing line numbers / non-target local-variable labels stay after the terminal.
            for (int j = executable + 1; j < block.instructions.size(); j++) {
                output.add(block.instructions.get(j));
            }
        }

        output.add(dispatch);
        output.add(new VarInsnNode(Opcodes.ILOAD, stateSlot));
        LabelNode[] blockLabels = new LabelNode[blocks.size()];
        for (int i = 0; i < blocks.size(); i++) blockLabels[i] = blocks.get(i).label;
        LabelNode invalidState = new LabelNode();
        output.add(new TableSwitchInsnNode(0, blocks.size() - 1, invalidState, blockLabels));
        output.add(invalidState);
        output.add(new JumpInsnNode(Opcodes.GOTO, dispatch));

        method.instructions = output;
        method.maxLocals = stateSlot + 1;
        method.maxStack = 0;
        return true;
    }

    /**
     * BasicInterpreter with reference-type merges resolved through the injected ClassPool
     * (Minecraft/Fabric library hierarchy). Plain BasicInterpreter degrades different reference
     * types to UNINITIALIZED, which hides conflicting local slots and lets the dispatcher emit a
     * wrong (e.g. Object) box for MC types such as class_2338.
     */
    private static final class PoolInterpreter extends BasicInterpreter {
        private final ClassPool pool;

        PoolInterpreter(ClassPool pool) {
            super(Opcodes.ASM9);
            this.pool = pool;
        }

        @Override
        public BasicValue merge(BasicValue first, BasicValue second) {
            if (first.equals(second)) return first;
            Type type1 = first.getType();
            Type type2 = second.getType();
            if (type1 == null) return second;
            if (type2 == null) return first;
            boolean ref1 = type1.getSort() == Type.OBJECT || type1.getSort() == Type.ARRAY;
            boolean ref2 = type2.getSort() == Type.OBJECT || type2.getSort() == Type.ARRAY;
            if (ref1 != ref2) return BasicValue.UNINITIALIZED_VALUE;
            if (!ref1) {
                return type1.equals(type2) ? first : BasicValue.UNINITIALIZED_VALUE;
            }
            String name1 = internalName(type1);
            String name2 = internalName(type2);
            if ("null".equals(name1)) return second;
            if ("null".equals(name2)) return first;
            String common = pool.commonSuperClass(name1, name2);
            if (common == null) return BasicValue.UNINITIALIZED_VALUE;
            return new BasicValue(Type.getObjectType(common));
        }

        private static String internalName(Type type) {
            return type.getSort() == Type.ARRAY ? type.getDescriptor() : type.getInternalName();
        }
    }

    private static void debug(MethodNode method, String reason) {
        if (Boolean.getBoolean("chimera.cfg.debug")) {
            System.err.println("[cfg-debug] " + method.name + method.desc + " skip: " + reason);
        }
    }

    private static AbstractInsnNode firstExecutable(List<AbstractInsnNode> instructions) {
        for (AbstractInsnNode insn : instructions) {
            if (insn.getOpcode() >= 0) return insn;
        }
        return null;
    }

    private static int lastExecutable(List<AbstractInsnNode> instructions) {
        for (int i = instructions.size() - 1; i >= 0; i--) {
            if (instructions.get(i).getOpcode() >= 0) return i;
        }
        return -1;
    }

    private static void appendAll(InsnList output, List<AbstractInsnNode> instructions, int count) {
        for (int i = 0; i < count; i++) output.add(instructions.get(i));
    }

    private static void appendStateJump(InsnList output, int stateSlot, int targetBlock, LabelNode dispatch) {
        output.add(pushInt(targetBlock));
        output.add(new VarInsnNode(Opcodes.ISTORE, stateSlot));
        output.add(new JumpInsnNode(Opcodes.GOTO, dispatch));
    }

    private static void appendTableSwitch(InsnList output, int stateSlot, LabelNode dispatch,
                                          Map<LabelNode, Integer> labelToBlock, TableSwitchInsnNode node) {
        LabelNode[] trampolines = new LabelNode[node.labels.size()];
        int[] targets = new int[node.labels.size()];
        for (int i = 0; i < node.labels.size(); i++) {
            trampolines[i] = new LabelNode();
            targets[i] = labelToBlock.get(node.labels.get(i));
        }
        LabelNode defaultTrampoline = new LabelNode();
        int defaultTarget = labelToBlock.get(node.dflt);
        output.add(new TableSwitchInsnNode(node.min, node.max, defaultTrampoline, trampolines));
        for (int i = 0; i < trampolines.length; i++) {
            output.add(trampolines[i]);
            appendStateJump(output, stateSlot, targets[i], dispatch);
        }
        output.add(defaultTrampoline);
        appendStateJump(output, stateSlot, defaultTarget, dispatch);
    }

    private static void appendLookupSwitch(InsnList output, int stateSlot, LabelNode dispatch,
                                           Map<LabelNode, Integer> labelToBlock, LookupSwitchInsnNode node) {
        LabelNode[] trampolines = new LabelNode[node.labels.size()];
        int[] targets = new int[node.labels.size()];
        for (int i = 0; i < node.labels.size(); i++) {
            trampolines[i] = new LabelNode();
            targets[i] = labelToBlock.get(node.labels.get(i));
        }
        LabelNode defaultTrampoline = new LabelNode();
        int defaultTarget = labelToBlock.get(node.dflt);
        output.add(new LookupSwitchInsnNode(defaultTrampoline, node.keys.stream().mapToInt(Integer::intValue).toArray(),
                trampolines));
        for (int i = 0; i < trampolines.length; i++) {
            output.add(trampolines[i]);
            appendStateJump(output, stateSlot, targets[i], dispatch);
        }
        output.add(defaultTrampoline);
        appendStateJump(output, stateSlot, defaultTarget, dispatch);
    }

    private static void collectTargets(AbstractInsnNode insn, Set<LabelNode> targets) {
        if (insn instanceof JumpInsnNode jump) {
            targets.add(jump.label);
        } else if (insn instanceof TableSwitchInsnNode tableSwitch) {
            targets.add(tableSwitch.dflt);
            for (LabelNode label : tableSwitch.labels) targets.add(label);
        } else if (insn instanceof LookupSwitchInsnNode lookupSwitch) {
            targets.add(lookupSwitch.dflt);
            for (LabelNode label : lookupSwitch.labels) targets.add(label);
        }
    }

    private static boolean endsBlock(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        if (insn instanceof JumpInsnNode) return true; // GOTO/JSR/conditional
        if (insn instanceof TableSwitchInsnNode || insn instanceof LookupSwitchInsnNode) return true;
        return (opcode >= Opcodes.IRETURN && opcode <= Opcodes.RETURN) || opcode == Opcodes.ATHROW;
    }

    private static AbstractInsnNode pushInt(int value) {
        if (value >= -1 && value <= 5) return new InsnNode(Opcodes.ICONST_0 + value);
        return new LdcInsnNode(Integer.valueOf(value));
    }

    private static final class Block {
        final int index;
        final LabelNode label = new LabelNode();
        final List<AbstractInsnNode> instructions = new ArrayList<>();

        Block(int index) {
            this.index = index;
        }
    }
}
