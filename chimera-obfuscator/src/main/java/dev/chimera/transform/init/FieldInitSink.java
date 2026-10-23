package dev.chimera.transform.init;

import dev.chimera.core.TransformContext;
import dev.chimera.core.Transformer;
import dev.chimera.transform.indy.IndyDispatchTransformer;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.FrameNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * G4 (S6): sinks literal constant field initializations out of initializer methods into private
 * synthetic helper methods.
 *
 * <p>Patterns handled:</p>
 * <ul>
 *   <li>{@code <init>}: {@code ALOAD 0; <literal constant>; PUTFIELD this.<field>} triples for a
 *       non-final, non-volatile instance field declared by the same class. A maximal run of such
 *       triples (labels/line numbers between them are allowed) becomes one private static
 *       {@code chimera$init$N(Owner)} method, called from the exact position of the first triple.
 *       Call-site stack shape is unchanged (receiver -&gt; void), so existing frames stay valid.</li>
 *   <li>{@code <clinit>}: {@code <literal constant>; PUTSTATIC <field>} pairs for a non-final,
 *       non-volatile static field declared by the same class. A maximal run becomes one private
 *       static {@code chimera$init$N()} method called at the same position, so class-initialization
 *       order (including reads of the field later in {@code <clinit>}) is untouched.</li>
 * </ul>
 *
 * <p>Hard safety rules:</p>
 * <ul>
 *   <li>Mixin classes, records, enums, interfaces, annotation types and {@code dev/chimera/}
 *       runtime classes are skipped entirely; {@link #transformClass(byte[])} returns Mixin class
 *       bytes verbatim (Signature/debug attributes preserved).</li>
 *   <li>Any initializer with a try/catch block is skipped as a whole: removing instructions from a
 *       protected range would change handler coverage.</li>
 *   <li>Final fields are never moved. The JVM only permits {@code putfield}/{@code putstatic} to a
 *       final field inside {@code <init>}/{@code <clinit>} of the declaring class (JVMS 4.9.2 and
 *       the {@code putfield}/{@code putstatic} rules), so a helper method cannot assign them. This
 *       is how "final semantics" are preserved; the assignment stays where javac put it.</li>
 *   <li>Volatile fields are not moved (cross-thread visibility must stay at the original point).</li>
 *   <li>Only fields declared by the current class are considered (no inherited-field edge cases).</li>
 *   <li>Only literal constants are moved ({@code ICONST_*}/{@code LCONST_*}/{@code FCONST_*}/
 *       {@code DCONST_*}/{@code ACONST_NULL}/{@code BIPUSH}/{@code SIPUSH}/{@code LDC} of
 *       Integer/Long/Float/Double/String). Parameter- or expression-dependent values are skipped
 *       and counted as {@link SkipReason#NON_CONSTANT}.</li>
 *   <li>A triple is skipped when one of its instructions is a jump target or when a stack-map
 *       frame sits in the middle of it (both indicate a control-flow boundary that must not move).</li>
 *   <li>Static field writes found in a constructor are <em>not</em> moved into {@code <clinit>}:
 *       that would perform the write once at class initialization instead of once per instance,
 *       changing observable behaviour. They are counted as
 *       {@link SkipReason#STATIC_FIELD_IN_INIT}.</li>
 * </ul>
 *
 * <p>The transformer is idempotent: generated helper methods are never initializer methods, so a
 * second pass finds no new triples and produces the same class bytes.</p>
 */
public final class FieldInitSink implements Transformer {

    private static final String HELPER_PREFIX = "chimera$init$";
    private static final String SELF_PACKAGE = "dev/chimera/";
    private static final String MIXIN_ANNOTATION_PREFIX = "Lorg/spongepowered/asm/mixin";
    private static final String MIXIN_EXTRAS_PREFIX = "Lcom/llamalad7/mixinextras/";

    /** Why one candidate assignment was left in place. */
    public enum SkipReason {
        NON_CONSTANT("non_constant"),
        FINAL_FIELD("final_field"),
        VOLATILE_FIELD("volatile_field"),
        TRY_CATCH("try_catch"),
        FIELD_NOT_OWNED("field_not_owned"),
        UNKNOWN_FIELD("unknown_field"),
        STATIC_FIELD_IN_INIT("static_field_in_init"),
        UNSAFE_TARGET("unsafe_target");

        private final String label;

        SkipReason(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }
    }

    /** Immutable statistics snapshot (the Lead maps these to {@code dev.chimera.core.Stats}). */
    public record Stats(int classesVisited, int classesSkipped, int sunkFields, int skipped,
                        int sinkMethods, Map<String, Integer> skipDistribution) {

        public int skipCount(SkipReason reason) {
            return skipDistribution.getOrDefault(reason.label(), 0);
        }

        @Override
        public String toString() {
            return "initClasses=" + classesVisited + ", skippedClasses=" + classesSkipped
                    + ", sunkFields=" + sunkFields + ", skipped=" + skipped
                    + ", sinkMethods=" + sinkMethods + ", reasons=" + skipDistribution;
        }
    }

    /** Result of {@link #transformClass(byte[])}. */
    public record TransformResult(byte[] bytes, Stats stats) {
    }

    private int classesVisited;
    private int classesSkipped;
    private int sunkFields;
    private int skipped;
    private int sinkMethods;
    private final EnumMap<SkipReason, Integer> skips = new EnumMap<>(SkipReason.class);

    @Override
    public void transform(String internalName, ClassNode node, TransformContext ctx) {
        transformNode(node);
    }

    /** Applies the transform to {@code node} in place. */
    public void transformNode(ClassNode node) {
        classesVisited++;
        if (node == null || node.name == null) {
            return;
        }
        if (isSkippedClass(node)) {
            classesSkipped++;
            return;
        }
        if (node.methods == null || node.methods.isEmpty()) {
            return;
        }
        // Snapshot: flush() appends helper methods to node.methods.
        for (MethodNode method : new ArrayList<>(node.methods)) {
            if (method == null || method.instructions == null || method.instructions.size() == 0) {
                continue;
            }
            if ("<init>".equals(method.name)) {
                sinkInstanceInitializer(node, method);
            } else if ("<clinit>".equals(method.name)) {
                sinkStaticInitializer(node, method);
            }
        }
    }

    // ------------------------------------------------------------------ instance constructors

    private void sinkInstanceInitializer(ClassNode owner, MethodNode method) {
        List<AbstractInsnNode> code = codeOf(method);
        if (code.isEmpty()) {
            return;
        }
        boolean tryCatch = hasTryCatch(method);
        Set<AbstractInsnNode> targets = collectJumpTargets(method);
        Set<AbstractInsnNode> frameAnchors = collectFrameAnchors(method);
        List<Assignment> run = new ArrayList<>();
        int i = 0;
        while (i < code.size()) {
            Assignment assignment = i + 2 < code.size() ? matchInstanceTriple(code, i) : null;
            if (assignment != null) {
                SkipReason reason = instanceReason(owner, assignment, tryCatch, targets, frameAnchors);
                if (reason == null) {
                    // A jump/frame target on the receiver is a legal place to start a helper call,
                    // but the run must break there: merging across it would skip earlier triples on
                    // the path that jumps to this label.
                    if (targets.contains(assignment.receiver)
                            || frameAnchors.contains(assignment.receiver)) {
                        flush(owner, method, run);
                    }
                    run.add(assignment);
                    i += 3;
                    continue;
                }
                flush(owner, method, run);
                skip(reason);
                i += 3;
                continue;
            }
            flush(owner, method, run);
            AbstractInsnNode insn = code.get(i);
            if (insn instanceof FieldInsnNode field && field.getOpcode() == Opcodes.PUTFIELD
                    && owner.name.equals(field.owner)) {
                // this.f = <non-literal expression> (parameter, call, arithmetic, ...)
                skip(SkipReason.NON_CONSTANT);
            } else if (insn instanceof FieldInsnNode stat && stat.getOpcode() == Opcodes.PUTSTATIC
                    && owner.name.equals(stat.owner)) {
                // Constructor writes a static field: moving it to <clinit> changes the write time.
                skip(SkipReason.STATIC_FIELD_IN_INIT);
            }
            i++;
        }
        flush(owner, method, run);
    }

    private static Assignment matchInstanceTriple(List<AbstractInsnNode> code, int index) {
        AbstractInsnNode receiver = code.get(index);
        if (!(receiver instanceof VarInsnNode var) || var.getOpcode() != Opcodes.ALOAD || var.var != 0) {
            return null;
        }
        AbstractInsnNode value = code.get(index + 1);
        if (!isLiteralConstant(value)) {
            return null;
        }
        AbstractInsnNode put = code.get(index + 2);
        if (!(put instanceof FieldInsnNode field) || put.getOpcode() != Opcodes.PUTFIELD) {
            return null;
        }
        return new Assignment(var, value, field);
    }

    private static SkipReason instanceReason(ClassNode owner, Assignment assignment, boolean tryCatch,
                                             Set<AbstractInsnNode> targets,
                                             Set<AbstractInsnNode> frameAnchors) {
        if (tryCatch) {
            return SkipReason.TRY_CATCH;
        }
        // The receiver may legitimately be a jump/frame target (start of a branch): the helper
        // call is inserted at the same position and the operand stack is unchanged. Only a
        // control-flow boundary between the receiver and the assignment is unsafe.
        if (unsafe(assignment.value, targets, frameAnchors)
                || unsafe(assignment.field, targets, frameAnchors)) {
            return SkipReason.UNSAFE_TARGET;
        }
        if (!owner.name.equals(assignment.field.owner)) {
            return SkipReason.FIELD_NOT_OWNED;
        }
        FieldNode field = findField(owner, assignment.field.name, assignment.field.desc);
        if (field == null) {
            return SkipReason.UNKNOWN_FIELD;
        }
        if ((field.access & Opcodes.ACC_FINAL) != 0) {
            return SkipReason.FINAL_FIELD;
        }
        if ((field.access & Opcodes.ACC_VOLATILE) != 0) {
            return SkipReason.VOLATILE_FIELD;
        }
        return null;
    }

    // ------------------------------------------------------------------ class initializers

    private void sinkStaticInitializer(ClassNode owner, MethodNode method) {
        List<AbstractInsnNode> code = codeOf(method);
        if (code.isEmpty()) {
            return;
        }
        boolean tryCatch = hasTryCatch(method);
        Set<AbstractInsnNode> targets = collectJumpTargets(method);
        Set<AbstractInsnNode> frameAnchors = collectFrameAnchors(method);
        List<Assignment> run = new ArrayList<>();
        int i = 0;
        while (i < code.size()) {
            Assignment assignment = i + 1 < code.size() ? matchStaticPair(code, i) : null;
            if (assignment != null) {
                SkipReason reason = staticReason(owner, assignment, tryCatch, targets, frameAnchors);
                if (reason == null) {
                    // A static pair has no receiver; a jump/frame target on the constant is a
                    // legal call position, but the run must break there so a jump into the middle
                    // of the run cannot skip earlier assignments.
                    if (targets.contains(assignment.value)
                            || frameAnchors.contains(assignment.value)) {
                        flush(owner, method, run);
                    }
                    run.add(assignment);
                    i += 2;
                    continue;
                }
                flush(owner, method, run);
                skip(reason);
                i += 2;
                continue;
            }
            flush(owner, method, run);
            AbstractInsnNode insn = code.get(i);
            if (insn instanceof FieldInsnNode field && field.getOpcode() == Opcodes.PUTSTATIC
                    && owner.name.equals(field.owner)) {
                skip(SkipReason.NON_CONSTANT);
            }
            i++;
        }
        flush(owner, method, run);
    }

    private static Assignment matchStaticPair(List<AbstractInsnNode> code, int index) {
        AbstractInsnNode value = code.get(index);
        if (!isLiteralConstant(value)) {
            return null;
        }
        AbstractInsnNode put = code.get(index + 1);
        if (!(put instanceof FieldInsnNode field) || put.getOpcode() != Opcodes.PUTSTATIC) {
            return null;
        }
        return new Assignment(null, value, field);
    }

    private static SkipReason staticReason(ClassNode owner, Assignment assignment, boolean tryCatch,
                                           Set<AbstractInsnNode> targets,
                                           Set<AbstractInsnNode> frameAnchors) {
        if (tryCatch) {
            return SkipReason.TRY_CATCH;
        }
        // The constant may be a jump/frame target (a branch into a static assignment): the helper
        // call is emitted at the same position with the same (unchanged) operand stack. Only a
        // boundary at the consuming PUTSTATIC is unsafe.
        if (unsafe(assignment.field, targets, frameAnchors)) {
            return SkipReason.UNSAFE_TARGET;
        }
        if (!owner.name.equals(assignment.field.owner)) {
            return SkipReason.FIELD_NOT_OWNED;
        }
        FieldNode field = findField(owner, assignment.field.name, assignment.field.desc);
        if (field == null) {
            return SkipReason.UNKNOWN_FIELD;
        }
        if ((field.access & Opcodes.ACC_FINAL) != 0) {
            return SkipReason.FINAL_FIELD;
        }
        if ((field.access & Opcodes.ACC_VOLATILE) != 0) {
            return SkipReason.VOLATILE_FIELD;
        }
        return null;
    }

    // ------------------------------------------------------------------ helper emission

    private void flush(ClassNode owner, MethodNode method, List<Assignment> run) {
        if (run.isEmpty()) {
            return;
        }
        Assignment first = run.get(0);
        boolean instance = first.receiver != null;
        String helperName = nextHelperName(owner);
        String descriptor = instance ? "(L" + owner.name + ";)V" : "()V";
        int access = Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC;
        MethodNode helper = new MethodNode(access, helperName, descriptor, null, null);

        InsnList call = new InsnList();
        if (instance) {
            call.add(new VarInsnNode(Opcodes.ALOAD, 0));
        }
        call.add(new MethodInsnNode(Opcodes.INVOKESTATIC, owner.name, helperName, descriptor,
                (owner.access & Opcodes.ACC_INTERFACE) != 0));
        AbstractInsnNode anchor = instance ? first.receiver : first.value;
        method.instructions.insertBefore(anchor, call);

        for (Assignment assignment : run) {
            if (assignment.receiver != null) {
                method.instructions.remove(assignment.receiver);
                helper.instructions.add(assignment.receiver);
            }
            method.instructions.remove(assignment.value);
            helper.instructions.add(assignment.value);
            method.instructions.remove(assignment.field);
            helper.instructions.add(assignment.field);
        }
        helper.instructions.add(new InsnNode(Opcodes.RETURN));
        helper.maxStack = 8;
        helper.maxLocals = instance ? 1 : 0;
        owner.methods.add(helper);

        sunkFields += run.size();
        sinkMethods++;
        run.clear();
    }

    private static String nextHelperName(ClassNode owner) {
        for (int i = 0; ; i++) {
            String candidate = HELPER_PREFIX + i;
            boolean clash = false;
            for (MethodNode method : owner.methods) {
                if (candidate.equals(method.name)) {
                    clash = true;
                    break;
                }
            }
            if (!clash) {
                return candidate;
            }
        }
    }

    // ------------------------------------------------------------------ eligibility helpers

    private static boolean isSkippedClass(ClassNode node) {
        int access = node.access;
        if ((access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION | Opcodes.ACC_ENUM
                | Opcodes.ACC_RECORD)) != 0) {
            return true;
        }
        if (node.name.startsWith(SELF_PACKAGE) || "module-info".equals(node.name)) {
            return true;
        }
        return isMixinClass(node);
    }

    /** Mixin / MixinExtras detection shared by both skip paths and the byte-preserving facade. */
    public static boolean isMixinClass(ClassNode node) {
        if (node == null) {
            return false;
        }
        if (IndyDispatchTransformer.isMixinClass(node)) {
            return true;
        }
        return hasAnnotationPrefix(node.visibleAnnotations, MIXIN_EXTRAS_PREFIX)
                || hasAnnotationPrefix(node.invisibleAnnotations, MIXIN_EXTRAS_PREFIX);
    }

    private static boolean hasAnnotationPrefix(List<AnnotationNode> annotations, String prefix) {
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

    private static FieldNode findField(ClassNode owner, String name, String descriptor) {
        if (owner.fields == null) {
            return null;
        }
        for (FieldNode field : owner.fields) {
            if (name.equals(field.name) && descriptor.equals(field.desc)) {
                return field;
            }
        }
        return null;
    }

    private static boolean isLiteralConstant(AbstractInsnNode insn) {
        if (insn == null) {
            return false;
        }
        int opcode = insn.getOpcode();
        if (opcode >= Opcodes.ICONST_M1 && opcode <= Opcodes.ICONST_5) {
            return true;
        }
        if (opcode == Opcodes.LCONST_0 || opcode == Opcodes.LCONST_1
                || opcode == Opcodes.FCONST_0 || opcode == Opcodes.FCONST_1 || opcode == Opcodes.FCONST_2
                || opcode == Opcodes.DCONST_0 || opcode == Opcodes.DCONST_1
                || opcode == Opcodes.ACONST_NULL
                || opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH) {
            return true;
        }
        if (insn instanceof LdcInsnNode ldc) {
            Object constant = ldc.cst;
            return constant instanceof Integer || constant instanceof Long
                    || constant instanceof Float || constant instanceof Double
                    || constant instanceof String;
        }
        return false;
    }

    private static boolean unsafe(AbstractInsnNode insn, Set<AbstractInsnNode> targets,
                                  Set<AbstractInsnNode> frameAnchors) {
        return targets.contains(insn) || frameAnchors.contains(insn);
    }

    private static boolean hasTryCatch(MethodNode method) {
        return method.tryCatchBlocks != null && !method.tryCatchBlocks.isEmpty();
    }

    /** Real bytecode instructions only (no labels/line numbers/frames). */
    private static List<AbstractInsnNode> codeOf(MethodNode method) {
        List<AbstractInsnNode> out = new ArrayList<>();
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn.getOpcode() >= 0) {
                out.add(insn);
            }
        }
        return out;
    }

    /** First real instruction after every branch target label. */
    private static Set<AbstractInsnNode> collectJumpTargets(MethodNode method) {
        Set<LabelNode> labels = new HashSet<>();
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof JumpInsnNode jump) {
                labels.add(jump.label);
            } else if (insn instanceof TableSwitchInsnNode table) {
                labels.add(table.dflt);
                labels.addAll(table.labels);
            } else if (insn instanceof LookupSwitchInsnNode lookup) {
                labels.add(lookup.dflt);
                labels.addAll(lookup.labels);
            }
        }
        if (method.tryCatchBlocks != null) {
            for (TryCatchBlockNode block : method.tryCatchBlocks) {
                if (block.start != null) {
                    labels.add(block.start);
                }
                if (block.end != null) {
                    labels.add(block.end);
                }
                if (block.handler != null) {
                    labels.add(block.handler);
                }
            }
        }
        Set<AbstractInsnNode> targets = new HashSet<>();
        for (LabelNode label : labels) {
            AbstractInsnNode next = nextRealInstruction(label);
            if (next != null) {
                targets.add(next);
            }
        }
        return targets;
    }

    /** First real instruction after every stack-map frame (frames must not land mid-triple). */
    private static Set<AbstractInsnNode> collectFrameAnchors(MethodNode method) {
        Set<AbstractInsnNode> anchors = new HashSet<>();
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof FrameNode) {
                AbstractInsnNode next = nextRealInstruction(insn);
                if (next != null) {
                    anchors.add(next);
                }
            }
        }
        return anchors;
    }

    private static AbstractInsnNode nextRealInstruction(AbstractInsnNode node) {
        for (AbstractInsnNode next = node.getNext(); next != null; next = next.getNext()) {
            if (next.getOpcode() >= 0) {
                return next;
            }
        }
        return null;
    }

    private void skip(SkipReason reason) {
        skipped++;
        skips.merge(reason, 1, Integer::sum);
    }

    // ------------------------------------------------------------------ counters / facade

    public int sunkFields() {
        return sunkFields;
    }

    public int skipped() {
        return skipped;
    }

    public int sinkMethods() {
        return sinkMethods;
    }

    public int classesVisited() {
        return classesVisited;
    }

    public int classesSkipped() {
        return classesSkipped;
    }

    public int skipCount(SkipReason reason) {
        return skips.getOrDefault(reason, 0);
    }

    public Map<String, Integer> skipDistribution() {
        Map<String, Integer> out = new LinkedHashMap<>();
        for (SkipReason reason : SkipReason.values()) {
            int count = skipCount(reason);
            if (count > 0) {
                out.put(reason.label(), count);
            }
        }
        return out;
    }

    public Stats stats() {
        return new Stats(classesVisited, classesSkipped, sunkFields, skipped, sinkMethods,
                Collections.unmodifiableMap(skipDistribution()));
    }

    /**
     * Reads, transforms and writes one class. Mixin classes are returned byte-identical, which is
     * required because Mixin reads Signature/debug attributes at runtime.
     */
    public static TransformResult transformClass(byte[] classBytes) {
        ClassReader reader = new ClassReader(classBytes);
        ClassNode node = new ClassNode();
        reader.accept(node, 0);
        FieldInitSink sink = new FieldInitSink();
        boolean mixin = isMixinClass(node);
        sink.transformNode(node);
        if (mixin) {
            return new TransformResult(classBytes, sink.stats());
        }
        ClassWriter writer = new ClassWriter(reader, 0);
        node.accept(writer);
        return new TransformResult(writer.toByteArray(), sink.stats());
    }

    // ------------------------------------------------------------------ internal model

    private static final class Assignment {
        final VarInsnNode receiver;
        final AbstractInsnNode value;
        final FieldInsnNode field;

        Assignment(VarInsnNode receiver, AbstractInsnNode value, FieldInsnNode field) {
            this.receiver = receiver;
            this.value = value;
            this.field = field;
        }
    }
}
