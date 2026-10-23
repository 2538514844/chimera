package dev.chimera.transform.sink;

import dev.chimera.core.TransformContext;
import dev.chimera.core.Transformer;
import dev.chimera.nativecode.compile.NativeBodyCompiler;
import dev.chimera.transform.indy.IndyDispatchTransformer;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.IdentityHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;

/**
 * Sink stage: moves supported Java method bodies into JNI and leaves an empty native declaration
 * behind.
 *
 * <p>Per selected method the transformer:</p>
 * <ol>
 *   <li>keeps the original {@link MethodNode} (instructions, try/catch, debug info) in
 *       {@link SinkResult};</li>
 *   <li>replaces the class-file method with a body-less {@code native} declaration that keeps the
 *       original access flags (in particular {@code static}/{@code instance}), signature,
 *       exceptions and annotations;</li>
 *   <li>generates the JNI C++ function with
 *       {@link NativeBodyCompiler#compile(String, MethodNode, boolean)} and exposes it through
 *       {@link SinkResult#cppUnit()}.</li>
 * </ol>
 *
 * <p>RegisterNatives wiring is generated as well ({@link SinkResult#registerNativesSnippet()});
 * every failure path returns {@code JNI_ERR} (fail closed). Mixin classes are never touched, so
 * their bytes, {@code Signature} and debug attributes survive unchanged.</p>
 *
 * <p>Determinism: candidates are sorted before the per-class budget is applied, and every generated
 * artifact is canonically sorted by {@code owner/name/descriptor} (see
 * {@link SinkResult#selectedMethods()}), so the same set of selected methods always yields the same
 * manifest, function order and {@code RegisterNatives} groups regardless of class visitation order.
 * The build-wide budget ({@link Options#maxMethodsPerBuild()}) is necessarily consumed in visitation
 * order because each class is rewritten when {@link #transform} is called; when that budget is meant
 * to bind, the selected set itself can therefore depend on class order. Set it well above the
 * expected method count when order-independent output is required.</p>
 *
 * <p>This class does <b>not</b> modify {@code ChimeraConfig}, {@code Stats},
 * {@code ChimeraEngine} or the CLI. The Lead wires it with
 * {@link #transform(String, ClassNode, TransformContext)} and consumes
 * {@link #result()} / {@link #stats()} after the build pass.</p>
 */
public final class NativeSinkTransformer implements Transformer {

    private static final String MIXIN_ANNOTATION_PREFIX = "Lorg/spongepowered/asm/mixin";
    private static final String MIXIN_EXTRAS_PREFIX = "Lcom/llamalad7/mixinextras/";
    private static final String CHIMERA_ANNOTATION_PREFIX = "Ldev/chimera/annotations/";

    /** Why a method was left in Java. Labels are stable and used by {@link Stats}. */
    public enum SkipReason {
        MIXIN_CLASS("mixin_class"),
        MIXIN_MEMBER("mixin_member"),
        CHIMERA_ANNOTATION("chimera_annotation"),
        EXCLUDED_CLASS("excluded_class"),
        CONSTRUCTOR("constructor"),
        CLASS_INITIALIZER("class_initializer"),
        SYNCHRONIZED("synchronized"),
        NATIVE("native"),
        ABSTRACT("abstract"),
        BRIDGE("bridge"),
        INTERFACE_METHOD("interface_method"),
        NO_CODE("no_code"),
        TOO_FEW_INSTRUCTIONS("too_few_instructions"),
        TOO_MANY_INSTRUCTIONS("too_many_instructions"),
        TOO_LARGE("too_large"),
        UNSUPPORTED_BYTECODE("unsupported_bytecode"),
        CLASS_BUDGET("class_budget"),
        BUILD_BUDGET("build_budget");

        private final String label;

        SkipReason(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }
    }

    /**
     * Selection policy. All limits use {@code <= 0} as "unlimited"; weights rank candidates so
     * larger / call-heavy / branch-heavy bodies win when a budget cuts the candidate list.
     */
    public record Options(
            boolean enabled,
            int maxMethodBytes,
            int minInstructions,
            int maxInstructions,
            int maxMethodsPerClass,
            int maxMethodsPerBuild,
            int instructionWeight,
            int callWeight,
            int fieldWeight,
            int branchWeight,
            Set<String> excludedClassPrefixes) {

        public static final Set<String> DEFAULT_EXCLUDED_PREFIXES = Set.of(
                "dev/chimera/",
                "org/spongepowered/asm/",
                "com/llamalad7/mixinextras/");

        public Options {
            if (maxMethodBytes < 0 || minInstructions < 0 || maxInstructions < 0
                    || maxMethodsPerClass < 0 || maxMethodsPerBuild < 0
                    || instructionWeight < 0 || callWeight < 0
                    || fieldWeight < 0 || branchWeight < 0) {
                throw new IllegalArgumentException("NativeSinkTransformer options must not be negative");
            }
            if (maxInstructions > 0 && minInstructions > maxInstructions) {
                throw new IllegalArgumentException(
                        "minInstructions (" + minInstructions + ") exceeds maxInstructions (" + maxInstructions + ")");
            }
            excludedClassPrefixes = excludedClassPrefixes == null
                    ? DEFAULT_EXCLUDED_PREFIXES
                    : Collections.unmodifiableSet(new LinkedHashSet<>(excludedClassPrefixes));
        }

        public static Options defaults() {
            return new Options(true, 8192, 1, 400, 8, 256, 1, 4, 2, 3, DEFAULT_EXCLUDED_PREFIXES);
        }

        public static Options withBudget(int maxMethodsPerBuild) {
            Options d = defaults();
            return new Options(d.enabled, d.maxMethodBytes, d.minInstructions, d.maxInstructions,
                    d.maxMethodsPerClass, maxMethodsPerBuild, d.instructionWeight, d.callWeight,
                    d.fieldWeight, d.branchWeight, d.excludedClassPrefixes);
        }

        public boolean isExcluded(String internalName) {
            if (internalName == null) {
                return false;
            }
            for (String prefix : excludedClassPrefixes) {
                if (internalName.startsWith(prefix)) {
                    return true;
                }
            }
            return false;
        }
    }

    /** Class-level gating used by the build-side whole-jar pre-pass (B1 selection strategy). */
    private java.util.Set<String> allowedClasses;
    private boolean allowedClassesActive;

    /**
     * Restricts sinking to the supplied classes (from {@link NativeSinkPlanner}); {@code null}
     * clears the gate and restores "every non-mixin class is eligible".
     */
    public synchronized void restrictTo(java.util.Set<String> internalNames) {
        this.allowedClasses = internalNames == null ? null : java.util.Set.copyOf(internalNames);
        this.allowedClassesActive = internalNames != null;
    }

    /** Immutable statistics snapshot; the Lead maps these onto {@code dev.chimera.core.Stats}. */
    public record Stats(
            int selected,
            Map<String, Integer> skippedByReason,
            int generatedFunctions,
            int methodsVisited,
            int classesVisited,
            int mixinClassesSkipped) {

        public Stats {
            skippedByReason = skippedByReason == null
                    ? Map.of()
                    : Collections.unmodifiableMap(new TreeMap<>(skippedByReason));
        }

        public int skipped() {
            int total = 0;
            for (int value : skippedByReason.values()) {
                total += value;
            }
            return total;
        }

        public int skipCount(SkipReason reason) {
            return reason == null ? 0 : skippedByReason.getOrDefault(reason.label(), 0);
        }

        @Override
        public String toString() {
            return "nativeSinkSelected=" + selected
                    + ", nativeSinkFunctions=" + generatedFunctions
                    + ", nativeSinkSkipped=" + skipped()
                    + ", methodsVisited=" + methodsVisited
                    + ", classesVisited=" + classesVisited
                    + ", mixinClassesSkipped=" + mixinClassesSkipped
                    + ", reasons=" + skippedByReason;
        }
    }

    private record Candidate(MethodNode method, NativeBodyCompiler.CompiledMethod compiled, long weight) {
    }

    private final Options options;
    private final List<SinkSelectedMethod> selected = new ArrayList<>();
    private final EnumMap<SkipReason, Integer> skippedByReason = new EnumMap<>(SkipReason.class);
    private int methodsVisited;
    private int classesVisited;
    private int mixinClassesSkipped;

    public NativeSinkTransformer() {
        this(Options.defaults());
    }

    public NativeSinkTransformer(Options options) {
        this.options = Objects.requireNonNull(options, "options");
    }

    public Options options() {
        return options;
    }

    @Override
    public synchronized void transform(String internalName, ClassNode node, TransformContext ctx) throws Exception {
        if (node == null) {
            throw new IllegalArgumentException("NativeSinkTransformer: ClassNode is required");
        }
        if (ctx == null) {
            throw new IllegalArgumentException("NativeSinkTransformer: TransformContext is required");
        }
        String owner = node.name != null ? node.name : internalName;
        if (owner == null || owner.isEmpty()) {
            throw new IllegalArgumentException("NativeSinkTransformer: class internal name is required");
        }
        if (internalName != null && node.name != null && !internalName.equals(node.name)) {
            throw new IllegalArgumentException("NativeSinkTransformer: owner mismatch: parameter '"
                    + internalName + "' but ClassNode.name '" + node.name + "'");
        }

        classesVisited++;
        if (!options.enabled()) {
            return;
        }

        boolean mixinClass = IndyDispatchTransformer.isMixinClass(node);
        if (mixinClass) {
            mixinClassesSkipped++;
        }

        List<MethodNode> methods = node.methods == null ? List.of() : node.methods;
        Map<MethodNode, Integer> indexes = new IdentityHashMap<>();
        Map<String, Integer> nameCounts = new TreeMap<>();
        for (int i = 0; i < methods.size(); i++) {
            MethodNode method = methods.get(i);
            if (method == null) {
                throw new IllegalArgumentException("NativeSinkTransformer: null method in " + owner);
            }
            indexes.put(method, i);
            nameCounts.merge(method.name, 1, Integer::sum);
        }

        List<Candidate> candidates = new ArrayList<>();
        for (MethodNode method : methods) {
            methodsVisited++;
            SkipReason reason = screen(owner, node, method, mixinClass);
            if (reason != null) {
                skip(reason);
                continue;
            }
            boolean overloaded = nameCounts.getOrDefault(method.name, 0) > 1;
            NativeBodyCompiler.CompiledMethod compiled;
            try {
                compiled = NativeBodyCompiler.compile(owner, method, overloaded);
            } catch (NativeBodyCompiler.UnsupportedInstruction unsupported) {
                skip(SkipReason.UNSUPPORTED_BYTECODE);
                continue;
            }
            candidates.add(new Candidate(method, compiled, weight(method)));
        }

        candidates.sort(Comparator.comparingLong(Candidate::weight).reversed()
                .thenComparing(candidate -> candidate.method().name)
                .thenComparing(candidate -> candidate.method().desc));

        int classBudget = options.maxMethodsPerClass() <= 0
                ? Integer.MAX_VALUE : options.maxMethodsPerClass();
        int buildBudget = options.maxMethodsPerBuild() <= 0
                ? Integer.MAX_VALUE : options.maxMethodsPerBuild();
        int classSelected = 0;
        for (Candidate candidate : candidates) {
            if (classSelected >= classBudget) {
                skip(SkipReason.CLASS_BUDGET);
                continue;
            }
            if (selected.size() >= buildBudget) {
                skip(SkipReason.BUILD_BUDGET);
                continue;
            }
            MethodNode original = candidate.method();
            String source = candidate.compiled().source();
            if (source == null || source.isBlank()) {
                throw new IllegalStateException(
                        "NativeSinkTransformer: empty C++ for " + owner + "." + original.name + original.desc);
            }
            replaceWithNativeStub(node, indexes, original, ctx);
            selected.add(new SinkSelectedMethod(owner, original.name, original.desc, original.signature,
                    original.access, (original.access & Opcodes.ACC_STATIC) != 0,
                    candidate.weight(), candidate.compiled().symbol(), original, source));
            classSelected++;
        }
    }

    private SkipReason screen(String owner, ClassNode node, MethodNode method, boolean mixinClass) {
        if (mixinClass) {
            return SkipReason.MIXIN_CLASS;
        }
        if (options.isExcluded(owner)) {
            return SkipReason.EXCLUDED_CLASS;
        }
        if (allowedClassesActive && (allowedClasses == null || !allowedClasses.contains(owner))) {
            return SkipReason.EXCLUDED_CLASS;
        }
        if (hasMixinAnnotation(method.visibleAnnotations) || hasMixinAnnotation(method.invisibleAnnotations)) {
            return SkipReason.MIXIN_MEMBER;
        }
        // @ChimeraNative / @ChimeraVM / @ChimeraEntangle / ... methods belong to another stage: never
        // sink them, even when this transformer runs before that stage (which would otherwise strip
        // the annotated body and silently disable the protection). Running after the owning stage
        // also lands here for methods it already made native.
        if (hasChimeraAnnotation(method.visibleAnnotations)
                || hasChimeraAnnotation(method.invisibleAnnotations)) {
            return SkipReason.CHIMERA_ANNOTATION;
        }
        if ("<init>".equals(method.name)) {
            return SkipReason.CONSTRUCTOR;
        }
        if ("<clinit>".equals(method.name)) {
            return SkipReason.CLASS_INITIALIZER;
        }
        if ((method.access & Opcodes.ACC_SYNCHRONIZED) != 0) {
            return SkipReason.SYNCHRONIZED;
        }
        if ((method.access & Opcodes.ACC_NATIVE) != 0) {
            return SkipReason.NATIVE;
        }
        if ((method.access & Opcodes.ACC_ABSTRACT) != 0) {
            return SkipReason.ABSTRACT;
        }
        if ((method.access & Opcodes.ACC_BRIDGE) != 0) {
            return SkipReason.BRIDGE;
        }
        if ((node.access & Opcodes.ACC_INTERFACE) != 0) {
            // Default / static / private interface methods: Java forbids native interface methods,
            // so they must stay in bytecode.
            return SkipReason.INTERFACE_METHOD;
        }
        // Conservative gate (real-client regression): reference-returning bodies are where the
        // C++ backend produced a null object and crashed Wurst's FullbrightHack constructor.
        // Sink only void/primitive results until the object-return path is validated.
        int returnSort = org.objectweb.asm.Type.getReturnType(method.desc).getSort();
        if (returnSort == org.objectweb.asm.Type.OBJECT
                || returnSort == org.objectweb.asm.Type.ARRAY
                || returnSort == org.objectweb.asm.Type.METHOD) {
            return SkipReason.UNSUPPORTED_BYTECODE;
        }
        int insns = instructionCount(method);
        if (insns == 0) {
            return SkipReason.NO_CODE;
        }
        if (options.minInstructions() > 0 && insns < options.minInstructions()) {
            return SkipReason.TOO_FEW_INSTRUCTIONS;
        }
        if (options.maxInstructions() > 0 && insns > options.maxInstructions()) {
            return SkipReason.TOO_MANY_INSTRUCTIONS;
        }
        if (options.maxMethodBytes() > 0 && estimatedCodeBytes(method) > options.maxMethodBytes()) {
            return SkipReason.TOO_LARGE;
        }
        return null;
    }

    private void replaceWithNativeStub(ClassNode node, Map<MethodNode, Integer> indexes,
                                       MethodNode original, TransformContext ctx) {
        Integer index = indexes.get(original);
        if (index == null) {
            throw new IllegalStateException(
                    "NativeSinkTransformer: method vanished from " + node.name + "." + original.name + original.desc);
        }
        MethodNode stub = new MethodNode(original.access | Opcodes.ACC_NATIVE,
                original.name, original.desc, original.signature,
                original.exceptions == null ? null : original.exceptions.toArray(new String[0]));
        stub.visibleAnnotations = copy(original.visibleAnnotations);
        stub.invisibleAnnotations = copy(original.invisibleAnnotations);
        stub.visibleTypeAnnotations = copy(original.visibleTypeAnnotations);
        stub.invisibleTypeAnnotations = copy(original.invisibleTypeAnnotations);
        stub.visibleParameterAnnotations = copyParameterAnnotations(original.visibleParameterAnnotations);
        stub.invisibleParameterAnnotations = copyParameterAnnotations(original.invisibleParameterAnnotations);
        stub.parameters = copy(original.parameters);
        stub.annotationDefault = original.annotationDefault;
        stub.attrs = copy(original.attrs);
        node.methods.set(index, stub);
        if (ctx.stats != null) {
            ctx.stats.methodsNativeStubbed++;
        }
    }

    private long weight(MethodNode method) {
        int calls = 0;
        int fields = 0;
        int branches = 0;
        for (AbstractInsnNode insn : method.instructions) {
            if (insn instanceof MethodInsnNode) {
                calls++;
            } else if (insn instanceof FieldInsnNode) {
                fields++;
            } else if (insn instanceof JumpInsnNode
                    || insn instanceof TableSwitchInsnNode
                    || insn instanceof LookupSwitchInsnNode) {
                branches++;
            }
        }
        return (long) options.instructionWeight() * instructionCount(method)
                + (long) options.callWeight() * calls
                + (long) options.fieldWeight() * fields
                + (long) options.branchWeight() * branches;
    }

    private void skip(SkipReason reason) {
        skippedByReason.merge(reason, 1, Integer::sum);
    }

    private Map<String, Integer> skippedLabels() {
        Map<String, Integer> out = new TreeMap<>();
        for (Map.Entry<SkipReason, Integer> entry : skippedByReason.entrySet()) {
            out.put(entry.getKey().label(), entry.getValue());
        }
        return out;
    }

    private static boolean hasChimeraAnnotation(List<AnnotationNode> annotations) {
        if (annotations == null) {
            return false;
        }
        for (AnnotationNode annotation : annotations) {
            if (annotation != null && annotation.desc != null
                    && annotation.desc.startsWith(CHIMERA_ANNOTATION_PREFIX)) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasMixinAnnotation(List<AnnotationNode> annotations) {
        if (annotations == null) {
            return false;
        }
        for (AnnotationNode annotation : annotations) {
            if (annotation == null || annotation.desc == null) {
                continue;
            }
            if (annotation.desc.startsWith(MIXIN_ANNOTATION_PREFIX)
                    || annotation.desc.startsWith(MIXIN_EXTRAS_PREFIX)) {
                return true;
            }
        }
        return false;
    }

    private static int instructionCount(MethodNode method) {
        if (method.instructions == null) {
            return 0;
        }
        int count = 0;
        for (AbstractInsnNode insn : method.instructions) {
            if (insn.getOpcode() >= 0) {
                count++;
            }
        }
        return count;
    }

    /**
     * Conservative estimate of the JVM {@code Code} attribute length. ASM does not expose the
     * encoded size without re-serializing the method, and the threshold only needs to be stable,
     * so wide constant-pool operands are assumed for {@code ldc} and all invokes are counted at
     * their widest form.
     */
    private static int estimatedCodeBytes(MethodNode method) {
        if (method.instructions == null) {
            return 0;
        }
        int total = 0;
        for (AbstractInsnNode insn : method.instructions) {
            int op = insn.getOpcode();
            if (op < 0) {
                continue;
            }
            total += switch (op) {
                case Opcodes.BIPUSH, Opcodes.ILOAD, Opcodes.LLOAD, Opcodes.FLOAD, Opcodes.DLOAD, Opcodes.ALOAD,
                     Opcodes.ISTORE, Opcodes.LSTORE, Opcodes.FSTORE, Opcodes.DSTORE, Opcodes.ASTORE,
                     Opcodes.NEWARRAY -> 2;
                case Opcodes.SIPUSH, Opcodes.LDC, Opcodes.IINC,
                     Opcodes.IFEQ, Opcodes.IFNE, Opcodes.IFLT, Opcodes.IFGE, Opcodes.IFGT, Opcodes.IFLE,
                     Opcodes.IF_ICMPEQ, Opcodes.IF_ICMPNE, Opcodes.IF_ICMPLT, Opcodes.IF_ICMPGE,
                     Opcodes.IF_ICMPGT, Opcodes.IF_ICMPLE, Opcodes.IF_ACMPEQ, Opcodes.IF_ACMPNE,
                     Opcodes.GOTO, Opcodes.JSR, Opcodes.IFNULL, Opcodes.IFNONNULL,
                     Opcodes.NEW, Opcodes.ANEWARRAY, Opcodes.CHECKCAST, Opcodes.INSTANCEOF,
                     Opcodes.GETSTATIC, Opcodes.PUTSTATIC, Opcodes.GETFIELD, Opcodes.PUTFIELD,
                     Opcodes.INVOKEVIRTUAL, Opcodes.INVOKESPECIAL, Opcodes.INVOKESTATIC -> 3;
                case Opcodes.INVOKEINTERFACE, Opcodes.INVOKEDYNAMIC -> 5;
                case Opcodes.MULTIANEWARRAY -> 4;
                case Opcodes.TABLESWITCH -> 16 + 4 * ((TableSwitchInsnNode) insn).labels.size();
                case Opcodes.LOOKUPSWITCH -> 12 + 8 * ((LookupSwitchInsnNode) insn).keys.size();
                default -> 1;
            };
        }
        return total;
    }

    private static <T> List<T> copy(List<T> source) {
        return source == null ? null : new ArrayList<>(source);
    }

    private static List<AnnotationNode>[] copyParameterAnnotations(List<AnnotationNode>[] source) {
        if (source == null) {
            return null;
        }
        @SuppressWarnings("unchecked")
        List<AnnotationNode>[] result = new List[source.length];
        for (int i = 0; i < source.length; i++) {
            result[i] = source[i] == null ? null : new ArrayList<>(source[i]);
        }
        return result;
    }

    /** Snapshot of everything selected so far (canonical order, original MethodNodes, codegen). */
    public synchronized SinkResult result() {
        return new SinkResult(new ArrayList<>(selected), skippedLabels(),
                methodsVisited, classesVisited, mixinClassesSkipped);
    }

    /** Statistics snapshot; {@code selected + skipped == methodsVisited}. */
    public synchronized Stats stats() {
        return new Stats(selected.size(), skippedLabels(), selected.size(),
                methodsVisited, classesVisited, mixinClassesSkipped);
    }

    /** Selected methods in selection order; use {@link SinkResult#selectedMethods()} for canonical order. */
    public synchronized List<SinkSelectedMethod> selectedMethods() {
        return List.copyOf(selected);
    }

    /** One line per selected method: {@code owner\tname\tdesc\tsignature}. */
    public synchronized String encodeSinkManifest() {
        return result().encodeSinkManifest();
    }

    /** RegisterNatives wiring plus a guarded standalone {@code JNI_OnLoad}. */
    public synchronized String registerNativesSnippet() {
        return result().registerNativesSnippet();
    }

    /** RegisterNatives wiring; set {@code includeJniOnLoad=false} for existing native libs. */
    public synchronized String registerNativesSnippet(boolean includeJniOnLoad) {
        return result().registerNativesSnippet(includeJniOnLoad);
    }

    /** Complete generated translation unit (functions + registration). */
    public synchronized String cppUnit() {
        return result().cppUnit();
    }

    /** Complete generated translation unit without the {@code JNI_OnLoad} wrapper. */
    public synchronized String cppUnit(boolean includeJniOnLoad) {
        return result().cppUnit(includeJniOnLoad);
    }

    /** Clears accumulated state so one transformer instance can serve several build passes. */
    public synchronized void reset() {
        selected.clear();
        skippedByReason.clear();
        methodsVisited = 0;
        classesVisited = 0;
        mixinClassesSkipped = 0;
    }

    /** Sum of the selected methods' weights (reporting). */
    public synchronized long selectedWeight() {
        long total = 0;
        for (SinkSelectedMethod method : selected) {
            total += method.weight();
        }
        return total;
    }
}
