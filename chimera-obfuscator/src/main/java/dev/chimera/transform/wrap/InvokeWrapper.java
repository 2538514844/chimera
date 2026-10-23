package dev.chimera.transform.wrap;

import dev.chimera.core.TransformContext;
import dev.chimera.core.Transformer;
import dev.chimera.transform.indy.IndyDispatchTransformer;
import dev.chimera.transform.indy.MemberIdRegistry;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * B6 / S6: rewrites external {@code INVOKESTATIC}/{@code INVOKEVIRTUAL} call sites into calls to
 * generated private static wrapper methods.
 *
 * <p>Two wrapper bodies are supported:</p>
 * <ul>
 *   <li>{@link Mode#DIRECT} (default): the wrapper contains the original invocation. The call site
 *       no longer names the external owner/member, the operand-stack shape is unchanged, and
 *       exceptions/returns behave exactly like the original call. This is suitable for Fabric
 *       production today and is a pre-stage for S5: once the target class moves into a hidden
 *       class, only the wrapper body needs to be rewritten.</li>
 *   <li>{@link Mode#MEMBER_ID}: the wrapper resolves the target through
 *       {@link MemberIdRegistry} and invokes a cached {@link java.lang.invoke.MethodHandle} via
 *       {@link WrapperSupport}. The call site and the wrapper body only carry two {@code long}
 *       ids, removing the target symbol from the class file. Requires the CHMI member table
 *       (including {@link Stats#targets()}) to be loaded at runtime.</li>
 * </ul>
 *
 * <p>Conservative skip rules (never rewritten):</p>
 * <ul>
 *   <li>Mixin / MixinExtras classes as a whole; {@link #transformClass(byte[])} returns their
 *       bytes verbatim (Signature/debug attributes preserved);</li>
 *   <li>{@code <init>}/{@code <clinit>} bodies (constructors are the most order/exception
 *       sensitive code and are left byte-for-byte structurally intact);</li>
 *   <li>calls whose owner is the current class (keeps the transform idempotent and avoids wrapping
 *       helper methods recursively), the obfuscator's own {@code dev/chimera/} packages, arrays,
 *       and reflection/MethodHandle-sensitive JDK owners;</li>
 *   <li>owners in the configurable whitelist (default: JDK packages {@code java/ javax/ jdk/ sun/
 *       com/sun/});</li>
 *   <li>interfaces compiled before Java 9 (private interface methods are illegal there).</li>
 * </ul>
 *
 * <p>Generated wrapper methods are named {@code chimera$invoke$N}, are private static synthetic,
 * have the same parameter/return shape as the replaced site (the receiver becomes the first
 * parameter for virtual calls) and are deduplicated per target. A second pass skips generated
 * wrappers, so the transform is idempotent.</p>
 */
public final class InvokeWrapper implements Transformer {

    private static final String WRAPPER_PREFIX = "chimera$invoke$";
    private static final String SELF_PACKAGE = "dev/chimera/";
    private static final String WRAPPER_SUPPORT = "dev/chimera/transform/wrap/WrapperSupport";
    private static final String MIXIN_ANNOTATION_PREFIX = "Lorg/spongepowered/asm/mixin";
    private static final String MIXIN_EXTRAS_PREFIX = "Lcom/llamalad7/mixinextras/";

    private static final Set<String> REFLECTIVE_OWNERS = Set.of(
            "java/lang/Class",
            "java/lang/ClassLoader",
            "java/lang/Module",
            "java/lang/reflect/AccessibleObject",
            "java/lang/invoke/MethodHandles",
            "java/lang/invoke/MethodHandle",
            "java/lang/invoke/MethodType",
            "java/lang/invoke/MethodHandles$Lookup"
    );

    /** How a wrapper method reaches its target. */
    public enum Mode {
        /** Wrapper contains the original invocation (behaviour-identical, default). */
        DIRECT,
        /** Wrapper resolves (classId, memberId) through {@link MemberIdRegistry} and a MethodHandle. */
        MEMBER_ID
    }

    /** Configuration; the Lead can map these to {@code ChimeraConfig} fields. */
    public record Options(Mode mode, Set<String> whitelist) {

        /** JDK packages are never wrapped: no S5 benefit and pure overhead. */
        public static final Set<String> DEFAULT_WHITELIST =
                Set.of("java/", "javax/", "jdk/", "sun/", "com/sun/");

        public Options(Mode mode, Set<String> whitelist) {
            this.mode = mode == null ? Mode.DIRECT : mode;
            this.whitelist = whitelist == null ? DEFAULT_WHITELIST : Set.copyOf(whitelist);
        }

        public static Options defaults() {
            return new Options(Mode.DIRECT, DEFAULT_WHITELIST);
        }

        public static Options direct(Set<String> whitelist) {
            return new Options(Mode.DIRECT, whitelist);
        }

        public static Options memberId() {
            return new Options(Mode.MEMBER_ID, DEFAULT_WHITELIST);
        }
    }

    /** Why one call site was left as a direct invocation. */
    public enum SkipReason {
        METHOD_INIT("init_method"),
        METHOD_CLINIT("clinit_method"),
        CONSTRUCTOR_CALL("constructor_call"),
        MIXIN_CLASS("mixin_class"),
        SELF_CLASS("self_class"),
        SELF_PACKAGE("self_package"),
        REFLECTION_SENSITIVE("reflection_sensitive"),
        WHITELIST("whitelist"),
        UNSUPPORTED_OWNER("unsupported_owner"),
        INTERFACE_VERSION("interface_version"),
        UNSUPPORTED_METHOD("unsupported_method");

        private final String label;

        SkipReason(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }
    }

    /** One rewritten member target, needed to extend the runtime member-id table (MEMBER_ID mode). */
    public record Target(long classId, long memberId, String owner, String name, String desc,
                         boolean isStatic) {
    }

    /** Immutable statistics snapshot (the Lead maps these to {@code dev.chimera.core.Stats}). */
    public record Stats(int classesVisited, int classesSkippedMixin, int classesSkippedInterfaceVersion,
                        int classesSkippedSelfPackage, int invokeSites, int rewritten,
                        int rewrittenStatic, int rewrittenVirtual, int wrappersGenerated,
                        int classesWithRewrite, Map<String, Integer> skipDistribution,
                        List<Target> targets) {

        public int skipped() {
            return invokeSites - rewritten;
        }

        public int preservedMixinClasses() {
            return classesSkippedMixin;
        }

        public int skipCount(SkipReason reason) {
            return skipDistribution.getOrDefault(reason.label(), 0);
        }

        @Override
        public String toString() {
            return "wrapClasses=" + classesVisited + ", mixinSkip=" + classesSkippedMixin
                    + ", sites=" + invokeSites + ", wrapped=" + rewritten + "/" + invokeSites
                    + ", wrappers=" + wrappersGenerated + ", skipped=" + skipped()
                    + ", reasons=" + skipDistribution + ", targets=" + targets.size();
        }
    }

    /** Result of {@link #transformClass(byte[])}. */
    public record TransformResult(byte[] bytes, Stats stats) {
    }

    private final Options options;

    private int classesVisited;
    private int classesSkippedMixin;
    private int classesSkippedInterfaceVersion;
    private int classesSkippedSelfPackage;
    private int invokeSites;
    private int rewritten;
    private int rewrittenStatic;
    private int rewrittenVirtual;
    private int wrappersGenerated;
    private int classesWithRewrite;
    private final EnumMap<SkipReason, Integer> skips = new EnumMap<>(SkipReason.class);
    private final LinkedHashMap<String, Target> targets = new LinkedHashMap<>();

    public InvokeWrapper() {
        this(Options.defaults());
    }

    public InvokeWrapper(Options options) {
        this.options = options == null ? Options.defaults() : options;
    }

    public Options options() {
        return options;
    }

    @Override
    public void transform(String internalName, ClassNode node, TransformContext ctx) {
        transformNode(node);
    }

    /** Applies the transform to {@code node} in place. */
    public void transformNode(ClassNode node) {
        classesVisited++;
        if (node == null || node.name == null || node.methods == null) {
            return;
        }
        if (node.name.startsWith(SELF_PACKAGE) || "module-info".equals(node.name)) {
            classesSkippedSelfPackage++;
            countSkippedSites(node, SkipReason.SELF_PACKAGE);
            return;
        }
        if (isMixinClass(node)) {
            classesSkippedMixin++;
            countSkippedSites(node, SkipReason.MIXIN_CLASS);
            return;
        }
        boolean interfaceOwner = (node.access & Opcodes.ACC_INTERFACE) != 0;
        if (interfaceOwner && node.version < Opcodes.V9) {
            classesSkippedInterfaceVersion++;
            countSkippedSites(node, SkipReason.INTERFACE_VERSION);
            return;
        }

        int rewrittenBefore = rewritten;
        Map<SiteKey, String> wrappers = new LinkedHashMap<>();
        for (MethodNode method : new ArrayList<>(node.methods)) {
            if (method == null || method.instructions == null || isGeneratedWrapper(method)) {
                continue;
            }
            int sites = eligibleSites(method);
            if (sites == 0) {
                continue;
            }
            invokeSites += sites;
            if ("<init>".equals(method.name)) {
                skipMany(sites, SkipReason.METHOD_INIT);
                continue;
            }
            if ("<clinit>".equals(method.name)) {
                skipMany(sites, SkipReason.METHOD_CLINIT);
                continue;
            }
            if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) {
                skipMany(sites, SkipReason.UNSUPPORTED_METHOD);
                continue;
            }
            rewriteMethod(node, method, wrappers, interfaceOwner);
        }
        if (rewritten > rewrittenBefore) {
            classesWithRewrite++;
        }
    }

    private void rewriteMethod(ClassNode owner, MethodNode method, Map<SiteKey, String> wrappers,
                               boolean interfaceOwner) {
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext();
            if (insn instanceof MethodInsnNode call) {
                int opcode = call.getOpcode();
                if (opcode == Opcodes.INVOKESTATIC || opcode == Opcodes.INVOKEVIRTUAL) {
                    SkipReason reason = classify(owner, call);
                    if (reason != null) {
                        skip(reason);
                    } else {
                        SiteKey key = new SiteKey(opcode, call.owner, call.name, call.desc);
                        String wrapperName = wrappers.get(key);
                        if (wrapperName == null) {
                            wrapperName = nextWrapperName(owner);
                            addWrapper(owner, call, wrapperName, opcode);
                            wrappers.put(key, wrapperName);
                            wrappersGenerated++;
                            recordTarget(call, opcode);
                        }
                        String siteDescriptor = siteDescriptor(call, opcode);
                        method.instructions.set(insn, new MethodInsnNode(Opcodes.INVOKESTATIC,
                                owner.name, wrapperName, siteDescriptor, interfaceOwner));
                        rewritten++;
                        if (opcode == Opcodes.INVOKESTATIC) {
                            rewrittenStatic++;
                        } else {
                            rewrittenVirtual++;
                        }
                    }
                }
            }
            insn = next;
        }
    }

    private SkipReason classify(ClassNode owner, MethodInsnNode call) {
        if ("<init>".equals(call.name) || "<clinit>".equals(call.name)) {
            return SkipReason.CONSTRUCTOR_CALL;
        }
        if (call.owner == null || call.owner.isEmpty() || call.owner.startsWith("[")) {
            return SkipReason.UNSUPPORTED_OWNER;
        }
        if (call.owner.equals(owner.name)) {
            // Same-class calls do not leak an external symbol and this keeps a second pass idempotent.
            return SkipReason.SELF_CLASS;
        }
        if (call.owner.startsWith(SELF_PACKAGE)) {
            return SkipReason.SELF_PACKAGE;
        }
        if (isReflectionSensitive(call.owner)) {
            return SkipReason.REFLECTION_SENSITIVE;
        }
        if (whitelisted(call.owner)) {
            return SkipReason.WHITELIST;
        }
        return null;
    }

    private boolean whitelisted(String owner) {
        for (String prefix : options.whitelist()) {
            if (owner.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isReflectionSensitive(String owner) {
        return owner.startsWith("java/lang/reflect/")
                || owner.startsWith("java/lang/invoke/")
                || REFLECTIVE_OWNERS.contains(owner);
    }

    // ------------------------------------------------------------------ wrapper emission

    private void addWrapper(ClassNode owner, MethodInsnNode call, String wrapperName, int opcode) {
        String wrapperDescriptor = siteDescriptor(call, opcode);
        int access = Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC;
        MethodNode wrapper = new MethodNode(access, wrapperName, wrapperDescriptor, null, null);
        if (options.mode() == Mode.MEMBER_ID) {
            emitMemberIdWrapper(wrapper, call, wrapperDescriptor, opcode);
        } else {
            emitDirectWrapper(wrapper, call, wrapperDescriptor, opcode);
        }
        owner.methods.add(wrapper);
    }

    private static void emitDirectWrapper(MethodNode wrapper, MethodInsnNode call,
                                          String descriptor, int opcode) {
        Type[] parameters = Type.getArgumentTypes(descriptor);
        int slot = 0;
        for (Type parameter : parameters) {
            wrapper.instructions.add(load(parameter, slot));
            slot += parameter.getSize();
        }
        wrapper.instructions.add(new MethodInsnNode(opcode, call.owner, call.name, call.desc, call.itf));
        wrapper.instructions.add(returnInstruction(Type.getReturnType(call.desc)));
        wrapper.maxLocals = slot;
        wrapper.maxStack = slot + 6;
    }

    private static void emitMemberIdWrapper(MethodNode wrapper, MethodInsnNode call,
                                            String descriptor, int opcode) {
        Type[] parameters = Type.getArgumentTypes(descriptor);
        Type returnType = Type.getReturnType(call.desc);
        boolean virtual = opcode == Opcodes.INVOKEVIRTUAL;
        InsnList code = wrapper.instructions;
        pushLong(code, MemberIdRegistry.classId(call.owner));
        pushLong(code, MemberIdRegistry.memberId(call.owner, call.name, call.desc));
        if (virtual) {
            code.add(new VarInsnNode(Opcodes.ALOAD, 0));
        } else {
            code.add(new InsnNode(Opcodes.ACONST_NULL));
        }
        int argumentCount = parameters.length - (virtual ? 1 : 0);
        pushInt(code, argumentCount);
        code.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Object"));
        int slot = 0;
        int arrayIndex = 0;
        for (int i = 0; i < parameters.length; i++) {
            Type parameter = parameters[i];
            if (virtual && i == 0) {
                slot += parameter.getSize();
                continue;
            }
            code.add(new InsnNode(Opcodes.DUP));
            pushInt(code, arrayIndex++);
            code.add(load(parameter, slot));
            box(code, parameter);
            code.add(new InsnNode(Opcodes.AASTORE));
            slot += parameter.getSize();
        }
        code.add(new MethodInsnNode(Opcodes.INVOKESTATIC, WRAPPER_SUPPORT, "invoke",
                "(JJLjava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false));
        appendConvertedReturn(code, returnType);
        wrapper.maxLocals = slot;
        wrapper.maxStack = Math.max(8, slot + 8);
    }

    private static String siteDescriptor(MethodInsnNode call, int opcode) {
        if (opcode == Opcodes.INVOKESTATIC) {
            return call.desc;
        }
        Type returnType = Type.getReturnType(call.desc);
        Type[] arguments = Type.getArgumentTypes(call.desc);
        Type[] siteArguments = new Type[arguments.length + 1];
        siteArguments[0] = Type.getObjectType(call.owner);
        System.arraycopy(arguments, 0, siteArguments, 1, arguments.length);
        return Type.getMethodDescriptor(returnType, siteArguments);
    }

    private static VarInsnNode load(Type type, int slot) {
        return switch (type.getSort()) {
            case Type.BOOLEAN, Type.BYTE, Type.CHAR, Type.SHORT, Type.INT
                    -> new VarInsnNode(Opcodes.ILOAD, slot);
            case Type.LONG -> new VarInsnNode(Opcodes.LLOAD, slot);
            case Type.FLOAT -> new VarInsnNode(Opcodes.FLOAD, slot);
            case Type.DOUBLE -> new VarInsnNode(Opcodes.DLOAD, slot);
            default -> new VarInsnNode(Opcodes.ALOAD, slot);
        };
    }

    private static InsnNode returnInstruction(Type type) {
        return switch (type.getSort()) {
            case Type.VOID -> new InsnNode(Opcodes.RETURN);
            case Type.LONG -> new InsnNode(Opcodes.LRETURN);
            case Type.FLOAT -> new InsnNode(Opcodes.FRETURN);
            case Type.DOUBLE -> new InsnNode(Opcodes.DRETURN);
            case Type.OBJECT, Type.ARRAY -> new InsnNode(Opcodes.ARETURN);
            default -> new InsnNode(Opcodes.IRETURN);
        };
    }

    private static void box(InsnList code, Type type) {
        switch (type.getSort()) {
            case Type.BOOLEAN -> code.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                    "java/lang/Boolean", "valueOf", "(Z)Ljava/lang/Boolean;", false));
            case Type.BYTE -> code.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                    "java/lang/Byte", "valueOf", "(B)Ljava/lang/Byte;", false));
            case Type.CHAR -> code.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                    "java/lang/Character", "valueOf", "(C)Ljava/lang/Character;", false));
            case Type.SHORT -> code.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                    "java/lang/Short", "valueOf", "(S)Ljava/lang/Short;", false));
            case Type.INT -> code.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                    "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;", false));
            case Type.LONG -> code.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                    "java/lang/Long", "valueOf", "(J)Ljava/lang/Long;", false));
            case Type.FLOAT -> code.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                    "java/lang/Float", "valueOf", "(F)Ljava/lang/Float;", false));
            case Type.DOUBLE -> code.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                    "java/lang/Double", "valueOf", "(D)Ljava/lang/Double;", false));
            default -> {
                // reference/array values are already objects
            }
        }
    }

    private static void appendConvertedReturn(InsnList code, Type type) {
        switch (type.getSort()) {
            case Type.VOID -> {
                code.add(new InsnNode(Opcodes.POP));
                code.add(new InsnNode(Opcodes.RETURN));
            }
            case Type.BOOLEAN -> {
                code.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Boolean"));
                code.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Boolean",
                        "booleanValue", "()Z", false));
                code.add(new InsnNode(Opcodes.IRETURN));
            }
            case Type.BYTE -> {
                code.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Byte"));
                code.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Byte",
                        "byteValue", "()B", false));
                code.add(new InsnNode(Opcodes.IRETURN));
            }
            case Type.CHAR -> {
                code.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Character"));
                code.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Character",
                        "charValue", "()C", false));
                code.add(new InsnNode(Opcodes.IRETURN));
            }
            case Type.SHORT -> {
                code.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Short"));
                code.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Short",
                        "shortValue", "()S", false));
                code.add(new InsnNode(Opcodes.IRETURN));
            }
            case Type.INT -> {
                code.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Integer"));
                code.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Integer",
                        "intValue", "()I", false));
                code.add(new InsnNode(Opcodes.IRETURN));
            }
            case Type.LONG -> {
                code.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Long"));
                code.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Long",
                        "longValue", "()J", false));
                code.add(new InsnNode(Opcodes.LRETURN));
            }
            case Type.FLOAT -> {
                code.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Float"));
                code.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Float",
                        "floatValue", "()F", false));
                code.add(new InsnNode(Opcodes.FRETURN));
            }
            case Type.DOUBLE -> {
                code.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Double"));
                code.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Double",
                        "doubleValue", "()D", false));
                code.add(new InsnNode(Opcodes.DRETURN));
            }
            case Type.ARRAY -> {
                code.add(new TypeInsnNode(Opcodes.CHECKCAST, type.getDescriptor()));
                code.add(new InsnNode(Opcodes.ARETURN));
            }
            default -> {
                code.add(new TypeInsnNode(Opcodes.CHECKCAST, type.getInternalName()));
                code.add(new InsnNode(Opcodes.ARETURN));
            }
        }
    }

    private static void pushInt(InsnList code, int value) {
        if (value >= -1 && value <= 5) {
            code.add(new InsnNode(Opcodes.ICONST_0 + value));
        } else if (value >= Byte.MIN_VALUE && value <= Byte.MAX_VALUE) {
            code.add(new org.objectweb.asm.tree.IntInsnNode(Opcodes.BIPUSH, value));
        } else if (value >= Short.MIN_VALUE && value <= Short.MAX_VALUE) {
            code.add(new org.objectweb.asm.tree.IntInsnNode(Opcodes.SIPUSH, value));
        } else {
            code.add(new org.objectweb.asm.tree.LdcInsnNode(Integer.valueOf(value)));
        }
    }

    private static void pushLong(InsnList code, long value) {
        if (value == 0L) {
            code.add(new InsnNode(Opcodes.LCONST_0));
        } else if (value == 1L) {
            code.add(new InsnNode(Opcodes.LCONST_1));
        } else {
            code.add(new org.objectweb.asm.tree.LdcInsnNode(Long.valueOf(value)));
        }
    }

    // ------------------------------------------------------------------ bookkeeping

    private void countSkippedSites(ClassNode node, SkipReason reason) {
        int sites = 0;
        for (MethodNode method : node.methods) {
            if (method == null || method.instructions == null || isGeneratedWrapper(method)) {
                continue;
            }
            sites += eligibleSites(method);
        }
        invokeSites += sites;
        skipMany(sites, reason);
    }

    private static int eligibleSites(MethodNode method) {
        if (method.instructions == null) {
            return 0;
        }
        int count = 0;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            int opcode = insn.getOpcode();
            if (opcode == Opcodes.INVOKESTATIC || opcode == Opcodes.INVOKEVIRTUAL) {
                count++;
            }
        }
        return count;
    }

    private void recordTarget(MethodInsnNode call, int opcode) {
        long classId = MemberIdRegistry.classId(call.owner);
        long memberId = MemberIdRegistry.memberId(call.owner, call.name, call.desc);
        String key = classId + ":" + memberId;
        targets.putIfAbsent(key, new Target(classId, memberId, call.owner, call.name, call.desc,
                opcode == Opcodes.INVOKESTATIC));
    }

    private static String nextWrapperName(ClassNode owner) {
        for (int i = 0; ; i++) {
            String candidate = WRAPPER_PREFIX + i;
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

    private static boolean isGeneratedWrapper(MethodNode method) {
        return method.name != null && method.name.startsWith(WRAPPER_PREFIX)
                && (method.access & Opcodes.ACC_SYNTHETIC) != 0;
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

    private void skip(SkipReason reason) {
        skips.merge(reason, 1, Integer::sum);
    }

    private void skipMany(int count, SkipReason reason) {
        if (count > 0) {
            skips.merge(reason, count, Integer::sum);
        }
    }

    // ------------------------------------------------------------------ counters / facade

    public int invokeSites() {
        return invokeSites;
    }

    public int rewritten() {
        return rewritten;
    }

    public int skipped() {
        return invokeSites - rewritten;
    }

    public int wrappersGenerated() {
        return wrappersGenerated;
    }

    public int classesWithRewrite() {
        return classesWithRewrite;
    }

    public int classesVisited() {
        return classesVisited;
    }

    public int preservedMixinClasses() {
        return classesSkippedMixin;
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

    public List<Target> targets() {
        return List.copyOf(targets.values());
    }

    public Stats stats() {
        return new Stats(classesVisited, classesSkippedMixin, classesSkippedInterfaceVersion,
                classesSkippedSelfPackage, invokeSites, rewritten, rewrittenStatic, rewrittenVirtual,
                wrappersGenerated, classesWithRewrite,
                Collections.unmodifiableMap(skipDistribution()), List.copyOf(targets.values()));
    }

    /**
     * Encodes the {@link Stats#targets()} of a build as a CHMI member table accepted by
     * {@link MemberIdRegistry#loadMemberTable(byte[], ClassLoader)}. The engine can write these
     * bytes as a resource and load them before the first MEMBER_ID wrapper call; the target table
     * may be loaded in addition to the M10 indy table (the registry merges entries).
     */
    public static byte[] encodeTargetTable(Stats stats) {
        if (stats == null) {
            throw new IllegalArgumentException("stats must not be null");
        }
        List<Target> entries = stats.targets();
        LinkedHashMap<Long, String> owners = new LinkedHashMap<>();
        for (Target target : entries) {
            owners.putIfAbsent(target.classId(), target.owner());
        }
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream(
                    32 + (owners.size() + entries.size()) * 64);
            DataOutputStream out = new DataOutputStream(buffer);
            out.writeInt(MemberIdRegistry.MEMBER_TABLE_MAGIC);
            out.writeInt(MemberIdRegistry.MEMBER_TABLE_VERSION);
            out.writeInt(owners.size() + entries.size());
            for (Map.Entry<Long, String> owner : owners.entrySet()) {
                out.writeByte(MemberIdRegistry.ENTRY_CLASS);
                out.writeLong(owner.getKey());
                out.writeLong(0L);
                writeUtf(out, owner.getValue());
                writeUtf(out, "");
                writeUtf(out, "");
            }
            for (Target target : entries) {
                out.writeByte(MemberIdRegistry.ENTRY_METHOD);
                out.writeLong(target.classId());
                out.writeLong(target.memberId());
                writeUtf(out, target.owner());
                writeUtf(out, target.name());
                writeUtf(out, target.desc());
            }
            out.flush();
            return buffer.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("InvokeWrapper target table encoding failed", e);
        }
    }

    private static void writeUtf(DataOutputStream out, String value) throws IOException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        out.writeInt(bytes.length);
        out.write(bytes);
    }

    /**
     * Reads, transforms and writes one class. Mixin classes are returned byte-identical, which is
     * required because Mixin reads Signature/debug attributes at runtime.
     */
    public static TransformResult transformClass(byte[] classBytes) {
        return transformClass(classBytes, Options.defaults());
    }

    /** Options-aware variant of {@link #transformClass(byte[])}. */
    public static TransformResult transformClass(byte[] classBytes, Options options) {
        ClassReader reader = new ClassReader(classBytes);
        ClassNode node = new ClassNode();
        reader.accept(node, 0);
        InvokeWrapper wrapper = new InvokeWrapper(options);
        boolean mixin = isMixinClass(node);
        wrapper.transformNode(node);
        if (mixin) {
            return new TransformResult(classBytes, wrapper.stats());
        }
        ClassWriter writer = new ClassWriter(reader, 0);
        node.accept(writer);
        return new TransformResult(writer.toByteArray(), wrapper.stats());
    }

    // ------------------------------------------------------------------ internal model

    private record SiteKey(int opcode, String owner, String name, String desc) {
    }
}
