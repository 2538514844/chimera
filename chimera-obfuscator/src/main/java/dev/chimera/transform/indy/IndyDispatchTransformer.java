package dev.chimera.transform.indy;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * M10: rewrites static / virtual / interface (and optionally special) call sites into
 * {@code invokedynamic} bound to {@link ChimeraBootstrap}. The symbol reference
 * (owner/name/desc) is replaced by an opaque {@code (classId, memberId)} pair resolved through
 * {@link MemberIdRegistry}; the original call target is therefore absent from static call graphs.
 *
 * <p>Skipped (never rewritten), with per-reason counters:</p>
 * <ul>
 *   <li>{@code <init>} / {@code <clinit>} method bodies when {@link Options#rewriteInitializers()}
 *       is false (default, conservative);</li>
 *   <li>Mixin classes (annotations/name/super type), because Mixin rewrites bodies at runtime -
 *       their bytes are preserved verbatim by {@link #transformClass(byte[])};</li>
 *   <li>constructor calls ({@code invokespecial <init>});</li>
 *   <li>{@code invokespecial} private/super calls unless {@link Options#rewriteSpecialCalls()};</li>
 *   <li>reflection-sensitive targets ({@code java/lang/reflect/**}, {@code java/lang/invoke/**},
 *       {@code Class}/{@code ClassLoader}/{@code Module});</li>
 *   <li>the obfuscator's own runtime packages ({@code dev/chimera/**});</li>
 *   <li>unsupported owners (arrays).</li>
 * </ul>
 *
 * <p>G3 additionally rewrites field reads ({@code GETFIELD}/{@code GETSTATIC}) into
 * {@code invokedynamic} with {@link ChimeraBootstrap#KIND_FIELD} /
 * {@link ChimeraBootstrap#KIND_STATIC_FIELD}; field writes ({@code PUTFIELD}/{@code PUTSTATIC}) and
 * class literals ({@code LDC Type}) are intentionally TODO and only counted. G8 optionally rotates
 * the bootstrap owner over {@link BsmClassGenerator} ({@code classId ^ siteIndex}).</p>
 *
 * <p>The transformer mutates a {@link ClassNode} in place. Instruction replacement keeps the
 * operand-stack shape identical (receiver+args -&gt; return for calls, receiver -&gt; value for
 * field reads), so existing stack-map frames remain valid; {@link #transformClass(byte[])} writes
 * with a fresh {@link ClassWriter} (no frame re-verification, dead constants from replaced sites
 * are dropped) and is therefore usable on large third-party jars without a class hierarchy.</p>
 */
public final class IndyDispatchTransformer {

    /** Rewrite-eligible JVM invocations. */
    private static final int[] REWRITABLE_OPCODES = {
            Opcodes.INVOKESTATIC, Opcodes.INVOKEVIRTUAL, Opcodes.INVOKEINTERFACE
    };

    /** Single legacy bootstrap owner, used when BSM dispersion is disabled. */
    private static final Handle LEGACY_BSM = new Handle(Opcodes.H_INVOKESTATIC,
            ChimeraBootstrap.OWNER, ChimeraBootstrap.BSM_NAME, ChimeraBootstrap.BSM_DESC, false);

    /** Mask for the {@code (classId ^ siteIndex)} BSM rotation (count is a power of two). */
    private static final int BSM_OWNER_MASK = BsmClassGenerator.DEFAULT_COUNT - 1;

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

    /** Why one invoke site / method / class was left untouched. */
    public enum SkipReason {
        METHOD_INIT("init_method"),
        METHOD_CLINIT("clinit_method"),
        MIXIN_CLASS("mixin_class"),
        CONSTRUCTOR_CALL("constructor_call"),
        SPECIAL_CALL("special_call"),
        REFLECTION_SENSITIVE("reflection_sensitive"),
        SELF_PACKAGE("self_package"),
        UNSUPPORTED_OWNER("unsupported_owner");

        private final String label;

        SkipReason(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }
    }

    /**
     * Rewrite options; conservative is the M10 baseline, aggressive consumes initializer/special
     * sites. {@code disperseBsm} selects the G8 rotation over {@link BsmClassGenerator} owners;
     * the two-argument constructor keeps the legacy source contract (single
     * {@link ChimeraBootstrap} owner) so direct {@code transformClass} callers see no behaviour
     * change. {@link IndyIntegration} enables dispersion explicitly.
     */
    public record Options(boolean rewriteInitializers, boolean rewriteSpecialCalls,
                          boolean disperseBsm) {
        /** Original M10 behaviour: constructors/static initializers and invokespecial are skipped. */
        public static final Options CONSERVATIVE = new Options(false, false, false);
        /** M10 completion: rewrite eligible calls inside &lt;init&gt;/&lt;clinit&gt; and invokespecial. */
        public static final Options AGGRESSIVE = new Options(true, true, false);

        /** Legacy single-BSM-owner options (source compatible with the pre-G8 two-arg form). */
        public Options(boolean rewriteInitializers, boolean rewriteSpecialCalls) {
            this(rewriteInitializers, rewriteSpecialCalls, false);
        }

        public static Options defaults() {
            return CONSERVATIVE;
        }
    }

    /**
     * One rewritten member target, needed to build the runtime member-id table. Method entries
     * carry a method descriptor; field entries carry the raw field descriptor (e.g. {@code I}).
     */
    public record MemberEntry(long classId, long memberId, String owner, String name, String desc) {
    }

    /** One rewritten owner class, needed by {@code MemberIdRegistry.b()}. */
    public record ClassEntry(long classId, String internalName) {
    }

    /**
     * Aggregated rewrite/skip counters plus the deduplicated class/member payload used to build the
     * CHMI member table. Method and field entries are tracked separately so the table encoder can
     * emit {@code ENTRY_METHOD} / {@code ENTRY_FIELD} without changing the {@link MemberEntry}
     * record shape.
     */
    public static final class Stats {
        private int transformedClasses;
        private int invokeSites;
        private int rewritten;
        private int classesWithRewrite;
        private int rewrittenStatic;
        private int rewrittenVirtual;
        private int rewrittenInterface;
        private int rewrittenSpecial;
        private int fieldAccessSites;
        private int fieldReadsRewritten;
        private int fieldWritesSkipped;
        private int fieldSkippedByPolicy;
        private int classConstantsSkipped;
        private final EnumMap<SkipReason, Integer> skips = new EnumMap<>(SkipReason.class);
        private final LinkedHashMap<String, MemberEntry> methods = new LinkedHashMap<>();
        private final LinkedHashMap<String, MemberEntry> fields = new LinkedHashMap<>();
        private final LinkedHashMap<Long, String> classes = new LinkedHashMap<>();
        private final Set<String> bsmOwners = new java.util.LinkedHashSet<>();

        public int transformedClasses() {
            return transformedClasses;
        }

        public int invokeSites() {
            return invokeSites;
        }

        public int rewritten() {
            return rewritten;
        }

        public int skipped() {
            return invokeSites - rewritten;
        }

        public int classesWithRewrite() {
            return classesWithRewrite;
        }

        public int rewrittenStatic() {
            return rewrittenStatic;
        }

        public int rewrittenVirtual() {
            return rewrittenVirtual;
        }

        public int rewrittenInterface() {
            return rewrittenInterface;
        }

        public int rewrittenSpecial() {
            return rewrittenSpecial;
        }

        /** GETFIELD/GETSTATIC/PUTFIELD/PUTSTATIC sites seen (G3). */
        public int fieldAccessSites() {
            return fieldAccessSites;
        }

        /** GETFIELD/GETSTATIC sites replaced by invokedynamic (G3 reads). */
        public int fieldReadsRewritten() {
            return fieldReadsRewritten;
        }

        /** PUTFIELD/PUTSTATIC sites left untouched (G3 setter path is TODO) and counted. */
        public int fieldWritesSkipped() {
            return fieldWritesSkipped;
        }

        /** Field reads left untouched because of Mixin/initializer policy or owner classification. */
        public int fieldSkippedByPolicy() {
            return fieldSkippedByPolicy;
        }

        /** LDC class-literal sites left untouched (G3 class constants are TODO) and counted. */
        public int classConstantsSkipped() {
            return classConstantsSkipped;
        }

        /** Distinct dispersed bootstrap owners actually referenced by rewritten sites (G8). */
        public int distinctBsmOwners() {
            return bsmOwners.size();
        }

        /** Bootstrap owner internal names referenced by rewritten sites (G8 diagnostics). */
        public Set<String> bsmOwners() {
            return Set.copyOf(bsmOwners);
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

        /** Deduplicated rewritten method targets (CHMI {@code ENTRY_METHOD}). */
        public List<MemberEntry> methodEntries() {
            return List.copyOf(methods.values());
        }

        /** Deduplicated rewritten field targets (CHMI {@code ENTRY_FIELD}). */
        public List<MemberEntry> fieldEntries() {
            return List.copyOf(fields.values());
        }

        /**
         * Deduplicated rewritten targets, fields first (matching the encoded table order). Kept for
         * the existing count-based contract; use {@link #methodEntries()} / {@link #fieldEntries()}
         * when the entry kind matters.
         */
        public List<MemberEntry> memberEntries() {
            List<MemberEntry> all = new java.util.ArrayList<>(fields.size() + methods.size());
            all.addAll(fields.values());
            all.addAll(methods.values());
            return List.copyOf(all);
        }

        /** Deduplicated rewritten owner classes (for the runtime member table). */
        public List<ClassEntry> classEntries() {
            return classes.entrySet().stream()
                    .map(entry -> new ClassEntry(entry.getKey().longValue(), entry.getValue()))
                    .toList();
        }

        public void merge(Stats other) {
            transformedClasses += other.transformedClasses;
            invokeSites += other.invokeSites;
            rewritten += other.rewritten;
            classesWithRewrite += other.classesWithRewrite;
            rewrittenStatic += other.rewrittenStatic;
            rewrittenVirtual += other.rewrittenVirtual;
            rewrittenInterface += other.rewrittenInterface;
            rewrittenSpecial += other.rewrittenSpecial;
            fieldAccessSites += other.fieldAccessSites;
            fieldReadsRewritten += other.fieldReadsRewritten;
            fieldWritesSkipped += other.fieldWritesSkipped;
            fieldSkippedByPolicy += other.fieldSkippedByPolicy;
            classConstantsSkipped += other.classConstantsSkipped;
            for (SkipReason reason : SkipReason.values()) {
                int value = other.skipCount(reason);
                if (value > 0) {
                    skips.merge(reason, value, Integer::sum);
                }
            }
            methods.putAll(other.methods);
            fields.putAll(other.fields);
            classes.putAll(other.classes);
            bsmOwners.addAll(other.bsmOwners);
        }

        private void skip(SkipReason reason) {
            skips.merge(reason, 1, Integer::sum);
        }

        void recordBsmOwner(String owner) {
            if (owner != null) {
                bsmOwners.add(owner);
            }
        }

        void recordMethodMember(long classId, long memberId, String owner, String name, String desc) {
            recordMember(methods, classId, memberId, owner, name, desc);
        }

        void recordFieldMember(long classId, long memberId, String owner, String name, String desc) {
            recordMember(fields, classId, memberId, owner, name, desc);
        }

        private void recordMember(LinkedHashMap<String, MemberEntry> target, long classId,
                                  long memberId, String owner, String name, String desc) {
            target.putIfAbsent(classId + ":" + memberId,
                    new MemberEntry(classId, memberId, owner, name, desc));
            classes.putIfAbsent(Long.valueOf(classId), owner);
        }

        @Override
        public String toString() {
            return "classes=" + transformedClasses + ", rewrittenClasses=" + classesWithRewrite
                    + ", invokeSites=" + invokeSites + ", rewritten=" + rewritten
                    + ", skipped=" + skipped() + ", reasons=" + skipDistribution()
                    + ", fields=" + fieldReadsRewritten + "r/" + fieldWritesSkipped + "w"
                    + ", classLdc=" + classConstantsSkipped
                    + ", bsmOwners=" + bsmOwners.size()
                    + ", members=" + (methods.size() + fields.size());
        }
    }

    /** Result of {@link #transformClass(byte[])}. */
    public record TransformResult(byte[] bytes, Stats stats) {
    }

    private final Options options;

    public IndyDispatchTransformer() {
        this(Options.CONSERVATIVE);
    }

    public IndyDispatchTransformer(Options options) {
        this.options = options == null ? Options.CONSERVATIVE : options;
    }

    public Options options() {
        return options;
    }

    /** Rewrites all eligible call and field-read sites of {@code node} in place. */
    public Stats transform(ClassNode node) {
        Stats stats = new Stats();
        stats.transformedClasses++;
        if (node == null || node.methods == null || node.methods.isEmpty()) {
            return stats;
        }

        boolean mixin = isMixinClass(node);
        // Per-class site ordinal feeding the G8 (classId ^ siteIndex) BSM rotation.
        int[] siteCounter = {0};
        for (MethodNode method : node.methods) {
            int sites = countInvokeSites(method);
            int fieldSites = countFieldSites(method);
            stats.invokeSites += sites;
            stats.fieldAccessSites += fieldSites;
            stats.classConstantsSkipped += countClassConstants(method);
            if (sites == 0 && fieldSites == 0) {
                continue;
            }
            if (mixin) {
                for (int i = 0; i < sites; i++) {
                    stats.skip(SkipReason.MIXIN_CLASS);
                }
                stats.fieldSkippedByPolicy += fieldSites;
                continue;
            }
            if (!options.rewriteInitializers() && "<init>".equals(method.name)) {
                for (int i = 0; i < sites; i++) {
                    stats.skip(SkipReason.METHOD_INIT);
                }
                stats.fieldSkippedByPolicy += fieldSites;
                continue;
            }
            if (!options.rewriteInitializers() && "<clinit>".equals(method.name)) {
                for (int i = 0; i < sites; i++) {
                    stats.skip(SkipReason.METHOD_CLINIT);
                }
                stats.fieldSkippedByPolicy += fieldSites;
                continue;
            }
            if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0
                    || method.instructions == null) {
                for (int i = 0; i < sites; i++) {
                    stats.skip(SkipReason.UNSUPPORTED_OWNER);
                }
                stats.fieldSkippedByPolicy += fieldSites;
                continue;
            }
            rewriteMethod(method, stats, siteCounter);
        }
        if (stats.rewritten > 0 || stats.fieldReadsRewritten > 0) {
            stats.classesWithRewrite++;
        }
        return stats;
    }

    private void rewriteMethod(MethodNode method, Stats stats, int[] siteCounter) {
        AbstractInsnNode insn = method.instructions.getFirst();
        while (insn != null) {
            AbstractInsnNode next = insn.getNext();
            if (insn instanceof MethodInsnNode call) {
                int opcode = call.getOpcode();
                if (opcode == Opcodes.INVOKESPECIAL) {
                    boolean constructor = "<init>".equals(call.name) || "<clinit>".equals(call.name);
                    if (options.rewriteSpecialCalls() && !constructor) {
                        SkipReason skip = classify(call);
                        if (skip != null) {
                            stats.skip(skip);
                        } else {
                            install(method, insn, call, ChimeraBootstrap.KIND_SPECIAL,
                                    siteCounter, stats);
                        }
                    } else {
                        stats.skip(constructor ? SkipReason.CONSTRUCTOR_CALL : SkipReason.SPECIAL_CALL);
                    }
                } else if (opcode == Opcodes.INVOKESTATIC || opcode == Opcodes.INVOKEVIRTUAL
                        || opcode == Opcodes.INVOKEINTERFACE) {
                    SkipReason skip = classify(call);
                    if (skip != null) {
                        stats.skip(skip);
                    } else {
                        int kind = opcode == Opcodes.INVOKESTATIC
                                ? ChimeraBootstrap.KIND_STATIC
                                : opcode == Opcodes.INVOKEINTERFACE
                                        ? ChimeraBootstrap.KIND_INTERFACE
                                        : ChimeraBootstrap.KIND_VIRTUAL;
                        install(method, insn, call, kind, siteCounter, stats);
                    }
                }
            } else if (insn instanceof FieldInsnNode field) {
                int opcode = field.getOpcode();
                if (opcode == Opcodes.GETFIELD || opcode == Opcodes.GETSTATIC) {
                    if (classifyField(field) != null) {
                        stats.fieldSkippedByPolicy++;
                    } else {
                        installField(method, insn, field,
                                opcode == Opcodes.GETSTATIC
                                        ? ChimeraBootstrap.KIND_STATIC_FIELD
                                        : ChimeraBootstrap.KIND_FIELD,
                                siteCounter, stats);
                    }
                } else if (opcode == Opcodes.PUTFIELD || opcode == Opcodes.PUTSTATIC) {
                    // G3 setter path (findSetter/findStaticSetter) is intentionally TODO: writes
                    // stay plain and are counted so the report exposes the remaining surface.
                    stats.fieldWritesSkipped++;
                }
            }
            insn = next;
        }
    }

    private void install(MethodNode method, AbstractInsnNode insn, MethodInsnNode call,
                         int kind, int[] siteCounter, Stats stats) {
        String siteDescriptor = callSiteDescriptor(call, kind);
        long classId = MemberIdRegistry.classId(call.owner);
        long memberId = MemberIdRegistry.memberId(call.owner, call.name, call.desc);
        InvokeDynamicInsnNode indy = new InvokeDynamicInsnNode(call.name, siteDescriptor,
                bsmHandle(classId, siteCounter[0]++, stats),
                Long.valueOf(classId), Long.valueOf(memberId), Integer.valueOf(kind));
        method.instructions.set(insn, indy);
        stats.rewritten++;
        switch (kind) {
            case ChimeraBootstrap.KIND_STATIC -> stats.rewrittenStatic++;
            case ChimeraBootstrap.KIND_INTERFACE -> stats.rewrittenInterface++;
            case ChimeraBootstrap.KIND_SPECIAL -> stats.rewrittenSpecial++;
            default -> stats.rewrittenVirtual++;
        }
        stats.recordMethodMember(classId, memberId, call.owner, call.name, call.desc);
    }

    /**
     * G3: rewrites a field read into {@code invokedynamic}. The call-site descriptor keeps the
     * original operand-stack shape ({@code (Owner)Value} for GETFIELD, {@code ()Value} for
     * GETSTATIC), so existing stack-map frames stay valid. Field writes are TODO and never
     * rewritten.
     */
    private void installField(MethodNode method, AbstractInsnNode insn, FieldInsnNode field,
                              int kind, int[] siteCounter, Stats stats) {
        long classId = MemberIdRegistry.classId(field.owner);
        long memberId = MemberIdRegistry.memberId(field.owner, field.name, field.desc);
        Type valueType = fieldSiteValueType(field.desc);
        String siteDescriptor = kind == ChimeraBootstrap.KIND_STATIC_FIELD
                ? Type.getMethodDescriptor(valueType)
                : Type.getMethodDescriptor(valueType, Type.getObjectType(field.owner));
        InvokeDynamicInsnNode indy = new InvokeDynamicInsnNode(field.name, siteDescriptor,
                bsmHandle(classId, siteCounter[0]++, stats),
                Long.valueOf(classId), Long.valueOf(memberId), Integer.valueOf(kind));
        method.instructions.set(insn, indy);
        stats.fieldReadsRewritten++;
        stats.recordFieldMember(classId, memberId, field.owner, field.name, field.desc);
    }

    /** G8: picks the dispersed bootstrap owner ({@code classId ^ siteIndex}) or the legacy one. */
    private Handle bsmHandle(long classId, int siteIndex, Stats stats) {
        if (!options.disperseBsm()) {
            return LEGACY_BSM;
        }
        int index = (int) ((classId ^ (long) siteIndex) & BSM_OWNER_MASK);
        String owner = BsmClassGenerator.owner(index);
        stats.recordBsmOwner(owner);
        return BsmClassGenerator.handle(index);
    }

    /**
     * Value type used in the field call-site descriptor. The declared descriptor is reused
     * verbatim: {@code Z/B/C/S} all verify as {@code int}, so the operand-stack shape is
     * unchanged, while the call-site type matches {@code Lookup.findGetter/findStaticGetter}
     * exactly. That matters for {@code boolean}, where {@code MethodHandle.asType} performs no
     * {@code boolean -> int} conversion (byte/char/short would widen, but exact is simpler).
     */
    static Type fieldSiteValueType(String fieldDescriptor) {
        return Type.getType(fieldDescriptor);
    }

    private static SkipReason classify(MethodInsnNode call) {
        if ("<init>".equals(call.name) || "<clinit>".equals(call.name)) {
            return SkipReason.CONSTRUCTOR_CALL;
        }
        if (call.owner == null || call.owner.isEmpty() || call.owner.startsWith("[")) {
            return SkipReason.UNSUPPORTED_OWNER;
        }
        if (call.owner.startsWith("dev/chimera/")) {
            return SkipReason.SELF_PACKAGE;
        }
        if (isReflectionSensitive(call)) {
            return SkipReason.REFLECTION_SENSITIVE;
        }
        return null;
    }

    private static boolean isReflectionSensitive(MethodInsnNode call) {
        return isReflectiveOwner(call.owner);
    }

    private static boolean isReflectiveOwner(String owner) {
        return owner != null && (owner.startsWith("java/lang/reflect/")
                || owner.startsWith("java/lang/invoke/")
                || REFLECTIVE_OWNERS.contains(owner));
    }

    /**
     * G3 owner policy for field reads: the same self-package / reflection exclusions as calls.
     * Array owners never appear on FieldInsnNode, but an empty owner is still rejected.
     */
    private static SkipReason classifyField(FieldInsnNode field) {
        if (field.name == null || field.name.isEmpty() || field.owner == null
                || field.owner.isEmpty() || field.owner.startsWith("[")) {
            return SkipReason.UNSUPPORTED_OWNER;
        }
        if (field.owner.startsWith("dev/chimera/")) {
            return SkipReason.SELF_PACKAGE;
        }
        if (isReflectiveOwner(field.owner)) {
            return SkipReason.REFLECTION_SENSITIVE;
        }
        return null;
    }

    private static String callSiteDescriptor(MethodInsnNode call, int kind) {
        if (kind == ChimeraBootstrap.KIND_STATIC) {
            return call.desc;
        }
        Type returnType = Type.getReturnType(call.desc);
        Type[] arguments = Type.getArgumentTypes(call.desc);
        Type[] siteArguments = new Type[arguments.length + 1];
        siteArguments[0] = Type.getObjectType(call.owner);
        System.arraycopy(arguments, 0, siteArguments, 1, arguments.length);
        return Type.getMethodDescriptor(returnType, siteArguments);
    }

    private static int countInvokeSites(MethodNode method) {
        if (method.instructions == null) {
            return 0;
        }
        int count = 0;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            int opcode = insn.getOpcode();
            if (opcode == Opcodes.INVOKESTATIC || opcode == Opcodes.INVOKEVIRTUAL
                    || opcode == Opcodes.INVOKEINTERFACE || opcode == Opcodes.INVOKESPECIAL) {
                count++;
            }
        }
        return count;
    }

    /** GETFIELD/GETSTATIC/PUTFIELD/PUTSTATIC sites in one method (G3 accounting). */
    private static int countFieldSites(MethodNode method) {
        if (method.instructions == null) {
            return 0;
        }
        int count = 0;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (isFieldAccessOpcode(insn.getOpcode())) {
                count++;
            }
        }
        return count;
    }

    /** LDC class-literal sites (TODO in G3) in one method. */
    private static int countClassConstants(MethodNode method) {
        if (method.instructions == null) {
            return 0;
        }
        int count = 0;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof Type type
                    && (type.getSort() == Type.OBJECT || type.getSort() == Type.ARRAY)) {
                count++;
            }
        }
        return count;
    }

    private static boolean isFieldAccessOpcode(int opcode) {
        return opcode == Opcodes.GETFIELD || opcode == Opcodes.GETSTATIC
                || opcode == Opcodes.PUTFIELD || opcode == Opcodes.PUTSTATIC;
    }

    /** True for Mixin classes (annotation, name or super type), which Mixin rewrites at runtime. */
    public static boolean isMixinClass(ClassNode node) {
        if (node == null) {
            return false;
        }
        if (node.name != null) {
            String lower = node.name.toLowerCase(Locale.ROOT);
            if (lower.contains("mixin") || lower.startsWith("org/spongepowered/")) {
                return true;
            }
        }
        if (node.superName != null && node.superName.startsWith("org/spongepowered/asm/mixin")) {
            return true;
        }
        if (node.interfaces != null) {
            for (String itf : node.interfaces) {
                if (itf != null && itf.startsWith("org/spongepowered/asm/mixin")) {
                    return true;
                }
            }
        }
        return hasMixinAnnotation(node.visibleAnnotations) || hasMixinAnnotation(node.invisibleAnnotations);
    }

    private static boolean hasMixinAnnotation(List<AnnotationNode> annotations) {
        if (annotations == null) {
            return false;
        }
        for (AnnotationNode annotation : annotations) {
            if (annotation.desc != null && annotation.desc.startsWith("Lorg/spongepowered/asm/mixin")) {
                return true;
            }
        }
        return false;
    }

    /**
     * Convenience entry point: reads a class, rewrites it and writes it back with a fresh
     * {@link ClassWriter} (dead constants from replaced call/field sites are dropped). Mixin classes
     * are returned byte-identical (their Signature/debug attributes must be preserved because Mixin
     * reads them at runtime).
     */
    public static TransformResult transformClass(byte[] classBytes) {
        return transformClass(classBytes, Options.CONSERVATIVE);
    }

    /** Options-aware variant of {@link #transformClass(byte[])}. */
    public static TransformResult transformClass(byte[] classBytes, Options options) {
        ClassReader reader = new ClassReader(classBytes);
        ClassNode node = new ClassNode();
        reader.accept(node, 0);
        Stats stats = new IndyDispatchTransformer(options).transform(node);
        if (isMixinClass(node)) {
            // Preserve the original class file verbatim (Signature, SourceFile, LineNumberTable,
            // LocalVariableTable, annotations, attribute order, ...).
            return new TransformResult(classBytes, stats);
        }
        // Fresh writer: drop dead constant-pool entries left over from replaced call sites.
        // No COMPUTE_FRAMES - the call-site descriptors preserve the stack shape, so the original
        // frames remain valid and no class hierarchy is needed.
        ClassWriter writer = new ClassWriter(0);
        node.accept(writer);
        return new TransformResult(writer.toByteArray(), stats);
    }

    /** Node-level variant of {@link #transformClass(byte[])}. */
    public static Stats transformNode(ClassNode node) {
        return new IndyDispatchTransformer().transform(node);
    }

    /** Node-level variant with explicit options. */
    public static Stats transformNode(ClassNode node, Options options) {
        return new IndyDispatchTransformer(options).transform(node);
    }

    /** True when the opcode is one of the rewrite-eligible invocation types (diagnostics). */
    public static boolean isRewritableOpcode(int opcode) {
        for (int candidate : REWRITABLE_OPCODES) {
            if (candidate == opcode) {
                return true;
            }
        }
        return false;
    }

    /** True when the opcode is a G3 field read that this transformer can rewrite. */
    public static boolean isRewritableFieldReadOpcode(int opcode) {
        return opcode == Opcodes.GETFIELD || opcode == Opcodes.GETSTATIC;
    }
}
