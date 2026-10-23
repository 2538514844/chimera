package dev.chimera.transform.naming;

import dev.chimera.core.TransformContext;
import dev.chimera.core.Transformer;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.ConstantDynamic;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.Remapper;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.FrameNode;
import org.objectweb.asm.tree.InnerClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LocalVariableNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.MultiANewArrayInsnNode;
import org.objectweb.asm.tree.RecordComponentNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.TypeInsnNode;

import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * M13: invisible-character naming (Hachimi parity).
 *
 * <p>Appends invisible code points ({@link InvisibleNames#LTR}, {@link InvisibleNames#RTL},
 * {@link InvisibleNames#WJ}) to member names and class names. Because the characters are not
 * Java identifier characters, decompiled output looks identical ("a" vs "a\u200E") while the JVM
 * treats the names as distinct, which degrades search/replace oriented patching and symbol lookup.
 * Optionally (experimental, <b>off by default</b>) a NUL prefix is added to the class simple name,
 * matching Hachimi's {@code \0eK\u200e} jar entries.</p>
 *
 * <p><b>This is a whole-jar pre-pass.</b> Renaming a class or member requires rewriting every
 * reference, so the engine must call {@link #apply(Map, Map, Options)} once, before
 * {@code ClassPool} creation and before any transformer that bakes names into generated code
 * (VM programs, native templates, hidden-class fragments). The {@link Transformer#transform}
 * method is intentionally a no-op, mirroring {@code RenamerTransformer}.</p>
 *
 * <p>Safety model (production Minecraft mods):</p>
 * <ul>
 *   <li>classes are <b>never</b> renamed when they are Mixin classes, listed in a Mixin config,
 *       enums, records, annotation types, interfaces (by default), Chimera VM/native owners,
 *       hidden fragments ({@code $chimera$}), or excluded packages;</li>
 *   <li>members are never renamed in skipped classes; constructors, class initializers,
 *       {@code main}, native/abstract/synthetic methods are always kept;</li>
 *   <li>virtual methods are only renamed in final classes whose whole supertype chain is inside
 *       the input jar (no external override contract), mirroring {@code RenamerTransformer}'s
 *       gate;</li>
 *   <li>constant-pool string constants, JSON resources ({@code fabric.mod.json}, mixin configs,
 *       refmaps), AccessWidener files and {@code META-INF/services} entries are synchronised;
 *       class file names in the output map are updated.</li>
 * </ul>
 *
 * <p>Residual risks (documented, not silently ignored): reflection by hard-coded member name,
 * Java serialization of renamed fields, cross-mod compile-time references to renamed classes,
 * and native/JNI symbol names. Mixin classes are copied byte-for-byte, so their Signature and
 * debug attributes are preserved.</p>
 */
public final class InvisibleNameTransformer implements Transformer {

    /** Every Sponge Mixin annotation starts with this descriptor prefix. */
    static final String MIXIN_ANNOTATION_PREFIX = "Lorg/spongepowered/asm/mixin/";
    static final String NATIVE_ANNOTATION = "Ldev/chimera/annotations/ChimeraNative;";
    static final String VM_ANNOTATION = "Ldev/chimera/annotations/ChimeraVM;";
    static final String[] SKIP_PREFIXES = {
            "dev/chimera/runtime/",
            "dev/chimera/annotations/"
    };
    static final Set<String> OBJECT_METHODS = Set.of(
            "equals", "hashCode", "toString", "clone", "finalize", "compareTo");
    private static final String INTERNAL_IDENTIFIERS =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_$/";
    private static final String BINARY_IDENTIFIERS =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_$.";
    private static final Set<String> TEXT_EXTENSIONS = Set.of("json", "accesswidener", "toml", "mf");
    private static final Pattern JSON_CLASS_CANDIDATE = Pattern.compile(
            "\"([A-Za-z_$][A-Za-z0-9_$]*(?:[./][A-Za-z_$][A-Za-z0-9_$]*)+)\"");
    private static final Pattern SIGNATURE_CLASS_TOKEN = Pattern.compile("L([A-Za-z0-9_$/]+)");

    private InvisibleNameTransformer() {
    }

    /** Options for the pre-pass; {@link #defaults()} matches the M13 defaults. */
    public static final class Options {
        /** Rename class names (append invisible suffix, optional NUL prefix). */
        public boolean renameClasses = true;
        /** Rename non-skipped member names. */
        public boolean renameMembers = true;
        /** Rename fields as well as methods. */
        public boolean renameFields = true;
        /** Experimental: prefix class simple names with NUL (Hachimi parity), off by default. */
        public boolean nulPrefix = false;
        /** Rename interface class names (off: external implementors would break). */
        public boolean renameInterfaces = false;
        /** G1: replace class simple names with 1-2 character tokens (original name not kept). */
        public boolean shortClassNames = false;
        /** G1: replace member base names with 1-2 character tokens (override-safe gates apply). */
        public boolean shortMemberNames = false;
        /** Packages/classes never touched (same prefix semantics as {@code ChimeraConfig.excludes}). */
        public Set<String> excludes = Set.of();
        /** Hachimi parity: rename Mixin classes too (their configs are rewritten afterwards). */
        public boolean renameMixinClasses = false;
        /** Hachimi parity: drop the original package and use one short package for renamed classes. */
        public boolean flattenPackages = false;
        /** Package used by {@link #flattenPackages}. */
        public String flattenedPackage = "p/";
        /** Also rename enum/record/annotation classes (Hachimi renames everything). */
        public boolean renameValueClasses = false;

        public static Options defaults() {
            return new Options();
        }
    }

    /** Result of one whole-jar pre-pass. */
    public record Result(Map<String, byte[]> classes,
                         Map<String, byte[]> resources,
                         int classesRenamed,
                         int methodsRenamed,
                         int fieldsRenamed,
                         int stringsSynced,
                         int resourcesSynced,
                         int protectedClasses,
                         int protectedMembers) {

        /** Total member rename count (Hachimi reports members, not methods+fields separately). */
        public int membersRenamed() {
            return methodsRenamed + fieldsRenamed;
        }
    }

    @Override
    public void transform(String internalName, ClassNode node, TransformContext ctx) {
        // Invisible naming needs whole-jar reference rewriting; the engine calls apply(...) as a
        // pre-pass. Nothing is done per class here (same contract as RenamerTransformer).
    }

    /** Convenience overload using {@link Options#defaults()}. */
    public static Result apply(Map<String, byte[]> classes, Map<String, byte[]> resources) {
        return apply(classes, resources, Options.defaults());
    }

    /**
     * Renames classes/members and synchronises all references, resources and JSON metadata.
     *
     * @param classes   input map keyed by jar entry name ({@code a/b/C.class})
     * @param resources input map of non-class jar entries
     * @param options   rename switches
     * @return new maps plus rename counters (never mutates the inputs)
     */
    /** Rename plan exposed for follow-up resource passes (G2 mixin support). */
    public record Mappings(Result result,
                           java.util.Map<String, String> classRenames,
                           java.util.Map<String, java.util.Map<String, String>> memberRenames) {
    }

    /** Same as {@link #apply(Map, Map, Options)} but also returns the applied rename maps. */
    public static Mappings applyWithMappings(Map<String, byte[]> classes,
                                             Map<String, byte[]> resources, Options options) {
        return applyInternal(classes, resources, options);
    }

    /** @deprecated use {@link #applyWithMappings(Map, Map, Options)} when mappings are needed */
    public static Result apply(Map<String, byte[]> classes, Map<String, byte[]> resources, Options options) {
        return applyInternal(classes, resources, options).result();
    }

    private static Mappings applyInternal(Map<String, byte[]> classes, Map<String, byte[]> resources, Options options) {
        if (classes == null || resources == null || options == null) {
            throw new IllegalArgumentException("classes, resources and options are required");
        }
        Plan plan = buildPlan(classes, resources, options);
        if (plan.classRenames.isEmpty() && plan.methodRenames.isEmpty() && plan.fieldRenames.isEmpty()) {
            return new Mappings(new Result(new LinkedHashMap<>(classes),
                    new LinkedHashMap<>(resources), 0, 0, 0, 0, 0, 0, 0),
                    java.util.Collections.emptyMap(), java.util.Collections.emptyMap());
        }
        State state = new State(plan);
        Map<String, byte[]> outClasses = new LinkedHashMap<>();
        for (Map.Entry<String, byte[]> entry : new TreeMap<>(classes).entrySet()) {
            String key = entry.getKey();
            if (!key.endsWith(".class")) {
                outClasses.put(key, entry.getValue());
                continue;
            }
            String internalName = key.substring(0, key.length() - ".class".length());
            // Frozen classes (Mixin classes, enums/records/annotations, interfaces, VM/native
            // owners, excludes, already-renamed output) keep their exact bytes: Signature, debug
            // info and refmap-relevant members stay untouched. Every other class is rewritten even
            // when nothing inside it is renamed, because it may reference renamed classes.
            if (plan.skipped.contains(internalName) || !plan.nodes.containsKey(internalName)) {
                // Package flattening moves callers out of their original package, so even classes
                // that keep their name must expose their package-private members to them.
                outClasses.put(key, options.flattenPackages
                        ? promoteAccess(entry.getValue()) : entry.getValue());
                continue;
            }
            ClassReader reader = new ClassReader(entry.getValue());
            ClassWriter writer = new ClassWriter(0);
            ClassVisitor visitor = new ClassRemapper(writer, state);
            reader.accept(visitor, 0);
            String newName = plan.classRenames.getOrDefault(internalName, internalName);
            byte[] renamedBytes = writer.toByteArray();
            if (options.flattenPackages) {
                renamedBytes = promoteAccess(renamedBytes);
            }
            outClasses.put(newName + ".class", renamedBytes);
        }
        Map<String, byte[]> outResources = new LinkedHashMap<>();
        for (Map.Entry<String, byte[]> entry : new TreeMap<>(resources).entrySet()) {
            String key = entry.getKey();
            byte[] data = entry.getValue();
            boolean changed = false;
            String kind = textKind(key);
            if (kind != null && isText(data)) {
                String text = new String(data, StandardCharsets.UTF_8);
                String synced = syncText(text, plan, kind);
                if (!synced.equals(text)) {
                    data = synced.getBytes(StandardCharsets.UTF_8);
                    changed = true;
                }
            }
            String newKey = syncResourceKey(key, plan);
            if (!newKey.equals(key)) {
                changed = true;
            }
            outResources.put(newKey, data);
            if (changed) {
                state.resourcesSynced++;
            }
        }
        Result result = new Result(outClasses, outResources,
                plan.classRenames.size(),
                plan.methodsRenamed,
                plan.fieldsRenamed,
                state.stringsSynced,
                state.resourcesSynced,
                plan.protectedClasses.size(),
                plan.protectedMembers);;
        java.util.Map<String, java.util.Map<String, String>> members = new java.util.LinkedHashMap<>();
        for (var entry : plan.methodRenames.entrySet()) {
            members.put(entry.getKey(), new java.util.LinkedHashMap<>(entry.getValue()));
        }
        for (var entry : plan.fieldRenames.entrySet()) {
            members.computeIfAbsent(entry.getKey(), k -> new java.util.LinkedHashMap<>()).putAll(entry.getValue());
        }
        return new Mappings(result, new java.util.LinkedHashMap<>(plan.classRenames), members);
    }

    // ------------------------------------------------------------------
    // Plan building
    // ------------------------------------------------------------------

    private static Plan buildPlan(Map<String, byte[]> classes, Map<String, byte[]> resources,
                                  Options options) {
        Plan plan = new Plan();
        Map<String, ClassNode> nodes = new TreeMap<>();
        for (Map.Entry<String, byte[]> entry : classes.entrySet()) {
            if (!entry.getKey().endsWith(".class")) {
                continue;
            }
            String internalName = entry.getKey().substring(0, entry.getKey().length() - ".class".length());
            if (internalName.endsWith("module-info") || internalName.endsWith("package-info")) {
                continue;
            }
            ClassNode node = new ClassNode();
            // Frames carry class names too: a frozen class whose StackMapTable still points at a
            // renamed class would fail verification, so they participate in the reference graph.
            new ClassReader(entry.getValue()).accept(node, 0);
            nodes.put(node.name, node);
        }
        plan.nodes.putAll(nodes);
        for (ClassNode node : nodes.values()) {
            List<String> parents = new ArrayList<>(2);
            if (node.superName != null) {
                parents.add(node.superName);
            }
            if (node.interfaces != null) {
                parents.addAll(node.interfaces);
            }
            plan.superTypes.put(node.name, parents);
        }
        Set<String> protectedByMixinConfig = mixinConfigClassNames(resources, nodes.keySet());
        Set<String> usedClassNames = new HashSet<>(nodes.keySet());

        // 1) Frozen classes: their bytes are emitted unchanged, so every reference they make is a
        //    hard constraint on the rename plan.
        for (ClassNode node : nodes.values()) {
            if (isSkipped(node, options, protectedByMixinConfig)) {
                plan.skipped.add(node.name);
            }
        }
        // 2) Reference graph from frozen classes plus in-jar Mixin targets. A class still linked by
        //    frozen bytecode must keep its name; a member it links must keep its name. Mixin
        //    targets are frozen entirely because @Shadow/@Accessor/@Inject resolve members by name.
        plan.mixinTargets.addAll(mixinTargets(nodes));
        RefGraph references = scanReferences(nodes, plan.superTypes, plan.skipped);
        for (String referenced : references.classes) {
            if (nodes.containsKey(referenced) && !plan.skipped.contains(referenced)) {
                plan.protectedClasses.add(referenced);
            }
        }
        for (String target : plan.mixinTargets) {
            if (nodes.containsKey(target) && !plan.skipped.contains(target)) {
                plan.protectedClasses.add(target);
            }
        }
        for (Map.Entry<String, Set<String>> entry : references.members.entrySet()) {
            if (!plan.skipped.contains(entry.getKey())) {
                plan.protectedMemberKeys.put(entry.getKey(), entry.getValue());
            }
        }
        // 2a) JNI symbol binding: the JVM links a native method that is not registered through
        //     RegisterNatives by looking up the exported symbol Java_<mangled owner>_<mangled
        //     name>_<mangled desc>. That symbol lives in a library we do not own and cannot
        //     rewrite, so renaming the owner (or moving it out of its package, which the flatten
        //     pass does) makes every one of its native methods unresolvable. Observed on
        //     PrismHack: polaris/sdk/ui/render/NativeGpu -> p.rf... broke liquidglass-ui.dll and
        //     the HUD fell back to a broken layout. Framework rule: any class that declares a
        //     native method keeps its binary name, for every mod.
        int jniClassesBefore = plan.protectedClasses.size();
        for (ClassNode node : nodes.values()) {
            if (plan.skipped.contains(node.name) || plan.protectedClasses.contains(node.name)) {
                continue;
            }
            if (declaresNativeMethod(node)) {
                plan.protectedClasses.add(node.name);
            }
        }
        if (plan.protectedClasses.size() != jniClassesBefore) {
            System.err.println("[chimera] JNI symbol owners kept: +"
                    + (plan.protectedClasses.size() - jniClassesBefore));
        }
        // 2b) Reflection-by-name: Class.forName / getMethod("x") / Lookup.find* resolve names that
        //     no bytecode reference graph can see. Keep those names stable, otherwise a renamed
        //     class or member breaks at runtime (observed on PeakHack: NoSuchMethodException on a
        //     renamed reflective registrar, ClassNotFoundException on a renamed module class).
        int classesBefore = plan.protectedClasses.size();
        int membersBefore = plan.reflectiveMemberNames.size();
        scanReflectionNames(nodes, plan);
        System.err.println("[chimera] reflection names kept: classes+="
                + (plan.protectedClasses.size() - classesBefore) + " members+="
                + (plan.reflectiveMemberNames.size() - membersBefore));

        // 3) Rename plan with the protection gates.
        int classId = 0;
        for (ClassNode node : nodes.values()) {
            if (plan.skipped.contains(node.name)) {
                continue;
            }
            boolean mixinClassOwner = hasMixinAnnotation(node.visibleAnnotations)
                    || hasMixinAnnotation(node.invisibleAnnotations);
            if (options.renameClasses && !plan.protectedClasses.contains(node.name)) {
                String newName = nextClassName(node.name, options, usedClassNames, classId++,
                        mixinClassOwner, plan);
                plan.classRenames.put(node.name, newName);
            }
            if (!options.renameMembers) {
                continue;
            }
            boolean mixinOwner = hasMixinAnnotation(node.visibleAnnotations)
                    || hasMixinAnnotation(node.invisibleAnnotations);
            if (mixinOwner && options.renameMixinClasses) {
                // @Shadow/@Inject/@Accessor resolve members by name: keep mixin members stable.
                continue;
            }
            Set<String> usedMethodNames = new HashSet<>();
            for (MethodNode method : node.methods) {
                usedMethodNames.add(method.name);
            }
            Set<String> usedFieldNames = new HashSet<>();
            for (FieldNode field : node.fields) {
                usedFieldNames.add(field.name);
            }
            boolean mixinTarget = plan.mixinTargets.contains(node.name);
            List<MethodNode> methods = new ArrayList<>(node.methods);
            methods.sort(Comparator.comparing((MethodNode m) -> m.name).thenComparing(m -> m.desc));
            Map<String, String> methodRenames = new TreeMap<>();
            for (MethodNode method : methods) {
                if (!canRenameMethod(node, method, nodes)) {
                    continue;
                }
                if (mixinTarget || isProtectedMember(plan, node.name, method.name, method.desc)) {
                    plan.protectedMembers++;
                    continue;
                }
                if (plan.reflectiveMemberNames.contains(method.name)) {
                    plan.protectedMembers++;
                    continue;
                }
                String newName = nextMemberName(method.name, usedMethodNames, plan.methodId++,
                        options.shortMemberNames);
                methodRenames.put(method.name + method.desc, newName);
            }
            if (!methodRenames.isEmpty()) {
                plan.methodRenames.put(node.name, methodRenames);
                plan.methodsRenamed += methodRenames.size();
            }
            if (!options.renameFields) {
                continue;
            }
            List<FieldNode> fields = new ArrayList<>(node.fields);
            fields.sort(Comparator.comparing((FieldNode f) -> f.name).thenComparing(f -> f.desc));
            Map<String, String> fieldRenames = new TreeMap<>();
            for (FieldNode field : fields) {
                if ((field.access & Opcodes.ACC_SYNTHETIC) != 0
                        || (field.access & Opcodes.ACC_ENUM) != 0
                        || field.name.startsWith("this$")
                        || InvisibleNames.alreadyRenamed(field.name)) {
                    continue;
                }
                if (mixinTarget || isProtectedMember(plan, node.name, field.name, field.desc)) {
                    plan.protectedMembers++;
                    continue;
                }
                if (plan.reflectiveMemberNames.contains(field.name)) {
                    plan.protectedMembers++;
                    continue;
                }
                String newName = nextMemberName(field.name, usedFieldNames, plan.fieldId++,
                        options.shortMemberNames);
                fieldRenames.put(field.name + field.desc, newName);
            }
            if (!fieldRenames.isEmpty()) {
                plan.fieldRenames.put(node.name, fieldRenames);
                plan.fieldsRenamed += fieldRenames.size();
            }
        }
        return plan;
    }

    // ------------------------------------------------------------------
    // Frozen-class reference graph (crash prevention)
    // ------------------------------------------------------------------

    /** Classes/members linked by byte-identical (frozen) classes. */
    private static final class RefGraph {
        final Set<String> classes = new LinkedHashSet<>();
        final Map<String, Set<String>> members = new LinkedHashMap<>();
    }

    private static RefGraph scanReferences(Map<String, ClassNode> nodes,
                                           Map<String, List<String>> superTypes,
                                           Set<String> skipped) {
        RefGraph graph = new RefGraph();
        ScanContext context = new ScanContext(nodes, superTypes, skipped, graph);
        for (ClassNode node : nodes.values()) {
            if (skipped.contains(node.name)) {
                scanFrozenClass(context, node);
            }
        }
        return graph;
    }

    private static void scanFrozenClass(ScanContext c, ClassNode node) {
        c.addType(node.superName);
        if (node.interfaces != null) {
            for (String itf : node.interfaces) {
                c.addType(itf);
            }
        }
        c.addSignature(node.signature);
        c.scanAnnotations(node.visibleAnnotations);
        c.scanAnnotations(node.invisibleAnnotations);
        c.scanAnnotations(node.visibleTypeAnnotations);
        c.scanAnnotations(node.invisibleTypeAnnotations);
        c.addType(node.outerClass);
        c.addType(node.nestHostClass);
        if (node.nestMembers != null) {
            for (String member : node.nestMembers) {
                c.addType(member);
            }
        }
        if (node.permittedSubclasses != null) {
            for (String subclass : node.permittedSubclasses) {
                c.addType(subclass);
            }
        }
        if (node.innerClasses != null) {
            for (InnerClassNode inner : node.innerClasses) {
                c.addType(inner.name);
                c.addType(inner.outerName);
            }
        }
        if (node.recordComponents != null) {
            for (RecordComponentNode component : node.recordComponents) {
                c.addDescriptor(component.descriptor);
                c.addSignature(component.signature);
                c.scanAnnotations(component.visibleAnnotations);
                c.scanAnnotations(component.invisibleAnnotations);
            }
        }
        for (FieldNode field : node.fields) {
            c.addDescriptor(field.desc);
            c.addSignature(field.signature);
            c.scanAnnotations(field.visibleAnnotations);
            c.scanAnnotations(field.invisibleAnnotations);
            c.scanAnnotations(field.visibleTypeAnnotations);
            c.scanAnnotations(field.invisibleTypeAnnotations);
        }
        for (MethodNode method : node.methods) {
            c.addMethodDescriptor(method.desc);
            c.addSignature(method.signature);
            if (method.exceptions != null) {
                for (String exception : method.exceptions) {
                    c.addType(exception);
                }
            }
            c.scanAnnotations(method.visibleAnnotations);
            c.scanAnnotations(method.invisibleAnnotations);
            c.scanAnnotations(method.visibleTypeAnnotations);
            c.scanAnnotations(method.invisibleTypeAnnotations);
            c.scanParameterAnnotations(method.visibleParameterAnnotations);
            c.scanParameterAnnotations(method.invisibleParameterAnnotations);
            if (method.tryCatchBlocks != null) {
                for (TryCatchBlockNode block : method.tryCatchBlocks) {
                    c.addType(block.type);
                }
            }
            if (method.localVariables != null) {
                for (LocalVariableNode local : method.localVariables) {
                    c.addDescriptor(local.desc);
                    c.addSignature(local.signature);
                }
            }
            if (method.instructions == null) {
                continue;
            }
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                c.scanInstruction(insn);
            }
        }
    }

    /** Collector for the reference graph; resolves member owners through the known hierarchy. */
    private static final class ScanContext {
        private final Map<String, ClassNode> nodes;
        private final Map<String, List<String>> superTypes;
        private final Set<String> skipped;
        private final RefGraph graph;

        private ScanContext(Map<String, ClassNode> nodes, Map<String, List<String>> superTypes,
                            Set<String> skipped, RefGraph graph) {
            this.nodes = nodes;
            this.superTypes = superTypes;
            this.skipped = skipped;
            this.graph = graph;
        }

        void addType(String internalName) {
            if (internalName == null || internalName.isEmpty()) {
                return;
            }
            if (internalName.charAt(0) == '[') {
                addDescriptor(internalName);
                return;
            }
            if (nodes.containsKey(internalName) && !skipped.contains(internalName)) {
                graph.classes.add(internalName);
            }
        }

        void addDescriptor(String descriptor) {
            if (descriptor == null || descriptor.isEmpty()) {
                return;
            }
            try {
                if (descriptor.charAt(0) == '(') {
                    addMethodDescriptor(descriptor);
                } else {
                    addType(Type.getType(descriptor));
                }
            } catch (RuntimeException ignored) {
                // Not a valid descriptor (e.g. a generic signature); handled by addSignature.
            }
        }

        void addMethodDescriptor(String descriptor) {
            try {
                Type methodType = Type.getMethodType(descriptor);
                for (Type argument : methodType.getArgumentTypes()) {
                    addType(argument);
                }
                addType(methodType.getReturnType());
            } catch (RuntimeException ignored) {
                // Not a method descriptor.
            }
        }

        void addType(Type type) {
            if (type == null) {
                return;
            }
            Type element = type;
            while (element.getSort() == Type.ARRAY) {
                element = element.getElementType();
            }
            if (element.getSort() == Type.OBJECT) {
                addType(element.getInternalName());
            }
        }

        void addSignature(String signature) {
            if (signature == null || signature.isEmpty()) {
                return;
            }
            Matcher matcher = SIGNATURE_CLASS_TOKEN.matcher(signature);
            while (matcher.find()) {
                addType(matcher.group(1));
            }
        }

        void addNameString(String value) {
            if (value == null || value.isEmpty()) {
                return;
            }
            String candidate = value;
            if (candidate.endsWith(".class")) {
                candidate = candidate.substring(0, candidate.length() - ".class".length());
            }
            if (nodes.containsKey(candidate)) {
                addType(candidate);
                return;
            }
            String internal = candidate.replace('.', '/');
            if (nodes.containsKey(internal)) {
                addType(internal);
            }
        }

        void addMember(String owner, String name, String desc, boolean field) {
            if (owner == null || name == null || desc == null) {
                return;
            }
            String declaring = findDeclaring(owner, name, desc, field);
            if (declaring != null && !skipped.contains(declaring)) {
                graph.members.computeIfAbsent(declaring, key -> new TreeSet<>()).add(name + desc);
            }
        }

        private String findDeclaring(String owner, String name, String desc, boolean field) {
            Deque<String> queue = new ArrayDeque<>();
            Set<String> seen = new HashSet<>();
            queue.add(owner);
            while (!queue.isEmpty()) {
                String type = queue.poll();
                if (!seen.add(type)) {
                    continue;
                }
                ClassNode node = nodes.get(type);
                if (node == null) {
                    continue;
                }
                if (field) {
                    for (FieldNode candidate : node.fields) {
                        if (candidate.name.equals(name) && candidate.desc.equals(desc)) {
                            return type;
                        }
                    }
                } else {
                    for (MethodNode candidate : node.methods) {
                        if (candidate.name.equals(name) && candidate.desc.equals(desc)) {
                            return type;
                        }
                    }
                }
                if (node.superName != null) {
                    queue.add(node.superName);
                }
                if (node.interfaces != null) {
                    queue.addAll(node.interfaces);
                }
            }
            return null;
        }

        void scanAnnotations(List<? extends AnnotationNode> annotations) {
            if (annotations == null) {
                return;
            }
            for (AnnotationNode annotation : annotations) {
                if (annotation.desc != null) {
                    addDescriptor(annotation.desc);
                }
                scanValues(annotation.values);
            }
        }

        void scanParameterAnnotations(List<AnnotationNode>[] parameterAnnotations) {
            if (parameterAnnotations == null) {
                return;
            }
            for (List<AnnotationNode> annotations : parameterAnnotations) {
                scanAnnotations(annotations);
            }
        }

        private void scanValues(List<Object> values) {
            if (values == null) {
                return;
            }
            for (int i = 0; i + 1 < values.size(); i += 2) {
                scanValue(values.get(i + 1));
            }
        }

        void scanValue(Object value) {
            if (value == null) {
                return;
            }
            if (value instanceof Type type) {
                addDescriptor(type.getDescriptor());
            } else if (value instanceof String text) {
                addNameString(text);
            } else if (value instanceof Handle handle) {
                scanHandle(handle);
            } else if (value instanceof ConstantDynamic dynamic) {
                scanConstantDynamic(dynamic);
            } else if (value instanceof List<?> list) {
                for (Object item : list) {
                    scanValue(item);
                }
            } else if (value instanceof Object[] array) {
                for (Object item : array) {
                    scanValue(item);
                }
            }
        }

        void scanInstruction(AbstractInsnNode insn) {
            if (insn instanceof TypeInsnNode type) {
                addType(type.desc);
            } else if (insn instanceof FieldInsnNode field) {
                addType(field.owner);
                addDescriptor(field.desc);
                addMember(field.owner, field.name, field.desc, true);
            } else if (insn instanceof MethodInsnNode method) {
                addType(method.owner);
                addDescriptor(method.desc);
                addMember(method.owner, method.name, method.desc, false);
            } else if (insn instanceof InvokeDynamicInsnNode indy) {
                addDescriptor(indy.desc);
                scanHandle(indy.bsm);
                if (indy.bsmArgs != null) {
                    for (Object argument : indy.bsmArgs) {
                        scanValue(argument);
                    }
                }
            } else if (insn instanceof MultiANewArrayInsnNode array) {
                addDescriptor(array.desc);
            } else if (insn instanceof LdcInsnNode ldc) {
                scanValue(ldc.cst);
            } else if (insn instanceof FrameNode frame) {
                scanFrameTypes(frame.local);
                scanFrameTypes(frame.stack);
            }
        }

        private void scanHandle(Handle handle) {
            if (handle == null) {
                return;
            }
            addType(handle.getOwner());
            addDescriptor(handle.getDesc());
            boolean field = handle.getTag() >= Opcodes.H_GETFIELD && handle.getTag() <= Opcodes.H_PUTSTATIC;
            addMember(handle.getOwner(), handle.getName(), handle.getDesc(), field);
        }

        private void scanConstantDynamic(ConstantDynamic dynamic) {
            if (dynamic == null) {
                return;
            }
            addDescriptor(dynamic.getDescriptor());
            scanHandle(dynamic.getBootstrapMethod());
            for (int i = 0; i < dynamic.getBootstrapMethodArgumentCount(); i++) {
                scanValue(dynamic.getBootstrapMethodArgument(i));
            }
        }

        private void scanFrameTypes(List<Object> types) {
            if (types == null) {
                return;
            }
            for (Object type : types) {
                if (type instanceof String internalName) {
                    addType(internalName);
                }
            }
        }
    }

    private static Set<String> mixinTargets(Map<String, ClassNode> nodes) {
        Set<String> targets = new LinkedHashSet<>();
        for (ClassNode node : nodes.values()) {
            scanMixinTargetAnnotations(node.visibleAnnotations, nodes, targets);
            scanMixinTargetAnnotations(node.invisibleAnnotations, nodes, targets);
        }
        return targets;
    }

    private static void scanMixinTargetAnnotations(List<AnnotationNode> annotations,
                                                   Map<String, ClassNode> nodes, Set<String> targets) {
        if (annotations == null) {
            return;
        }
        for (AnnotationNode annotation : annotations) {
            if (annotation.desc == null || !"Lorg/spongepowered/asm/mixin/Mixin;".equals(annotation.desc)) {
                continue;
            }
            if (annotation.values == null) {
                continue;
            }
            for (int i = 0; i + 1 < annotation.values.size(); i += 2) {
                String key = String.valueOf(annotation.values.get(i));
                if (!"targets".equals(key) && !"value".equals(key)) {
                    continue;
                }
                addMixinTargetValue(annotation.values.get(i + 1), nodes, targets);
            }
        }
    }

    private static void addMixinTargetValue(Object value, Map<String, ClassNode> nodes, Set<String> targets) {
        if (value == null) {
            return;
        }
        if (value instanceof Type type) {
            addMixinTargetName(type.getInternalName(), nodes, targets);
        } else if (value instanceof String text) {
            addMixinTargetName(text, nodes, targets);
        } else if (value instanceof List<?> list) {
            for (Object item : list) {
                addMixinTargetValue(item, nodes, targets);
            }
        } else if (value instanceof Object[] array) {
            for (Object item : array) {
                addMixinTargetValue(item, nodes, targets);
            }
        }
    }

    private static void addMixinTargetName(String name, Map<String, ClassNode> nodes, Set<String> targets) {
        if (name == null || name.isEmpty()) {
            return;
        }
        String internal = name;
        if (!nodes.containsKey(internal)) {
            internal = name.replace('.', '/');
        }
        if (nodes.containsKey(internal)) {
            targets.add(internal);
        }
    }

    private static boolean isProtectedMember(Plan plan, String owner, String name, String desc) {
        String key = name + desc;
        Deque<String> queue = new ArrayDeque<>();
        Set<String> seen = new HashSet<>();
        queue.add(owner);
        while (!queue.isEmpty()) {
            String type = queue.poll();
            if (!seen.add(type)) {
                continue;
            }
            Set<String> keys = plan.protectedMemberKeys.get(type);
            if (keys != null && keys.contains(key)) {
                return true;
            }
            List<String> parents = plan.superTypes.get(type);
            if (parents != null) {
                queue.addAll(parents);
            }
        }
        return false;
    }

    /**
     * True when the class declares at least one {@code native} method. Such a class is the owner
     * part of an externally exported JNI symbol, so its binary name is not ours to change.
     *
     * <p>The sink pass runs after this naming pass, so a method that this build later turns into a
     * native stub cannot be seen here; that direction is safe because the sink registers its own
     * table with {@code RegisterNatives} and never relies on symbol lookup.</p>
     */
    private static boolean declaresNativeMethod(ClassNode node) {
        for (MethodNode method : node.methods) {
            if ((method.access & Opcodes.ACC_NATIVE) != 0) {
                return true;
            }
        }
        return false;
    }

    private static boolean isSkipped(ClassNode node, Options options, Set<String> protectedByMixin) {        // Nested classes of a Mixin (and of any class listed in a Mixin config) are part of the
        // Mixin's runtime contract; renaming them breaks the generated inner-class name.
        String outer = node.name;
        int separator = outer.lastIndexOf('/');
        separator = outer.lastIndexOf(java.io.File.separatorChar);
        separator = outer.lastIndexOf('\u0024');
        while (separator > 0) {
            outer = outer.substring(0, separator);
            if (protectedByMixin.contains(outer)) {
                return true;
            }
            separator = outer.lastIndexOf('\u0024');
        }
        // mixin package rule: classes sharing a package with a configured Mixin are part of the
        // Mixin's generated-name contract (inner classes, accessors); never rename them.
        int lastSlash = node.name.lastIndexOf('/');
        String packageName = lastSlash < 0 ? "" : node.name.substring(0, lastSlash);
        for (String mixinName : protectedByMixin) {
            int mixinSlash = mixinName.lastIndexOf('/');
            String mixinPackage = mixinSlash < 0 ? "" : mixinName.substring(0, mixinSlash);
            if (!mixinPackage.isEmpty() && mixinPackage.equals(packageName)) {
                return true;
            }
        }

        if (node.name == null || node.name.isEmpty()) {
            return true;
        }
        if ((node.access & Opcodes.ACC_MODULE) != 0) {
            return true;
        }
        for (String prefix : SKIP_PREFIXES) {
            if (node.name.startsWith(prefix)) {
                return true;
            }
        }
        for (String exclude : options.excludes) {
            if (node.name.equals(exclude) || node.name.startsWith(exclude)) {
                return true;
            }
        }
        if (node.name.contains("$chimera$") || InvisibleNames.alreadyRenamed(node.name)) {
            return true;
        }
        boolean mixinClass = hasMixinAnnotation(node.visibleAnnotations)
                || hasMixinAnnotation(node.invisibleAnnotations);
        if (protectedByMixin.contains(node.name) && !(options.renameMixinClasses && mixinClass)) {
            return true;
        }
        if (mixinClass && !options.renameMixinClasses) {
            return true;
        }
        if (!options.renameValueClasses) {
            if ((node.access & Opcodes.ACC_ENUM) != 0 || "java/lang/Enum".equals(node.superName)) {
                return true;
            }
            if ((node.access & Opcodes.ACC_RECORD) != 0 || "java/lang/Record".equals(node.superName)) {
                return true;
            }
            if ((node.access & Opcodes.ACC_ANNOTATION) != 0) {
                return true;
            }
        }
        if ((node.access & Opcodes.ACC_INTERFACE) != 0 && !options.renameInterfaces) {
            return true;
        }
        if (hasAnnotation(node.visibleAnnotations, NATIVE_ANNOTATION)
                || hasAnnotation(node.invisibleAnnotations, NATIVE_ANNOTATION)
                || hasAnnotation(node.visibleAnnotations, VM_ANNOTATION)
                || hasAnnotation(node.invisibleAnnotations, VM_ANNOTATION)) {
            // VM programs / native templates are generated from the original owner/method names.
            return true;
        }
        for (MethodNode method : node.methods) {
            if (hasAnnotation(method.visibleAnnotations, NATIVE_ANNOTATION)
                    || hasAnnotation(method.invisibleAnnotations, NATIVE_ANNOTATION)
                    || hasAnnotation(method.visibleAnnotations, VM_ANNOTATION)
                    || hasAnnotation(method.invisibleAnnotations, VM_ANNOTATION)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Member-level gate, mirroring {@code RenamerTransformer}: only private/static methods and
     * virtual methods of final classes with a fully-known supertype chain are renamed. This keeps
     * override dispatch (external implementors, Minecraft superclasses) intact.
     */
    private static boolean canRenameMethod(ClassNode owner, MethodNode method,
                                           Map<String, ClassNode> nodes) {
        if (method.name == null || method.name.startsWith("<")) {
            return false;
        }
        if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE
                | Opcodes.ACC_SYNTHETIC | Opcodes.ACC_BRIDGE)) != 0) {
            return false;
        }
        if ("main".equals(method.name) && "([Ljava/lang/String;)V".equals(method.desc)) {
            return false;
        }
        if (InvisibleNames.alreadyRenamed(method.name)) {
            return false;
        }
        if ((owner.access & Opcodes.ACC_INTERFACE) != 0) {
            return false;
        }
        boolean privateOrStatic = (method.access & (Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC)) != 0;
        if (privateOrStatic) {
            return true;
        }
        if ((owner.access & Opcodes.ACC_FINAL) == 0) {
            return false;
        }
        if (OBJECT_METHODS.contains(method.name)) {
            return false;
        }
        return !superChainDeclares(owner, method, nodes);
    }

    /** True when a supertype inside the jar or an unknown external supertype may declare the method. */
    private static boolean superChainDeclares(ClassNode owner, MethodNode method,
                                              Map<String, ClassNode> nodes) {
        List<String> queue = new ArrayList<>();
        if (owner.superName != null) {
            queue.add(owner.superName);
        }
        if (owner.interfaces != null) {
            queue.addAll(owner.interfaces);
        }
        Set<String> seen = new HashSet<>();
        while (!queue.isEmpty()) {
            String type = queue.remove(queue.size() - 1);
            if (!seen.add(type)) {
                continue;
            }
            if ("java/lang/Object".equals(type)) {
                continue;
            }
            ClassNode parent = nodes.get(type);
            if (parent == null) {
                // External superclass/interface (Minecraft, Fabric API, JDK types): an override
                // contract may exist and cannot be rewritten, so keep the method name.
                return true;
            }
            for (MethodNode candidate : parent.methods) {
                if (candidate.name.equals(method.name) && candidate.desc.equals(method.desc)) {
                    return true;
                }
            }
            if (parent.superName != null) {
                queue.add(parent.superName);
            }
            if (parent.interfaces != null) {
                queue.addAll(parent.interfaces);
            }
        }
        return false;
    }

    private static String nextClassName(String owner, Options options, Set<String> usedNames, int id,
                                        boolean keepPackage, Plan plan) {
        String packagePrefix;
        if (options.flattenPackages && !keepPackage) {
            packagePrefix = options.flattenedPackage;
        } else {
            packagePrefix = InvisibleNames.packagePrefix(owner);
        }
        String simple = InvisibleNames.simpleName(owner);
        int candidateId = id;
        while (true) {
            String base = options.shortClassNames ? shortToken(candidateId) : simple;
            String candidate = packagePrefix
                    + (options.nulPrefix ? String.valueOf(InvisibleNames.NUL) : "")
                    + base + InvisibleNames.suffix(candidateId);
            if (usedNames.add(candidate)) {
                return candidate;
            }
            candidateId++;
        }
    }

    private static String packageOf(String internalName) {
        int slash = internalName.lastIndexOf('/');
        return slash < 0 ? "" : internalName.substring(0, slash);
    }

    /**
     * Moving a class to another package breaks package-private access from classes that stayed.
     * Promoting the moved class and its package-private members to public keeps the rename safe.
     */
    private static boolean isMixinBytes(byte[] classBytes) {
        try {
            ClassNode node = new ClassNode();
            new ClassReader(classBytes).accept(node, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG);
            return hasMixinAnnotation(node.visibleAnnotations)
                    || hasMixinAnnotation(node.invisibleAnnotations);
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static byte[] promoteAccess(byte[] classBytes) {
        if (isMixinBytes(classBytes)) {
            // Mixin validates member visibility (@Inject handlers must stay private, @Shadow
            // fields must not become public): never rewrite mixin members.
            return classBytes;
        }
        ClassNode node = new ClassNode();
        new ClassReader(classBytes).accept(node, 0);
        node.access = (node.access & ~(Opcodes.ACC_PRIVATE | Opcodes.ACC_PROTECTED)) | Opcodes.ACC_PUBLIC;
        for (FieldNode field : node.fields) {
            // Renamed nestmates split across packages need every member reachable; private members
            // are promoted as well because the indy linker resolves them from the call site.
            field.access = (field.access & ~(Opcodes.ACC_PRIVATE | Opcodes.ACC_PROTECTED))
                    | Opcodes.ACC_PUBLIC;
        }
        for (MethodNode method : node.methods) {
            method.access = (method.access & ~(Opcodes.ACC_PRIVATE | Opcodes.ACC_PROTECTED))
                    | Opcodes.ACC_PUBLIC;
        }
        ClassWriter writer = new ClassWriter(0);
        node.accept(writer);
        return writer.toByteArray();
    }

    private static String nextMemberName(String original, Set<String> usedNames, int id,
                                        boolean shortNames) {
        int candidateId = id;
        while (true) {
            String candidate = (shortNames ? shortToken(candidateId) : original)
                    + InvisibleNames.suffix(candidateId);
            if (usedNames.add(candidate)) {
                return candidate;
            }
            candidateId++;
        }
    }

    /** G1: base-26 token (a..z, aa..az, ...) used when original names must not survive. */
    static String shortToken(int id) {
        StringBuilder sb = new StringBuilder();
        int value = Math.max(0, id);
        do {
            sb.append((char) ('a' + (value % 26)));
            value = value / 26 - 1;
        } while (value >= 0);
        return sb.reverse().toString();
    }

    // ------------------------------------------------------------------
    // Remapper / string + resource synchronisation
    // ------------------------------------------------------------------

    private static final class State extends Remapper {
        private final Plan plan;
        private final List<Map.Entry<String, String>> classEntries;
        int stringsSynced;
        int resourcesSynced;

        private State(Plan plan) {
            this.plan = plan;
            this.classEntries = new ArrayList<>(plan.classRenames.entrySet());
            this.classEntries.sort(Comparator.comparingInt(
                    (Map.Entry<String, String> e) -> e.getKey().length()).reversed());
        }

        @Override
        public String map(String internalName) {
            String mapped = plan.classRenames.get(internalName);
            return mapped == null ? internalName : mapped;
        }

        @Override
        public String mapMethodName(String owner, String name, String descriptor) {
            if (name == null || name.startsWith("<") || descriptor == null) {
                return name;
            }
            String mapped = lookupMethod(owner, name, descriptor);
            if (mapped == null) {
                mapped = lookupMethod(map(owner), name, descriptor);
            }
            return mapped == null ? name : mapped;
        }

        @Override
        public String mapFieldName(String owner, String name, String descriptor) {
            if (name == null || descriptor == null) {
                return name;
            }
            String mapped = lookupField(owner, name, descriptor);
            if (mapped == null) {
                mapped = lookupField(map(owner), name, descriptor);
            }
            return mapped == null ? name : mapped;
        }

        private String lookupMethod(String owner, String name, String descriptor) {
            String key = name + descriptor;
            Map<String, String> methods = plan.methodRenames.get(owner);
            if (methods != null) {
                String mapped = methods.get(key);
                if (mapped != null) {
                    return mapped;
                }
            }
            // Static/inherited references may use a subclass as owner; walk the known hierarchy.
            for (String ancestor : ancestry(owner)) {
                Map<String, String> inherited = plan.methodRenames.get(ancestor);
                if (inherited != null) {
                    String mapped = inherited.get(key);
                    if (mapped != null) {
                        return mapped;
                    }
                }
            }
            return null;
        }

        private String lookupField(String owner, String name, String descriptor) {
            String key = name + descriptor;
            Map<String, String> fields = plan.fieldRenames.get(owner);
            if (fields != null) {
                String mapped = fields.get(key);
                if (mapped != null) {
                    return mapped;
                }
            }
            for (String ancestor : ancestry(owner)) {
                Map<String, String> inherited = plan.fieldRenames.get(ancestor);
                if (inherited != null) {
                    String mapped = inherited.get(key);
                    if (mapped != null) {
                        return mapped;
                    }
                }
            }
            return null;
        }

        private List<String> ancestry(String owner) {
            List<String> order = new ArrayList<>();
            java.util.ArrayDeque<String> queue = new java.util.ArrayDeque<>();
            Set<String> seen = new HashSet<>();
            queue.add(owner);
            while (!queue.isEmpty()) {
                String type = queue.poll();
                if (!seen.add(type)) {
                    continue;
                }
                order.add(type);
                List<String> parents = plan.superTypes.get(type);
                if (parents != null) {
                    queue.addAll(parents);
                }
            }
            order.remove(0);
            return order;
        }

        @Override
        public String mapInnerClassName(String name, String outerName, String innerName) {
            String mapped = map(name);
            if (mapped.equals(name) || mapped.lastIndexOf('$') < 0) {
                return innerName;
            }
            return mapped.substring(mapped.lastIndexOf('$') + 1);
        }

        @Override
        public Object mapValue(Object value) {
            if (value instanceof String text) {
                String synced = syncString(text);
                if (!synced.equals(text)) {
                    stringsSynced++;
                }
                return synced;
            }
            return super.mapValue(value);
        }

        private String syncString(String text) {
            if (text.isEmpty() || (text.indexOf('/') < 0 && text.indexOf('.') < 0)) {
                return text;
            }
            String out = text;
            for (Map.Entry<String, String> entry : classEntries) {
                String oldName = entry.getKey();
                String newName = entry.getValue();
                out = out.replace("L" + oldName + ";", "L" + newName + ";");
                out = replaceToken(out, oldName, newName, INTERNAL_IDENTIFIERS);
                out = replaceToken(out, InvisibleNames.binaryName(oldName),
                        InvisibleNames.binaryName(newName), BINARY_IDENTIFIERS);
            }
            return out;
        }
    }

    private static String syncText(String text, Plan plan, String kind) {
        if (text.isEmpty()) {
            return text;
        }
        if ("services".equals(kind)) {
            return syncTokens(text, plan, false, true);
        }
        if ("accesswidener".equals(kind)) {
            return syncTokens(text, plan, false, false);
        }
        // JSON must escape the NUL prefix; toml/manifest are plain text.
        String out = syncTokens(text, plan, "json".equals(kind), true);
        return out;
    }

    private static String syncTokens(String text, Plan plan, boolean escapeJson, boolean binaryToo) {
        String out = text;
        for (Map.Entry<String, String> entry : plan.classRenames.entrySet()) {
            String oldName = entry.getKey();
            String newName = entry.getValue();
            String escapedInternal = escapeJson ? jsonEscape(newName) : newName;
            out = out.replace("L" + oldName + ";", "L" + escapedInternal + ";");
            out = replaceToken(out, oldName, escapedInternal, INTERNAL_IDENTIFIERS);
            if (binaryToo) {
                String oldBinary = InvisibleNames.binaryName(oldName);
                String newBinary = InvisibleNames.binaryName(newName);
                out = replaceToken(out, oldBinary,
                        escapeJson ? jsonEscape(newBinary) : newBinary, BINARY_IDENTIFIERS);
            }
        }
        return out;
    }

    /** Escapes a class name for JSON string literals (raw NUL is not valid JSON). */
    private static String jsonEscape(String value) {
        StringBuilder sb = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == InvisibleNames.NUL) {
                sb.append("\\u0000");
            } else if (c == '"' || c == '\\') {
                sb.append('\\').append(c);
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private static String syncResourceKey(String key, Plan plan) {
        return syncTokens(key, plan, false, true);
    }

    private static String replaceToken(String text, String token, String replacement, String identifiers) {
        if (text.indexOf(token) < 0) {
            return text;
        }
        StringBuilder sb = new StringBuilder(text.length() + 32);
        int index = 0;
        while (true) {
            int hit = text.indexOf(token, index);
            if (hit < 0) {
                sb.append(text, index, text.length());
                break;
            }
            int end = hit + token.length();
            boolean leftBoundary = hit == 0 || identifiers.indexOf(text.charAt(hit - 1)) < 0;
            boolean rightBoundary = end == text.length() || identifiers.indexOf(text.charAt(end)) < 0;
            sb.append(text, index, hit);
            sb.append(leftBoundary && rightBoundary ? replacement : token);
            index = end;
        }
        return sb.toString();
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static String textKind(String name) {
        if (name.startsWith("META-INF/services/")) {
            return "services";
        }
        int dot = name.lastIndexOf('.');
        if (dot < 0 || dot == name.length() - 1) {
            return null;
        }
        String extension = name.substring(dot + 1).toLowerCase(java.util.Locale.ROOT);
        return TEXT_EXTENSIONS.contains(extension) ? extension : null;
    }

    private static boolean isText(byte[] data) {
        if (data == null || data.length == 0) {
            return true;
        }
        for (byte b : data) {
            if (b == 0) {
                return false;
            }
        }
        return true;
    }

    private static Set<String> mixinConfigClassNames(Map<String, byte[]> resources, Set<String> knownClasses) {
        Set<String> protectedClasses = new LinkedHashSet<>();
        for (Map.Entry<String, byte[]> entry : resources.entrySet()) {
            String name = entry.getKey();
            if (!name.endsWith(".json")) {
                continue;
            }
            String lower = name.toLowerCase(java.util.Locale.ROOT);
            boolean mixinConfig = lower.contains("mixin");
            byte[] data = entry.getValue();
            if (data == null || data.length == 0 || !isText(data)) {
                continue;
            }
            String text = new String(data, StandardCharsets.UTF_8);
            if (!mixinConfig && !text.contains("\"mixins\"")) {
                continue;
            }
            Matcher matcher = JSON_CLASS_CANDIDATE.matcher(text);
            while (matcher.find()) {
                String candidate = matcher.group(1);
                String internal = candidate.replace('.', '/');
                if (knownClasses.contains(internal)) {
                    protectedClasses.add(internal);
                }
            }
        }
        return protectedClasses;
    }

    private static boolean hasMixinAnnotation(List<AnnotationNode> annotations) {
        if (annotations == null) {
            return false;
        }
        for (AnnotationNode annotation : annotations) {
            if (annotation.desc != null && annotation.desc.startsWith(MIXIN_ANNOTATION_PREFIX)) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasAnnotation(List<AnnotationNode> annotations, String descriptor) {
        if (annotations == null) {
            return false;
        }
        for (AnnotationNode annotation : annotations) {
            if (descriptor.equals(annotation.desc)) {
                return true;
            }
        }
        return false;
    }

    /** Runtime reflection entry points whose arguments are names resolved at runtime. */
    private static final Set<String> REFLECTIVE_LOOKUPS = Set.of(
            "forName", "loadClass",
            "getMethod", "getDeclaredMethod", "getMethods", "getDeclaredMethods",
            "getField", "getDeclaredField", "getFields", "getDeclaredFields",
            "findStatic", "findVirtual", "findSpecial", "findGetter", "findSetter",
            "findStaticGetter", "findStaticSetter", "findVarHandle", "findStaticVarHandle",
            "findConstructor", "findClass");

    /**
     * Keeps the names that runtime reflection resolves by string constant.
     *
     * <p>Two rules, both derived only from the artifact itself (no per-mod knowledge):</p>
     * <ul>
     *   <li>any string constant that exactly matches an in-jar class name protects that class -
     *       {@code Class.forName} strings are matched here regardless of the call site;</li>
     *   <li>inside a method that performs a reflective lookup, every string constant that matches an
     *       in-jar member name protects that name globally ({@code getMethod("registerAll")}).</li>
     * </ul>
     */
    private static void scanReflectionNames(Map<String, ClassNode> nodes, Plan plan) {
        Set<String> memberNames = new HashSet<>();
        for (ClassNode node : nodes.values()) {
            for (MethodNode method : node.methods) {
                memberNames.add(method.name);
            }
            for (FieldNode field : node.fields) {
                memberNames.add(field.name);
            }
        }
        for (ClassNode node : nodes.values()) {
            for (MethodNode method : node.methods) {
                InsnList insns = method.instructions;
                if (insns == null) {
                    continue;
                }
                boolean reflective = false;
                for (AbstractInsnNode insn = insns.getFirst(); insn != null; insn = insn.getNext()) {
                    if (insn instanceof MethodInsnNode call && REFLECTIVE_LOOKUPS.contains(call.name)) {
                        reflective = true;
                        break;
                    }
                }
                for (AbstractInsnNode insn = insns.getFirst(); insn != null; insn = insn.getNext()) {
                    if (!(insn instanceof LdcInsnNode ldc) || !(ldc.cst instanceof String text)
                            || text.isEmpty()) {
                        continue;
                    }
                    if (text.indexOf('.') > 0) {
                        String internal = text.replace('.', '/');
                        if (nodes.containsKey(internal)) {
                            plan.protectedClasses.add(internal);
                        }
                    }
                    if (reflective && memberNames.contains(text)) {
                        plan.reflectiveMemberNames.add(text);
                    }
                }
            }
        }
    }

    /** Immutable-ish plan shared by plan building and the remapper. */
    private static final class Plan {
        final Map<String, ClassNode> nodes = new LinkedHashMap<>();
        final Map<String, List<String>> superTypes = new HashMap<>();
        final Set<String> skipped = new HashSet<>();
        /** Classes whose names must stay (referenced by frozen bytecode or an in-jar Mixin target). */
        final Set<String> protectedClasses = new LinkedHashSet<>();
        /** Original mixin package (dotted) to its short replacement package. */
        final Map<String, String> mixinPackageRenames = new TreeMap<>();
        /** In-jar Mixin targets: every member name is kept for @Shadow/@Accessor/@Inject. */
        final Set<String> mixinTargets = new LinkedHashSet<>();
        /** Member keys ({@code name + desc}) that frozen bytecode links, per declaring class. */
        final Map<String, Set<String>> protectedMemberKeys = new HashMap<>();
        /** Bare member names that runtime reflection looks up by string (never renamed). */
        final Set<String> reflectiveMemberNames = new LinkedHashSet<>();
        final Map<String, String> classRenames = new TreeMap<>();
        final Map<String, Map<String, String>> methodRenames = new HashMap<>();
        final Map<String, Map<String, String>> fieldRenames = new HashMap<>();
        int protectedMembers;
        int methodsRenamed;
        int fieldsRenamed;
        int methodId;
        int fieldId;
    }
}
