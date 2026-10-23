package dev.chimera.transform.hidden;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ConstantDynamic;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.signature.SignatureReader;
import org.objectweb.asm.signature.SignatureVisitor;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.FrameNode;
import org.objectweb.asm.tree.InnerClassNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.MultiANewArrayInsnNode;
import org.objectweb.asm.tree.RecordComponentNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.TypeInsnNode;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * S5 隐藏集合规划器：扫描整个 jar 的引用图，输出哪些类可以进入隐藏集、哪些类必须保留及原因。
 *
 * <p><b>契约</b></p>
 * <ul>
 *   <li>{@link #plan(Map, HiddenSetOptions)} 只读字节，不修改 {@code classes} 中的任何数组；
 *       Mixin 类因此天然保持字节原样；</li>
 *   <li>输入/解析失败一律 fail-closed：抛 {@link IllegalArgumentException}，绝不返回“部分安全”的
 *       隐藏集合；</li>
 *   <li>输出确定性：{@code keepReasons}/{@code hiddenCandidates} 按 internal name 字典序；
 *       同一输入（含不同插入顺序）得到相等的 {@link Report}；</li>
 *   <li>{@link #writeCandidateList(Report, Path)} 按字典序、UTF-8、LF 行尾写出候选名单。</li>
 * </ul>
 *
 * <p><b>规则（结构保留，优先级从上到下，首个命中即原因）</b></p>
 * <ol>
 *   <li>{@code module-info}；</li>
 *   <li>{@code dev/chimera/} 前缀、{@code $chimera$} 片段名；</li>
 *   <li>{@code HiddenSetOptions.forcedKeep()} / {@code forcedKeepPrefixes()}（即 {@code excludes}）；</li>
 *   <li>{@code HiddenSetOptions.entrypoints()}（fabric.mod.json entrypoints、Mixin 配置类等）；</li>
 *   <li>类或成员上的 {@code @ChimeraNative} / {@code @ChimeraVM}；</li>
 *   <li>Mixin 类（任何 {@code Lorg/spongepowered/asm/mixin/} 类级注解）及其 jar 内 target；</li>
 *   <li>注解类型、record、enum、接口；</li>
 *   <li>反射字符串命中的类（{@code Class.forName}/{@code loadClass}/{@code findClass} 样式，
 *       以及 {@code getDeclaredMethod}/{@code getField} 样式的成员名命中）。</li>
 * </ol>
 *
 * <p><b>引用阻断规则</b>（把“不可隐藏类”的按名引用传递闭包加进保留集）：</p>
 * <ul>
 *   <li>被保留类引用：跨包时总是阻断；同包时仅当
 *       {@link HiddenSetOptions#samePackageReferencesPermitHiding()} 为 {@code false} 时阻断
 *       （默认放行，对应 S5 的引用间接化 / 同包重写能力）；</li>
 *   <li>被隐藏候选（即“已隐藏类”）引用：总是放行——该引用会随 S5 一起重写；</li>
 *   <li>自引用：放行。</li>
 * </ul>
 *
 * <p>被引用类必须在同一个 jar 内才会被计入；外部类（Minecraft/Fabric/JDK）不参与隐藏决策。</p>
 */
public final class HiddenSetPlanner {

    private static final int ASM_API = Opcodes.ASM9;

    private static final int CLASS_SIGNATURE = 0;
    private static final int FIELD_SIGNATURE = 1;
    private static final int METHOD_SIGNATURE = 2;

    /** Every Sponge Mixin annotation starts with this descriptor prefix. */
    private static final String MIXIN_ANNOTATION_PREFIX = "Lorg/spongepowered/asm/mixin/";
    private static final String MIXIN_DESCRIPTOR = "Lorg/spongepowered/asm/mixin/Mixin;";
    private static final String NATIVE_DESCRIPTOR = "Ldev/chimera/annotations/ChimeraNative;";
    private static final String VM_DESCRIPTOR = "Ldev/chimera/annotations/ChimeraVM;";

    private static final String CHIMERA_PACKAGE_PREFIX = "dev/chimera/";
    private static final String HIDDEN_FRAGMENT_MARKER = "$chimera$";

    /** Reflective APIs whose first/only String argument is a class name. */
    private static final Set<String> REFLECTIVE_NAME_LOOKUPS = Set.of(
            "forName",
            "loadClass",
            "findClass",
            "getMethod",
            "getDeclaredMethod",
            "getField",
            "getDeclaredField",
            "findStatic",
            "findVirtual",
            "findSpecial",
            "findGetter",
            "findSetter",
            "findStaticGetter",
            "findStaticSetter");

    private HiddenSetPlanner() {
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /**
     * Plans the hidden set for one jar.
     *
     * @param classes internal name ({@code a/b/C}, also accepting {@code a.b.C} or {@code a/b/C.class})
     *                to class file bytes; the map itself is never modified
     * @param options planner input rules
     * @return immutable, deterministic report
     * @throws IllegalArgumentException on null/invalid input, unparseable class files, duplicate names,
     *                                  a map key that disagrees with the class file's own name, or an
     *                                  invalid generic signature (fail-closed)
     */
    public static Report plan(Map<String, byte[]> classes, HiddenSetOptions options) {
        if (classes == null) {
            throw new IllegalArgumentException("classes must not be null");
        }
        if (options == null) {
            throw new IllegalArgumentException("options must not be null");
        }
        Map<String, ClassNode> nodes = readClasses(classes);

        Map<String, String> keepReasons = new TreeMap<>();
        for (ClassNode node : nodes.values()) {
            String reason = structuralReason(node, options);
            if (reason != null) {
                keepReasons.put(node.name, reason);
            }
        }
        keepMixinTargets(nodes, keepReasons);
        int reflectiveHits = keepReflectiveHits(nodes, keepReasons);

        Map<String, List<Edge>> outgoing = referenceGraph(nodes);
        applyKeptReferences(outgoing, keepReasons, options);

        Set<String> candidates = new TreeSet<>(nodes.keySet());
        candidates.removeAll(keepReasons.keySet());
        return new Report(keepReasons, candidates, nodes.size(), reflectiveHits, candidates.size());
    }

    /**
     * Writes {@link Report#hiddenCandidates()} to {@code path}: one internal name per line, sorted,
     * UTF-8, {@code \n} line endings. The write is atomic (temp file in the same directory + move)
     * and parent directories are created. An empty candidate set produces an empty file.
     *
     * @return the absolute path that was written
     * @throws IOException              when the file cannot be written
     * @throws IllegalArgumentException when {@code report} or {@code path} is null
     */
    public static Path writeCandidateList(Report report, Path path) throws IOException {
        if (report == null) {
            throw new IllegalArgumentException("report must not be null");
        }
        if (path == null) {
            throw new IllegalArgumentException("path must not be null");
        }
        StringBuilder text = new StringBuilder();
        for (String name : report.hiddenCandidates()) {
            text.append(name).append('\n');
        }
        Path absolute = path.toAbsolutePath().normalize();
        Path parent = absolute.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Path temp = parent == null
                ? Files.createTempFile("chimera-hidden-candidates", ".tmp")
                : Files.createTempFile(parent, ".chimera-hidden-candidates", ".tmp");
        try {
            Files.writeString(temp, text.toString(), StandardCharsets.UTF_8);
            try {
                Files.move(temp, absolute, StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException ignored) {
                Files.move(temp, absolute, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temp);
        }
        return absolute;
    }

    // ------------------------------------------------------------------
    // Input handling
    // ------------------------------------------------------------------

    private static Map<String, ClassNode> readClasses(Map<String, byte[]> classes) {
        Map<String, ClassNode> nodes = new TreeMap<>();
        for (Map.Entry<String, byte[]> entry : classes.entrySet()) {
            String key = normalizeKey(entry.getKey());
            byte[] bytes = entry.getValue();
            if (bytes == null) {
                throw new IllegalArgumentException("class bytes are null for " + key);
            }
            ClassNode node = new ClassNode();
            try {
                new ClassReader(bytes).accept(node, ClassReader.EXPAND_FRAMES | ClassReader.SKIP_DEBUG);
            } catch (RuntimeException e) {
                throw new IllegalArgumentException("failed to parse class file " + key + ": " + e, e);
            }
            if (node.name == null || node.name.isEmpty()) {
                throw new IllegalArgumentException("class file " + key + " has no name");
            }
            if (!node.name.equals(key)) {
                throw new IllegalArgumentException(
                        "class map key " + key + " does not match the class file name " + node.name);
            }
            if (nodes.put(node.name, node) != null) {
                throw new IllegalArgumentException("duplicate class " + node.name);
            }
        }
        return nodes;
    }

    private static String normalizeKey(String raw) {
        if (raw == null) {
            throw new IllegalArgumentException("class map contains a null key");
        }
        String name = raw.trim().replace('\\', '/');
        if (name.endsWith(".class")) {
            name = name.substring(0, name.length() - ".class".length());
        }
        name = name.replace('.', '/');
        while (name.startsWith("/")) {
            name = name.substring(1);
        }
        if (name.isEmpty()) {
            throw new IllegalArgumentException("class map contains an empty key");
        }
        for (int i = 0; i < name.length(); i++) {
            if (Character.isWhitespace(name.charAt(i))) {
                throw new IllegalArgumentException("class map key contains whitespace: " + raw);
            }
        }
        return name;
    }

    // ------------------------------------------------------------------
    // Structural keep rules
    // ------------------------------------------------------------------

    private static String structuralReason(ClassNode node, HiddenSetOptions options) {
        if ((node.access & Opcodes.ACC_MODULE) != 0) {
            return "module-info";
        }
        String name = node.name;
        if (name.startsWith(CHIMERA_PACKAGE_PREFIX)) {
            return "chimera package (dev/chimera)";
        }
        if (name.contains(HIDDEN_FRAGMENT_MARKER)) {
            return "chimera hidden fragment ($chimera$)";
        }
        if (options.forcedKeep().contains(name)) {
            return "forced keep (options.excludes)";
        }
        for (String prefix : options.forcedKeepPrefixes()) {
            if (name.equals(prefix) || name.startsWith(prefix + "/")) {
                return "forced keep prefix (options.excludes): " + prefix;
            }
        }
        if (options.entrypoints().contains(name)) {
            return "entrypoint (fabric.mod.json / mixin config)";
        }
        if (hasAnnotation(node.visibleAnnotations, NATIVE_DESCRIPTOR)
                || hasAnnotation(node.invisibleAnnotations, NATIVE_DESCRIPTOR)) {
            return "@ChimeraNative owner";
        }
        if (hasAnnotation(node.visibleAnnotations, VM_DESCRIPTOR)
                || hasAnnotation(node.invisibleAnnotations, VM_DESCRIPTOR)) {
            return "@ChimeraVM owner";
        }
        for (MethodNode method : node.methods) {
            if (hasAnnotation(method.visibleAnnotations, NATIVE_DESCRIPTOR)
                    || hasAnnotation(method.invisibleAnnotations, NATIVE_DESCRIPTOR)) {
                return "@ChimeraNative owner";
            }
            if (hasAnnotation(method.visibleAnnotations, VM_DESCRIPTOR)
                    || hasAnnotation(method.invisibleAnnotations, VM_DESCRIPTOR)) {
                return "@ChimeraVM owner";
            }
        }
        if (isMixin(node)) {
            return "Mixin class";
        }
        if ((node.access & Opcodes.ACC_ANNOTATION) != 0) {
            return "annotation type";
        }
        if ((node.access & Opcodes.ACC_RECORD) != 0 || "java/lang/Record".equals(node.superName)) {
            return "record";
        }
        if ((node.access & Opcodes.ACC_ENUM) != 0 || "java/lang/Enum".equals(node.superName)) {
            return "enum";
        }
        if ((node.access & Opcodes.ACC_INTERFACE) != 0) {
            return "interface";
        }
        return null;
    }

    private static boolean isMixin(ClassNode node) {
        return hasMixinAnnotation(node.visibleAnnotations) || hasMixinAnnotation(node.invisibleAnnotations);
    }

    private static boolean hasMixinAnnotation(List<? extends AnnotationNode> annotations) {
        if (annotations == null) {
            return false;
        }
        for (AnnotationNode annotation : annotations) {
            if (annotation != null && annotation.desc != null
                    && annotation.desc.startsWith(MIXIN_ANNOTATION_PREFIX)) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasAnnotation(List<? extends AnnotationNode> annotations, String descriptor) {
        if (annotations == null) {
            return false;
        }
        for (AnnotationNode annotation : annotations) {
            if (annotation != null && descriptor.equals(annotation.desc)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Mixin classes target in-jar classes through {@code @Mixin(value/targets=...)}. A targeted class
     * is merged into by Mixin at runtime and must never be moved into the hidden set.
     */
    private static void keepMixinTargets(Map<String, ClassNode> nodes, Map<String, String> keepReasons) {
        for (ClassNode node : nodes.values()) {
            if (!isMixin(node)) {
                continue;
            }
            Set<String> targets = new TreeSet<>();
            collectMixinTargets(node.visibleAnnotations, nodes.keySet(), targets);
            collectMixinTargets(node.invisibleAnnotations, nodes.keySet(), targets);
            for (String target : targets) {
                if (!keepReasons.containsKey(target)) {
                    keepReasons.put(target, "Mixin target of " + node.name);
                }
            }
        }
    }

    private static void collectMixinTargets(List<? extends AnnotationNode> annotations,
                                            Set<String> classNames, Set<String> out) {
        if (annotations == null) {
            return;
        }
        for (AnnotationNode annotation : annotations) {
            if (annotation == null || !MIXIN_DESCRIPTOR.equals(annotation.desc) || annotation.values == null) {
                continue;
            }
            for (int i = 0; i + 1 < annotation.values.size(); i += 2) {
                Object key = annotation.values.get(i);
                if (!"value".equals(key) && !"targets".equals(key)) {
                    continue;
                }
                collectMixinTargetValue(annotation.values.get(i + 1), classNames, out);
            }
        }
    }

    private static void collectMixinTargetValue(Object value, Set<String> classNames, Set<String> out) {
        if (value == null) {
            return;
        }
        if (value instanceof Type type) {
            Type element = type;
            while (element.getSort() == Type.ARRAY) {
                element = element.getElementType();
            }
            if (element.getSort() == Type.OBJECT && classNames.contains(element.getInternalName())) {
                out.add(element.getInternalName());
            }
        } else if (value instanceof String text) {
            String resolved = resolveClassName(text, classNames);
            if (resolved != null) {
                out.add(resolved);
            }
        } else if (value instanceof List<?> list) {
            for (Object item : list) {
                collectMixinTargetValue(item, classNames, out);
            }
        } else if (value instanceof Object[] array) {
            for (Object item : array) {
                collectMixinTargetValue(item, classNames, out);
            }
        }
    }

    // ------------------------------------------------------------------
    // Reflection strings
    // ------------------------------------------------------------------

    /**
     * Keeps classes named by string constants (a hidden class has no resolvable name, so
     * {@code Class.forName("...")} would fail), and classes that look themselves up by member name
     * through a reflective API. Returns the number of distinct classes hit.
     */
    private static int keepReflectiveHits(Map<String, ClassNode> nodes, Map<String, String> keepReasons) {
        Map<String, String> hits = new TreeMap<>();
        for (ClassNode node : nodes.values()) {
            ReflectionInfo info = scanReflection(node);
            for (String value : info.strings) {
                String target = resolveClassName(value, nodes.keySet());
                if (target != null && !hits.containsKey(target)) {
                    hits.put(target, "reflective class string \"" + value + "\" in " + node.name);
                }
            }
            if (info.nameLookup) {
                for (String member : declaredMemberNames(node)) {
                    if (info.strings.contains(member)) {
                        if (!hits.containsKey(node.name)) {
                            hits.put(node.name,
                                    "reflective member lookup \"" + member + "\" in " + node.name);
                        }
                        break;
                    }
                }
            }
        }
        for (Map.Entry<String, String> hit : hits.entrySet()) {
            if (!keepReasons.containsKey(hit.getKey())) {
                keepReasons.put(hit.getKey(), hit.getValue());
            }
        }
        return hits.size();
    }

    private static String resolveClassName(String value, Set<String> classNames) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        String candidate = value.trim();
        if (candidate.endsWith(".class")) {
            candidate = candidate.substring(0, candidate.length() - ".class".length());
        }
        if (candidate.startsWith("L") && candidate.endsWith(";")) {
            candidate = candidate.substring(1, candidate.length() - 1);
        }
        if (classNames.contains(candidate)) {
            return candidate;
        }
        String internal = candidate.replace('.', '/');
        if (classNames.contains(internal)) {
            return internal;
        }
        return null;
    }

    private static final class ReflectionInfo {
        private final Set<String> strings = new TreeSet<>();
        private boolean nameLookup;
    }

    private static ReflectionInfo scanReflection(ClassNode node) {
        ReflectionInfo info = new ReflectionInfo();
        collectAnnotationStrings(node.visibleAnnotations, info);
        collectAnnotationStrings(node.invisibleAnnotations, info);
        collectAnnotationStrings(node.visibleTypeAnnotations, info);
        collectAnnotationStrings(node.invisibleTypeAnnotations, info);
        if (node.recordComponents != null) {
            for (RecordComponentNode component : node.recordComponents) {
                collectAnnotationStrings(component.visibleAnnotations, info);
                collectAnnotationStrings(component.invisibleAnnotations, info);
                collectAnnotationStrings(component.visibleTypeAnnotations, info);
                collectAnnotationStrings(component.invisibleTypeAnnotations, info);
            }
        }
        for (FieldNode field : node.fields) {
            if (field.value instanceof String text) {
                info.strings.add(text);
            }
            collectAnnotationStrings(field.visibleAnnotations, info);
            collectAnnotationStrings(field.invisibleAnnotations, info);
            collectAnnotationStrings(field.visibleTypeAnnotations, info);
            collectAnnotationStrings(field.invisibleTypeAnnotations, info);
        }
        for (MethodNode method : node.methods) {
            collectAnnotationStrings(method.visibleAnnotations, info);
            collectAnnotationStrings(method.invisibleAnnotations, info);
            collectAnnotationStrings(method.visibleTypeAnnotations, info);
            collectAnnotationStrings(method.invisibleTypeAnnotations, info);
            collectParameterAnnotationStrings(method.visibleParameterAnnotations, info);
            collectParameterAnnotationStrings(method.invisibleParameterAnnotations, info);
            if (method.instructions == null) {
                continue;
            }
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn instanceof LdcInsnNode ldc) {
                    if (ldc.cst instanceof String text) {
                        info.strings.add(text);
                    }
                } else if (insn instanceof MethodInsnNode call) {
                    if (call.name != null && REFLECTIVE_NAME_LOOKUPS.contains(call.name)
                            && isReflectiveOwner(call.owner)) {
                        info.nameLookup = true;
                    }
                }
            }
        }
        return info;
    }

    private static boolean isReflectiveOwner(String owner) {
        return "java/lang/Class".equals(owner)
                || "java/lang/ClassLoader".equals(owner)
                || "java/lang/invoke/MethodHandles$Lookup".equals(owner)
                || (owner != null && owner.startsWith("java/lang/reflect/"));
    }

    private static void collectParameterAnnotationStrings(List<AnnotationNode>[] parameterAnnotations,
                                                          ReflectionInfo info) {
        if (parameterAnnotations == null) {
            return;
        }
        for (List<AnnotationNode> annotations : parameterAnnotations) {
            collectAnnotationStrings(annotations, info);
        }
    }

    private static void collectAnnotationStrings(List<? extends AnnotationNode> annotations,
                                                 ReflectionInfo info) {
        if (annotations == null) {
            return;
        }
        for (AnnotationNode annotation : annotations) {
            if (annotation == null || annotation.desc == null) {
                continue;
            }
            if (annotation.desc.startsWith(MIXIN_ANNOTATION_PREFIX)) {
                // @Mixin targets are handled by keepMixinTargets, not as reflective strings.
                continue;
            }
            collectValueStrings(annotation.values, info);
        }
    }

    private static void collectValueStrings(List<Object> values, ReflectionInfo info) {
        if (values == null) {
            return;
        }
        for (int i = 1; i < values.size(); i += 2) {
            collectValueString(values.get(i), info);
        }
    }

    private static void collectValueString(Object value, ReflectionInfo info) {
        if (value instanceof String text) {
            info.strings.add(text);
        } else if (value instanceof String[] pair) {
            // ASM encodes enum annotation values as {typeDescriptor, constantName};
            // the descriptor is a class reference, not a reflective string.
            if (pair.length != 2) {
                for (Object item : pair) {
                    collectValueString(item, info);
                }
            }
        } else if (value instanceof AnnotationNode nested) {
            collectValueStrings(nested.values, info);
        } else if (value instanceof List<?> list) {
            for (Object item : list) {
                collectValueString(item, info);
            }
        } else if (value instanceof Object[] array) {
            for (Object item : array) {
                collectValueString(item, info);
            }
        }
    }

    private static Set<String> declaredMemberNames(ClassNode node) {
        Set<String> names = new TreeSet<>();
        for (FieldNode field : node.fields) {
            if (field.name != null) {
                names.add(field.name);
            }
        }
        for (MethodNode method : node.methods) {
            if (method.name != null && !method.name.startsWith("<")) {
                names.add(method.name);
            }
        }
        return names;
    }

    // ------------------------------------------------------------------
    // Reference graph
    // ------------------------------------------------------------------

    private record Edge(String target, String kind) {
    }

    private static Map<String, List<Edge>> referenceGraph(Map<String, ClassNode> nodes) {
        Map<String, List<Edge>> outgoing = new TreeMap<>();
        for (ClassNode node : nodes.values()) {
            RefSink sink = new RefSink(nodes.keySet(), node.name);
            collectReferences(node, sink);
            List<Edge> edges = new ArrayList<>(sink.refs.size());
            for (Map.Entry<String, String> ref : sink.refs.entrySet()) {
                edges.add(new Edge(ref.getKey(), ref.getValue()));
            }
            outgoing.put(node.name, List.copyOf(edges));
        }
        return outgoing;
    }

    private static void applyKeptReferences(Map<String, List<Edge>> outgoing,
                                            Map<String, String> keepReasons,
                                            HiddenSetOptions options) {
        Deque<String> queue = new ArrayDeque<>(keepReasons.keySet());
        while (!queue.isEmpty()) {
            String from = queue.removeFirst();
            List<Edge> edges = outgoing.get(from);
            if (edges == null) {
                continue;
            }
            for (Edge edge : edges) {
                String target = edge.target();
                if (keepReasons.containsKey(target)) {
                    continue;
                }
                boolean blocking = !options.samePackageReferencesPermitHiding()
                        || !samePackage(from, target);
                if (!blocking) {
                    continue;
                }
                keepReasons.put(target, "referenced by kept " + from + " (" + edge.kind() + ")");
                queue.addLast(target);
            }
        }
    }

    private static boolean samePackage(String left, String right) {
        return packageOf(left).equals(packageOf(right));
    }

    private static String packageOf(String internalName) {
        int slash = internalName.lastIndexOf('/');
        return slash < 0 ? "" : internalName.substring(0, slash);
    }

    private static void collectReferences(ClassNode node, RefSink sink) {
        sink.type(node.superName, "superclass");
        if (node.interfaces != null) {
            for (String itf : node.interfaces) {
                sink.type(itf, "interface");
            }
        }
        sink.signature(node.signature, CLASS_SIGNATURE, "class signature");
        sink.annotations(node.visibleAnnotations, "class annotation");
        sink.annotations(node.invisibleAnnotations, "class annotation");
        sink.annotations(node.visibleTypeAnnotations, "class type annotation");
        sink.annotations(node.invisibleTypeAnnotations, "class type annotation");
        sink.type(node.outerClass, "outer class");
        sink.type(node.nestHostClass, "nest host");
        if (node.nestMembers != null) {
            for (String member : node.nestMembers) {
                sink.type(member, "nest member");
            }
        }
        if (node.permittedSubclasses != null) {
            for (String subclass : node.permittedSubclasses) {
                sink.type(subclass, "permitted subclass");
            }
        }
        if (node.innerClasses != null) {
            for (InnerClassNode inner : node.innerClasses) {
                sink.type(inner.name, "inner class");
                sink.type(inner.outerName, "inner outer class");
            }
        }
        if (node.recordComponents != null) {
            for (RecordComponentNode component : node.recordComponents) {
                sink.descriptor(component.descriptor, "record component");
                sink.signature(component.signature, FIELD_SIGNATURE, "record component signature");
                sink.annotations(component.visibleAnnotations, "record component annotation");
                sink.annotations(component.invisibleAnnotations, "record component annotation");
                sink.annotations(component.visibleTypeAnnotations, "record component type annotation");
                sink.annotations(component.invisibleTypeAnnotations, "record component type annotation");
            }
        }
        for (FieldNode field : node.fields) {
            sink.descriptor(field.desc, "field descriptor");
            sink.signature(field.signature, FIELD_SIGNATURE, "field signature");
            sink.annotations(field.visibleAnnotations, "field annotation");
            sink.annotations(field.invisibleAnnotations, "field annotation");
            sink.annotations(field.visibleTypeAnnotations, "field type annotation");
            sink.annotations(field.invisibleTypeAnnotations, "field type annotation");
        }
        for (MethodNode method : node.methods) {
            sink.descriptor(method.desc, "method descriptor");
            sink.signature(method.signature, METHOD_SIGNATURE, "method signature");
            if (method.exceptions != null) {
                for (String exception : method.exceptions) {
                    sink.type(exception, "throws clause");
                }
            }
            sink.annotations(method.visibleAnnotations, "method annotation");
            sink.annotations(method.invisibleAnnotations, "method annotation");
            sink.annotations(method.visibleTypeAnnotations, "method type annotation");
            sink.annotations(method.invisibleTypeAnnotations, "method type annotation");
            sink.parameterAnnotations(method.visibleParameterAnnotations, "parameter annotation");
            sink.parameterAnnotations(method.invisibleParameterAnnotations, "parameter annotation");
            if (method.tryCatchBlocks != null) {
                for (TryCatchBlockNode block : method.tryCatchBlocks) {
                    sink.type(block.type, "try-catch type");
                }
            }
            if (method.instructions == null) {
                continue;
            }
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                scanInstruction(insn, sink);
            }
        }
    }

    private static void scanInstruction(AbstractInsnNode insn, RefSink sink) {
        if (insn instanceof TypeInsnNode type) {
            sink.type(type.desc, "type instruction");
        } else if (insn instanceof FieldInsnNode field) {
            sink.type(field.owner, "field owner");
            sink.descriptor(field.desc, "field instruction descriptor");
        } else if (insn instanceof MethodInsnNode method) {
            sink.type(method.owner, "method owner");
            sink.descriptor(method.desc, "method instruction descriptor");
        } else if (insn instanceof InvokeDynamicInsnNode indy) {
            sink.descriptor(indy.desc, "invokedynamic descriptor");
            sink.handle(indy.bsm, "invokedynamic bootstrap");
            if (indy.bsmArgs != null) {
                for (Object argument : indy.bsmArgs) {
                    sink.value(argument, "invokedynamic bootstrap argument");
                }
            }
        } else if (insn instanceof MultiANewArrayInsnNode array) {
            sink.descriptor(array.desc, "multianewarray");
        } else if (insn instanceof LdcInsnNode ldc) {
            sink.value(ldc.cst, "ldc constant");
        } else if (insn instanceof FrameNode frame) {
            sink.frameTypes(frame.local);
            sink.frameTypes(frame.stack);
        }
    }

    /** Collects references to in-jar classes; the first kind seen for a target wins. */
    private static final class RefSink {
        private final Set<String> classNames;
        private final String owner;
        private final Map<String, String> refs = new TreeMap<>();

        private RefSink(Set<String> classNames, String owner) {
            this.classNames = classNames;
            this.owner = owner;
        }

        private void type(String internalName, String kind) {
            if (internalName == null || internalName.isEmpty()) {
                return;
            }
            if (internalName.charAt(0) == '[') {
                descriptor(internalName, kind);
                return;
            }
            if (internalName.charAt(0) == 'L' && internalName.endsWith(";")) {
                descriptor(internalName, kind);
                return;
            }
            if (internalName.equals(owner)) {
                return;
            }
            if (classNames.contains(internalName)) {
                refs.putIfAbsent(internalName, kind);
            }
        }

        private void descriptor(String descriptor, String kind) {
            if (descriptor == null || descriptor.isEmpty()) {
                return;
            }
            Type type;
            try {
                type = Type.getType(descriptor);
            } catch (RuntimeException e) {
                throw new IllegalArgumentException(
                        "invalid descriptor in " + owner + ": " + descriptor, e);
            }
            addType(type, kind);
        }

        private void addType(Type type, String kind) {
            if (type == null) {
                return;
            }
            switch (type.getSort()) {
                case Type.METHOD -> {
                    for (Type argument : type.getArgumentTypes()) {
                        addType(argument, kind);
                    }
                    addType(type.getReturnType(), kind);
                }
                case Type.ARRAY -> addType(type.getElementType(), kind);
                case Type.OBJECT -> type(type.getInternalName(), kind);
                default -> {
                    // primitives and void carry no class reference
                }
            }
        }

        private void signature(String signature, int kind, String label) {
            if (signature == null || signature.isEmpty()) {
                return;
            }
            try {
                SignatureReader reader = new SignatureReader(signature);
                SignatureNames visitor = new SignatureNames(this);
                if (kind == FIELD_SIGNATURE) {
                    reader.acceptType(visitor);
                } else {
                    reader.accept(visitor);
                }
            } catch (RuntimeException e) {
                throw new IllegalArgumentException(
                        "invalid " + label + " in " + owner + ": " + signature, e);
            }
        }

        private void handle(Handle handle, String kind) {
            if (handle == null) {
                return;
            }
            type(handle.getOwner(), kind);
            descriptor(handle.getDesc(), kind);
        }

        private void value(Object value, String kind) {
            if (value == null) {
                return;
            }
            if (value instanceof Type type) {
                addType(type, kind);
            } else if (value instanceof Handle handle) {
                handle(handle, kind);
            } else if (value instanceof ConstantDynamic dynamic) {
                descriptor(dynamic.getDescriptor(), kind);
                handle(dynamic.getBootstrapMethod(), kind);
                for (int i = 0; i < dynamic.getBootstrapMethodArgumentCount(); i++) {
                    value(dynamic.getBootstrapMethodArgument(i), kind);
                }
            } else if (value instanceof AnnotationNode annotation) {
                annotations(List.of(annotation), kind);
            } else if (value instanceof String[] pair) {
                if (pair.length == 2 && pair[0] != null && pair[0].startsWith("L")) {
                    descriptor(pair[0], kind);
                }
            } else if (value instanceof List<?> list) {
                for (Object item : list) {
                    value(item, kind);
                }
            } else if (value instanceof Object[] array) {
                for (Object item : array) {
                    value(item, kind);
                }
            }
        }

        private void annotations(List<? extends AnnotationNode> annotations, String kind) {
            if (annotations == null) {
                return;
            }
            for (AnnotationNode annotation : annotations) {
                if (annotation == null) {
                    continue;
                }
                descriptor(annotation.desc, kind);
                if (annotation.values != null) {
                    for (int i = 1; i < annotation.values.size(); i += 2) {
                        value(annotation.values.get(i), kind);
                    }
                }
            }
        }

        private void parameterAnnotations(List<AnnotationNode>[] parameterAnnotations, String kind) {
            if (parameterAnnotations == null) {
                return;
            }
            for (List<AnnotationNode> annotations : parameterAnnotations) {
                annotations(annotations, kind);
            }
        }

        private void frameTypes(List<Object> types) {
            if (types == null) {
                return;
            }
            for (Object type : types) {
                if (type instanceof String internalName) {
                    this.type(internalName, "stack map frame");
                }
            }
        }
    }

    /** Extracts class names from a generic signature, including {@code Outer.Inner} forms. */
    private static final class SignatureNames extends SignatureVisitor {
        private final RefSink sink;
        private String current;

        private SignatureNames(RefSink sink) {
            super(ASM_API);
            this.sink = sink;
        }

        @Override
        public void visitClassType(String name) {
            current = name;
            sink.type(name, "generic signature");
        }

        @Override
        public void visitInnerClassType(String name) {
            if (current != null) {
                current = current + "$" + name;
                sink.type(current, "generic signature");
            }
        }

        @Override
        public void visitEnd() {
            current = null;
        }
    }
}
