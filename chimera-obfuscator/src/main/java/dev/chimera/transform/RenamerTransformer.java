package dev.chimera.transform;

import dev.chimera.core.ChimeraConfig;
import dev.chimera.core.TransformContext;
import dev.chimera.core.Transformer;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.Remapper;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodNode;

import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * M7: opt-in class/method renaming for pure-logic classes.
 *
 * <p>Only classes annotated with {@code @ChimeraRename}, or methods annotated with it, are
 * renamed. Renaming runs before every other transformer, so later stages (string encryption,
 * native stubs, VM programs) already see the final names. A build-time safety gate refuses to
 * rename anything that could break a Fabric mod after runtime remapping:</p>
 *
 * <ul>
 *   <li>any {@code net.minecraft.*} / {@code net.fabricmc.*} / {@code com.mojang.*} reference
 *       in the class hierarchy, descriptors, signatures, annotations or method bodies;</li>
 *   <li>a Sponge Mixin annotation on the class or a method;</li>
 *   <li>a class name registered in {@code fabric.mod.json} (entrypoints, mixins, ...), or in a
 *       Mixin configuration JSON;</li>
 *   <li>interfaces/annotation types (external implementors would break).</li>
 * </ul>
 *
 * <p>Virtual methods are only renamed when the declaring class is final and no known supertype
 * declares the same method (override dispatch cannot be rewritten safely). Constructors,
 * class initializers and {@code main} are never renamed.</p>
 */
public final class RenamerTransformer implements Transformer {

    public static final String ANNOTATION_DESC = "Ldev/chimera/annotations/ChimeraRename;";
    private static final String MIXIN_PREFIX = "Lorg/spongepowered/asm/mixin/";
    private static final String VM_ANNOTATION = "Ldev/chimera/annotations/ChimeraVM;";
    private static final String NATIVE_ANNOTATION = "Ldev/chimera/annotations/ChimeraNative;";
    private static final Set<String> OBJECT_METHODS = Set.of(
            "equals", "hashCode", "toString", "clone", "finalize", "compareTo");

    private static volatile Plan lastPlan = Plan.EMPTY;

    private RenamerTransformer() {
    }

    /** The plan produced by the last {@link #prepare} call (diagnostics/tests only). */
    public static Plan lastPlan() {
        return lastPlan;
    }

    /**
     * Computes and validates the rename plan. Throws {@link IllegalArgumentException} when a
     * marked class/method is not safe to rename; the message explains the required fix.
     */
    public static Plan prepare(Map<String, byte[]> classes, Map<String, byte[]> resources,
                               ChimeraConfig config) {
        Map<String, ClassNode> nodes = new LinkedHashMap<>();
        for (Map.Entry<String, byte[]> entry : classes.entrySet()) {
            String key = entry.getKey();
            if (!key.endsWith(".class")) {
                continue;
            }
            String internalName = key.substring(0, key.length() - ".class".length());
            if (isExcluded(internalName, config)) {
                continue;
            }
            // A6: never touch M3's synthetic hidden-class fragments. They are named
            // <owner>$chimera$<id> and must keep their bootstrap identity if a jar is re-processed.
            if (internalName.contains("$chimera$")) {
                continue;
            }
            ClassNode node = new ClassNode();
            new ClassReader(entry.getValue()).accept(node, ClassReader.SKIP_FRAMES);
            nodes.put(node.name, node);
        }

        Map<String, String> guardedResources = guardedResourceClassNames(resources);
        Map<String, List<String>> superTypes = new HashMap<>();
        for (ClassNode node : nodes.values()) {
            List<String> parents = new ArrayList<>();
            if (node.superName != null) {
                parents.add(node.superName);
            }
            if (node.interfaces != null) {
                parents.addAll(node.interfaces);
            }
            superTypes.put(node.name, parents);
        }

        List<String> annotated = new ArrayList<>();
        for (ClassNode node : nodes.values()) {
            if (hasAnnotation(node.visibleAnnotations, ANNOTATION_DESC)
                    || hasAnnotation(node.invisibleAnnotations, ANNOTATION_DESC)) {
                annotated.add(node.name);
            }
        }
        Collections.sort(annotated);

        Set<String> usedNames = new HashSet<>();
        for (String name : classes.keySet()) {
            if (name.endsWith(".class")) {
                usedNames.add(name.substring(0, name.length() - ".class".length()));
            }
        }
        Map<String, String> classRenames = new LinkedHashMap<>();
        Map<String, Map<String, String>> methodRenames = new LinkedHashMap<>();
        int classCounter = 0;
        int methodCounter = 0;

        for (String owner : annotated) {
            ClassNode node = nodes.get(owner);
            validateClass(node, resources, guardedResources, nodes);
            classRenames.put(owner, nextClassName(owner, usedNames, ++classCounter));

            List<MethodNode> marked = new ArrayList<>();
            for (MethodNode method : node.methods) {
                if (hasAnnotation(method.visibleAnnotations, ANNOTATION_DESC)
                        || hasAnnotation(method.invisibleAnnotations, ANNOTATION_DESC)) {
                    marked.add(method);
                }
            }
            marked.sort((a, b) -> {
                int byName = a.name.compareTo(b.name);
                return byName != 0 ? byName : a.desc.compareTo(b.desc);
            });
            Map<String, String> ownerMethods = new LinkedHashMap<>();
            for (MethodNode method : marked) {
                validateMethod(node, method, nodes, superTypes);
                String newName = nextMethodName(node, ownerMethods, ++methodCounter);
                ownerMethods.put(method.name + method.desc, newName);
            }
            if (!ownerMethods.isEmpty()) {
                methodRenames.put(owner, ownerMethods);
            }
        }

        Plan plan = new Plan(classRenames, methodRenames, superTypes);
        lastPlan = plan;
        return plan;
    }

    /** Applies the plan to every class file and strips the marker annotation. */
    public static Map<String, byte[]> apply(Map<String, byte[]> classes, Plan plan) {
        if (plan.isEmpty()) {
            return classes;
        }
        Remapper remapper = plan.remapper();
        Map<String, byte[]> out = new LinkedHashMap<>();
        for (Map.Entry<String, byte[]> entry : classes.entrySet()) {
            String key = entry.getKey();
            if (!key.endsWith(".class")) {
                out.put(key, entry.getValue());
                continue;
            }
            String internalName = key.substring(0, key.length() - ".class".length());
            ClassReader reader = new ClassReader(entry.getValue());
            ClassWriter writer = new ClassWriter(0);
            ClassVisitor visitor = new ClassRemapper(new AnnotationStripper(writer), remapper);
            reader.accept(visitor, 0);
            String mapped = remapper.map(internalName);
            out.put(mapped + ".class", writer.toByteArray());
        }
        return out;
    }

    private static void validateClass(ClassNode node, Map<String, byte[]> resources,
                                      Map<String, String> guardedResources,
                                      Map<String, ClassNode> nodes) {
        String issue = dev.chimera.transform.FabricSafetyGuard.inspectClass(node);
        if (issue != null) {
            fail(node.name, issue);
        }
        for (FieldNode field : node.fields) {
            String offending = dev.chimera.transform.FabricSafetyGuard.findInDescriptor(field.desc);
            if (offending == null && field.signature != null) {
                offending = dev.chimera.transform.FabricSafetyGuard.findInDescriptor(field.signature);
            }
            if (offending != null) {
                fail(node.name + "." + field.name, "field " + field.desc + " -> " + offending);
            }
        }
        for (MethodNode method : node.methods) {
            String offending = dev.chimera.transform.FabricSafetyGuard.inspect(method);
            if (offending != null) {
                fail(node.name + "." + method.name + method.desc, offending);
            }
        }
        if ((node.access & Opcodes.ACC_INTERFACE) != 0 || (node.access & Opcodes.ACC_ANNOTATION) != 0) {
            fail(node.name, "interfaces and annotation types must not be renamed (external implementors "
                    + "would break); annotate a final pure-logic class instead");
        }
        String registered = guardedResources.get(node.name);
        if (registered != null) {
            fail(node.name, "class is registered in " + registered
                    + " (Fabric entrypoint or Mixin config); renaming it breaks mod loading");
        }
    }

    private static void validateMethod(ClassNode owner, MethodNode method,
                                       Map<String, ClassNode> nodes, Map<String, List<String>> superTypes) {
        if ("<init>".equals(method.name) || "<clinit>".equals(method.name)) {
            fail(owner.name + "." + method.name, "constructors/class initializers cannot be renamed");
        }
        if ("main".equals(method.name) && "([Ljava/lang/String;)V".equals(method.desc)) {
            fail(owner.name + ".main", "the main entrypoint cannot be renamed");
        }
        if ((method.access & Opcodes.ACC_ABSTRACT) != 0) {
            fail(owner.name + "." + method.name, "abstract methods cannot be renamed; annotate the "
                    + "concrete static/private method instead");
        }
        if (hasAnnotation(method.visibleAnnotations, VM_ANNOTATION)
                || hasAnnotation(method.invisibleAnnotations, VM_ANNOTATION)
                || hasAnnotation(method.visibleAnnotations, NATIVE_ANNOTATION)
                || hasAnnotation(method.invisibleAnnotations, NATIVE_ANNOTATION)) {
            fail(owner.name + "." + method.name, "a @ChimeraVM/@ChimeraNative method cannot also be "
                    + "renamed (its body is generated from the original name); rename the caller instead");
        }
        boolean staticOrPrivate = (method.access & (Opcodes.ACC_STATIC | Opcodes.ACC_PRIVATE)) != 0;
        if (staticOrPrivate) {
            return;
        }
        if ((owner.access & Opcodes.ACC_FINAL) == 0) {
            fail(owner.name + "." + method.name, "virtual methods are only renamed in a final class; "
                    + "override dispatch cannot be rewritten safely. Make the method static/private "
                    + "or mark the class final.");
        }
        if (OBJECT_METHODS.contains(method.name)) {
            fail(owner.name + "." + method.name, "methods overriding java.lang.Object cannot be renamed");
        }
        String unknown = unknownSuperType(owner, nodes);
        if (unknown != null) {
            fail(owner.name + "." + method.name, "class extends/implements unknown type " + unknown
                    + "; a virtual method may implement its contract, so it cannot be renamed safely");
        }
        if (overridesKnownSuper(owner, method, nodes, superTypes)) {
            fail(owner.name + "." + method.name, "method overrides a supertype method; rename is unsafe");
        }
    }

    private static String unknownSuperType(ClassNode owner, Map<String, ClassNode> nodes) {
        if (owner.superName != null && !"java/lang/Object".equals(owner.superName)
                && !nodes.containsKey(owner.superName)) {
            return owner.superName;
        }
        if (owner.interfaces != null) {
            for (String itf : owner.interfaces) {
                if (!nodes.containsKey(itf)) {
                    return itf;
                }
            }
        }
        return null;
    }

    private static boolean overridesKnownSuper(ClassNode owner, MethodNode method,
                                               Map<String, ClassNode> nodes,
                                               Map<String, List<String>> superTypes) {
        Deque<String> queue = new ArrayDeque<>();
        queue.addAll(superTypes.getOrDefault(owner.name, List.of()));
        Set<String> seen = new HashSet<>();
        while (!queue.isEmpty()) {
            String type = queue.poll();
            if (!seen.add(type)) {
                continue;
            }
            ClassNode node = nodes.get(type);
            if (node != null) {
                for (MethodNode candidate : node.methods) {
                    if (candidate.name.equals(method.name) && candidate.desc.equals(method.desc)) {
                        return true;
                    }
                }
            }
            queue.addAll(superTypes.getOrDefault(type, List.of()));
        }
        return false;
    }

    private static String nextClassName(String owner, Set<String> usedNames, int counter) {
        int slash = owner.lastIndexOf('/');
        String packagePrefix = slash < 0 ? "" : owner.substring(0, slash + 1);
        int n = counter;
        while (true) {
            String candidate = packagePrefix + "a$" + n;
            if (usedNames.add(candidate)) {
                return candidate;
            }
            n++;
        }
    }

    private static String nextMethodName(ClassNode owner, Map<String, String> ownerMethods, int counter) {
        Set<String> taken = new HashSet<>();
        for (MethodNode method : owner.methods) {
            taken.add(method.name + method.desc);
        }
        int n = counter;
        while (true) {
            String candidate = "m$" + n;
            if (!containsName(taken, candidate)) {
                return candidate;
            }
            n++;
        }
    }

    private static boolean containsName(Set<String> signatures, String name) {
        for (String signature : signatures) {
            int paren = signature.indexOf('(');
            String existing = paren < 0 ? signature : signature.substring(0, paren);
            if (existing.equals(name)) {
                return true;
            }
        }
        return false;
    }

    private static Map<String, String> guardedResourceClassNames(Map<String, byte[]> resources) {
        Map<String, String> guarded = new HashMap<>();
        for (Map.Entry<String, byte[]> entry : resources.entrySet()) {
            String name = entry.getKey();
            if (!name.endsWith(".json")) {
                continue;
            }
            String lower = name.toLowerCase(java.util.Locale.ROOT);
            boolean relevant = lower.equals("fabric.mod.json") || lower.contains("mixins");
            if (!relevant) {
                continue;
            }
            String text = new String(entry.getValue(), StandardCharsets.UTF_8);
            Matcher matcher = Pattern.compile("\"([A-Za-z0-9_$.]+)\"").matcher(text);
            while (matcher.find()) {
                String value = matcher.group(1);
                if (value.indexOf('.') < 0 && value.indexOf('/') < 0) {
                    continue;
                }
                if (value.contains("/")) {
                    guarded.put(value, name);
                } else if (value.matches("[A-Za-z_$][A-Za-z0-9_$]*(\\.[A-Za-z_$][A-Za-z0-9_$]*)+")) {
                    guarded.put(value.replace('.', '/'), name);
                }
            }
        }
        return guarded;
    }

    private static boolean hasAnnotation(List<org.objectweb.asm.tree.AnnotationNode> annotations,
                                         String descriptor) {
        if (annotations == null) {
            return false;
        }
        for (org.objectweb.asm.tree.AnnotationNode annotation : annotations) {
            if (annotation.desc != null && annotation.desc.equals(descriptor)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isExcluded(String internalName, ChimeraConfig config) {
        if (config == null) {
            return false;
        }
        if (internalName.startsWith("dev/chimera/runtime/")
                || internalName.startsWith("dev/chimera/annotations/")) {
            return true;
        }
        for (String exclude : config.excludes) {
            if (internalName.equals(exclude) || internalName.startsWith(exclude + "/")
                    || internalName.startsWith(exclude)) {
                return true;
            }
        }
        return false;
    }

    private static void fail(String owner, String issue) {
        throw new IllegalArgumentException("Chimera rename safety check failed for " + owner + ": "
                + issue + ".\nRenaming would break Fabric runtime remapping/mod loading. Fix: keep "
                + "@ChimeraRename on a final pure-logic class that has no Minecraft/Fabric types, "
                + "no Mixin annotations and is not listed in fabric.mod.json or a mixin config.");
    }

    @Override
    public void transform(String internalName, ClassNode node, TransformContext ctx) {
        // Renaming is a whole-jar pre-pass (see ChimeraEngine); nothing is done per class here.
    }

    /** Immutable rename plan. */
    public static final class Plan {
        public static final Plan EMPTY = new Plan(Map.of(), Map.of(), Map.of());

        private final Map<String, String> classRenames;
        private final Map<String, Map<String, String>> methodRenames;
        private final Map<String, List<String>> superTypes;

        private Plan(Map<String, String> classRenames,
                     Map<String, Map<String, String>> methodRenames,
                     Map<String, List<String>> superTypes) {
            this.classRenames = classRenames;
            this.methodRenames = methodRenames;
            this.superTypes = superTypes;
        }

        public boolean isEmpty() {
            return classRenames.isEmpty() && methodRenames.isEmpty();
        }

        public int classCount() {
            return classRenames.size();
        }

        public int methodCount() {
            int count = 0;
            for (Map<?, ?> methods : methodRenames.values()) {
                count += methods.size();
            }
            return count;
        }

        public Map<String, String> classRenames() {
            return Collections.unmodifiableMap(new TreeMap<>(classRenames));
        }

        public Map<String, Map<String, String>> methodRenames() {
            return Collections.unmodifiableMap(new TreeMap<>(methodRenames));
        }

        public Remapper remapper() {
            return new Remapper() {
                @Override
                public String map(String internalName) {
                    String mapped = classRenames.get(internalName);
                    return mapped == null ? internalName : mapped;
                }

                @Override
                public String mapMethodName(String owner, String name, String descriptor) {
                    String mapped = methodName(owner, name, descriptor);
                    return mapped == null ? name : mapped;
                }
            };
        }

        public String methodName(String owner, String name, String descriptor) {
            String key = name + descriptor;
            String type = owner;
            Set<String> seen = new HashSet<>();
            while (type != null && seen.add(type)) {
                Map<String, String> methods = methodRenames.get(type);
                if (methods != null && methods.containsKey(key)) {
                    return methods.get(key);
                }
                List<String> parents = superTypes.get(type);
                if (parents == null || parents.isEmpty()) {
                    return null;
                }
                type = parents.get(0);
            }
            return null;
        }
    }

    /** Strips the marker annotation so the output does not reveal which classes were renamed. */
    private static final class AnnotationStripper extends ClassVisitor {
        private AnnotationStripper(ClassVisitor delegate) {
            super(Opcodes.ASM9, delegate);
        }

        @Override
        public org.objectweb.asm.AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
            if (ANNOTATION_DESC.equals(descriptor)) {
                return null;
            }
            return super.visitAnnotation(descriptor, visible);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor,
                                         String signature, String[] exceptions) {
            MethodVisitor delegate = super.visitMethod(access, name, descriptor, signature, exceptions);
            if (delegate == null) {
                return null;
            }
            return new MethodVisitor(Opcodes.ASM9, delegate) {
                @Override
                public org.objectweb.asm.AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
                    if (ANNOTATION_DESC.equals(descriptor)) {
                        return null;
                    }
                    return super.visitAnnotation(descriptor, visible);
                }
            };
        }
    }
}
