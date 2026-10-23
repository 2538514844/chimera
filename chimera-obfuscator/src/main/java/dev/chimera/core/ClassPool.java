package dev.chimera.core;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Opcodes;

import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Resolves class hierarchy information for ASM frame computation.
 *
 * <p>Classes supplied by the input jar are parsed with ASM and never loaded or
 * initialized. Unknown classes fall back to a non-initializing
 * {@link Class#forName(String, boolean, ClassLoader)} lookup against the plugin/JDK
 * class loader; everything else is treated as unknown (falling back to
 * {@code java/lang/Object} where a super type is required). Results are cached.</p>
 */
public final class ClassPool {
    private static final String OBJECT = "java/lang/Object";
    private static final String CLONEABLE = "java/lang/Cloneable";
    private static final String SERIALIZABLE = "java/io/Serializable";
    private static final String[] EMPTY_INTERFACES = new String[0];

    /** Sentinel for classes that could not be resolved; ConcurrentHashMap forbids null values. */
    private static final ClassInfo UNKNOWN = new ClassInfo(null, null, EMPTY_INTERFACES, false);

    /** JDK hierarchy cache shared by all pools (the JDK hierarchy never changes). */
    private static final Map<String, ClassInfo> JDK_CACHE = new ConcurrentHashMap<>();

    private final Map<String, ClassInfo> classes = new ConcurrentHashMap<>();
    /** Phase 0: types frame computation needed but could neither be found nor resolved. */
    private final Set<String> unresolved = ConcurrentHashMap.newKeySet();
    private volatile boolean strictHierarchy;
    private final Map<String, ClassInfo> arrayCache = new ConcurrentHashMap<>();
    private final Map<String, String> commonSuperCache = new ConcurrentHashMap<>();

    /**
     * @param classes map from entry name ("pkg/C.class" or "pkg/C") to class file bytes
     */
    public ClassPool(Map<String, byte[]> classes) {
        if (classes == null) {
            return;
        }
        for (Map.Entry<String, byte[]> entry : classes.entrySet()) {
            String key = entry.getKey();
            byte[] bytes = entry.getValue();
            if (key == null || bytes == null || bytes.length == 0) {
                continue;
            }
            String normalized = normalize(key);
            if (normalized.isEmpty()) {
                continue;
            }
            ClassInfo info = parse(normalized, bytes);
            if (info != null) {
                this.classes.put(info.name(), info);
            }
        }
    }

    /**
     * Registers one library class (from a jar given via {@code --classpath}) for hierarchy
     * resolution. Obfuscators need the library classpath the same way ProGuard needs
     * {@code -libraryjars}: without Minecraft/Fabric classes ASM frame computation degrades to
     * {@code java/lang/Object} and produces invalid StackMapTables.
     */
    public void addClassBytes(String entryName, byte[] bytes) {
        if (entryName == null || bytes == null || bytes.length == 0) {
            return;
        }
        String normalized = normalize(entryName);
        if (normalized.isEmpty()) {
            return;
        }
        ClassInfo info = parse(normalized, bytes);
        if (info != null) {
            this.classes.put(info.name(), info);
        }
    }

    /**
     * Phase 0 (C-15): in release builds frame computation must not silently degrade to
     * {@code java/lang/Object}. With strict hierarchy enabled, every type the frame algorithm
     * cannot resolve is recorded and the build fails instead of emitting a VerifyError.
     */
    public void setStrictHierarchy(boolean strict) {
        this.strictHierarchy = strict;
    }

    /** @return types that frame computation required but could not resolve (sorted) */
    public java.util.List<String> unresolvedTypes() {
        java.util.List<String> out = new java.util.ArrayList<>(unresolved);
        java.util.Collections.sort(out);
        return out;
    }

    /** @return true if hierarchy information for the type is available (input jar or JDK) */
    public boolean has(String internalName) {
        return info(internalName) != null;
    }

    /** @return the super class internal name, or null for {@code java/lang/Object} / unknown classes */
    public String superName(String internalName) {
        ClassInfo info = info(internalName);
        return info == null ? null : info.superName();
    }

    /** @return the direct super interfaces (empty for unknown classes) */
    public List<String> interfaces(String internalName) {
        ClassInfo info = info(internalName);
        if (info == null || info.interfaces().length == 0) {
            return Collections.emptyList();
        }
        return List.of(info.interfaces());
    }

    /**
     * @return true if a value of type {@code from} can be assigned to a variable of type {@code to}
     *         (i.e. {@code from} is {@code to} or a subtype of it)
     */
    public boolean isAssignable(String from, String to) {
        if (from == null || to == null) {
            return false;
        }
        if (from.equals(to)) {
            return true;
        }
        if (isArray(from) || isArray(to)) {
            return arrayAssignable(from, to);
        }
        if (OBJECT.equals(to)) {
            return true;
        }
        Set<String> visited = new HashSet<>();
        Deque<String> queue = new ArrayDeque<>();
        queue.add(from);
        while (!queue.isEmpty()) {
            String type = queue.poll();
            if (!visited.add(type)) {
                continue;
            }
            if (type.equals(to)) {
                return true;
            }
            ClassInfo info = info(type);
            if (info == null) {
                continue;
            }
            if (info.superName() != null) {
                queue.add(info.superName());
            }
            for (String itf : info.interfaces()) {
                queue.add(itf);
            }
        }
        return false;
    }

    /**
     * Standard ASM algorithm: equal types, assignable types, interface involvement,
     * then the first super type of {@code a} that is a super type of {@code b}.
     * Unknown types degrade to {@code java/lang/Object}. Results are cached.
     */
    public String commonSuperClass(String a, String b) {
        if (a == null || b == null) {
            return OBJECT;
        }
        if (a.equals(b)) {
            return a;
        }
        if (strictHierarchy) {
            recordIfUnresolved(a);
            recordIfUnresolved(b);
        }
        String cacheKey = a + '\0' + b;
        String cached = commonSuperCache.get(cacheKey);
        if (cached != null) {
            return cached;
        }
        String result = computeCommonSuperClass(a, b);
        commonSuperCache.put(cacheKey, result);
        return result;
    }

    private void recordIfUnresolved(String internalName) {
        if (internalName == null || internalName.isEmpty() || isArray(internalName)) {
            return;
        }
        if (!has(internalName)) {
            unresolved.add(internalName);
        }
    }

    private String computeCommonSuperClass(String a, String b) {
        if (a.equals(b)) {
            return a;
        }
        if (isArray(a) || isArray(b)) {
            return arrayCommonSuperClass(a, b);
        }
        if (isAssignable(a, b)) {
            return b;
        }
        if (isAssignable(b, a)) {
            return a;
        }
        if (isInterface(a) || isInterface(b)) {
            return OBJECT;
        }
        for (String parent = superName(a); parent != null; parent = superName(parent)) {
            if (isAssignable(b, parent)) {
                return parent;
            }
        }
        return OBJECT;
    }

    /** Handles assignment for arrays (covariance plus Cloneable/Serializable/Object). */
    private boolean arrayAssignable(String from, String to) {
        if (!isArray(to)) {
            // 'from' must be an array here.
            return OBJECT.equals(to) || CLONEABLE.equals(to) || SERIALIZABLE.equals(to);
        }
        if (!isArray(from)) {
            return false;
        }
        String fromElement = arrayElement(from);
        String toElement = arrayElement(to);
        if (fromElement == null || toElement == null) {
            // Primitive arrays: only identical descriptors are assignable.
            return from.equals(to);
        }
        return isAssignable(fromElement, toElement);
    }

    private String arrayCommonSuperClass(String a, String b) {
        if (a.equals(b)) {
            return a;
        }
        if (!isArray(a) || !isArray(b)) {
            String other = isArray(a) ? b : a;
            if (OBJECT.equals(other) || CLONEABLE.equals(other) || SERIALIZABLE.equals(other)) {
                return other;
            }
            return OBJECT;
        }
        String elementA = arrayElement(a);
        String elementB = arrayElement(b);
        if (elementA == null || elementB == null) {
            return OBJECT;
        }
        String commonElement = commonSuperClass(elementA, elementB);
        if (isArray(commonElement)) {
            return "[" + commonElement;
        }
        if (OBJECT.equals(commonElement)) {
            // Reference arrays are covariant: Object[] is a common super type.
            return "[Ljava/lang/Object;";
        }
        return "[L" + commonElement + ";";
    }

    private boolean isInterface(String internalName) {
        ClassInfo info = info(internalName);
        return info != null && info.isInterface();
    }

    private ClassInfo info(String internalName) {
        if (internalName == null || internalName.isEmpty()) {
            return null;
        }
        ClassInfo local = classes.get(internalName);
        if (local != null) {
            return local;
        }
        if (isArray(internalName)) {
            return arrayCache.computeIfAbsent(internalName, ClassPool::arrayInfo);
        }
        ClassInfo cached = JDK_CACHE.get(internalName);
        if (cached == UNKNOWN) {
            return null;
        }
        if (cached != null) {
            return cached;
        }
        ClassInfo resolved = resolveJdk(internalName);
        JDK_CACHE.putIfAbsent(internalName, resolved == null ? UNKNOWN : resolved);
        return resolved;
    }

    private static ClassInfo parse(String expectedName, byte[] bytes) {
        try {
            Header header = new Header();
            new ClassReader(bytes).accept(header,
                    ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
            String name = header.name == null ? expectedName : header.name;
            return new ClassInfo(name, header.superName, header.interfaces,
                    (header.access & Opcodes.ACC_INTERFACE) != 0);
        } catch (RuntimeException ex) {
            // Malformed class: leave it unknown so frame computation degrades to java/lang/Object.
            return null;
        }
    }

    private static ClassInfo resolveJdk(String internalName) {
        if (OBJECT.equals(internalName)) {
            return new ClassInfo(OBJECT, null, EMPTY_INTERFACES, false);
        }
        try {
            Class<?> type = Class.forName(internalName.replace('/', '.'), false,
                    ChimeraEngine.class.getClassLoader());
            if (type.isPrimitive()) {
                return null;
            }
            Class<?> superClass = type.getSuperclass();
            Class<?>[] interfaces = type.getInterfaces();
            String[] names = new String[interfaces.length];
            for (int i = 0; i < interfaces.length; i++) {
                names[i] = interfaces[i].getName().replace('.', '/');
            }
            return new ClassInfo(internalName,
                    superClass == null ? null : superClass.getName().replace('.', '/'),
                    names, type.isInterface());
        } catch (ClassNotFoundException | LinkageError | SecurityException ex) {
            return null;
        }
    }

    private static ClassInfo arrayInfo(String descriptor) {
        return new ClassInfo(descriptor, OBJECT, new String[]{CLONEABLE, SERIALIZABLE}, false);
    }

    private static String normalize(String key) {
        String name = key;
        if (name.endsWith(".class")) {
            name = name.substring(0, name.length() - ".class".length());
        }
        int start = 0;
        while (start < name.length() && name.charAt(start) == '/') {
            start++;
        }
        return name.substring(start);
    }

    private static boolean isArray(String internalName) {
        return internalName != null && !internalName.isEmpty() && internalName.charAt(0) == '[';
    }

    /**
     * @return the internal name of the element type, the nested array descriptor,
     *         or null for a primitive element type
     */
    private static String arrayElement(String arrayDescriptor) {
        String element = arrayDescriptor.substring(1);
        if (element.startsWith("L") && element.endsWith(";") && element.length() > 2) {
            return element.substring(1, element.length() - 1);
        }
        if (element.startsWith("[")) {
            return element;
        }
        return null;
    }

    private static final class Header extends ClassVisitor {
        private String name;
        private String superName;
        private String[] interfaces = EMPTY_INTERFACES;
        private int access;

        private Header() {
            super(Opcodes.ASM9);
        }

        @Override
        public void visit(int version, int access, String name, String signature,
                          String superName, String[] interfaces) {
            this.access = access;
            this.name = name;
            this.superName = superName;
            this.interfaces = interfaces == null || interfaces.length == 0
                    ? EMPTY_INTERFACES : interfaces.clone();
        }
    }

    private record ClassInfo(String name, String superName, String[] interfaces, boolean isInterface) {
    }
}
