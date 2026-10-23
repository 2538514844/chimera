package dev.chimera.transform.indy;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.lang.invoke.MethodType;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * M10: dynamic (classId, memberId) -&gt; Class/Field/Method cache, signature-compatible with the
 * Hachimi {@code af} linker observed in the reference sample:
 *
 * <pre>
 *   public static int     a(long classId, long memberId)  // membership probe: 1 = resolvable, 0 = not
 *   public static Class   b(long classId, long memberId)  // class for classId
 *   public static Field   c(long classId, long memberId)  // registered field
 *   public static Method  d(long classId, long memberId)  // registered method
 * </pre>
 *
 * <p>Unlike the reference sample, ids are deterministic FNV-1a hashes so a build and the tests can
 * derive them independently; a future release build can replace {@link #classId(String)} /
 * {@link #memberId(String, String, String)} with a per-build randomized table without changing the
 * bootstrap contract.</p>
 *
 * <p>The registry is populated by the build pipeline (or by tests) before transformed classes are
 * linked. Lookups are cached; {@link #classLookups()} / {@link #memberLookups()} expose counters so
 * tests can prove the bootstrap only resolves once per call site.</p>
 */
public final class MemberIdRegistry {

    /** {@code a()} member kind: registered field. */
    public static final int MEMBER_FIELD = 1;
    /** {@code a()} member kind: registered method. */
    public static final int MEMBER_METHOD = 2;

    private static final long FNV_OFFSET = 0xcbf29ce484222325L;
    private static final long FNV_PRIME = 0x100000001b3L;

    private static final ConcurrentHashMap<Long, Class<?>> CLASSES = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<MemberKey, Object> MEMBERS = new ConcurrentHashMap<>();
    private static final AtomicLong CLASS_LOOKUPS = new AtomicLong();
    private static final AtomicLong MEMBER_LOOKUPS = new AtomicLong();
    private static final AtomicLong MISSES = new AtomicLong();

    private MemberIdRegistry() {
    }

    /** Immutable (classId, memberId) cache key. */
    public record MemberKey(long classId, long memberId) {
    }

    // ------------------------------------------------------------------ id derivation

    /** Deterministic class id (FNV-1a 64 over the internal name). */
    public static long classId(String internalName) {
        if (internalName == null || internalName.isEmpty()) {
            return 0L;
        }
        long hash = FNV_OFFSET;
        for (byte b : internalName.getBytes(StandardCharsets.UTF_8)) {
            hash ^= (b & 0xffL);
            hash *= FNV_PRIME;
        }
        return hash == 0L ? 1L : hash;
    }

    /** Deterministic member id (FNV-1a 64 over owner, name and descriptor). */
    public static long memberId(String owner, String name, String desc) {
        if (owner == null || name == null || desc == null) {
            return 0L;
        }
        long hash = FNV_OFFSET;
        hash = mix(hash, owner);
        hash = mix(hash, "\u0000");
        hash = mix(hash, name);
        hash = mix(hash, "\u0000");
        hash = mix(hash, desc);
        return hash == 0L ? 1L : hash;
    }

    private static long mix(long hash, String value) {
        for (byte b : value.getBytes(StandardCharsets.UTF_8)) {
            hash ^= (b & 0xffL);
            hash *= FNV_PRIME;
        }
        return hash;
    }

    /** Internal name for a non-array class ({@code a.b.C -> a/b/C}). */
    public static String internalName(Class<?> type) {
        if (type == null) {
            throw new IllegalArgumentException("type must not be null");
        }
        if (type.isArray()) {
            throw new IllegalArgumentException("array types are not supported: " + type.getName());
        }
        return type.getName().replace('.', '/');
    }

    // ------------------------------------------------------------------ population

    public static void registerClass(long classId, Class<?> type) {
        if (type == null) {
            throw new IllegalArgumentException("type must not be null");
        }
        CLASSES.put(Long.valueOf(classId), type);
    }

    public static void registerClass(String internalName, Class<?> type) {
        registerClass(classId(internalName), type);
    }

    public static void registerClass(Class<?> type) {
        registerClass(internalName(type), type);
    }

    public static void registerField(long classId, long memberId, Field field) {
        if (field == null) {
            throw new IllegalArgumentException("field must not be null");
        }
        MEMBERS.put(new MemberKey(classId, memberId), field);
    }

    public static void registerMethod(long classId, long memberId, Method method) {
        if (method == null) {
            throw new IllegalArgumentException("method must not be null");
        }
        MEMBERS.put(new MemberKey(classId, memberId), method);
    }

    /** Registers a field by reflection (test/build helper). */
    public static void registerField(Class<?> owner, String name) {
        try {
            Field field = owner.getDeclaredField(name);
            field.setAccessible(true);
            registerField(classId(internalName(owner)),
                    memberId(internalName(owner), name, descriptorOf(field.getType())),
                    field);
        } catch (NoSuchFieldException e) {
            throw new IllegalArgumentException("unknown field " + owner.getName() + "." + name, e);
        }
    }

    /** Registers {@code owner.name(parameterTypes)} by reflection (test/build helper). */
    public static void registerMethod(Class<?> owner, String name, Class<?>... parameterTypes) {
        try {
            Method method = owner.getDeclaredMethod(name, parameterTypes);
            method.setAccessible(true);
            registerMethod(classId(internalName(owner)),
                    memberId(internalName(owner), name, methodDescriptorOf(method)),
                    method);
        } catch (NoSuchMethodException e) {
            throw new IllegalArgumentException("unknown method " + owner.getName() + "." + name, e);
        }
    }

    public static void clearForTests() {
        memberTableLoaded = false;
        unresolvedMembers = 0;
        CLASSES.clear();
        MEMBERS.clear();
        CLASS_LOOKUPS.set(0L);
        MEMBER_LOOKUPS.set(0L);
        MISSES.set(0L);
    }

    // ------------------------------------------------------------------ af-compatible lookups

    /** {@code a(JJ)I}: 1 when the member is registered, 0 otherwise; never throws. */
    public static int a(long classId, long memberId) {
        Object member = MEMBERS.get(new MemberKey(classId, memberId));
        if (member == null) {
            MISSES.incrementAndGet();
            return 0;
        }
        return member instanceof Field ? MEMBER_FIELD : MEMBER_METHOD;
    }

    /** {@code b(JJ)Class}: class for {@code classId}; null when not registered. */
    public static Class<?> b(long classId, long memberId) {
        CLASS_LOOKUPS.incrementAndGet();
        Class<?> type = CLASSES.get(Long.valueOf(classId));
        if (type == null) {
            MISSES.incrementAndGet();
        }
        return type;
    }

    /** {@code c(JJ)Field}: registered field; null when absent or a method was registered. */
    public static Field c(long classId, long memberId) {
        Object member = lookupMember(classId, memberId);
        return member instanceof Field field ? field : null;
    }

    /** {@code d(JJ)Method}: registered method; null when absent or a field was registered. */
    public static Method d(long classId, long memberId) {
        Object member = lookupMember(classId, memberId);
        return member instanceof Method method ? method : null;
    }

    private static Object lookupMember(long classId, long memberId) {
        MEMBER_LOOKUPS.incrementAndGet();
        Object member = MEMBERS.get(new MemberKey(classId, memberId));
        if (member == null) {
            MISSES.incrementAndGet();
        }
        return member;
    }

    /** True when the registered member is static (helper for the bootstrap). */
    public static boolean isStatic(long classId, long memberId) {
        Object member = MEMBERS.get(new MemberKey(classId, memberId));
        if (member instanceof Method method) {
            return Modifier.isStatic(method.getModifiers());
        }
        return false;
    }

    // ------------------------------------------------------------------ runtime member table

    /** "CHMI" member-table magic (see {@code docs/M10-INDY-REPORT.md}). */
    public static final int MEMBER_TABLE_MAGIC = 0x43484D49;
    public static final int MEMBER_TABLE_VERSION = 1;
    public static final int ENTRY_CLASS = 0;
    public static final int ENTRY_FIELD = 1;
    public static final int ENTRY_METHOD = 2;

    /**
     * Loads the build-time member-id table into this registry. The table carries class ids and
     * member ids plus owner/name/descriptor strings, so the runtime does not need to recompute
     * ids or carry a large literal map. Classes are resolved without initialization via the
     * supplied loader; fields/methods are looked up on the declaring class.
     */
    private static volatile boolean memberTableLoaded;
    private static volatile int unresolvedMembers;

    /** Members present in the table but not resolvable at runtime (diagnostics). */
    public static int unresolvedMembers() {
        return unresolvedMembers;
    }

    /** True once a CHMI member table has been loaded (build-time resource or explicit load). */
    public static boolean isMemberTableLoaded() {
        return memberTableLoaded;
    }

    /**
     * Lenient variant of {@link #loadMemberTable(byte[], ClassLoader, boolean)}: an entry whose
     * field/method cannot be resolved is counted in {@link #unresolvedMembers()} and the affected
     * call site still fails closed at first link.
     */
    /** S5: defines a hidden owner lazily so class loading does not run before the license gate. */
    private static boolean defineHiddenOwner(ClassLoader loader, String owner) {
        try {
            Class<?> registry = Class.forName("dev.chimera.runtime.ChimeraHiddenRegistry", true, loader);
            Object defined = registry.getMethod("defineByName", ClassLoader.class, String.class)
                    .invoke(null, loader, owner);
            boolean ok = Boolean.TRUE.equals(defined);
            try {
                java.nio.file.Path dir = java.nio.file.Path.of(
                        System.getProperty("user.home", "."), ".chimera");
                java.nio.file.Files.createDirectories(dir);
                java.nio.file.Files.writeString(dir.resolve("hidden-install.log"),
                        "lazy owner=" + owner + " ok=" + ok + "\n",
                        java.nio.charset.StandardCharsets.UTF_8,
                        java.nio.file.StandardOpenOption.CREATE,
                        java.nio.file.StandardOpenOption.APPEND);
            } catch (Throwable ignored) {
            }
            return ok;
        } catch (Throwable ignored) {
            return false;
        }
    }

    /** S5 fallback: defines every hidden class (native multi-pass) when one definition failed. */
    private static void defineAllHidden(ClassLoader loader) {
        try {
            Class<?> registry = Class.forName("dev.chimera.runtime.ChimeraHiddenRegistry", true, loader);
            registry.getMethod("install", ClassLoader.class).invoke(null, loader);
        } catch (Throwable ignored) {
            // Fail closed: the caller still throws ClassNotFoundException.
        }
    }

    public static void loadMemberTable(byte[] table, ClassLoader loader) {
        loadMemberTable(table, loader, false);
    }

    /**
     * Loads a CHMI table, including {@code ENTRY_FIELD} entries (G3). Fields are resolved along
     * the superclass/interface hierarchy and their descriptor is verified, so a table that names a
     * subclass owner but a field declared in a super type still resolves.
     *
     * @param strict when true, any unresolvable entry rejects the whole table
     *               ({@link IllegalArgumentException}); the default (false) keeps per-entry
     *               tolerance while never turning an unresolved site into a successful link.
     */
    public static void loadMemberTable(byte[] table, ClassLoader loader, boolean strict) {
        if (table == null) {
            throw new IllegalArgumentException("member table must not be null");
        }
        ClassLoader effectiveLoader = loader == null ? ClassLoader.getSystemClassLoader() : loader;
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(table))) {
            int magic = in.readInt();
            if (magic != MEMBER_TABLE_MAGIC) {
                throw new IllegalArgumentException("bad member-table magic: 0x"
                        + Integer.toHexString(magic));
            }
            int version = in.readInt();
            if (version != MEMBER_TABLE_VERSION) {
                throw new IllegalArgumentException("unsupported member-table version: " + version);
            }
            int count = in.readInt();
            if (count < 0 || count > 1_000_000) {
                throw new IllegalArgumentException("bad member-table count: " + count);
            }
            for (int i = 0; i < count; i++) {
                int kind = in.readUnsignedByte();
                long classId = in.readLong();
                long memberId = in.readLong();
                String owner = readUtf(in);
                String name = readUtf(in);
                String desc = readUtf(in);
                Class<?> ownerClass;
                try {
                    ownerClass = Class.forName(owner.replace('/', '.'), false, effectiveLoader);
                } catch (ClassNotFoundException | LinkageError missingOwner) {
                    if (!defineHiddenOwner(effectiveLoader, owner)) {
                        // Superclass ordering can make a single definition fail; fall back to the
                        // full native pass once, then retry the lookup.
                        defineAllHidden(effectiveLoader);
                    }
                    try {
                        ownerClass = Class.forName(owner.replace('/', '.'), false, effectiveLoader);
                    } catch (ClassNotFoundException | LinkageError stillMissing) {
                        // Optional third-party dependency (e.g. an API not shipped in this jar):
                        // skip its entries; a real use site still fails closed at link time.
                        unresolvedMembers++;
                        continue;
                    }
                }
                try {
                switch (kind) {
                    case ENTRY_CLASS -> registerClass(classId, ownerClass);
                    case ENTRY_FIELD -> {
                        try {
                            Field field = resolveField(ownerClass, name);
                            if (!descriptorOf(field.getType()).equals(desc)) {
                                throw new IllegalArgumentException(
                                        "member-table field descriptor mismatch: "
                                                + owner + "." + name + " expected " + desc);
                            }
                            setAccessibleQuietly(field);
                            registerField(classId, memberId, field);
                        } catch (NoSuchFieldException unresolved) {
                            // Lenient mode: the site still fails closed at link time with a
                            // member-not-registered error. Strict mode rejects the table.
                            unresolvedMembers++;
                            if (strict) {
                                throw new IllegalArgumentException(
                                        "member-table field not resolvable: " + owner + "." + name
                                                + " " + desc, unresolved);
                            }
                        }
                    }
                    case ENTRY_METHOD -> {
                        try {
                            MethodType methodType =
                                    MethodType.fromMethodDescriptorString(desc, effectiveLoader);
                            Method method = resolveMethod(ownerClass, name, methodType);
                            setAccessibleQuietly(method);
                            registerMethod(classId, memberId, method);
                        } catch (NoSuchMethodException unresolved) {
                            unresolvedMembers++;
                            if (strict) {
                                throw new IllegalArgumentException(
                                        "member-table method not resolvable: " + owner + "." + name
                                                + " " + desc, unresolved);
                            }
                        }
                    }
                    default -> throw new IllegalArgumentException("bad member-table entry kind: " + kind);
                }
                } catch (LinkageError unresolvedType) {
                    // Missing optional supertypes (external mod APIs) must not abort the table.
                    unresolvedMembers++;
                }
            }
            memberTableLoaded = true;
        } catch (IOException e) {
            throw new IllegalArgumentException("truncated member table", e);
        }
    }

    /**
     * Field type descriptor without a build-time ASM dependency: this class is injected into the
     * product jar, where ASM is not guaranteed to be visible to the mod class loader.
     */
    static String descriptorOf(Class<?> type) {
        if (type.isArray()) {
            return type.getName().replace('.', '/');
        }
        if (type.isPrimitive()) {
            if (type == void.class) return "V";
            if (type == boolean.class) return "Z";
            if (type == byte.class) return "B";
            if (type == char.class) return "C";
            if (type == short.class) return "S";
            if (type == int.class) return "I";
            if (type == long.class) return "J";
            if (type == float.class) return "F";
            return "D";
        }
        return "L" + type.getName().replace('.', '/') + ";";
    }

    /** Method descriptor without ASM (see {@link #descriptorOf(Class)}). */
    static String methodDescriptorOf(Method method) {
        StringBuilder sb = new StringBuilder("(");
        for (Class<?> parameter : method.getParameterTypes()) {
            sb.append(descriptorOf(parameter));
        }
        sb.append(')').append(descriptorOf(method.getReturnType()));
        return sb.toString();
    }

    /**
     * Resolves a field along the superclass/interface chain. Build-time call sites may name a
     * concrete JDK owner while the field is declared in a super type (e.g. LinkedHashMap extends
     * HashMap); {@code getDeclaredField} alone would reject a valid member table.
     */
    static Field resolveField(Class<?> owner, String name) throws NoSuchFieldException {
        for (Class<?> current = owner; current != null; current = current.getSuperclass()) {
            try {
                return current.getDeclaredField(name);
            } catch (NoSuchFieldException ignored) {
                // try interfaces and super class
            }
            for (Class<?> itf : current.getInterfaces()) {
                Field field = findFieldInInterface(itf, name);
                if (field != null) return field;
            }
        }
        throw new NoSuchFieldException(owner.getName() + "." + name);
    }

    private static Field findFieldInInterface(Class<?> type, String name) {
        try {
            return type.getDeclaredField(name);
        } catch (NoSuchFieldException ignored) {
            for (Class<?> itf : type.getInterfaces()) {
                Field field = findFieldInInterface(itf, name);
                if (field != null) return field;
            }
            return null;
        }
    }

    /** Method counterpart of {@link #resolveField(Class, String)}. */
    static Method resolveMethod(Class<?> owner, String name, MethodType type)
            throws NoSuchMethodException {
        Class<?>[] parameters = type.parameterArray();
        for (Class<?> current = owner; current != null; current = current.getSuperclass()) {
            try {
                return current.getDeclaredMethod(name, parameters);
            } catch (NoSuchMethodException ignored) {
                // try interfaces and super class
            }
            for (Class<?> itf : current.getInterfaces()) {
                Method method = findMethodInInterface(itf, name, parameters);
                if (method != null) return method;
            }
        }
        // Interface types have no super class, but they inherit Object's public methods
        // (toString/equals/hashCode) for invokevirtual purposes.
        try {
            return Object.class.getDeclaredMethod(name, parameters);
        } catch (NoSuchMethodException ignored) {
            // fall through
        }
        throw new NoSuchMethodException(owner.getName() + "." + name);
    }

    private static Method findMethodInInterface(Class<?> type, String name, Class<?>[] parameters) {
        try {
            return type.getDeclaredMethod(name, parameters);
        } catch (NoSuchMethodException ignored) {
            for (Class<?> itf : type.getInterfaces()) {
                Method method = findMethodInInterface(itf, name, parameters);
                if (method != null) return method;
            }
            return null;
        }
    }

    private static String readUtf(DataInputStream in) throws IOException {
        int length = in.readInt();
        if (length < 0 || length > 1 << 16) {
            throw new IOException("bad member-table string length: " + length);
        }
        byte[] bytes = new byte[length];
        in.readFully(bytes);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static void setAccessibleQuietly(java.lang.reflect.AccessibleObject object) {
        try {
            object.setAccessible(true);
        } catch (Throwable ignored) {
            // public members remain accessible without setAccessible
        }
    }

    // ------------------------------------------------------------------ diagnostics

    public static long classLookups() {
        return CLASS_LOOKUPS.get();
    }

    public static long memberLookups() {
        return MEMBER_LOOKUPS.get();
    }

    public static long misses() {
        return MISSES.get();
    }

    public static int registeredClasses() {
        return CLASSES.size();
    }

    public static int registeredMembers() {
        return MEMBERS.size();
    }
}
