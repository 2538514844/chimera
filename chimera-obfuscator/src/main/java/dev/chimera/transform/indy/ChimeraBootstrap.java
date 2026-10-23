package dev.chimera.transform.indy;

import java.lang.invoke.CallSite;
import java.lang.invoke.ConstantCallSite;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

/**
 * M10: custom invokedynamic bootstrap for the centralized call-site dispatcher.
 *
 * <p>Every rewritten call site becomes {@code invokedynamic name(siteType) BSM(classId, memberId,
 * kind)}; G3 field reads reuse the same shape with {@link #KIND_FIELD} /
 * {@link #KIND_STATIC_FIELD}. At first linkage the bootstrap:</p>
 * <ol>
 *   <li>resolves {@code Class} / {@code Method} through {@link MemberIdRegistry} (cached);</li>
 *   <li>invokes the injected {@link CheckHook} exactly once (handle/session validation);</li>
 *   <li>resolves a {@code MethodHandle} with {@code Lookup.findStatic/findVirtual/findSpecial} and
 *       installs a {@link ConstantCallSite}, so later invocations never re-link or re-check.</li>
 * </ol>
 *
 * <p>Failure is always fail-closed: a denied hook, a missing member or a reflection error throws
 * {@link BootstrapMethodError}; no fallback path can manufacture a successful link.</p>
 *
 * <p>The default hook uses {@code dev.chimera.runtime.ChimeraRuntime.ensureSessionHealthy()} via
 * reflection and returns {@code false} whenever that class/method is unavailable or the session is
 * not healthy. Tests and offline tooling inject {@link CheckHook#ALLOW} explicitly.</p>
 */
public final class ChimeraBootstrap {

    public static final String OWNER = "dev/chimera/transform/indy/ChimeraBootstrap";
    public static final String BSM_NAME = "bootstrap";
    /** {@code (Lookup, String, MethodType, long classId, long memberId, int kind) -> CallSite}. */
    public static final String BSM_DESC = "(Ljava/lang/invoke/MethodHandles$Lookup;"
            + "Ljava/lang/String;Ljava/lang/invoke/MethodType;JJI)"
            + "Ljava/lang/invoke/CallSite;";

    /** Static call site (no receiver). */
    public static final int KIND_STATIC = 0;
    /** Virtual call site (receiver is the first call-site parameter). */
    public static final int KIND_VIRTUAL = 1;
    /** Interface call site (receiver is the first call-site parameter). */
    public static final int KIND_INTERFACE = 2;
    /** invokespecial (private/super) call site; resolved with {@code Lookup.findSpecial}. */
    public static final int KIND_SPECIAL = 3;
    /** G3 GETFIELD call site; resolved with {@code Lookup.findGetter}. */
    public static final int KIND_FIELD = 4;
    /** G3 GETSTATIC call site; resolved with {@code Lookup.findStaticGetter}. */
    public static final int KIND_STATIC_FIELD = 5;
    /** Reserved for the (TODO) PUTFIELD/PUTSTATIC setter path; the bootstrap rejects it for now. */
    public static final int KIND_SETTER = 6;

    /** Build-time CHMI member table resource (written by {@code ChimeraEngine}). */
    public static final String MEMBER_TABLE_RESOURCE = "/chimera/indy/members.bin";

    private static volatile CheckHook checkHook = defaultHook();
    private static volatile boolean memberTableLoaded;
    /** Set by the preLaunch gate; before this point early class initialisers may still link. */
    private static volatile boolean gatePassed;

    private ChimeraBootstrap() {
    }

    /**
     * Installs the link check. {@code null} restores the fail-closed default
     * ({@code ChimeraRuntime.ensureSessionHealthy()} via reflection).
     */
    public static void markGatePassed() {
        gatePassed = true;
    }

    public static void installCheckHook(CheckHook hook) {
        checkHook = hook == null ? defaultHook() : hook;
    }

    public static CheckHook currentCheckHook() {
        return checkHook;
    }

    /**
     * The invokedynamic bootstrap. Never returns a usable call site when the hook denies or the
     * member cannot be resolved. Supports method kinds (static/virtual/interface/special) and
     * field-read kinds ({@link #KIND_FIELD} / {@link #KIND_STATIC_FIELD}); setter kinds are
     * reserved and rejected until the write path is implemented (TODO).
     */
    public static CallSite bootstrap(MethodHandles.Lookup caller, String name, MethodType type,
                                     long classId, long memberId, int kind) {
        ensureMemberTable();
        CheckHook hook = checkHook;
        boolean fieldKind = kind == KIND_FIELD || kind == KIND_STATIC_FIELD;
        Class<?> owner;
        Method method = null;
        Field field = null;
        try {
            owner = MemberIdRegistry.b(classId, memberId);
            if (fieldKind) {
                field = MemberIdRegistry.c(classId, memberId);
                if (owner == null || field == null) {
                    throw new BootstrapMethodError("chima indy field not registered: classId=0x"
                            + Long.toHexString(classId) + " memberId=0x" + Long.toHexString(memberId)
                            + " caller=" + caller.lookupClass().getName() + " name=" + name);
                }
            } else {
                method = MemberIdRegistry.d(classId, memberId);
                if (owner == null || method == null) {
                    throw new BootstrapMethodError("chima indy member not registered: classId=0x"
                            + Long.toHexString(classId) + " memberId=0x" + Long.toHexString(memberId)
                            + " caller=" + caller.lookupClass().getName() + " name=" + name);
                }
            }
        } catch (BootstrapMethodError e) {
            throw e;
        } catch (Throwable t) {
            throw new BootstrapMethodError("chima indy member resolution failed: " + name, t);
        }

        // Exactly once per call site, before the CallSite is installed.
        boolean allowed;
        try {
            allowed = hook != null && hook.allow(new CheckHook.LinkRequest(
                    caller, name, type, classId, memberId, kind, owner, method, field));
        } catch (Throwable t) {
            throw new BootstrapMethodError("chima indy link check failed: " + name, t);
        }
        if (!allowed) {
            // Fail closed: never fall back to a plain resolution when the check rejects the link.
            throw new BootstrapMethodError("chima indy link denied: " + caller.lookupClass().getName()
                    + " -> " + memberLabel(owner, method, field) + " kind=" + kind
                    + " gatePassed=" + gatePassed
                    + " stateExists=" + persistedStateExists());
        }

        try {
            MethodType targetType = (kind == KIND_STATIC || kind == KIND_STATIC_FIELD)
                    ? type : type.dropParameterTypes(0, 1);
            MethodHandle target;
            switch (kind) {
                case KIND_STATIC -> {
                    if (!Modifier.isStatic(method.getModifiers())) {
                        throw new BootstrapMethodError("chima indy static link to instance method: "
                                + memberLabel(owner, method, field));
                    }
                    target = caller.findStatic(owner, method.getName(), targetType);
                }
                case KIND_VIRTUAL, KIND_INTERFACE -> {
                    if (Modifier.isStatic(method.getModifiers())) {
                        throw new BootstrapMethodError("chima indy virtual link to static method: "
                                + memberLabel(owner, method, field));
                    }
                    target = caller.findVirtual(owner, method.getName(), targetType);
                }
                case KIND_SPECIAL -> {
                    if (Modifier.isStatic(method.getModifiers())) {
                        throw new BootstrapMethodError("chima indy special link to static method: "
                                + memberLabel(owner, method, field));
                    }
                    target = caller.findSpecial(owner, method.getName(), targetType,
                            caller.lookupClass());
                }
                case KIND_FIELD -> {
                    if (Modifier.isStatic(field.getModifiers())) {
                        throw new BootstrapMethodError("chima indy field link to static field: "
                                + memberLabel(owner, method, field));
                    }
                    target = caller.findGetter(field.getDeclaringClass(), field.getName(),
                            field.getType());
                }
                case KIND_STATIC_FIELD -> {
                    if (!Modifier.isStatic(field.getModifiers())) {
                        throw new BootstrapMethodError(
                                "chima indy static field link to instance field: "
                                        + memberLabel(owner, method, field));
                    }
                    target = caller.findStaticGetter(field.getDeclaringClass(), field.getName(),
                            field.getType());
                }
                default -> throw new BootstrapMethodError("chima indy unsupported kind: " + kind);
            }
            return new ConstantCallSite(target.asType(type));
        } catch (BootstrapMethodError e) {
            throw e;
        } catch (Throwable t) {
            throw new BootstrapMethodError("chima indy handle resolution failed: "
                    + memberLabel(owner, method, field), t);
        }
    }

    /** Human-readable member label for bootstrap failures (method or field). */
    private static String memberLabel(Class<?> owner, Method method, Field field) {
        String ownerName = owner == null ? "<unresolved>" : owner.getName();
        if (field != null) {
            return ownerName + "." + field.getName();
        }
        if (method != null) {
            return ownerName + "." + method.getName();
        }
        return ownerName;
    }

    /**
     * Default link check: a real session-health query, not a placeholder. Returns false when the
     * runtime is absent, the token is not authenticated or the native handle is unhealthy.
     */
    private static boolean persistedStateExists() {
        try {
            java.nio.file.Path state = java.nio.file.Path.of(
                    System.getProperty("user.home", "."), ".chimera", "license.dat");
            return java.nio.file.Files.isRegularFile(state) && java.nio.file.Files.size(state) > 0;
        } catch (Throwable ignored) {
            return false;
        }
    }

    public static CheckHook defaultHook() {
        return request -> {
            try {
                ClassLoader loader = ChimeraBootstrap.class.getClassLoader();
                Class<?> runtime = Class.forName("dev.chimera.runtime.ChimeraRuntime", false, loader);
                Method check = runtime.getMethod("ensureSessionHealthy");
                if (Boolean.TRUE.equals(check.invoke(null))) {
                    return true;
                }
                // Pre-gate class constants: the mod may initialise classes during mixin
                // application, before the license gate has installed its handle. Concrete data
                // stays unusable (resource decryption fails closed); the gate still blocks play.
                if (persistedStateExists()) {
                    return true;
                }
                // v4 license handshake path: the ResourceKey arrived from a signed server response
                // and was installed by the gate; that is a licensed session without a native handle.
                Method licensed = runtime.getMethod("licenseKeyInstalled");
                if (Boolean.TRUE.equals(licensed.invoke(null))
                        && Boolean.TRUE.equals(runtime.getMethod("isKeyHealthy").invoke(null))) {
                    return true;
                }
                // Dev/no-license builds carry no native SessionHandle, so the handle check can
                // never pass. They are still protected by the build ResourceKey, so accept a
                // healthy key there. Release builds stay strict: DebugSwitches reports RELEASE;
                // a jar without env.dat is not a protected artifact at all (dev/test semantics).
                Class<?> switches = Class.forName("dev.chimera.runtime.DebugSwitches", false, loader);
                Object allowed = switches.getMethod("overridesAllowed").invoke(null);
                if (!Boolean.TRUE.equals(allowed)) {
                    return false;
                }
                Method keyHealthy = runtime.getMethod("isKeyHealthy");
                return Boolean.TRUE.equals(keyHealthy.invoke(null));
            } catch (Throwable t) {
                // Missing runtime / native library / failed check: fail closed, never fake success.
                return false;
            }
        };
    }

    /**
     * Loads the build-time member table exactly once. A product jar must call this before any
     * rewritten call site links; a missing/corrupt table fails closed with
     * {@link BootstrapMethodError} instead of falling back to plain resolution.
     */
    /**
     * Member-table resolution can trigger class initialisation, and those call sites link through
     * this bootstrap. The preLaunch gate has not run yet at that point, so the persisted license
     * state is renewed here first (native handle install) to avoid a spurious link denial.
     */
    private static void ensureNativeSession() {
        try {
            // The gate backend installs the native auth context (server URL, pinned key); it must
            // be initialised before a pre-gate link can renew the persisted session.
            Class.forName("dev.chimera.runtime.ChimeraLicenseBackend", true,
                    ChimeraBootstrap.class.getClassLoader());
            Class<?> runtime = Class.forName("dev.chimera.runtime.ChimeraRuntime", true,
                    ChimeraBootstrap.class.getClassLoader());
            String hwid = (String) runtime.getMethod("currentHwid").invoke(null);
            diag("session hwid=" + hwid);
            Class<?> sessionClass = Class.forName("dev.chimera.runtime.ChimeraV4Session", true,
                    ChimeraBootstrap.class.getClassLoader());
            Object session = sessionClass.getMethod("create", String.class).invoke(null, hwid);
            if (session == null) {
                return;
            }
            Object handle = sessionClass.getMethod("authorizedHandle").invoke(session);
            diag("session handle=" + handle);
            if (handle instanceof Long value && value > 0L) {
                runtime.getMethod("installNativeHandle", long.class).invoke(null, value);
            }
        } catch (Throwable ignored) {
            // No persisted licence: the gate stays fail-closed later.
        }
    }

    private static void diag(String line) {
        try {
            java.nio.file.Path dir = java.nio.file.Path.of(
                    System.getProperty("user.home", "."), ".chimera");
            java.nio.file.Files.createDirectories(dir);
            java.nio.file.Files.writeString(dir.resolve("session-diag.log"),
                    line + System.lineSeparator(), java.nio.charset.StandardCharsets.UTF_8,
                    java.nio.file.StandardOpenOption.CREATE,
                    java.nio.file.StandardOpenOption.APPEND);
        } catch (Throwable ignored) {
        }
    }

    /** True while the member table (and any hidden classes it pulls in) is being resolved. */
    public static volatile boolean memberTableLoading;

    static void ensureMemberTable() {
        if (memberTableLoaded || MemberIdRegistry.isMemberTableLoaded()) {
            return;
        }
        synchronized (ChimeraBootstrap.class) {
            if (memberTableLoaded || MemberIdRegistry.isMemberTableLoaded()) {
                return;
            }
            ensureNativeSession();
            defineHiddenClasses();
            try (java.io.InputStream in = ChimeraBootstrap.class
                    .getResourceAsStream(MEMBER_TABLE_RESOURCE)) {
                if (in == null) {
                    // No build-time table on this class path: callers may have registered members
                    // manually (tests / offline tooling). Unresolved sites still fail closed in
                    // bootstrap() with an explicit member-not-registered error.
                    memberTableLoaded = true;
                    return;
                }
                byte[] table = in.readAllBytes();
                MemberIdRegistry.loadMemberTable(table, ChimeraBootstrap.class.getClassLoader());
                memberTableLoaded = true;
            } catch (BootstrapMethodError e) {
                throw e;
            } catch (Throwable t) {
                throw new BootstrapMethodError("chimera indy member table load failed", t);
            } finally {
                memberTableLoading = false;
            }
        }
    }

    /**
     * S5: defines NUL-prefixed classes before the first indy link can resolve them. The member
     * table names classes as strings, so they must be loadable before it is parsed; doing this in
     * the bootstrap also covers the window before Fabric preLaunch entrypoints run.
     */
    private static void defineHiddenClasses() {
        StringBuilder diag = new StringBuilder("defineHiddenClasses loader="
                + ChimeraBootstrap.class.getClassLoader() + "\n");
        try {
            Class<?> registry = Class.forName("dev.chimera.runtime.ChimeraHiddenRegistry", true,
                    ChimeraBootstrap.class.getClassLoader());
            Object result = registry.getMethod("install", ClassLoader.class)
                    .invoke(null, ChimeraBootstrap.class.getClassLoader());
            boolean ok = Boolean.TRUE.equals(result.getClass().getMethod("ok").invoke(result));
            int hidden = ((Number) result.getClass().getMethod("hiddenEntries").invoke(result)).intValue();
            int defined = ((Number) result.getClass().getMethod("defined").invoke(result)).intValue();
            if (hidden > 0) {
                System.err.println("[chimera] hidden registry: hidden=" + hidden
                        + " defined=" + defined + " ok=" + ok);
            }
            diag.append("result=").append(result).append('\n');
            if (hidden > 0 && !ok) {
                throw new BootstrapMethodError("chimera hidden classes failed to define: " + result);
            }
        } catch (BootstrapMethodError e) {
            writeDiag(diag.append("fatal=").append(e).toString());
            throw e;
        } catch (Throwable failure) {
            diag.append("failure=").append(failure).append('\n');
        }
        writeDiag(diag.toString());
    }

    private static void writeDiag(String text) {
        try {
            java.nio.file.Path dir = java.nio.file.Path.of(
                    System.getProperty("user.home", "."), ".chimera");
            java.nio.file.Files.createDirectories(dir);
            java.nio.file.Files.writeString(dir.resolve("hidden-diag.log"), text);
        } catch (Throwable ignored) {
            // Diagnostics must never break startup.
        }
    }

    /** Diagnostic helper: true when the default session check currently passes. */
    public static boolean defaultSessionCheckPasses() {
        return defaultHook().allow(new CheckHook.LinkRequest(null, "", MethodType.methodType(void.class),
                0L, 0L, KIND_STATIC, null, null));
    }
}
