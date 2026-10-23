package dev.chimera.transform.wrap;

import dev.chimera.transform.indy.MemberIdRegistry;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Runtime half of {@link InvokeWrapper}'s {@code MEMBER_ID} mode: resolves a
 * {@code (classId, memberId)} pair through {@link MemberIdRegistry} once, caches a
 * {@link MethodHandle} per pair, and invokes the target.
 *
 * <p>The wrapper methods emitted by {@link InvokeWrapper} only reference this class and two
 * {@code long} constants; the target owner/name/descriptor never appear in the transformed call
 * site. This is the reference-indirection pre-stage for S5 hidden classes.</p>
 *
 * <p>Exceptions are propagated as the target's own throwable: {@code invokeWithArguments} does not
 * wrap them, and the reflective fallback unwraps {@link InvocationTargetException}. The stack trace
 * necessarily contains the wrapper/support frames, but type and message are unchanged.</p>
 *
 * <p>Runtime requirements: {@link MemberIdRegistry} and this class must be present in the protected
 * jar, the CHMI member table must be loaded before the first wrapped call, and the wrapper target
 * entries collected by {@link InvokeWrapper.Stats#targets()} must be part of that table.</p>
 */
public final class WrapperSupport {

    private static final ConcurrentHashMap<Key, Resolved> CACHE = new ConcurrentHashMap<>();
    private static final AtomicLong RESOLUTIONS = new AtomicLong();

    private WrapperSupport() {
    }

    /**
     * Invokes a registered member.
     *
     * @param classId  owner class id (FNV-1a, see {@link MemberIdRegistry#classId(String)})
     * @param memberId member id (see {@link MemberIdRegistry#memberId(String, String, String)})
     * @param receiver receiver for instance calls, {@code null} for static calls
     * @param args     boxed arguments (empty array for a no-argument method)
     * @return boxed return value, or {@code null} for {@code void}
     */
    public static Object invoke(long classId, long memberId, Object receiver, Object[] args) throws Throwable {
        if (args == null) {
            args = EMPTY_ARGS;
        }
        Key key = new Key(classId, memberId);
        Resolved resolved = CACHE.get(key);
        if (resolved == null) {
            resolved = resolve(classId, memberId);
            CACHE.putIfAbsent(key, resolved);
            RESOLUTIONS.incrementAndGet();
        }
        if (resolved.handle != null) {
            if (resolved.isStatic) {
                return resolved.handle.invokeWithArguments(args);
            }
            Object[] callArgs = new Object[args.length + 1];
            callArgs[0] = receiver;
            System.arraycopy(args, 0, callArgs, 1, args.length);
            return resolved.handle.invokeWithArguments(callArgs);
        }
        // Reflective fallback for members whose MethodHandle cannot be unreflected (access rules).
        try {
            return resolved.method.invoke(resolved.isStatic ? null : receiver, args);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            throw cause == null ? e : cause;
        }
    }

    private static Resolved resolve(long classId, long memberId) {
        Method method = MemberIdRegistry.d(classId, memberId);
        if (method == null) {
            throw new IllegalStateException("InvokeWrapper target is not registered: classId=0x"
                    + Long.toHexString(classId) + ", memberId=0x" + Long.toHexString(memberId)
                    + " (load the CHMI member table before the first wrapped call)");
        }
        boolean isStatic = Modifier.isStatic(method.getModifiers());
        MethodHandle handle = null;
        try {
            handle = MethodHandles.lookup().unreflect(method);
        } catch (IllegalAccessException ignored) {
            try {
                method.setAccessible(true);
                handle = MethodHandles.lookup().unreflect(method);
            } catch (RuntimeException | IllegalAccessException stillInaccessible) {
                // Keep the reflective fallback; do not fail the call site eagerly.
            }
        }
        return new Resolved(method, isStatic, handle);
    }

    /** Number of times a target had to be resolved (cache misses); tests use this. */
    public static long resolutions() {
        return RESOLUTIONS.get();
    }

    /** Clears the per-build cache; tests use this. */
    public static void clearForTests() {
        CACHE.clear();
        RESOLUTIONS.set(0L);
    }

    private static final Object[] EMPTY_ARGS = new Object[0];

    private record Key(long classId, long memberId) {
    }

    private record Resolved(Method method, boolean isStatic, MethodHandle handle) {
    }
}
