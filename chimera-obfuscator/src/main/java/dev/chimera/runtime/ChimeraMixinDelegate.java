package dev.chimera.runtime;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * S3' runtime side of the generated mixin-config plugin.
 *
 * <p>Why this exists: Mixin builds every {@code MixinConfig} and instantiates its plugin during
 * {@code MixinProcessor.selectConfigs}, which runs <b>before</b> {@code prepareMixins} reads any
 * mixin class. That is the only point in the boot sequence where mod-controlled code runs early
 * enough to attach the decrypting agent, so mixin classes can stay CHENC1 ciphertext on disk
 * instead of being split into plaintext shells (S3 thin shell) or shipped in the clear.</p>
 *
 * <p>The generated plugin class is a thin ASM shell; all behaviour lives here so the bytecode
 * stays trivial. If the original config declared its own plugin, every call is forwarded to it by
 * reflection - the protected mod keeps its exact mixin selection semantics.</p>
 */
public final class ChimeraMixinDelegate {

    private static final Map<String, Object> DELEGATES = new HashMap<>();

    /** Cached "run as an inert mod" decision; null until the native check has been made. */
    private static volatile Boolean VM_EMPTY;

    private ChimeraMixinDelegate() {
    }

    /**
     * Loads the native payload, then attaches the decrypting agent; idempotent, fails closed.
     *
     * <p>A4: the mixin config plugin runs during {@code MixinProcessor.selectConfigs}, i.e. before
     * every {@code preLaunch} entrypoint. Attaching the agent first left the native payload unloaded,
     * so the first decrypted class that touched the string table hit {@code string table mac
     * missing/mismatch} (the MAC is verified through the native session, C-06), poisoned the runtime
     * and surfaced as a decoy NUL path crash. Load the payload in the same order the preLaunch gate
     * does, otherwise any mod that declares its own mixin plugin dies at startup.</p>
     */
    public static void boot() {
        ChimeraPayload.ensureLoaded();
        ChimeraAttach.install();
    }

    private static Object delegate(String className) {
        if (className == null || className.isEmpty()) {
            return null;
        }
        synchronized (DELEGATES) {
            if (DELEGATES.containsKey(className)) {
                return DELEGATES.get(className);
            }
            Object instance = null;
            try {
                ClassLoader loader = Thread.currentThread().getContextClassLoader();
                if (loader == null) {
                    loader = ChimeraMixinDelegate.class.getClassLoader();
                }
                Class<?> type = Class.forName(className, true, loader);
                instance = type.getDeclaredConstructor().newInstance();
            } catch (Throwable failure) {
                System.err.println("[chimera] mixin plugin delegate unavailable: "
                        + className + " -> " + failure);
            }
            DELEGATES.put(className, instance);
            return instance;
        }
    }

    private static Object invoke(String className, String method, Object[] args) {
        Object target = delegate(className);
        if (target == null) {
            return null;
        }
        try {
            Method found = null;
            for (Method candidate : target.getClass().getMethods()) {
                if (!candidate.getName().equals(method)
                        || candidate.getParameterCount() != args.length) {
                    continue;
                }
                Class<?>[] types = candidate.getParameterTypes();
                boolean compatible = true;
                for (int i = 0; i < types.length; i++) {
                    if (args[i] != null && !types[i].isInstance(args[i])) {
                        compatible = false;
                        break;
                    }
                }
                if (compatible) {
                    found = candidate;
                    break;
                }
            }
            if (found == null) {
                return null;
            }
            found.setAccessible(true);
            return found.invoke(target, args);
        } catch (Throwable failure) {
            System.err.println("[chimera] mixin plugin delegate failed: "
                    + className + "." + method + " -> " + failure);
            return null;
        }
    }

    public static void onLoad(String mixinPackage, String delegateName) {
        boot();
        invoke(delegateName, "onLoad", new Object[]{mixinPackage});
    }

    public static String getRefMapperConfig(String delegateName) {
        Object result = invoke(delegateName, "getRefMapperConfig", new Object[0]);
        return result instanceof String value ? value : null;
    }

    public static boolean shouldApplyMixin(String target, String mixin, String delegateName) {
        // VM mode: apply nothing. The class bodies are stubbed out as well, so leaving mixins on
        // would make Mixin parse empty classes and crash instead of yielding an inert mod.
        if (vmEmptyMode()) {
            return false;
        }
        Object result = invoke(delegateName, "shouldApplyMixin", new Object[]{target, mixin});
        return !(result instanceof Boolean value) || value;
    }

    public static void acceptTargets(Set<String> mine, Set<String> others, String delegateName) {
        invoke(delegateName, "acceptTargets", new Object[]{mine, others});
    }

    @SuppressWarnings("unchecked")
    public static List<String> getMixins(String delegateName) {
        if (vmEmptyMode()) {
            return java.util.Collections.emptyList();
        }
        Object result = invoke(delegateName, "getMixins", new Object[0]);
        return result instanceof List<?> list ? (List<String>) list : null;
    }

    /**
     * VM mode: the mod loads but does nothing.
     *
     * <p>Decided once, natively (a patched jar cannot answer "not a VM"), and cached. When set,
     * mixins are not applied and every mod class body is replaced by an empty stub, so the artifact
     * stays in the mod list with its metadata intact but exposes no features.</p>
     */
    static boolean vmEmptyMode() {
        Boolean cached = VM_EMPTY;
        if (cached != null) {
            return cached;
        }
        boolean detected = ChimeraRuntime.isVirtualMachine();
        VM_EMPTY = detected;
        return detected;
    }

    public static void preApply(String target, Object targetClass, String mixin,
                                Object mixinInfo, String delegateName) {
        invoke(delegateName, "preApply", new Object[]{target, targetClass, mixin, mixinInfo});
    }

    public static void postApply(String target, Object targetClass, String mixin,
                                 Object mixinInfo, String delegateName) {
        invoke(delegateName, "postApply", new Object[]{target, targetClass, mixin, mixinInfo});
    }
}
