package dev.chimera.runtime;

/**
 * Phase 0 (C-01..C-05): single policy point for the diagnostic system properties.
 *
 * <p>The engine records the build kind in {@code /chimera/env.dat} (version 2, bit 0 of the
 * flags word = dev build). A <b>release</b> build ignores every diagnostic override that could
 * downgrade protection: runtime-hash skip, fragment timing window, VM probe limits and native
 * anti-debug relaxations. A <b>dev</b> build keeps them for tests and field diagnostics.</p>
 *
 * <p>SECURITY (audit 2026-10-22 #5): the default is <b>deny</b>. Only a positively resolved
 * {@link #DEV} build honours overrides; {@link #UNKNOWN} (no marker read yet, unreadable marker,
 * or a runtime that never resolved one) is treated like release, so deleting resources or racing
 * the resolution cannot re-enable {@code -Dchimera.runtime.hash.skip} and friends. A malformed
 * {@code env.dat} is reported as release as well.</p>
 */
public final class DebugSwitches {
    public static final int UNKNOWN = 0;
    public static final int DEV = 1;
    public static final int RELEASE = 2;

    private static volatile int state = UNKNOWN;
    private static volatile boolean resolved;

    private DebugSwitches() {
    }

    /** Called by {@code ChimeraRuntime.ensureEnv()} once the environment flags are known. */
    public static void configure(boolean devBuild) {
        state = devBuild ? DEV : RELEASE;
        resolved = true;
    }

    public static int state() {
        resolve();
        return state;
    }

    public static boolean release() {
        return state() == RELEASE;
    }

    /**
     * True when a diagnostic property may influence behaviour. Only a resolved dev build allows
     * it: release <b>and</b> unresolved/unknown artifacts deny, so {@code
     * -Dchimera.runtime.hash.skip=true} and friends are inert unless the build is positively dev.
     */
    public static boolean overridesAllowed() {
        return state() == DEV;
    }

    /** Property value honouring the release policy: {@code null} means "use the default". */
    public static String property(String key) {
        return overridesAllowed() ? System.getProperty(key) : null;
    }

    /** Boolean property honouring the release policy. */
    public static boolean propertyTrue(String key) {
        return overridesAllowed() && Boolean.getBoolean(key);
    }

    /** Test hook: forget the resolved build kind so the next query re-reads the environment. */
    static void resetForTests() {
        state = UNKNOWN;
        resolved = false;
    }

    private static void resolve() {
        if (resolved) {
            return;
        }
        resolved = true;
        try {
            ChimeraRuntime.loadEnvironmentMarker();
        } catch (Throwable ignored) {
            // Cannot inspect the artifact -> stay UNKNOWN, which now denies every override.
        }
    }
}
