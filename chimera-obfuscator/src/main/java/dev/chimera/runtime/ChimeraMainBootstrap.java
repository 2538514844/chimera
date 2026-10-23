package dev.chimera.runtime;

/**
 * Post-bootstrap initialisation: runs from the generated main entrypoint, after Minecraft's
 * registry bootstrap, so native class definition and RegisterNatives cannot force Minecraft
 * classes to initialise too early. Fail-closed: any failure aborts startup.
 */
public final class ChimeraMainBootstrap {

    private static boolean ran;

    private ChimeraMainBootstrap() {
    }

    public static synchronized void onInitialize() {
        if (ran) {
            return;
        }
        ran = true;
        // P0-1 "bypass means death": this entrypoint runs after the preLaunch gate and before any
        // game code. A release artifact whose gate never recorded an authorized licence is refused
        // here even if the gate itself was patched out of blocking.
        ChimeraPreLaunch.requireGateAuthorized("main");
        try {
            ChimeraPayload.ensureLoaded();
        } catch (Throwable failure) {
            throw new IllegalStateException("embedded native load failed", failure);
        }
        if ("true".equalsIgnoreCase(System.getProperty("chimera.traceEarly", "false"))) {
            try {
                ChimeraRuntime.nativeTraceMark();
            } catch (Throwable ignored) {
                // tracing is best-effort
            }
        }
        try {
            ChimeraHiddenRegistry.install(ChimeraMainBootstrap.class.getClassLoader());
        } catch (Throwable ignored) {
            // registry reports its own failures; hidden entries are optional for some mods
        }
        // B-6: opt-in runtime audit of the hidden entries (-Dchimera.hiddenAudit=<file>). Runs after
        // the registry step so the loaded/registered state matches what the game will see.
        HiddenNameAudit.runIfRequested();
        // SECURITY (audit 2026-10-22 #6): the failure policy lives OUTSIDE the try. A Throwable
        // from the native call (UnsatisfiedLinkError because the DLL was swapped, a native crash
        // surface, an unbound method) means nothing bound, so it is treated as rc=-1 and halts -
        // previously the catch swallowed it and the halt below never ran.
        int rc;
        try {
            rc = ChimeraRuntime.nativeRegisterSinkMethods();
        } catch (Throwable failure) {
            rc = -1;
            diag("sink register threw: " + failure);
        }
        diag("sink register rc=" + rc);
        // C-3 failure policy: 0 = every host class bound, >0 = that many groups failed
        // (recorded, the JVM still binds those through their exported Java_* symbols),
        // -2 = this DLL carries no sink table. Any other negative value means nothing bound:
        // fail closed instead of shipping a protection layer that only exists on paper.
        if (rc < 0 && rc != -2) {
            diag("sink register fail-closed rc=" + rc);
            System.err.println("[chimera] native sink registration failed for every host class ("
                    + (-rc) + "); refusing to start with an unbound sink layer");
            Runtime.getRuntime().halt(4);
        }
    }

    private static void diag(String line) {
        try {
            java.nio.file.Path dir = java.nio.file.Path.of(
                    System.getProperty("user.home", "."), ".chimera");
            java.nio.file.Files.createDirectories(dir);
            java.nio.file.Files.writeString(dir.resolve("sink-register.log"),
                    line + System.lineSeparator(), java.nio.charset.StandardCharsets.UTF_8,
                    java.nio.file.StandardOpenOption.CREATE,
                    java.nio.file.StandardOpenOption.APPEND);
        } catch (Throwable ignored) {
            // diagnostics must never break startup
        }
    }
}
