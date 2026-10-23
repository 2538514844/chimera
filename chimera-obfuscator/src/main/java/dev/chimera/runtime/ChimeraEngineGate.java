package dev.chimera.runtime;

/**
 * G1.10: engine self-protect license hard lock.
 *
 * <p>The self-protected engine jar embeds the native auth DLL and the license server config. When
 * that payload is present, the engine refuses to run without a valid license for this machine -
 * the check runs before any CLI work, so a copied engine jar cannot build anything. Plain
 * development engines (no embedded payload) are unaffected.</p>
 */
public final class ChimeraEngineGate {

    private ChimeraEngineGate() {
    }

    public static void requireLicense() {
        if (!selfProtected()) {
            return;
        }
        try {
            java.nio.file.Path state = java.nio.file.Path.of(
                    System.getProperty("user.home", "."), ".chimera", "license.dat");
            if (!java.nio.file.Files.isRegularFile(state)) {
                fail("engine license required: no license state for this machine (hwid="
                        + ChimeraRuntime.currentHwid() + "); activate this build first");
                return;
            }
            loadNative();
            // #9: authenticate chimera/manifest.dat before any other resource is consumed; a
            // tampered auth.dat/strings.dat/env.dat halts here with exit code 4.
            ChimeraRuntime.verifyResourceManifest();
            Class.forName("dev.chimera.runtime.ChimeraLicenseBackend", true, loader());
            // restoreOnce returns true only after it installed a native handle from a valid,
            // unexpired v4 session (isKeyHealthy() is a poison flag, not a license check).
            if (ChimeraSessionRestorer.restoreOnce()) {
                diag("engine license ok hwid=" + ChimeraRuntime.currentHwid());
                return;
            }
            fail("engine license rejected or expired (hwid=" + ChimeraRuntime.currentHwid() + ")");
        } catch (Throwable failure) {
            fail("engine license check failed: " + failure);
        }
    }

    /** True when the jar carries a native payload, i.e. it is meant to be gated. */
    private static boolean selfProtected() {
        ClassLoader loader = ChimeraEngineGate.class.getClassLoader();
        return loader.getResource(ChimeraStealthLoader.RESOURCE_NAME) != null
                || loader.getResource("chimera/embedded.dll") != null;
    }

    private static void loadNative() throws Exception {
        ChimeraPayload.ensureLoaded();
    }

    private static ClassLoader loader() {
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        return loader != null ? loader : ChimeraEngineGate.class.getClassLoader();
    }

    private static void fail(String message) {
        System.err.println("[chimera] " + message);
        diag(message);
        Runtime.getRuntime().halt(4);
    }

    private static void diag(String line) {
        try {
            java.nio.file.Path dir = java.nio.file.Path.of(
                    System.getProperty("user.home", "."), ".chimera");
            java.nio.file.Files.createDirectories(dir);
            java.nio.file.Files.writeString(dir.resolve("engine-gate.log"),
                    line + System.lineSeparator(), java.nio.charset.StandardCharsets.UTF_8,
                    java.nio.file.StandardOpenOption.CREATE,
                    java.nio.file.StandardOpenOption.APPEND);
        } catch (Throwable ignored) {
            // diagnostics only
        }
    }
}
