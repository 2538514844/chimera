package dev.chimera.runtime;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Restores a persisted v4 session on first use. Some classes decrypt strings during class
 * initialisation that can happen before the Fabric preLaunch gate, so the runtime renews its
 * native handle lazily instead of producing a fail-closed decoy first.
 */
final class ChimeraSessionRestorer {

    private static volatile boolean attempted;

    private ChimeraSessionRestorer() {
    }

    private static void diag(String line) {
        try {
            java.nio.file.Path dir = java.nio.file.Path.of(
                    System.getProperty("user.home", "."), ".chimera");
            java.nio.file.Files.createDirectories(dir);
            java.nio.file.Files.writeString(dir.resolve("restorer-diag.log"),
                    line + System.lineSeparator(), java.nio.charset.StandardCharsets.UTF_8,
                    java.nio.file.StandardOpenOption.CREATE,
                    java.nio.file.StandardOpenOption.APPEND);
        } catch (Throwable ignored) {
        }
    }

    static synchronized boolean restoreOnce() {
        if (attempted) {
            return ChimeraRuntime.isKeyHealthy();
        }
        attempted = true;
        try {
            Path state = Path.of(System.getProperty("user.home", "."), ".chimera", "license.dat");
            if (!Files.isRegularFile(state)) {
                diag("restorer-diag no-state");
                return false;
            }
            // The gate backend installs the native auth context; initialise it before restoring.
            Class.forName("dev.chimera.runtime.ChimeraLicenseBackend", true,
                    ChimeraSessionRestorer.class.getClassLoader());
            String hwid = ChimeraRuntime.currentHwid();
            if (hwid.isEmpty()) {
                return false;
            }
            ChimeraV4Session session = ChimeraV4Session.create(hwid);
            if (session == null) {
                diag("restorer-diag null-session");
                return false;
            }
            long handle = session.authorizedHandle();
            if (handle <= 0L) {
                diag("restorer-diag handle=0 hwid=" + hwid);
                return false;
            }
            ChimeraRuntime.installNativeHandle(handle);
            return true;
        } catch (Throwable failure) {
            diag("restorer-diag failed " + failure);
            return false;
        }
    }
}
