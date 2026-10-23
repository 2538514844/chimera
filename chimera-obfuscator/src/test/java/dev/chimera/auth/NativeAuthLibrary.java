package dev.chimera.auth;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.UUID;

/**
 * Test helper: locates/prepares the native auth DLL and points ChimeraRuntime at it.
 * The DLL is statically linked (M7): OpenSSL and the MinGW runtime are inside chimera_auth.dll,
 * so no libcrypto-3-x64.dll / libgcc DLL has to be shipped or added to PATH.
 */
public final class NativeAuthLibrary {

    private NativeAuthLibrary() {
    }

    public static Path prebuiltDirectory() {
        return Path.of("native", "windows-x64").toAbsolutePath();
    }

    /**
     * Dev/test DLL directory (QA hooks + short TTL allowed). The Gradle test task builds it into
     * build/native-auth-dev; release DLLs in native/windows-x64 have the hooks compiled out.
     */
    public static Path devNativeDirectory() {
        String configured = System.getProperty("chimera.native.dev.dir");
        if (configured != null && !configured.isBlank()) {
            return Path.of(configured).toAbsolutePath();
        }
        return prebuiltDirectory();
    }

    public static synchronized String prepare() {
        String configured = System.getProperty("chimera.native.auth.path");
        if (configured != null && !configured.isBlank() && Files.isRegularFile(Path.of(configured))) {
            return configured;
        }
        Path source = prebuiltDirectory().resolve("chimera_auth.dll");
        if (!Files.isRegularFile(source)) {
            throw new IllegalStateException("native auth DLL missing: " + source
                    + "; build it with the command in docs/NATIVE-AUTH.md");
        }
        System.setProperty("chimera.native.auth.path", source.toString());
        return source.toString();
    }

    /**
     * Copies the DLL into a unique file name in the same (already PATH-visible) directory so a
     * second classloader can load its own instance without sharing native method registration.
     */
    public static synchronized String prepareIsolatedCopy() {
        Path source = devNativeDirectory().resolve("chimera_auth.dll");
        if (!Files.isRegularFile(source)) {
            return prepare();
        }
        try {
            Path target = source.getParent().resolve(
                    "chimera_auth_" + UUID.randomUUID().toString().replace("-", "") + ".dll");
            Files.copy(source, target, StandardCopyOption.REPLACE_EXISTING);
            // The static DLL is ~6.4 MB; do not leave one copy per test JVM behind.
            target.toFile().deleteOnExit();
            System.setProperty("chimera.native.auth.path", target.toString());
            return target.toString();
        } catch (IOException e) {
            throw new IllegalStateException("cannot prepare isolated native auth DLL", e);
        }
    }
}
