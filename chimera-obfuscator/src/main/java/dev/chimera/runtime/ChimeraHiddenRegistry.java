package dev.chimera.runtime;

import java.net.URL;
import java.nio.file.Path;
import java.security.CodeSource;
import java.util.ArrayList;
import java.util.List;

/**
 * S1: hidden entries stay in the artifact under their real (invisible) class names, so the Fabric
 * class loader resolves them by name at the exact moment the JVM needs them.
 *
 * <p>Earlier revisions renamed the entries to names the zip reader could not match and defined the
 * bytes through JNI {@code DefineClass}. That required predicting which classes are loaded before
 * the entrypoint ran, and every prediction error surfaced as {@code NoClassDefFoundError} or
 * {@code Not bootstrapped}. This class therefore no longer defines anything: the methods below are
 * compatibility shims for the indy bootstrap / member table and only keep diagnostics.</p>
 */
public final class ChimeraHiddenRegistry {

    private ChimeraHiddenRegistry() {
    }

    /** Result of one registration pass. */
    public record Result(int hiddenEntries, int defined, List<String> failures, String artifact) {
        public boolean ok() {
            return failures.isEmpty();
        }
    }

    private static volatile Result cached;
    private static volatile ClassLoader installedInto;

    /** S1: no-op; entries are loaded by name, nothing to define up-front. */
    public static synchronized Result install(ClassLoader loader) {
        if (cached != null && installedInto == loader) {
            return cached;
        }
        Result result = new Result(0, 0, new ArrayList<>(), "entry-name-mode");
        diag("install entry-name-mode artifact=" + artifactPath());
        cached = result;
        installedInto = loader;
        return result;
    }

    /** S1: the early tier is obsolete; entries load on demand. */
    static Result defineEarly(ClassLoader loader) {
        return new Result(0, 0, new ArrayList<>(), "entry-name-mode");
    }

    static void appendMissing(String internalName) {
        diag("missing " + internalName);
    }

    /**
     * S1: never defines classes natively. Returning false lets the caller fall back to the normal
     * class-loader resolution path, which now succeeds because the entry name matches the class
     * internal name.
     */
    public static boolean defineByName(ClassLoader loader, String internalName) {
        return false;
    }

    private static void diag(String line) {
        try {
            Path dir = Path.of(System.getProperty("user.home", "."), ".chimera");
            java.nio.file.Files.createDirectories(dir);
            java.nio.file.Files.writeString(dir.resolve("hidden-install.log"),
                    line + System.lineSeparator(), java.nio.charset.StandardCharsets.UTF_8,
                    java.nio.file.StandardOpenOption.CREATE,
                    java.nio.file.StandardOpenOption.APPEND);
        } catch (Throwable ignored) {
            // Diagnostics must never break startup.
        }
    }

    static Path artifactPath() {
        try {
            CodeSource source = ChimeraHiddenRegistry.class.getProtectionDomain().getCodeSource();
            URL location = source == null ? null : source.getLocation();
            if (location != null && "file".equals(location.getProtocol())) {
                return Path.of(location.toURI());
            }
        } catch (Throwable ignored) {
            // Fabric class loaders may not expose a code source; fall back to a resource lookup.
        }
        try {
            URL marker = ChimeraHiddenRegistry.class.getResource("/chimera/env.dat");
            if (marker == null) {
                marker = ChimeraHiddenRegistry.class.getResource("/fabric.mod.json");
            }
            if (marker == null) {
                return null;
            }
            String text = marker.toString();
            int bang = text.indexOf("!/");
            if (text.startsWith("jar:") && bang > 4) {
                String file = text.substring(4, bang);
                if (file.startsWith("file:")) {
                    return Path.of(java.net.URI.create(file));
                }
            }
        } catch (Throwable ignored) {
            // Not a jar-backed artifact.
        }
        return null;
    }
}
