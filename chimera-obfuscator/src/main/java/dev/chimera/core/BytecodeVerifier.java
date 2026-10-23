package dev.chimera.core;

import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Phase B verification gate: loads every class of a produced jar through a real
 * {@link URLClassLoader} and forces linking, so the JVM verifier turns invalid bytecode
 * (mostly bad StackMapTable merges from control-flow transforms) into a build failure instead of a
 * crash at game start.
 *
 * <p>Class initialisation is not triggered ({@code initialize=false}); only verification runs.</p>
 */
public final class BytecodeVerifier {

    /** One class the JVM rejected. */
    public record Failure(String className, String message) {
    }

    private BytecodeVerifier() {
    }

    /** @return verify failures (empty = clean) */
    public static List<Failure> verify(Path jar, List<Path> classpath) {
        List<URL> urls = new ArrayList<>();
        try {
            urls.add(jar.toUri().toURL());
            for (Path path : classpath) {
                urls.add(path.toUri().toURL());
            }
        } catch (IOException e) {
            throw new IllegalStateException("cannot build verification class path", e);
        }
        List<Failure> failures = new ArrayList<>();
        try (URLClassLoader loader = new URLClassLoader(urls.toArray(new URL[0]),
                ClassLoader.getPlatformClassLoader());
             ZipFile zip = new ZipFile(jar.toFile())) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();
                if (!name.endsWith(".class") || name.equals("module-info.class")
                        || name.startsWith("META-INF/versions/")) {
                    continue;
                }
                String binary = name.substring(0, name.length() - 6).replace('/', '.');
                try {
                    Class<?> type = Class.forName(binary, false, loader);
                    type.getDeclaredMethods();
                    type.getDeclaredFields();
                    type.getDeclaredConstructors();
                } catch (VerifyError error) {
                    failures.add(new Failure(binary, firstLine(error.getMessage())));
                } catch (Throwable ignored) {
                    // Missing optional dependencies (or a class path gap) is not a verifier failure;
                    // the frame gate only reports bytecode the JVM itself rejected.
                }
            }
        } catch (IOException e) {
            throw new IllegalStateException("cannot read jar for verification: " + jar, e);
        }
        return failures;
    }

    private static String firstLine(String message) {
        if (message == null) {
            return "VerifyError";
        }
        int newline = message.indexOf('\n');
        return newline < 0 ? message : message.substring(0, newline);
    }
}
