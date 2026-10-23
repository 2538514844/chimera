package dev.chimera.gradle;

import org.gradle.api.DefaultTask;
import org.gradle.api.GradleException;
import org.gradle.api.tasks.Internal;
import org.gradle.api.tasks.TaskAction;
import org.gradle.process.ExecOperations;

import javax.inject.Inject;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

/**
 * Compiles every generated JNI {@code .cpp} under {@code chimera.nativeOutDir} into a shared
 * library ({@code .dll}/{@code .so}/{@code .dylib}) under {@code chimera.nativeLibDir}.
 *
 * <p>The Java headers are taken from the current JVM ({@code java.home}/include and the
 * platform-specific subdirectory), so no extra configuration is needed on a normal JDK.</p>
 */
public abstract class ChimeraNativeCompileTask extends DefaultTask {
    private ChimeraExtension extension;

    @Internal
    public ChimeraExtension getExtension() {
        return extension;
    }

    public void setExtension(ChimeraExtension extension) {
        this.extension = extension;
    }

    @Inject
    protected abstract ExecOperations getExecOperations();

    @TaskAction
    public void compile() throws IOException {
        if (!isWindows()) {
            throw new GradleException("chimeraNativeCompile supports Windows only (MinGW gcc/clang "
                    + "producing .dll). Cross-compilation for Linux/macOS was removed by design.");
        }
        ChimeraExtension ext = getExtension();
        if (ext == null) throw new GradleException("chimera extension missing");
        if (ext.nativeOutDir == null) {
            throw new GradleException("chimera.nativeOutDir is not set; run chimeraObfuscate first");
        }
        Path sourceDir = ext.nativeOutDir.toPath();
        if (!Files.isDirectory(sourceDir)) {
            throw new GradleException("chimera.nativeOutDir does not exist: " + sourceDir.toAbsolutePath());
        }
        List<Path> sources;
        try (Stream<Path> walk = Files.walk(sourceDir)) {
            sources = walk.filter(Files::isRegularFile)
                    .filter(p -> p.getFileName().toString().endsWith(".cpp"))
                    .sorted(Comparator.comparing(Path::toString))
                    .toList();
        }
        if (sources.isEmpty()) {
            getLogger().lifecycle("[chimera-native] no .cpp templates found in {} (nothing to compile)",
                    sourceDir.toAbsolutePath());
            return;
        }

        String compiler = ext.nativeCompiler == null || ext.nativeCompiler.isBlank()
                ? "gcc" : ext.nativeCompiler;
        Path libDir = (ext.nativeLibDir != null
                ? ext.nativeLibDir.toPath()
                : getProject().getLayout().getBuildDirectory().dir("native-lib").get().getAsFile().toPath());
        Files.createDirectories(libDir);

        String configuredJavaHome = System.getenv("JAVA_HOME");
        File javaHome = configuredJavaHome != null && !configuredJavaHome.isBlank()
                ? new File(configuredJavaHome)
                : new File(System.getProperty("java.home"));
        File includeDir = new File(javaHome, "include");
        if (!includeDir.isDirectory()) {
            // Gradle daemon may run on a different JRE than the project toolchain; prefer the
            // selected toolchain's java.home when JAVA_HOME is stale.
            javaHome = new File(System.getProperty("java.home"));
            includeDir = new File(javaHome, "include");
        }
        File platformInclude = new File(includeDir, platformIncludeDirName());
        if (!includeDir.isDirectory() || !platformInclude.isDirectory()) {
            throw new GradleException("JNI headers not found under " + javaHome
                    + " (expected include/ and include/" + platformIncludeDirName() + ")");
        }

        String librarySuffix = librarySuffix();
        List<String> failures = new ArrayList<>();
        for (Path source : sources) {
            String fileName = source.getFileName().toString();
            String base = fileName.substring(0, fileName.length() - ".cpp".length());
            Path output = libDir.resolve(base + librarySuffix);
            List<String> command = new ArrayList<>();
            command.add(compiler);
            command.add("-shared");
            command.add("-O2");
            command.add("-std=c++17");
            // Keep float/double arithmetic bit-identical to the Java reference for M4 diff tests.
            command.add("-ffp-contract=off");
            command.add("-I" + includeDir.getAbsolutePath());
            command.add("-I" + platformInclude.getAbsolutePath());
            command.add("-o");
            command.add(output.toAbsolutePath().toString());
            command.add(source.toAbsolutePath().toString());
            // Static MinGW runtime: no libgcc/libstdc++/libwinpthread DLLs next to the game.
            command.add("-static-libgcc");
            String compilerName = compiler.toLowerCase(java.util.Locale.ROOT);
            if (compilerName.contains("g++") || compilerName.contains("clang++")) {
                command.add("-static-libstdc++");
            }
            if (extension.opensslStaticDir != null) {
                File opensslInclude = new File(extension.opensslStaticDir, "include");
                File opensslLib = new File(extension.opensslStaticDir, "lib");
                command.add("-I" + opensslInclude.getAbsolutePath());
                command.add("-L" + opensslLib.getAbsolutePath());
                // Fully static OpenSSL: one DLL for the user to download.
                command.add("-static");
                command.add("-lcrypto");
                command.add("-lssl");
            }

            ByteArrayOutputStream captured = new ByteArrayOutputStream();
            int exit;
            try {
                String joined = String.join(" ", command);
                getLogger().lifecycle("[chimera-native] {}", joined);
                exit = getExecOperations().exec(spec -> {
                    spec.commandLine(command);
                    spec.setStandardOutput(captured);
                    spec.setErrorOutput(captured);
                    spec.setIgnoreExitValue(true);
                }).getExitValue();
            } catch (Exception e) {
                throw new GradleException("failed to start native compiler '" + compiler
                        + "'; set chimera.nativeCompiler to gcc/clang (or an absolute path)", e);
            }
            String log = captured.toString(StandardCharsets.UTF_8);
            if (!log.isBlank()) {
                getLogger().lifecycle(log.stripTrailing());
            }
            if (exit != 0) {
                failures.add(fileName + " (exit " + exit + ")");
            } else if (!Files.isRegularFile(output)) {
                failures.add(fileName + " (compiler reported success but " + output.getFileName() + " is missing)");
            } else {
                getLogger().lifecycle("[chimera-native] built {}", output.toAbsolutePath());
            }
        }
        if (!failures.isEmpty()) {
            throw new GradleException("native compilation failed for: " + String.join(", ", failures)
                    + "; check that chimera.nativeCompiler points to a working gcc/clang");
        }
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase().contains("win");
    }

    private static String platformIncludeDirName() {
        return "win32";
    }

    private static String librarySuffix() {
        return ".dll";
    }
}
