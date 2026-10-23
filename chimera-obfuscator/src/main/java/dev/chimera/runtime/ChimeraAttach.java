package dev.chimera.runtime;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.concurrent.TimeUnit;

/**
 * S2 bootstrap: extracts the embedded agent jar, attaches it to this JVM through a helper process
 * at {@code preLaunch}, then proves the transformer works by defining an encrypted sentinel class.
 *
 * <p>Fail-closed: any failure halts the JVM before the game starts. There is no plaintext fallback,
 * because the protected classes only exist as CHENC1 ciphertext in the artifact.</p>
 */
public final class ChimeraAttach {

    private static final String SENTINEL = "dev.chimera.probe.ChimeraSentinel";
    private static final String AGENT_STATE = "dev.chimera.attach.AgentState";
    private static volatile boolean installed;

    private ChimeraAttach() {
    }

    public static synchronized void install() {
        if (installed) {
            return;
        }
        try {
            ClassLoader loader = ChimeraAttach.class.getClassLoader();
            Path agentJar = extractAgent();
            runHelper(agentJar);
            waitForSentinel(loader);
            installed = true;
            diag("attach ok");
        } catch (Throwable failure) {
            java.io.StringWriter trace = new java.io.StringWriter();
            failure.printStackTrace(new java.io.PrintWriter(trace));
            diag("attach failed: " + trace);
            System.err.println("[chimera] protection bootstrap failed: " + failure);
            Runtime.getRuntime().halt(4);
        }
    }

    private static Path extractAgent() throws Exception {
        try (InputStream in = ChimeraAttach.class.getResourceAsStream("/chimera/attach/agent.jar")) {
            if (in == null) {
                throw new IllegalStateException("embedded agent jar missing");
            }
            Path temp = Files.createTempFile("chimera-agent-", ".jar");
            temp.toFile().deleteOnExit();
            Files.copy(in, temp, StandardCopyOption.REPLACE_EXISTING);
            return temp;
        }
    }

    private static void runHelper(Path agentJar) throws Exception {
        if (agentAlreadyInstalled()) {
            diag("agent already installed (re-entrant call)");
            return;
        }
        String javaHome = System.getProperty("java.home");
        String exe = System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT).contains("win")
                ? "java.exe" : "java";
        Path java = Path.of(javaHome, "bin", exe);
        long pid = ProcessHandle.current().pid();
        // The helper only loads jdk.attach and reflects into it: keep its footprint minimal so it
        // still starts on machines that are close to their commit limit.
        ProcessBuilder builder = new ProcessBuilder(
                java.toString(),
                "-Xmx96m",
                "-XX:+UseSerialGC",
                "-XX:TieredStopAtLevel=1",
                "-XX:-UsePerfData",
                "-Xss512k",
                "-cp", agentJar.toString(),
                "dev.chimera.attach.Attacher",
                String.valueOf(pid),
                agentJar.toString());
        builder.redirectErrorStream(true);
        Process process = builder.start();
        String output;
        try (InputStream in = process.getInputStream()) {
            output = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        if (!process.waitFor(30, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            throw new IllegalStateException("attach helper timed out");
        }
        if (process.exitValue() != 0) {
            throw new IllegalStateException("attach helper failed (" + process.exitValue() + "): " + output);
        }
        diag("helper output: " + output.trim());
    }

    /** The agent is functional iff it can decrypt the encrypted sentinel class. */
    private static void waitForSentinel(ClassLoader loader) throws Exception {
        Throwable last = null;
        for (int attempt = 0; attempt < 200; attempt++) {
            try {
                Class<?> sentinel = Class.forName(SENTINEL, true, loader);
                Object result = sentinel.getMethod("probe").invoke(null);
                if (!Boolean.TRUE.equals(result)) {
                    throw new IllegalStateException("sentinel probe returned " + result);
                }
                diag("sentinel ok " + agentState());
                return;
            } catch (ClassNotFoundException | NoClassDefFoundError notYet) {
                last = notYet;
                Thread.sleep(100L);
            }
        }
        throw new IllegalStateException("encrypted sentinel never loaded: " + last, last);
    }

    /** True when a previous install already registered the transformer in this JVM. */
    private static boolean agentAlreadyInstalled() {
        try {
            Class<?> state = Class.forName(AGENT_STATE, true, ClassLoader.getSystemClassLoader());
            return Boolean.TRUE.equals(state.getField("installed").get(null));
        } catch (Throwable ignored) {
            return false;
        }
    }

    /** Diagnostics only: best-effort state snapshot through the system loader. */
    private static String agentState() {
        try {
            Class<?> state = Class.forName(AGENT_STATE, true, ClassLoader.getSystemClassLoader());
            return "decrypted=" + state.getField("decrypted").get(null)
                    + " failures=" + state.getField("failures").get(null)
                    + " keyId=" + state.getField("keyId").get(null);
        } catch (Throwable ignored) {
            return "state=unavailable";
        }
    }

    private static void diag(String line) {
        try {
            Path dir = Path.of(System.getProperty("user.home", "."), ".chimera");
            Files.createDirectories(dir);
            Files.writeString(dir.resolve("attach.log"), line + System.lineSeparator(),
                    StandardCharsets.UTF_8,
                    java.nio.file.StandardOpenOption.CREATE,
                    java.nio.file.StandardOpenOption.APPEND);
        } catch (Throwable ignored) {
            // Diagnostics must never break startup.
        }
    }
}
