package dev.chimera.runtime;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * B-6: runtime hidden-class load audit.
 *
 * <p>S1 keeps hidden entries in the artifact under their real internal names, so "the class can be
 * loaded by name" is the property that actually matters - and it cannot be checked offline, because
 * the class bodies are CHENC1 ciphertext until the attach agent decrypts them. The offline
 * {@code HiddenLoadCheck} therefore only counts entries; this audit runs inside a live JVM (after
 * the gate authorised the session and the agent is attached) and loads every hidden name once.</p>
 *
 * <p>Opt-in and non-fatal: only a JVM started with {@code -Dchimera.hiddenAudit=<file>} pays for it,
 * and a failure is written to the report instead of aborting the game (an audit is diagnostics; the
 * fail-closed decision for a genuinely missing class is still made by the loader when the bytecode
 * references it).</p>
 */
public final class HiddenNameAudit {

    public static final String PROPERTY = "chimera.hiddenAudit";
    private static final String RESOURCE = "/chimera/hidden/names.txt";
    private static final int MAX_REPORTED_FAILURES = 40;

    private HiddenNameAudit() {
    }

    /** Runs once when {@link #PROPERTY} is set; never throws. */
    public static void runIfRequested() {
        String output = System.getProperty(PROPERTY);
        if (output == null || output.isEmpty()) {
            return;
        }
        try {
            run(Path.of(output));
        } catch (Throwable ignored) {
            // diagnostics only: an audit must never break startup
        }
    }

    static void run(Path output) throws Exception {
        ClassLoader loader = HiddenNameAudit.class.getClassLoader();
        List<String> names = readNames(loader);
        int loaded = 0;
        List<String> failures = new ArrayList<>();
        for (String name : names) {
            String binary = name.replace('/', '.');
            try {
                Class<?> loadedClass = Class.forName(binary, false, loader);
                if (loadedClass != null) {
                    loaded++;
                } else {
                    failures.add(name + " -> null class");
                }
            } catch (Throwable failure) {
                if (failures.size() < MAX_REPORTED_FAILURES) {
                    failures.add(name + " -> " + failure.getClass().getName()
                            + ": " + failure.getMessage());
                } else {
                    failures.add("...");
                    break;
                }
            }
        }
        StringBuilder report = new StringBuilder(4096);
        report.append("hidden entries: ").append(names.size()).append('\n');
        report.append("loaded by name: ").append(loaded).append('\n');
        report.append("failed: ").append(Math.max(0, names.size() - loaded)).append('\n');
        report.append("loader: ").append(loader == null ? "<bootstrap>" : loader.getClass().getName())
                .append('\n');
        for (String failure : failures) {
            report.append("FAIL ").append(failure).append('\n');
        }
        report.append("verdict: ").append(loaded == names.size() ? "PASS" : "FAIL").append('\n');
        Files.writeString(output, report.toString(), StandardCharsets.UTF_8);
        System.err.println("[chimera] hidden audit: " + loaded + "/" + names.size()
                + " loaded -> " + output);
    }

    private static List<String> readNames(ClassLoader loader) throws Exception {
        List<String> names = new ArrayList<>();
        InputStream in = HiddenNameAudit.class.getResourceAsStream(RESOURCE);
        if (in == null && loader != null) {
            in = loader.getResourceAsStream(RESOURCE.substring(1));
        }
        if (in == null) {
            return names;
        }
        try (InputStream source = in) {
            String text = new String(source.readAllBytes(), StandardCharsets.UTF_8);
            for (String line : text.split("\\R")) {
                String trimmed = line.trim();
                if (!trimmed.isEmpty()) {
                    names.add(trimmed);
                }
            }
        }
        return names;
    }
}
