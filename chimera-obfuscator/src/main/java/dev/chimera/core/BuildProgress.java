package dev.chimera.core;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * I1: machine-readable build progress for the E-language GUI ({@code --progress-json}).
 *
 * <p>One NDJSON object per line, flushed on every event so a reader can tail the file. Events are
 * {@code start}, {@code stage}, {@code stats}, {@code done}, {@code error}; {@code pct} is 0-100 and
 * never decreases. All strings are JSON-escaped; the file is UTF-8 with \n line endings.</p>
 */
public final class BuildProgress {

    private static Path target;
    private static int lastPct = -1;
    private static long startedAt = System.currentTimeMillis();
    private static final Object LOCK = new Object();

    private BuildProgress() {
    }

    /** Opens (truncates) the progress file; a null path disables all events. */
    public static void open(Path path) {
        synchronized (LOCK) {
            target = path;
            lastPct = -1;
            startedAt = System.currentTimeMillis();
            if (target == null) {
                return;
            }
            try {
                Path parent = target.toAbsolutePath().getParent();
                if (parent != null) {
                    Files.createDirectories(parent);
                }
                Files.write(target, new byte[0]);
            } catch (IOException failure) {
                target = null;
                System.err.println("[chimera] WARNING: progress file unavailable: " + failure);
            }
        }
    }

    public static void start(String version, String input, String output) {
        event("start", ",\"version\":\"" + escape(version)
                + "\",\"input\":\"" + escape(input)
                + "\",\"output\":\"" + escape(output) + "\"");
    }

    /** Emits a stage event; repeated ids with the same percentage are suppressed. */
    public static void stage(String id, String label, int pct) {
        synchronized (LOCK) {
            int clamped = Math.max(0, Math.min(100, pct));
            if (clamped < lastPct) {
                clamped = lastPct;
            }
            if (clamped == lastPct) {
                return;
            }
            lastPct = clamped;
            event("stage", ",\"id\":\"" + escape(id) + "\",\"label\":\"" + escape(label)
                    + "\",\"pct\":" + clamped);
        }
    }

    public static void stats(String statsJson) {
        event("stats", ",\"stats\":" + statsJson);
    }

    public static void done(String output, long elapsedMs) {
        synchronized (LOCK) {
            lastPct = 100;
        }
        event("done", ",\"pct\":100,\"elapsed_ms\":" + elapsedMs
                + ",\"output\":\"" + escape(output) + "\"");
    }

    public static void error(int code, String message) {
        event("error", ",\"code\":" + code + ",\"message\":\"" + escape(message) + "\"");
    }

    private static void event(String kind, String extra) {
        synchronized (LOCK) {
            if (target == null) {
                return;
            }
            String line = "{\"event\":\"" + kind + "\",\"t\":"
                    + (System.currentTimeMillis() - startedAt) + extra + "}\n";
            try {
                Files.writeString(target, line, StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            } catch (IOException ignored) {
                // Progress reporting must never break a build.
            }
        }
    }

    private static String escape(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\\' -> sb.append("\\\\");
                case '"' -> sb.append("\\\"");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }
}
