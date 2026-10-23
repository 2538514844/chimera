package dev.chimera.runtime;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.util.Arrays;

/**
 * M9 timing probe (CPU-time edition) used by {@link ChimeraVmRuntime}.
 *
 * <p>The old probe measured wall-clock time between 1024 interpreted instructions. That is
 * guaranteed to false-positive on a paying player: a screen-mode switch, a GC pause, CPU frequency
 * scaling, or a hijacked scheduler makes an interval arbitrarily long without any debugger being
 * attached. This probe measures <b>per-thread CPU time</b> via
 * {@link ThreadMXBean#getCurrentThreadCpuTime()}, which does not include time spent blocked,
 * descheduled or in a stop-the-world pause.</p>
 *
 * <p>Policy (anti-false-positive):</p>
 * <ul>
 *   <li>{@code telemetry} (default): anomalies are written to stderr and counted, but never poison
 *       the runtime by themselves;</li>
 *   <li>{@code strict}: poison after {@code chimera.vm.probeRequiredSuspicions} anomalies
 *       (default 3) - opt-in only, for controlled debugging/hardening builds;</li>
 *   <li>{@code off}: probe disabled.</li>
 * </ul>
 *
 * <p>Regardless of mode, when a Java agent/JDWP/Frida signal is already detected by
 * {@link ChimeraRuntime#timingAgentDetected()}, a single CPU-time anomaly is enough to poison:
 * explicit instrumentation is not a false positive.</p>
 *
 * <p>The CPU budget is calibrated at first use: the median CPU time of 20 synthetic
 * interpreter-shaped rounds ({@code interval} iterations of record decoding + an AES block
 * update, the dominant per-instruction cost) multiplied by a safety ratio (default 8x), with a
 * 50 ms floor. All values are configurable: {@code chimera.vm.probeInterval},
 * {@code chimera.vm.probeBudgetNanos}, {@code chimera.vm.probeRatio},
 * {@code chimera.vm.probeFloorMs}, {@code chimera.vm.probeRequiredSuspicions},
 * {@code chimera.vm.probe.mode}, {@code chimera.vm.probe.debug}.</p>
 */
public final class ChimeraVmProbe {

    public static final int MODE_OFF = 0;
    public static final int MODE_TELEMETRY = 1;
    public static final int MODE_STRICT = 2;

    private static final long DEFAULT_INTERVAL = 1024L;
    private static final long DEFAULT_FLOOR_NANOS = 50_000_000L;
    private static final long DEFAULT_RATIO = 8L;
    private static final int DEFAULT_REQUIRED_SUSPICIONS = 3;
    private static final int CALIBRATION_WARMUP = 3;
    private static final int CALIBRATION_ROUNDS = 20;
    private static final int MAX_INSTRUCTION_BYTES = 12;
    private static final int MAX_LOGGED_ANOMALIES = 10;

    private static byte[] calibrationKey() {
        byte[] key = new byte[32];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) (i * 37 + 11);
        }
        return key;
    }

    private static volatile int cachedMode = -1;
    private static volatile long cachedInterval = -1L;
    private static volatile long budget = -1L;
    private static volatile boolean calibrationFailed;
    private static volatile int requiredSuspicions = -1;
    private static volatile boolean cpuTimeSupported = true;

    private static volatile int suspicionCount;
    private static volatile int telemetryLogs;
    private static volatile int agentPoisonCount;
    private static volatile long lastElapsedNanos;
    private static volatile long lastBudgetNanos;

    /** Test hooks: a synthetic CPU clock (calibration always uses the real clock). */
    private static volatile boolean testClockEnabled;
    private static volatile long testClockValue;
    private static volatile long testClockStep;
    /** -1 = consult the real detector, 0/1 = deterministic test override. */
    private static volatile int agentOverride = -1;

    private ChimeraVmProbe() {
    }

    public static int mode() {
        int mode = cachedMode;
        if (mode >= 0) {
            return mode;
        }
        // Phase 0 (C-04): release builds ignore probe tuning properties.
        String value = DebugSwitches.property("chimera.vm.probe.mode");
        int parsed = MODE_TELEMETRY;
        if (value != null) {
            String trimmed = value.trim().toLowerCase(java.util.Locale.ROOT);
            if ("off".equals(trimmed) || "false".equals(trimmed) || "disabled".equals(trimmed)) {
                parsed = MODE_OFF;
            } else if ("strict".equals(trimmed) || "enforce".equals(trimmed)) {
                parsed = MODE_STRICT;
            } else if ("telemetry".equals(trimmed) || "log".equals(trimmed)) {
                parsed = MODE_TELEMETRY;
            }
        }
        cachedMode = parsed;
        return parsed;
    }

    /** Number of interpreted instructions between two CPU-time samples. */
    public static long interval() {
        long interval = cachedInterval;
        if (interval > 0) {
            return interval;
        }
        String value = DebugSwitches.property("chimera.vm.probeInterval");
        long parsed = DEFAULT_INTERVAL;
        if (value != null) {
            try {
                parsed = Long.parseLong(value.trim());
            } catch (NumberFormatException ignored) {
                // keep default
            }
        }
        if (parsed < 1L) {
            parsed = 1L;
        }
        if (parsed > 1_000_000L) {
            parsed = 1_000_000L;
        }
        cachedInterval = parsed;
        return parsed;
    }

    /** False when the JVM cannot provide per-thread CPU time and no test clock is installed. */
    public static boolean clockAvailable() {
        if (testClockEnabled) {
            return true;
        }
        if (!cpuTimeSupported) {
            return false;
        }
        ThreadMXBean bean = threadBean();
        if (bean == null || !bean.isCurrentThreadCpuTimeSupported()) {
            cpuTimeSupported = false;
            return false;
        }
        return true;
    }

    /** Current thread CPU time in nanoseconds (or the synthetic test clock). */
    public static long cpuNanos() {
        if (testClockEnabled) {
            long step = testClockStep;
            long value = testClockValue + step;
            testClockValue = value;
            return value;
        }
        ThreadMXBean bean = threadBean();
        if (bean != null) {
            try {
                long cpu = bean.getCurrentThreadCpuTime();
                if (cpu >= 0L) {
                    return cpu;
                }
            } catch (Throwable ignored) {
                // fall through to wall clock; the probe stays disabled by clockAvailable()
            }
        }
        return System.nanoTime();
    }

    /**
     * Evaluates one probe interval. Returns true when the runtime must be poisoned.
     *
     * @param elapsed CPU nanoseconds spent in the last {@link #interval()} instructions
     */
    public static boolean evaluate(long elapsed) {
        int mode = mode();
        if (mode == MODE_OFF) {
            return false;
        }
        if (elapsed < 0L) {
            return false;
        }
        long limit = budgetNanos();
        lastElapsedNanos = elapsed;
        lastBudgetNanos = limit;
        if (elapsed <= limit) {
            return false;
        }
        int suspicion = ++suspicionCount;
        boolean agent = agentDetected();
        logTelemetry(elapsed, limit, suspicion, agent);
        if (agent) {
            agentPoisonCount++;
            return true;
        }
        if (mode == MODE_STRICT) {
            return suspicion >= requiredSuspicions();
        }
        // Telemetry mode: never punish a paying player from a timing sample alone.
        return false;
    }

    private static boolean agentDetected() {
        int override = agentOverride;
        if (override >= 0) {
            return override == 1;
        }
        try {
            return ChimeraRuntime.timingAgentDetected();
        } catch (Throwable ignored) {
            return false;
        }
    }

    /** Test-only deterministic agent signal (production never calls this). */
    public static void setAgentDetectedForTests(boolean detected) {
        agentOverride = detected ? 1 : 0;
    }

    public static void clearAgentDetectedForTests() {
        agentOverride = -1;
    }

    /** Per-interval CPU budget; calibrated once from a synthetic interpreter-shaped workload. */
    public static long budgetNanos() {
        long current = budget;
        if (current > 0L) {
            return current;
        }
        synchronized (ChimeraVmProbe.class) {
            if (budget > 0L) {
                return budget;
            }
            budget = computeBudget();
            return budget;
        }
    }

    private static long computeBudget() {
        String explicit = DebugSwitches.property("chimera.vm.probeBudgetNanos");
        if (explicit != null) {
            try {
                long parsed = Long.parseLong(explicit.trim());
                if (parsed > 0L) {
                    return parsed;
                }
            } catch (NumberFormatException ignored) {
                // fall through to calibration
            }
        }
        long floorNanos = floorNanos();
        long ratio = ratio();
        try {
            long median = calibrate();
            if (median <= 0L) {
                calibrationFailed = true;
                return floorNanos;
            }
            long scaled = median;
            if (ratio > 1L) {
                if (median > Long.MAX_VALUE / ratio) {
                    scaled = Long.MAX_VALUE;
                } else {
                    scaled = median * ratio;
                }
            }
            return Math.max(floorNanos, scaled);
        } catch (Throwable ignored) {
            calibrationFailed = true;
            return floorNanos;
        }
    }

    /**
     * Synthetic interpreter-shaped calibration: {@code interval} iterations of DataInputStream
     * record decoding plus one AES block update, which approximates the per-instruction cost of
     * {@code ChimeraVmRuntime} (edge keystream + instruction decode). 3 warmup rounds discard JIT
     * effects; the median of 20 rounds is used.
     */
    private static long calibrate() throws Exception {
        long interval = interval();
        if (interval > 65_536L) {
            interval = 65_536L;
        }
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(calibrationKey(), "AES"));
        byte[] record = new byte[MAX_INSTRUCTION_BYTES + 8];
        byte[] counter = new byte[16];
        byte[] keystream = new byte[16];
        byte[] sink = new byte[16];
        for (int i = 0; i < record.length; i++) {
            record[i] = (byte) (i * 31 + 7);
        }
        long[] samples = new long[CALIBRATION_ROUNDS];
        int rounds = CALIBRATION_WARMUP + CALIBRATION_ROUNDS;
        for (int round = 0; round < rounds; round++) {
            long started = rawCpuNanos();
            long checksum = 0L;
            for (long i = 0; i < interval; i++) {
                DataInputStream in = new DataInputStream(
                        new ByteArrayInputStream(record, 0, MAX_INSTRUCTION_BYTES));
                checksum += in.readUnsignedShort();
                int produced = cipher.update(counter, 0, 16, keystream, 0);
                if (produced != 16) {
                    throw new IllegalStateException("calibration cipher failure");
                }
                sink[(int) (i & 15)] = keystream[(int) (i & 15)];
                checksum += sink[(int) (i & 15)];
            }
            long elapsed = rawCpuNanos() - started;
            if (checksum == 0x7fffffffffffffffL) {
                return -1L;
            }
            if (round >= CALIBRATION_WARMUP) {
                samples[round - CALIBRATION_WARMUP] = elapsed;
            }
        }
        Arrays.sort(samples);
        long median = samples[samples.length / 2];
        Arrays.fill(keystream, (byte) 0);
        Arrays.fill(sink, (byte) 0);
        return median;
    }

    private static long floorNanos() {
        long floorMs = 50L;
        String value = DebugSwitches.property("chimera.vm.probeFloorMs");
        if (value != null) {
            try {
                floorMs = Long.parseLong(value.trim());
            } catch (NumberFormatException ignored) {
                // keep default
            }
        }
        if (floorMs < 0L) {
            floorMs = 0L;
        }
        if (floorMs > 3_600_000L) {
            floorMs = 3_600_000L;
        }
        return floorMs * 1_000_000L;
    }

    private static long ratio() {
        long ratio = DEFAULT_RATIO;
        String value = DebugSwitches.property("chimera.vm.probeRatio");
        if (value != null) {
            try {
                ratio = Long.parseLong(value.trim());
            } catch (NumberFormatException ignored) {
                // keep default
            }
        }
        if (ratio < 1L) {
            ratio = 1L;
        }
        if (ratio > 1000L) {
            ratio = 1000L;
        }
        return ratio;
    }

    private static int requiredSuspicions() {
        int current = requiredSuspicions;
        if (current > 0) {
            return current;
        }
        int parsed = DEFAULT_REQUIRED_SUSPICIONS;
        String value = DebugSwitches.property("chimera.vm.probeRequiredSuspicions");
        if (value != null) {
            try {
                parsed = Integer.parseInt(value.trim());
            } catch (NumberFormatException ignored) {
                // keep default
            }
        }
        if (parsed < 1) {
            parsed = 1;
        }
        if (parsed > 1000) {
            parsed = 1000;
        }
        requiredSuspicions = parsed;
        return parsed;
    }

    private static void logTelemetry(long elapsed, long limit, int suspicion, boolean agent) {
        int count = ++telemetryLogs;
        boolean debug = DebugSwitches.propertyTrue("chimera.vm.probe.debug");
        if (!debug && count > MAX_LOGGED_ANOMALIES && count % 100 != 0) {
            return;
        }
        int mode = mode();
        String modeName = mode == MODE_STRICT ? "strict" : "telemetry";
        boolean poison = agent || (mode == MODE_STRICT && suspicion >= requiredSuspicions());
        System.err.println("[chimera-vm-probe] CPU anomaly: elapsed=" + elapsed
                + "ns budget=" + limit + "ns interval=" + interval()
                + " suspicion=" + suspicion + " mode=" + modeName
                + " agent=" + agent + " -> " + (poison ? "POISON" : "telemetry only"));
    }

    private static ThreadMXBean threadBean() {
        try {
            return ManagementFactory.getThreadMXBean();
        } catch (Throwable ignored) {
            return null;
        }
    }

    /** Raw CPU clock used only for calibration (never the test clock). */
    private static long rawCpuNanos() {
        ThreadMXBean bean = threadBean();
        if (bean != null && bean.isCurrentThreadCpuTimeSupported()) {
            try {
                long cpu = bean.getCurrentThreadCpuTime();
                if (cpu >= 0L) {
                    return cpu;
                }
            } catch (Throwable ignored) {
                // fall through
            }
        }
        return System.nanoTime();
    }

    // ------------------------------------------------------------------ test/diagnostic hooks

    /** Installs a deterministic synthetic CPU clock: each read advances by {@code stepNanos}. */
    public static void setTestClock(long startNanos, long stepNanos) {
        testClockValue = startNanos;
        testClockStep = stepNanos;
        testClockEnabled = true;
    }

    public static void clearTestClock() {
        testClockEnabled = false;
        testClockStep = 0L;
    }

    public static int suspicionCount() {
        return suspicionCount;
    }

    public static int telemetryLogCount() {
        return telemetryLogs;
    }

    public static int agentPoisonCount() {
        return agentPoisonCount;
    }

    public static long lastIntervalElapsedNanos() {
        return lastElapsedNanos;
    }

    public static long lastIntervalBudgetNanos() {
        return lastBudgetNanos;
    }

    public static boolean clockSupported() {
        return cpuTimeSupported;
    }

    public static boolean calibrationFailed() {
        return calibrationFailed;
    }
}
