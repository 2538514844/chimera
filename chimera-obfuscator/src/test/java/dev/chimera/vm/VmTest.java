package dev.chimera.vm;

import dev.chimera.core.ChimeraConfig;
import dev.chimera.core.ChimeraEngine;
import dev.chimera.crypto.Crypto;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * M9 tests: obfuscate a fixture jar with the VM transformer enabled, load the result in an
 * isolated class loader and verify (a) virtualized arithmetic/control flow, (b) type-correct
 * poison without a key, (c) division-by-zero poisoning, (d) streaming resource format v2 and
 * MAC tamper detection, and (e) unsupported methods keep their Java bytecode.
 */
public class VmTest {

    private static final String KEY_PROPERTY = "chimera.contentKey";
    private static final String CONTENT_KEY = "test-content-key";
    private static final int VIRTUALIZED_METHODS = 27;

    private static byte[] key() {
        return Crypto.sha256(CONTENT_KEY.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] fixtureClass(String name) throws Exception {
        try (InputStream in = VmTest.class.getClassLoader().getResourceAsStream(name)) {
            assertNotNull(in, "missing fixture " + name);
            return in.readAllBytes();
        }
    }

    private static Path buildFixtureJar(Path jar) throws Exception {
        Files.createDirectories(jar.getParent());
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(jar))) {
            for (String name : new String[]{"fixtures/VmMath.class", "fixtures/VmState.class"}) {
                zos.putNextEntry(new ZipEntry(name));
                zos.write(fixtureClass(name));
                zos.closeEntry();
            }
        }
        return jar;
    }

    private static ChimeraConfig config(Path in, Path out) {
        ChimeraConfig cfg = new ChimeraConfig();
        cfg.inputJar = in;
        cfg.outputJar = out;
        cfg.keyMaterial = key();
        cfg.nativeOutDir = out.resolveSibling("native");
        cfg.integrityManifest = true;
        cfg.vm = true;
        return cfg;
    }

    private static Path obfuscate(Path work) throws Exception {
        Path in = buildFixtureJar(work.resolve("vm-fixtures.jar"));
        Path out = work.resolve("vm-fixtures-obf.jar");
        new ChimeraEngine(config(in, out)).run();
        return out;
    }

    private static Class<?> load(URLClassLoader loader, String name) throws Exception {
        return Class.forName(name, true, loader);
    }

    @Test
    public void virtualizedArithmeticAndControlFlowWithKey() throws Exception {
        Path work = Files.createTempDirectory("chimera-vm-compute");
        Path out = obfuscate(work);
        assertEquals(VIRTUALIZED_METHODS, countResources(out, "chimera/vm/vm_"),
                "every supported fixture method should produce one encrypted program");

        String previous = System.getProperty(KEY_PROPERTY);
        System.setProperty(KEY_PROPERTY, Crypto.hex(key()));
        try (URLClassLoader cl = new URLClassLoader(new URL[]{out.toUri().toURL()},
                ClassLoader.getPlatformClassLoader())) {
            Class<?> vm = load(cl, "fixtures.VmMath");
            assertEquals(15, vm.getMethod("addMul", int.class, int.class).invoke(null, 2, 3));
            assertEquals(17L, vm.getMethod("longChain", long.class, int.class).invoke(null, 5L, 7));
            double ratio = ((Double) vm.getMethod("ratio", int.class, int.class).invoke(null, 2, 3)).doubleValue();
            assertEquals(4.5d, ratio, 1e-12);
            assertEquals(12, vm.getMethod("mix", long.class, double.class).invoke(null, 5L, 2.75d));
            assertEquals(3, vm.getMethod("div", int.class, int.class).invoke(null, 7, 2));

            // if/else
            assertEquals(4, vm.getMethod("branchyAnnotated", int.class).invoke(null, 3));
            assertEquals(2, vm.getMethod("branchyAnnotated", int.class).invoke(null, -2));
            assertEquals(3, vm.getMethod("clamp", int.class, int.class, int.class).invoke(null, 5, 1, 3));
            assertEquals(1, vm.getMethod("clamp", int.class, int.class, int.class).invoke(null, -5, 1, 3));
            assertEquals(2, vm.getMethod("clamp", int.class, int.class, int.class).invoke(null, 2, 1, 3));
            assertEquals(9, vm.getMethod("max3", int.class, int.class, int.class).invoke(null, 3, 9, 5));
            assertEquals(0x1062, vm.getMethod("bitMix", int.class, int.class).invoke(null, 0x1234, 5));

            // long/double comparisons (LCMP / DCMPG / DCMPL)
            assertEquals(-1, vm.getMethod("longCmp", long.class, long.class).invoke(null, 3L, 7L));
            assertEquals(1, vm.getMethod("longCmp", long.class, long.class).invoke(null, 9L, 2L));
            assertEquals(0, vm.getMethod("longCmp", long.class, long.class).invoke(null, 5L, 5L));
            assertEquals(-1, vm.getMethod("doubleCmp", double.class, double.class).invoke(null, 1.0d, 2.0d));
            assertEquals(1, vm.getMethod("doubleCmp", double.class, double.class).invoke(null, 2.0d, 1.0d));
            assertEquals(0, vm.getMethod("doubleCmp", double.class, double.class).invoke(null, 1.0d, 1.0d));

            // object fields + MethodHandle static bridge (pure-logic object only)
            Class<?> stateClass = load(cl, "fixtures.VmState");
            Object state = stateClass.getConstructor(int.class, long.class, double.class)
                    .newInstance(3, 4L, 2.0d);
            Object[] noArgs = new Object[0];
            assertEquals(5.0d, ((Double) vm.getMethod("dist", stateClass).invoke(null, state)).doubleValue(), 1e-12);
            assertEquals(1, vm.getMethod("hpAfterDamage", stateClass, int.class).invoke(null, state, 2));
            assertEquals(0, vm.getMethod("hpAfterDamage", stateClass, int.class).invoke(null, state, 10));
            assertEquals(20, vm.getMethod("hpAfterDamage", stateClass, int.class).invoke(null, state, -30));
            assertEquals(9, vm.getMethod("addViaBridge", int.class, int.class).invoke(null, 4, 5));
            assertEquals(3.0d, ((Double) vm.getMethod("scaled", stateClass, double.class)
                    .invoke(null, state, 1.5d)).doubleValue(), 1e-12);
            assertEquals(11L, vm.getMethod("goldPlus", stateClass, long.class).invoke(null, state, 7L));

            // instance field writes + INVOKEVIRTUAL setters/getters
            assertEquals(7, vm.getMethod("writeHp", stateClass, int.class).invoke(null, state, 7));
            assertEquals(7, stateClass.getMethod("getHp").invoke(state));
            assertEquals(11, vm.getMethod("setHpViaVm", stateClass, int.class).invoke(null, state, 11));
            assertEquals(11, stateClass.getMethod("getHp").invoke(state));
            assertEquals(99L, vm.getMethod("setGoldViaVm", stateClass, long.class).invoke(null, state, 99L));
            assertEquals(99L, stateClass.getMethod("getGold").invoke(state));
            assertEquals(3.5d, ((Double) vm.getMethod("factorViaVm", stateClass, double.class)
                    .invoke(null, state, 3.5d)).doubleValue(), 1e-12);
            assertEquals(3.5d, ((Double) stateClass.getMethod("getFactor").invoke(state)).doubleValue(), 1e-12);
            assertEquals(16, vm.getMethod("hpPlus", stateClass, int.class).invoke(null, state, 5));
            assertEquals(55, vm.getMethod("setLimitViaVm", int.class).invoke(null, 55));
            assertEquals(55, stateClass.getField("LIMIT").getInt(null));
            stateClass.getField("LIMIT").setInt(null, 20);

            // loops: for / while / nested branches
            assertEquals(6, vm.getMethod("loops", int.class).invoke(null, 4));
            assertEquals(55, vm.getMethod("sumTo", int.class).invoke(null, 10));
            assertEquals(8, vm.getMethod("collatz", int.class).invoke(null, 6));
            assertEquals(6, vm.getMethod("gcd", int.class, int.class).invoke(null, 48, 18));
            assertEquals(0, vm.getMethod("sumTo", int.class).invoke(null, 0));

            // second calls reuse the memoized program
            assertEquals(15, vm.getMethod("addMul", int.class, int.class).invoke(null, 2, 3));
            assertEquals(Boolean.FALSE, cl.loadClass("dev.chimera.runtime.ChimeraVmRuntime")
                    .getMethod("isPoisoned").invoke(null));
        } finally {
            restore(previous);
        }
    }

    @Test
    public void missingKeyReturnsTypeCorrectPoisonWithoutThrowing() throws Exception {
        Path work = Files.createTempDirectory("chimera-vm-poison");
        Path out = obfuscate(work);

        String previous = System.getProperty(KEY_PROPERTY);
        System.clearProperty(KEY_PROPERTY);
        try (URLClassLoader cl = new URLClassLoader(new URL[]{out.toUri().toURL()},
                ClassLoader.getPlatformClassLoader())) {
            Class<?> vm = load(cl, "fixtures.VmMath");
            // A4: poison values are session-derived pseudo-random values, not fixed -1/-1L/NaN.
            // The acceptance property is "poisoned session + no healthy business value", not a
            // specific enumerable sentinel.
            assertNotEquals(Integer.valueOf(15),
                    vm.getMethod("addMul", int.class, int.class).invoke(null, 2, 3));
            assertNotEquals(Long.valueOf(17L),
                    vm.getMethod("longChain", long.class, int.class).invoke(null, 5L, 7));
            Object ratio = vm.getMethod("ratio", int.class, int.class).invoke(null, 2, 3);
            assertNotEquals(Double.valueOf(4.5d), ratio);
            assertNotEquals(Integer.valueOf(12),
                    vm.getMethod("mix", long.class, double.class).invoke(null, 5L, 2.75d));
            assertNotEquals(Integer.valueOf(4),
                    vm.getMethod("branchyAnnotated", int.class).invoke(null, 3));
            assertNotEquals(Integer.valueOf(6),
                    vm.getMethod("loops", int.class).invoke(null, 4));
            Class<?> stateClass = load(cl, "fixtures.VmState");
            Object state = stateClass.getConstructor(int.class, long.class, double.class)
                    .newInstance(3, 4L, 2.0d);
            assertNotEquals(Integer.valueOf(9),
                    vm.getMethod("addViaBridge", int.class, int.class).invoke(null, 4, 5));
            assertPoisoned(cl);
        } finally {
            restore(previous);
        }
    }

    @Test
    public void divisionByZeroPoisonsWithoutThrowing() throws Exception {
        Path work = Files.createTempDirectory("chimera-vm-div");
        Path out = obfuscate(work);

        String previous = System.getProperty(KEY_PROPERTY);
        System.setProperty(KEY_PROPERTY, Crypto.hex(key()));
        try (URLClassLoader cl = new URLClassLoader(new URL[]{out.toUri().toURL()},
                ClassLoader.getPlatformClassLoader())) {
            Class<?> vm = load(cl, "fixtures.VmMath");
            assertEquals(3, vm.getMethod("div", int.class, int.class).invoke(null, 7, 2));
            Object divByZero = vm.getMethod("div", int.class, int.class).invoke(null, 1, 0);
            Object afterFailure = vm.getMethod("addMul", int.class, int.class).invoke(null, 2, 3);
            assertPoisoned(cl);
            assertNotEquals(Integer.valueOf(3), divByZero,
                    "integer division by zero must not return the healthy result");
            assertNotEquals(Integer.valueOf(15), afterFailure,
                    "a VM fault poisons subsequent calls instead of throwing");
        } finally {
            restore(previous);
        }
    }

    @Test
    public void streamingResourceFormatIsV6AndTamperIsDetected() throws Exception {
        Path work = Files.createTempDirectory("chimera-vm-format");
        Path out = obfuscate(work);
        byte[] descriptor = "(II)I".getBytes(StandardCharsets.US_ASCII);

        try (ZipFile zip = new ZipFile(out.toFile())) {
            var entries = zip.entries();
            int resources = 0;
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (!entry.getName().startsWith("chimera/vm/vm_")) {
                    continue;
                }
                resources++;
                byte[] blob;
                try (InputStream in = zip.getInputStream(entry)) {
                    blob = in.readAllBytes();
                }
                assertEquals(0x43485642, readInt(blob, 0), "vm blob magic");
                assertEquals(6, readInt(blob, 8), "KI-28 stream format version must be 6");
                assertEquals(12, readInt(blob, 12), "nonce length");
                // v6: wrapped VM item key block (KI-28) precedes the plaintext length fields.
                assertEquals(12, readInt(blob, 28), "wrapped-key nonce length");
                assertEquals(48, readInt(blob, 44), "wrapped-key ciphertext length");
                int plainLength = readInt(blob, 96);
                int headerLength = readInt(blob, 100);
                int offsetsLength = readInt(blob, 104);
                int recordsLength = readInt(blob, 108);
                assertEquals(plainLength, headerLength + offsetsLength,
                        "outer header + offsets form the CTR-protected structure");
                assertEquals(112 + plainLength + recordsLength + 32, blob.length,
                        "v6 outer header + structure + edge records + HMAC");
                assertTrue(headerLength > 0 && offsetsLength > 0 && recordsLength > 0);
                assertFalse(contains(blob, descriptor), "the encrypted header must not leak descriptors");
                assertFalse(allZero(blob, blob.length - 32), "MAC trailer must be present");
            }
            assertEquals(VIRTUALIZED_METHODS, resources);
        }

        // Flip one ciphertext byte of program 0: HMAC must fail and the runtime must poison.
        Path tampered = work.resolve("vm-fixtures-tampered.jar");
        try (ZipFile zin = new ZipFile(out.toFile());
             ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(tampered))) {
            var entries = zin.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                byte[] data;
                try (InputStream in = zin.getInputStream(entry)) {
                    data = in.readAllBytes();
                }
                if (entry.getName().equals("chimera/vm/vm_0.bin")) {
                    data[data.length - 33] ^= 0x01;
                }
                zos.putNextEntry(new ZipEntry(entry.getName()));
                zos.write(data);
                zos.closeEntry();
            }
        }
        String previous = System.getProperty(KEY_PROPERTY);
        System.setProperty(KEY_PROPERTY, Crypto.hex(key()));
        try (URLClassLoader cl = new URLClassLoader(new URL[]{tampered.toUri().toURL()},
                ClassLoader.getPlatformClassLoader())) {
            Class<?> vm = load(cl, "fixtures.VmMath");
            Object result = vm.getMethod("addMul", int.class, int.class).invoke(null, 2, 3);
            assertPoisoned(cl);
            assertNotEquals(Integer.valueOf(15), result,
                    "a tampered vm blob must not return the healthy result");
        } finally {
            restore(previous);
        }
    }

    @Test
    public void unsupportedMethodsKeepTheirJavaBytecode() throws Exception {
        Path work = Files.createTempDirectory("chimera-vm-unsupported");
        Path out = obfuscate(work);

        byte[] classBytes = readEntry(out, "fixtures/VmMath.class");
        ClassNode node = new ClassNode();
        new ClassReader(classBytes).accept(node, ClassReader.EXPAND_FRAMES);

        for (String name : new String[]{"addMul", "branchyAnnotated", "loops", "clamp", "sumTo",
                "collatz", "dist", "addViaBridge", "text"}) {
            MethodNode method = method(node, name);
            assertNotNull(method, "missing method " + name);
            assertTrue(hasExecuteCall(method), name + " must call ChimeraVmRuntime.execute");
            assertFalse(hasVmAnnotation(method), name + " annotation must be removed after virtualization");
        }
        MethodNode instance = method(node, "instance");
        assertNotNull(instance);
        assertFalse(hasExecuteCall(instance), "instance must keep its Java bytecode");
        assertTrue(hasVmAnnotation(instance), "instance must keep its @ChimeraVM annotation");
        MethodNode plain = method(node, "plain");
        assertNotNull(plain);
        assertFalse(hasExecuteCall(plain));

        String previous = System.getProperty(KEY_PROPERTY);
        System.setProperty(KEY_PROPERTY, Crypto.hex(key()));
        try (URLClassLoader cl = new URLClassLoader(new URL[]{out.toUri().toURL()},
                ClassLoader.getPlatformClassLoader())) {
            Class<?> vm = load(cl, "fixtures.VmMath");
            assertEquals("vm", vm.getMethod("text").invoke(null));
            assertEquals(3, vm.getMethod("plain", int.class).invoke(null, 3));
        } finally {
            restore(previous);
        }
    }

    @Test
    public void vmStatsCountOnlyVirtualizedMethods() throws Exception {
        Path work = Files.createTempDirectory("chimera-vm-stats");
        Path in = buildFixtureJar(work.resolve("vm-fixtures.jar"));
        Path out = work.resolve("vm-fixtures-obf.jar");
        var stats = new ChimeraEngine(config(in, out)).run();
        assertEquals(VIRTUALIZED_METHODS, stats.vmMethods,
                "expected every supported control-flow method to be virtualized, got " + stats.vmMethods);
    }

    @Test
    public void strictProbePoisonsOnSuspiciousCpuTime() throws Exception {
        Path work = Files.createTempDirectory("chimera-vm-probe-strict");
        Path out = obfuscate(work);
        String previous = System.getProperty(KEY_PROPERTY);
        System.setProperty(KEY_PROPERTY, Crypto.hex(key()));
        System.setProperty("chimera.vm.probe.mode", "strict");
        System.setProperty("chimera.vm.probeInterval", "1");
        System.setProperty("chimera.vm.probeBudgetNanos", "1");
        System.setProperty("chimera.vm.probeRequiredSuspicions", "1");
        try (URLClassLoader cl = new URLClassLoader(new URL[]{out.toUri().toURL()},
                ClassLoader.getPlatformClassLoader())) {
            installFastTestClock(cl);
            Class<?> vm = load(cl, "fixtures.VmMath");
            Object probeResult = vm.getMethod("addMul", int.class, int.class).invoke(null, 2, 3);
            assertPoisoned(cl);
            assertNotEquals(Integer.valueOf(15), probeResult,
                    "strict CPU-time probe must not return the healthy result");
            assertEquals(Boolean.TRUE, cl.loadClass("dev.chimera.runtime.ChimeraVmRuntime")
                    .getMethod("isPoisoned").invoke(null));
        } finally {
            clearProbeProperties();
            restore(previous);
        }
    }

    @Test
    public void telemetryProbeNeverPoisonsWithoutAgent() throws Exception {
        Path work = Files.createTempDirectory("chimera-vm-probe-telemetry");
        Path out = obfuscate(work);
        String previous = System.getProperty(KEY_PROPERTY);
        System.setProperty(KEY_PROPERTY, Crypto.hex(key()));
        System.setProperty("chimera.vm.probe.mode", "telemetry");
        System.setProperty("chimera.vm.probeInterval", "1");
        System.setProperty("chimera.vm.probeBudgetNanos", "1");
        try (URLClassLoader cl = new URLClassLoader(new URL[]{out.toUri().toURL()},
                ClassLoader.getPlatformClassLoader())) {
            installFastTestClock(cl);
            Class.forName("dev.chimera.runtime.ChimeraVmProbe", true, cl)
                    .getMethod("setAgentDetectedForTests", boolean.class).invoke(null, false);
            Class<?> vm = load(cl, "fixtures.VmMath");
            assertEquals(15, vm.getMethod("addMul", int.class, int.class).invoke(null, 2, 3),
                    "telemetry mode must keep the correct result");
            Class<?> probe = cl.loadClass("dev.chimera.runtime.ChimeraVmProbe");
            int suspicions = ((Integer) probe.getMethod("suspicionCount").invoke(null)).intValue();
            assertTrue(suspicions > 0, "anomalies must still be counted for telemetry");
            assertEquals(Boolean.FALSE, cl.loadClass("dev.chimera.runtime.ChimeraVmRuntime")
                    .getMethod("isPoisoned").invoke(null), "telemetry must not poison a player");
        } finally {
            clearProbeProperties();
            restore(previous);
        }
    }

    private static void installFastTestClock(URLClassLoader loader) throws Exception {
        Class<?> probe = Class.forName("dev.chimera.runtime.ChimeraVmProbe", true, loader);
        probe.getMethod("setTestClock", long.class, long.class).invoke(null, 0L, 1_000_000L);
    }

    private static void assertPoisoned(URLClassLoader loader) throws Exception {
        assertEquals(Boolean.TRUE, loader.loadClass("dev.chimera.runtime.ChimeraVmRuntime")
                .getMethod("isPoisoned").invoke(null));
    }

    private static void clearProbeProperties() {
        System.clearProperty("chimera.vm.probe.mode");
        System.clearProperty("chimera.vm.probeInterval");
        System.clearProperty("chimera.vm.probeBudgetNanos");
        System.clearProperty("chimera.vm.probeRequiredSuspicions");
    }

    @Test
    public void chainedDecryptionRequiresExactPreviousPc() throws Exception {
        Path work = Files.createTempDirectory("chimera-vm-chain");
        Path out = obfuscate(work);
        String previous = System.getProperty(KEY_PROPERTY);
        System.setProperty(KEY_PROPERTY, Crypto.hex(key()));
        try (URLClassLoader cl = new URLClassLoader(new URL[]{out.toUri().toURL()},
                ClassLoader.getPlatformClassLoader())) {
            Class<?> runtime = Class.forName("dev.chimera.runtime.ChimeraVmRuntime", true, cl);
            var load = runtime.getDeclaredMethod("load", int.class);
            load.setAccessible(true);
            Object program = load.invoke(null, 0);
            Object[] array = (Object[]) program;
            byte[] records = (byte[]) array[18]; // P_RECORDS
            // First record entry layout: predCount(u2), prevPc(i32), len(u1), cipher...
            // Deliberately claim a bogus predecessor; the edge-chained copy no longer exists.
            records[2] = 0x7f;
            records[3] = 0x7f;
            records[4] = 0x7f;
            records[5] = 0x7f;
            var run = runtime.getDeclaredMethod("run", Object[].class, Object[].class);
            run.setAccessible(true);
            try {
                run.invoke(null, program, new Object[]{Integer.valueOf(2), Integer.valueOf(3)});
                fail("missing edge chain state must abort execution");
            } catch (java.lang.reflect.InvocationTargetException e) {
                assertTrue(e.getCause() instanceof IllegalStateException, String.valueOf(e.getCause()));
                assertTrue(e.getCause().getMessage().contains("edge chain"),
                        e.getCause().getMessage());
            }
        } finally {
            restore(previous);
        }
    }

    // ------------------------------------------------------------------ helpers

    private static void restore(String previous) {
        if (previous == null) {
            System.clearProperty(KEY_PROPERTY);
        } else {
            System.setProperty(KEY_PROPERTY, previous);
        }
    }

    private static int countResources(Path jar, String prefix) throws Exception {
        int count = 0;
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            var entries = zip.entries();
            while (entries.hasMoreElements()) {
                if (entries.nextElement().getName().startsWith(prefix)) {
                    count++;
                }
            }
        }
        return count;
    }

    private static byte[] readEntry(Path jar, String name) throws Exception {
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            ZipEntry entry = zip.getEntry(name);
            assertNotNull(entry, "missing entry " + name);
            try (InputStream in = zip.getInputStream(entry)) {
                return in.readAllBytes();
            }
        }
    }

    private static int readInt(byte[] data, int offset) {
        return ((data[offset] & 0xff) << 24)
                | ((data[offset + 1] & 0xff) << 16)
                | ((data[offset + 2] & 0xff) << 8)
                | (data[offset + 3] & 0xff);
    }

    private static boolean contains(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    private static boolean allZero(byte[] data, int offset) {
        for (int i = offset; i < data.length; i++) {
            if (data[i] != 0) {
                return false;
            }
        }
        return true;
    }

    private static MethodNode method(ClassNode node, String name) {
        List<MethodNode> methods = node.methods;
        if (methods == null) {
            return null;
        }
        for (MethodNode method : methods) {
            if (name.equals(method.name)) {
                return method;
            }
        }
        return null;
    }

    private static boolean hasExecuteCall(MethodNode method) {
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof MethodInsnNode call
                    && "dev/chimera/runtime/ChimeraVmRuntime".equals(call.owner)
                    && "execute".equals(call.name)) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasVmAnnotation(MethodNode method) {
        return containsVm(method.invisibleAnnotations) || containsVm(method.visibleAnnotations);
    }

    private static boolean containsVm(List<AnnotationNode> annotations) {
        if (annotations == null) {
            return false;
        }
        for (AnnotationNode annotation : annotations) {
            if ("Ldev/chimera/annotations/ChimeraVM;".equals(annotation.desc)) {
                return true;
            }
        }
        return false;
    }
}
