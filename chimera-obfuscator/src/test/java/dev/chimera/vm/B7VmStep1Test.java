package dev.chimera.vm;

import dev.chimera.core.ChimeraConfig;
import dev.chimera.core.ChimeraEngine;
import dev.chimera.core.ClassPool;
import dev.chimera.core.Stats;
import dev.chimera.core.TransformContext;
import dev.chimera.crypto.Crypto;
import dev.chimera.transform.VMTransformer;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * B7 step 1 tests: VM ISA extension (CALL_NATIVE / unsigned 256-bit compare / stack byte arrays /
 * VERIFY_DECISION).
 *
 * <p>Each case builds a real obfuscated jar with {@link ChimeraEngine} (which produces env.dat and
 * the injected runtime classes), replaces {@code /chimera/vm/vm_0.bin} with a hand-built program
 * encoded by the production {@link VMTransformer} encoder, then loads the jar in an isolated
 * class loader and calls {@code ChimeraVmRuntime.execute(0, args)}. No encryption/format logic is
 * reimplemented here, and the production random raw-&gt;canonical opcode table is exercised.</p>
 */
public class B7VmStep1Test {

    private static final String KEY_PROPERTY = "chimera.contentKey";
    private static final String CONTENT_KEY = "b7-step1-content-key";
    private static final int U256_BYTES = 32;
    private static final AtomicInteger JAR_SEQ = new AtomicInteger();

    // ------------------------------------------------------------------ program builder

    /** Builds the canonical instruction stream of a hand-written VM program. */
    private static final class ProgramBuilder {
        private final ByteArrayOutputStream code = new ByteArrayOutputStream();
        private final List<Integer> offsets = new ArrayList<>();

        void raw(int... bytes) {
            offsets.add(Integer.valueOf(code.size()));
            for (int b : bytes) {
                code.write(b & 0xff);
            }
        }

        void pushInt(int value) {
            raw(VmOpcode.PUSH_I,
                    value >>> 24, value >>> 16, value >>> 8, value);
        }

        void push256(byte[] value) {
            assertEquals(U256_BYTES, value.length);
            int[] instruction = new int[1 + U256_BYTES];
            instruction[0] = VmOpcode.PUSH_B256;
            for (int i = 0; i < U256_BYTES; i++) {
                instruction[i + 1] = value[i] & 0xff;
            }
            raw(instruction);
        }

        void pop256() {
            raw(VmOpcode.POP_B256);
        }

        void loadByte(int index) {
            raw(VmOpcode.LOAD_BYTE, index);
        }

        void cmpU256() {
            raw(VmOpcode.CMP_U256);
        }

        void callNative(int nativeIndex, int argumentCount, int returnKind) {
            raw(VmOpcode.CALL_NATIVE,
                    nativeIndex >>> 8, nativeIndex,
                    argumentCount, returnKind);
        }

        void verifyDecision() {
            raw(VmOpcode.VERIFY_DECISION);
        }

        void retInt() {
            raw(VmOpcode.RET, VmOpcode.TYPE_I);
        }

        VmCompiler.Compiled build(int maxStack, int maxLocals) {
            offsets.add(Integer.valueOf(code.size()));
            int[] array = new int[offsets.size()];
            for (int i = 0; i < offsets.size(); i++) {
                array[i] = offsets.get(i).intValue();
            }
            return new VmCompiler.Compiled("()I", code.toByteArray(), array,
                    maxStack, maxLocals, List.of());
        }
    }

    // ------------------------------------------------------------------ 256-bit compare

    @Test
    public void unsignedU256CompareProducesThreeResults() throws Exception {
        byte[] one = u256(1L);
        byte[] two = u256(2L);
        byte[] huge = u256HighBit();

        assertEquals(-1, runInt(programCompare(one, two)), "1 < 2");
        assertEquals(0, runInt(programCompare(one, one)), "1 == 1");
        assertEquals(1, runInt(programCompare(two, one)), "2 > 1");
        assertEquals(1, runInt(programCompare(huge, one)), "high-bit value > 1 (unsigned)");
        assertEquals(-1, runInt(programCompare(one, huge)), "1 < high-bit value (unsigned)");
    }

    private static VmCompiler.Compiled programCompare(byte[] a, byte[] b) {
        ProgramBuilder program = new ProgramBuilder();
        program.push256(a);
        program.push256(b);
        program.cmpU256();
        program.retInt();
        return program.build(4, 0);
    }

    // ------------------------------------------------------------------ byte arrays on stack

    @Test
    public void stackByteArrayOpsLoadAndPop() throws Exception {
        byte[] value = u256(0L);
        value[0] = (byte) 0x80;
        value[31] = (byte) 0xAB;

        ProgramBuilder load = new ProgramBuilder();
        load.push256(value);
        load.loadByte(31);
        load.retInt();
        assertEquals(0xAB, runInt(load.build(4, 0)), "LOAD_BYTE reads the unsigned last byte");

        ProgramBuilder high = new ProgramBuilder();
        high.push256(value);
        high.loadByte(0);
        high.retInt();
        assertEquals(0x80, runInt(high.build(4, 0)), "LOAD_BYTE returns an unsigned value");

        ProgramBuilder pop = new ProgramBuilder();
        pop.push256(value);
        pop.pop256();
        pop.pushInt(9);
        pop.retInt();
        assertEquals(9, runInt(pop.build(4, 0)), "POP_B256 leaves the stack clean");
    }

    @Test
    public void byteArrayOpsFailClosedOnIllegalBytecode() throws Exception {
        ProgramBuilder outOfBounds = new ProgramBuilder();
        outOfBounds.push256(u256(1L));
        outOfBounds.loadByte(32); // valid indexes are 0..31
        outOfBounds.retInt();
        assertPoisoned(outOfBounds.build(4, 0), null);

        ProgramBuilder wrongType = new ProgramBuilder();
        wrongType.pushInt(1);
        wrongType.cmpU256(); // int, not byte[32]
        wrongType.retInt();
        assertPoisoned(wrongType.build(4, 0), null);

        ProgramBuilder popWrongType = new ProgramBuilder();
        popWrongType.pushInt(1);
        popWrongType.pop256();
        popWrongType.retInt();
        assertPoisoned(popWrongType.build(4, 0), null);
    }

    // ------------------------------------------------------------------ CALL_NATIVE

    @Test
    public void callNativeDispatchesRegisteredHandlerByIndex() throws Exception {
        ProgramBuilder program = new ProgramBuilder();
        program.pushInt(5);
        program.pushInt(7);
        program.callNative(7, 2, VmOpcode.TYPE_I);
        program.retInt();

        Object[] status = runProgram(program.build(4, 0), runtime ->
                runtime.getMethod("registerNativeHandler", int.class, Function.class)
                        .invoke(null, 7, (Function<Object[], Object>) arguments ->
                                Integer.valueOf(((Integer) arguments[0]) + ((Integer) arguments[1]))));
        assertEquals(12, ((Number) status[0]).intValue(), "handler receives stack args and returns int");
        assertEquals(Boolean.FALSE, status[1]);
    }

    @Test
    public void callNativeWithoutHandlerFailsClosed() throws Exception {
        ProgramBuilder program = new ProgramBuilder();
        program.pushInt(1);
        program.callNative(4242, 0, VmOpcode.TYPE_I);
        program.retInt();
        assertPoisoned(program.build(4, 0), null);
    }

    @Test
    public void callNativeHandlerFaultsAndBadTypesFailClosed() throws Exception {
        ProgramBuilder throwing = new ProgramBuilder();
        throwing.callNative(11, 0, VmOpcode.TYPE_I);
        throwing.retInt();
        assertPoisoned(throwing.build(4, 0), runtime ->
                runtime.getMethod("registerNativeHandler", int.class, Function.class)
                        .invoke(null, 11, (Function<Object[], Object>) arguments -> {
                            throw new IllegalStateException("host failure");
                        }));

        ProgramBuilder wrongResultKind = new ProgramBuilder();
        wrongResultKind.callNative(12, 0, VmOpcode.TYPE_I);
        wrongResultKind.retInt();
        assertPoisoned(wrongResultKind.build(4, 0), runtime ->
                runtime.getMethod("registerNativeHandler", int.class, Function.class)
                        .invoke(null, 12, (Function<Object[], Object>) arguments -> "not an int"));

        ProgramBuilder tooManyArguments = new ProgramBuilder();
        tooManyArguments.pushInt(1);
        tooManyArguments.callNative(13, 3, VmOpcode.TYPE_I);
        tooManyArguments.retInt();
        assertPoisoned(tooManyArguments.build(4, 0), null);
    }

    // ------------------------------------------------------------------ VERIFY_DECISION

    @Test
    public void verifyDecisionWritesStateWithoutReturnValue() throws Exception {
        ProgramBuilder program = new ProgramBuilder();
        program.push256(u256(0x1234L));
        program.verifyDecision();
        program.pushInt(42);
        program.retInt();

        Object[] first = runProgram(program.build(4, 0), null);
        assertEquals(42, ((Number) first[0]).intValue(), "VERIFY_DECISION must not disturb the result");
        int stateOne = ((Number) first[2]).intValue();
        assertNotEquals(0, stateOne, "placeholder decision state must be written");

        byte[] otherTag = u256(0x9999L);
        ProgramBuilder other = new ProgramBuilder();
        other.push256(otherTag);
        other.verifyDecision();
        other.pushInt(42);
        other.retInt();
        Object[] second = runProgram(other.build(4, 0), null);
        assertEquals(42, ((Number) second[0]).intValue(), "different tag, same return value (no return path)");
        int stateTwo = ((Number) second[2]).intValue();
        assertNotEquals(stateOne, stateTwo, "tag must influence only the semantic state");
    }

    @Test
    public void verifyDecisionFailsClosedWithoutU256Tag() throws Exception {
        ProgramBuilder emptyStack = new ProgramBuilder();
        emptyStack.verifyDecision();
        emptyStack.pushInt(1);
        emptyStack.retInt();
        assertPoisoned(emptyStack.build(4, 0), null);

        ProgramBuilder wrongType = new ProgramBuilder();
        wrongType.pushInt(7);
        wrongType.verifyDecision();
        wrongType.pushInt(1);
        wrongType.retInt();
        assertPoisoned(wrongType.build(4, 0), null);
    }

    // ------------------------------------------------------------------ illegal bytes / MAC

    @Test
    public void truncatedAndUnknownInstructionsFailClosed() throws Exception {
        // PUSH_B256 with a truncated immediate (only 3 of 32 bytes).
        ProgramBuilder truncated = new ProgramBuilder();
        truncated.raw(VmOpcode.PUSH_B256, 1, 2, 3);
        truncated.pushInt(1);
        truncated.retInt();
        assertPoisoned(truncated.build(4, 0), null);

        // Unknown canonical opcode (not in the opcode table's known set for operand sizing).
        ProgramBuilder unknown = new ProgramBuilder();
        unknown.raw(250);
        unknown.retInt();
        assertPoisoned(unknown.build(4, 0), null);
    }

    @Test
    public void tamperedCiphertextFailsClosed() throws Exception {
        ProgramBuilder program = new ProgramBuilder();
        program.pushInt(1);
        program.retInt();
        Path work = Files.createTempDirectory("chimera-b7-tamper");

        byte[] keyMaterial = keyMaterial();
        Path baseJar = buildBaseJar(work, keyMaterial);
        Map<String, byte[]> entries = readJar(baseJar);
        TransformContext ctx = context(keyMaterial, envSalt(entries.get("chimera/env.dat")));
        byte[] blob = VMTransformer.encodeProgramForTest(ctx, 0, program.build(4, 0));
        blob[blob.length - 40] ^= 0x5A; // ciphertext / MAC region tamper
        entries.put("chimera/vm/vm_0.bin", blob);
        Path jar = writeJar(work, entries);

        Object[] status = withRuntime(jar, keyMaterial, runtime -> executeStatus(runtime));
        assertEquals(-1, ((Number) status[0]).intValue(), "tampered blob must fail closed");
        assertEquals(Boolean.TRUE, status[1], "runtime must be poisoned");
    }

    @Test
    public void randomizedOpcodeTableStillRunsTheSameProgram() throws Exception {
        byte[] keyMaterial = keyMaterial();
        Path work = Files.createTempDirectory("chimera-b7-random");
        Path baseJar = buildBaseJar(work, keyMaterial);
        Map<String, byte[]> entries = readJar(baseJar);
        TransformContext ctx = context(keyMaterial, envSalt(entries.get("chimera/env.dat")));

        ProgramBuilder program = new ProgramBuilder();
        program.push256(u256(7L));
        program.push256(u256(7L));
        program.cmpU256();
        program.retInt();
        VmCompiler.Compiled compiled = program.build(4, 0);

        byte[] first = VMTransformer.encodeProgramForTest(ctx, 0, compiled);
        byte[] second = VMTransformer.encodeProgramForTest(ctx, 0, compiled);
        assertFalse(java.util.Arrays.equals(first, second),
                "each encoding must use a fresh random opcode table/nonce");
        assertEquals(0, runBlob(work, entries, keyMaterial, first));
        assertEquals(0, runBlob(work, entries, keyMaterial, second));
    }

    // ------------------------------------------------------------------ harness

    private static int runInt(VmCompiler.Compiled program) throws Exception {
        Object[] status = runProgram(program, null);
        assertEquals(Boolean.FALSE, status[1], "program must not poison");
        return ((Number) status[0]).intValue();
    }

    private static void assertPoisoned(VmCompiler.Compiled program, RuntimeSetup setup) throws Exception {
        Object[] status = runProgram(program, setup);
        assertEquals(-1, ((Number) status[0]).intValue(),
                "illegal bytecode must return the type-neutral poison value");
        assertEquals(Boolean.TRUE, status[1], "runtime must be poisoned");
    }

    @FunctionalInterface
    private interface RuntimeSetup {
        void setup(Class<?> runtime) throws Exception;
    }

    @FunctionalInterface
    private interface RuntimeProbe {
        Object run(Class<?> runtime) throws Exception;
    }

    /** Runs a program encoded through the production encoder with a fresh jar/loader. */
    private static Object[] runProgram(VmCompiler.Compiled program, RuntimeSetup setup) throws Exception {
        byte[] keyMaterial = keyMaterial();
        Path work = Files.createTempDirectory("chimera-b7-run");
        Path baseJar = buildBaseJar(work, keyMaterial);
        Map<String, byte[]> entries = readJar(baseJar);
        TransformContext ctx = context(keyMaterial, envSalt(entries.get("chimera/env.dat")));
        byte[] blob = VMTransformer.encodeProgramForTest(ctx, 0, program);
        return runBlob(work, entries, keyMaterial, blob, setup);
    }

    private static int runBlob(Path work, Map<String, byte[]> base, byte[] keyMaterial, byte[] blob)
            throws Exception {
        Object[] status = runBlob(work, base, keyMaterial, blob, null);
        assertEquals(Boolean.FALSE, status[1]);
        return ((Number) status[0]).intValue();
    }

    private static Object[] runBlob(Path work, Map<String, byte[]> base, byte[] keyMaterial,
                                    byte[] blob, RuntimeSetup setup) throws Exception {
        Map<String, byte[]> entries = new LinkedHashMap<>(base);
        entries.put("chimera/vm/vm_0.bin", blob);
        Path jar = writeJar(work, entries);
        return withRuntime(jar, keyMaterial, runtime -> {
            if (setup != null) {
                setup.setup(runtime);
            }
            return executeStatus(runtime);
        });
    }

    private static Object[] executeStatus(Class<?> runtime) throws Exception {
        Object result = runtime.getMethod("execute", int.class, Object[].class)
                .invoke(null, 0, new Object[0]);
        Object poisoned = runtime.getMethod("isPoisoned").invoke(null);
        Object decisionState = runtime.getMethod("verifyDecisionStateForTest").invoke(null);
        return new Object[]{result, poisoned, decisionState};
    }

    private static Object[] withRuntime(Path jar, byte[] keyMaterial, RuntimeProbe probe) throws Exception {
        String previous = System.getProperty(KEY_PROPERTY);
        System.setProperty(KEY_PROPERTY, Crypto.hex(keyMaterial));
        try (URLClassLoader loader = new URLClassLoader(new URL[]{jar.toUri().toURL()},
                ClassLoader.getPlatformClassLoader())) {
            Class<?> runtime = Class.forName("dev.chimera.runtime.ChimeraVmRuntime", true, loader);
            Object result = probe.run(runtime);
            return (Object[]) result;
        } finally {
            if (previous == null) {
                System.clearProperty(KEY_PROPERTY);
            } else {
                System.setProperty(KEY_PROPERTY, previous);
            }
        }
    }

    // ------------------------------------------------------------------ fixtures / encoding

    private static byte[] keyMaterial() {
        return Crypto.sha256(CONTENT_KEY.getBytes(StandardCharsets.UTF_8));
    }

    private static TransformContext context(byte[] keyMaterial, byte[] envSalt) throws Exception {
        ChimeraConfig cfg = new ChimeraConfig();
        cfg.keyMaterial = keyMaterial;
        byte[] kek = Crypto.hkdf(keyMaterial,
                "chimera-kek-v1".getBytes(StandardCharsets.UTF_8),
                "kek".getBytes(StandardCharsets.UTF_8), 32);
        return new TransformContext(cfg, envSalt, kek, new ClassPool(Map.of()),
                (name, data) -> {
                }, new Stats(), "b7-step1-test");
    }

    private static byte[] envSalt(byte[] envDat) throws Exception {
        assertNotNull(envDat, "engine must write chimera/env.dat");
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(envDat));
        assertEquals(0x43485631, in.readInt(), "CHV1");
        // Phase 0: environment record v2 carries the build-kind flags before the salt block.
        assertEquals(2, in.readInt());
        in.readInt(); // flags: dev/release
        int length = in.readInt();
        assertTrue(length > 0 && length <= 64);
        byte[] salt = new byte[length];
        in.readFully(salt);
        return salt;
    }

    private static Path buildBaseJar(Path work, byte[] keyMaterial) throws Exception {
        Files.createDirectories(work);
        Path input = work.resolve("fixtures.jar");
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(input))) {
            zos.putNextEntry(new ZipEntry("fixtures/VmMath.class"));
            zos.write(fixtureClass("fixtures/VmMath.class"));
            zos.closeEntry();
        }
        Path output = work.resolve("obfuscated.jar");
        ChimeraConfig cfg = new ChimeraConfig();
        cfg.inputJar = input;
        cfg.outputJar = output;
        cfg.keyMaterial = keyMaterial;
        cfg.nativeOutDir = work.resolve("native");
        cfg.integrityManifest = true;
        new ChimeraEngine(cfg).run();
        return output;
    }

    private static byte[] fixtureClass(String name) throws Exception {
        try (InputStream in = B7VmStep1Test.class.getClassLoader().getResourceAsStream(name)) {
            assertNotNull(in, "missing fixture " + name);
            return in.readAllBytes();
        }
    }

    private static Map<String, byte[]> readJar(Path jar) throws Exception {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            var enumeration = zip.entries();
            while (enumeration.hasMoreElements()) {
                ZipEntry entry = enumeration.nextElement();
                if (entry.isDirectory()) {
                    continue;
                }
                try (InputStream in = zip.getInputStream(entry)) {
                    entries.put(entry.getName(), in.readAllBytes());
                }
            }
        }
        return entries;
    }

    private static Path writeJar(Path work, Map<String, byte[]> entries) throws Exception {
        Path jar = work.resolve("case-" + JAR_SEQ.incrementAndGet() + ".jar");
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(jar))) {
            for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                zos.putNextEntry(new ZipEntry(entry.getKey()));
                zos.write(entry.getValue());
                zos.closeEntry();
            }
        }
        return jar;
    }

    private static byte[] u256(long value) {
        byte[] bytes = new byte[U256_BYTES];
        for (int i = 0; i < 8; i++) {
            bytes[U256_BYTES - 1 - i] = (byte) (value >>> (8 * i));
        }
        return bytes;
    }

    private static byte[] u256HighBit() {
        byte[] bytes = new byte[U256_BYTES];
        bytes[0] = (byte) 0x80;
        return bytes;
    }
}
