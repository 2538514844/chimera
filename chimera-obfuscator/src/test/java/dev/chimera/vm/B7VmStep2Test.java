package dev.chimera.vm;

import dev.chimera.auth.MockLicenseServer;
import dev.chimera.auth.NativeAuthLibrary;
import dev.chimera.core.ChimeraConfig;
import dev.chimera.core.ChimeraEngine;
import dev.chimera.core.ClassPool;
import dev.chimera.core.Stats;
import dev.chimera.core.TransformContext;
import dev.chimera.crypto.Crypto;
import dev.chimera.transform.VMTransformer;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URI;
import java.net.URL;
import java.net.URLClassLoader;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * B7 step 2 VM-side tests (task-29).
 *
 * <p>Differential acceptance: 100,000 random inputs are computed twice - once through the native
 * AOT reference (nativeCompute op8) and once through the VM dispatcher (CALL_NATIVE op6 ->
 * native function table) - and the 32-byte results must be bit-identical. The VM program is
 * hand-built with {@link VmCompiler.Compiled} and encoded with the production encoder.</p>
 *
 * <p>The native side (op6/op8, function indexes 0..5) is owned by native-pipeline. When it is not
 * available yet this test is skipped with an explicit message (never faked); the VM-side code is
 * still exercised by {@link B7VmStep1Test} for the Java fallback path.</p>
 */
public class B7VmStep2Test {

    private static final String KEY_PROPERTY = "chimera.contentKey";
    private static final int TYPE_O = 3;
    private static final int OP_CALL_NATIVE = 204;
    private static final int OP_RET = 50;
    private static final int OP_PUSH_I = 1;
    private static final int OP_LOAD = 4;

    /** nativeCompute op bytes (must match ChimeraVmRuntime). */
    private static final int NATIVE_OP_VM_CALL = 6;
    private static final int NATIVE_OP_AOT_VERIFY_TAG_REF = 8;

    /** Opaque native function-table indexes from chimera_auth.cpp (step 2 contract). */
    private static final int FN_SESSION_NONCE = 0x39C5;
    private static final int FN_VERIFY_RESULT_TAG = 0xC40E;

    @Test
    void aotVsVmCallNative100kBitIdentical() throws Exception {
        NativeAuthLibrary.prepareIsolatedCopy();
        String previousAuto = System.getProperty("chimera.auth.autoHeartbeat");
        String previousServer = System.getProperty("chimera.auth.server");
        String previousPubkey = System.getProperty("chimera.auth.pubkey");
        String previousKey = System.getProperty("chimera.contentKey");
        System.setProperty("chimera.auth.autoHeartbeat", "false");
        System.clearProperty("chimera.auth.server");
        System.clearProperty("chimera.auth.pubkey");
        System.clearProperty(KEY_PROPERTY);
        try (MockLicenseServer server = new MockLicenseServer()) {
            Path work = Files.createTempDirectory("chimera-b7-step2");
            Path baseJar = buildAuthJar(work, server);
            Map<String, byte[]> entries = readJar(baseJar);
            byte[] envSalt = envSalt(entries.get("chimera/env.dat"));
            TransformContext ctx = context(server.resourceKey(), envSalt);

            // vm_0: (I)Ljava/lang/Object; -> CALL_NATIVE(5) nonce, CALL_NATIVE(1, result, nonce)
            entries.put("chimera/vm/vm_0.bin",
                    VMTransformer.encodeProgramForTest(ctx, 0, tagProgram()));
            // vm_1: ()Ljava/lang/Object; -> CALL_NATIVE(5) session nonce only
            entries.put("chimera/vm/vm_1.bin",
                    VMTransformer.encodeProgramForTest(ctx, 1, nonceProgram()));
            Path jar = writeJar(work, entries);

            try (URLClassLoader loader = new URLClassLoader(new URL[]{jar.toUri().toURL()},
                    ClassLoader.getPlatformClassLoader())) {
                Class<?> chimeraRuntime = Class.forName("dev.chimera.runtime.ChimeraRuntime", true, loader);
                Object available = chimeraRuntime.getMethod("nativeAuthAvailable").invoke(null);
                System.out.println("[b7-step2] nativeAuthAvailable=" + available);
                Assumptions.assumeTrue(Boolean.TRUE.equals(available),
                        "native auth DLL unavailable in the isolated loader; B7 step2 NOT executed");
                long handle = installNativeHandle(chimeraRuntime, server);
                Class<?> vmRuntime = Class.forName("dev.chimera.runtime.ChimeraVmRuntime", true, loader);
                Method execute = vmRuntime.getMethod("execute", int.class, Object[].class);
                Method nativeCompute = chimeraRuntime.getMethod("nativeCompute", long.class, byte[].class);

                byte[] aotNonce = (byte[]) nativeCompute.invoke(null, handle,
                        op6Params(FN_SESSION_NONCE, 0, TYPE_O));
                boolean nativeVmCallReady = aotNonce != null && aotNonce.length == 32;
                System.out.println("[b7-step2] op6(sessionNonce) length="
                        + (aotNonce == null ? "null" : String.valueOf(aotNonce.length))
                        + " handle=" + handle);
                Assumptions.assumeTrue(nativeVmCallReady,
                        "native B7 op6/function index 5 not implemented yet (native-pipeline pending); "
                                + "VM-side differential NOT executed");

                byte[] vmNonce = (byte[]) execute.invoke(null, 1, new Object[0]);
                assertArrayEquals(aotNonce, vmNonce,
                        "VM CALL_NATIVE(5) session nonce must be bit-identical to the AOT probe");

                byte[] probeRef = (byte[]) nativeCompute.invoke(null, handle,
                        op8Params(aotNonce, 0));
                System.out.println("[b7-step2] op8 length="
                        + (probeRef == null ? "null" : String.valueOf(probeRef.length)));
                Assumptions.assumeTrue(probeRef != null && probeRef.length == 32,
                        "native B7 op8 AOT_VERIFY_TAG_REF not implemented yet; differential NOT executed");

                int iterations = 100_000;
                Random random = new Random(0x42375F32L);
                int mismatches = 0;
                byte[] firstAot = null;
                byte[] firstVm = null;
                int firstMismatchIndex = -1;
                for (int i = 0; i < iterations; i++) {
                    int result = random.nextInt();
                    byte[] aot = (byte[]) nativeCompute.invoke(null, handle, op8Params(aotNonce, result));
                    byte[] vm = (byte[]) execute.invoke(null, 0, new Object[]{Integer.valueOf(result)});
                    if (!Arrays.equals(aot, vm)) {
                        mismatches++;
                        if (firstAot == null) {
                            firstAot = aot;
                            firstVm = vm;
                            firstMismatchIndex = i;
                        }
                    }
                }
                assertEquals(0, mismatches, "AOT vs VM mismatch(es): " + mismatches
                        + " first at iteration " + firstMismatchIndex
                        + " aot=" + toHex(firstAot) + " vm=" + toHex(firstVm)
                        + " iterations=" + iterations);
            }
        } finally {
            restore("chimera.auth.autoHeartbeat", previousAuto);
            restore("chimera.auth.server", previousServer);
            restore("chimera.auth.pubkey", previousPubkey);
            restore(KEY_PROPERTY, previousKey);
        }
    }

    // ------------------------------------------------------------------ VM programs

    /** (I)Ljava/lang/Object; : load result, CALL_NATIVE(5) nonce, CALL_NATIVE(1) tag. */
    private static VmCompiler.Compiled tagProgram() {
        ByteArrayOutputStream code = new ByteArrayOutputStream();
        List<Integer> offsets = new ArrayList<>();
        // ILOAD 0 (arg result)
        offsets.add(code.size());
        code.write(OP_LOAD);
        code.write(0);
        code.write(0);
        code.write(0);
        // CALL_NATIVE(SESSION_NONCE, argc=0, retKind=object) -> session nonce
        offsets.add(code.size());
        code.write(OP_CALL_NATIVE);
        code.write(FN_SESSION_NONCE >>> 8);
        code.write(FN_SESSION_NONCE);
        code.write(0);
        code.write(TYPE_O);
        // CALL_NATIVE(VERIFY_RESULT_TAG, argc=2, retKind=object) -> tag(result, nonce)
        offsets.add(code.size());
        code.write(OP_CALL_NATIVE);
        code.write(FN_VERIFY_RESULT_TAG >>> 8);
        code.write(FN_VERIFY_RESULT_TAG);
        code.write(2);
        code.write(TYPE_O);
        // RET object
        offsets.add(code.size());
        code.write(OP_RET);
        code.write(TYPE_O);
        offsets.add(code.size());
        return compiled("(I)Ljava/lang/Object;", code.toByteArray(), offsets, 2, 1);
    }

    /** ()Ljava/lang/Object; : CALL_NATIVE(5) session nonce only. */
    private static VmCompiler.Compiled nonceProgram() {
        ByteArrayOutputStream code = new ByteArrayOutputStream();
        List<Integer> offsets = new ArrayList<>();
        offsets.add(code.size());
        code.write(OP_CALL_NATIVE);
        code.write(FN_SESSION_NONCE >>> 8);
        code.write(FN_SESSION_NONCE);
        code.write(0);
        code.write(TYPE_O);
        offsets.add(code.size());
        code.write(OP_RET);
        code.write(TYPE_O);
        offsets.add(code.size());
        return compiled("()Ljava/lang/Object;", code.toByteArray(), offsets, 1, 0);
    }

    private static VmCompiler.Compiled compiled(String descriptor, byte[] code,
                                                List<Integer> offsets, int maxStack, int maxLocals) {
        int[] array = new int[offsets.size()];
        for (int i = 0; i < offsets.size(); i++) {
            array[i] = offsets.get(i);
        }
        return new VmCompiler.Compiled(descriptor, code, array, maxStack, maxLocals, List.of());
    }

    // ------------------------------------------------------------------ native param encoding (mirrors ChimeraVmRuntime)

    private static byte[] op6Params(int index, int argc, int retKind) {
        return new byte[]{NATIVE_OP_VM_CALL, (byte) (index >>> 8), (byte) index,
                (byte) argc, (byte) retKind};
    }

    private static byte[] op8Params(byte[] nonce32, int result) {
        byte[] params = new byte[1 + 32 + 8];
        params[0] = (byte) NATIVE_OP_AOT_VERIFY_TAG_REF;
        System.arraycopy(nonce32, 0, params, 1, 32);
        long value = result;
        for (int i = 0; i < 8; i++) {
            params[1 + 32 + 7 - i] = (byte) (value >>> (8 * i));
        }
        return params;
    }

    // ------------------------------------------------------------------ auth / jar harness

    private static long installNativeHandle(Class<?> chimeraRuntime, MockLicenseServer server)
            throws Exception {
        Method setContext = chimeraRuntime.getMethod("nativeSetAuthContext", byte[].class, byte[].class);
        Method createClient = chimeraRuntime.getMethod("nativeCreateClientKey");
        Method verifyAuth = chimeraRuntime.getMethod("nativeVerifyAuth", byte[].class, byte[].class);

        byte[] clientPublic = (byte[]) createClient.invoke(null);
        assertNotNull(clientPublic);
        byte[] pubkeyRaw = Base64.getDecoder().decode(server.publicKeyBase64());
        setContext.invoke(null, pubkeyRaw, MockLicenseServer.ACCOUNT.getBytes(StandardCharsets.UTF_8));

        String request = "{\"account\":\"" + MockLicenseServer.ACCOUNT
                + "\",\"password\":\"" + MockLicenseServer.PASSWORD
                + "\",\"hwid\":\"" + MockLicenseServer.HWID
                + "\",\"client_ephemeral_pub\":\""
                + Base64.getEncoder().encodeToString(clientPublic) + "\"}";
        HttpClient http = HttpClient.newHttpClient();
        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(server.baseUrl() + "/api/v1/license/activate"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(request))
                .build();
        HttpResponse<String> response = http.send(httpRequest, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), "mock activation must succeed");

        long handle = ((Number) verifyAuth.invoke(null,
                response.body().getBytes(StandardCharsets.UTF_8),
                MockLicenseServer.HWID.getBytes(StandardCharsets.UTF_8))).longValue();
        assertNotEquals(0L, handle, "nativeVerifyAuth must return a handle");

        // The VM runtime reads the current handle from ChimeraRuntime.nativeSessionHandle. The
        // production install path (authenticate()) will set it once the PENDING(3) integration is
        // done in ChimeraRuntime (owned by another module); tests set it directly.
        Field field = chimeraRuntime.getDeclaredField("nativeSessionHandle");
        field.setAccessible(true);
        field.setLong(null, handle);
        return handle;
    }

    private static Path buildAuthJar(Path work, MockLicenseServer server) throws Exception {
        Path input = work.resolve("fixtures.jar");
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(input))) {
            zos.putNextEntry(new ZipEntry("fixtures/Lic.class"));
            zos.write(fixtureClass("fixtures/Lic.class"));
            zos.closeEntry();
        }
        Path output = work.resolve("obfuscated.jar");
        ChimeraConfig cfg = new ChimeraConfig();
        cfg.inputJar = input;
        cfg.outputJar = output;
        cfg.nativeOutDir = work.resolve("native");
        cfg.resourceKeyMaterial = server.resourceKey();
        cfg.integrityManifest = true;
        cfg.authServer = server.baseUrl();
        cfg.authPubkey = server.publicKeyBase64();
        cfg.authHeartbeatMs = 60_000L;
        new ChimeraEngine(cfg).run();
        return output;
    }

    private static byte[] fixtureClass(String name) throws Exception {
        try (InputStream in = B7VmStep2Test.class.getClassLoader().getResourceAsStream(name)) {
            assertNotNull(in, "missing fixture " + name);
            return in.readAllBytes();
        }
    }

    private static TransformContext context(byte[] keyMaterial, byte[] envSalt) throws Exception {
        ChimeraConfig cfg = new ChimeraConfig();
        cfg.keyMaterial = keyMaterial;
        byte[] kek = Crypto.hkdf(keyMaterial,
                "chimera-kek-v1".getBytes(StandardCharsets.UTF_8),
                "kek".getBytes(StandardCharsets.UTF_8), 32);
        return new TransformContext(cfg, envSalt, kek, new ClassPool(Map.of()),
                (name, data) -> {
                }, new Stats(), "b7-step2-test");
    }

    private static byte[] envSalt(byte[] envDat) throws Exception {
        assertNotNull(envDat, "engine must write chimera/env.dat");
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(envDat));
        assertEquals(0x43485631, in.readInt(), "CHV1");
        // Phase 0: environment record v2 carries the build-kind flags before the salt block.
        assertEquals(2, in.readInt());
        in.readInt(); // flags: dev/release
        int length = in.readInt();
        byte[] salt = new byte[length];
        in.readFully(salt);
        return salt;
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
        Path jar = work.resolve("b7-step2.jar");
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(jar))) {
            for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                zos.putNextEntry(new ZipEntry(entry.getKey()));
                zos.write(entry.getValue());
                zos.closeEntry();
            }
        }
        return jar;
    }

    private static void restore(String name, String value) {
        if (value == null) {
            System.clearProperty(name);
        } else {
            System.setProperty(name, value);
        }
    }

    private static String toHex(byte[] value) {
        if (value == null) {
            return "null";
        }
        StringBuilder builder = new StringBuilder(value.length * 2);
        for (byte b : value) {
            builder.append(Character.forDigit((b >>> 4) & 0x0f, 16));
            builder.append(Character.forDigit(b & 0x0f, 16));
        }
        return builder.toString();
    }
}
