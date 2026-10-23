package dev.chimera.attach;

import java.io.InputStream;
import java.lang.instrument.Instrumentation;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Agent entry point: registers the CHENC1 decrypting transformer and patches Fabric's byte readers.
 *
 * <p>P0-2: neither the class key nor any key material exists in this jar or in the game's Java
 * heap. Each body is decrypted inside the native module with a key derived from the authorized
 * SessionHandle; only plaintext crosses the JNI boundary (see {@link #decryptBody}). Any failure
 * halts the JVM rather than handing ciphertext to the JVM.</p>
 */
public final class AttachAgent {

    private static final String DELEGATE = "net.fabricmc.loader.impl.launch.knot.KnotClassDelegate";
    private static final String KNOT = "net.fabricmc.loader.impl.launch.knot.Knot";
    private static final String RUNTIME = "dev.chimera.runtime.ChimeraRuntime";
    private static final String WATERMARK = "watermarkPayload";

    /** Set at attach time; class bodies are decrypted lazily through the runtime (see #decryptBody). */
    private static volatile Instrumentation ATTACH_INSTRUMENTATION;
    /** True once the runtime has successfully decrypted one body (i.e. the gate installed a handle). */
    private static volatile boolean decryptReady;
    /** Cached {@code ChimeraRuntime.decryptClassBody(byte[], String)}; resolving it is expensive. */
    private static volatile java.lang.reflect.Method decryptMethod;

    /** #19: resolved watermark constant; null until the runtime has a licence context. */
    private static volatile String watermark;

    /** Cached "replace every mod class with an empty stub" decision (native VM check). */
    private static volatile Boolean VM_STUB;

    /** True when the native module reported a virtual machine: the artifact loads but does nothing. */
    static boolean vmStubMode() {
        Boolean cached = VM_STUB;
        if (cached != null) {
            return cached;
        }
        boolean vm = false;
        for (Class<?> runtime : runtimeCandidates(ATTACH_INSTRUMENTATION)) {
            try {
                Object result = runtime.getMethod("isVirtualMachine").invoke(null);
                if (result instanceof Boolean value) {
                    vm = value;
                    break;
                }
            } catch (Throwable ignored) {
                // try the next candidate
            }
        }
        VM_STUB = vm;
        return vm;
    }

    /** Classes this artifact owns: not our runtime, not the JDK, not the loader or Minecraft. */
    static boolean isModClass(String internal) {
        return internal != null
                && !internal.startsWith("dev/chimera/")
                && !internal.startsWith("java/")
                && !internal.startsWith("javax/")
                && !internal.startsWith("jdk/")
                && !internal.startsWith("sun/")
                && !internal.startsWith("net/minecraft")
                && !internal.startsWith("com/mojang")
                && !internal.startsWith("org/spongepowered")
                && !internal.startsWith("net/fabricmc");
    }

    /**
     * Minimal valid class file: {@code public class X extends Object} with only a no-arg
     * constructor. Used in VM mode so the mod stays in Fabric's mod list with its metadata intact
     * but exposes no features - no crash, no panel, nothing to dump.
     */
    static byte[] emptyStub(String internalName) {
        java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream(96);
        java.io.DataOutputStream out = new java.io.DataOutputStream(bytes);
        try {
            out.writeInt(0xCAFEBABE);
            out.writeShort(0);   // minor
            out.writeShort(52);  // major: Java 8
            out.writeShort(10);  // constant pool count (9 entries + 1)
            out.writeByte(1);
            out.writeUTF(internalName);                 // #1
            out.writeByte(7);
            out.writeShort(1);                          // #2 Class(#1)
            out.writeByte(1);
            out.writeUTF("java/lang/Object");           // #3
            out.writeByte(7);
            out.writeShort(3);                          // #4 Class(#3)
            out.writeByte(1);
            out.writeUTF("<init>");                     // #5
            out.writeByte(1);
            out.writeUTF("()V");                        // #6
            out.writeByte(1);
            out.writeUTF("Code");                       // #7
            out.writeByte(12);
            out.writeShort(5);
            out.writeShort(6);                          // #8 NameAndType(#5,#6)
            out.writeByte(10);
            out.writeShort(4);
            out.writeShort(8);                          // #9 Methodref(#4,#8)
            out.writeShort(0x0021);                     // ACC_PUBLIC | ACC_SUPER
            out.writeShort(2);                          // this
            out.writeShort(4);                          // super
            out.writeShort(0);                          // interfaces
            out.writeShort(0);                          // fields
            out.writeShort(1);                          // methods: <init>
            out.writeShort(0x0001);
            out.writeShort(5);
            out.writeShort(6);
            out.writeShort(1);                          // one attribute: Code
            out.writeShort(7);
            out.writeInt(17);                           // Code attribute length
            out.writeShort(1);                          // max_stack
            out.writeShort(1);                          // max_locals
            out.writeInt(5);                            // code length
            out.writeByte(0x2A);                        // aload_0
            out.writeByte(0xB7);
            out.writeShort(9);                          // invokespecial Object.<init>
            out.writeByte(0xB1);                        // return
            out.writeShort(0);                          // exception table
            out.writeShort(0);                          // code attributes
            out.flush();
            return bytes.toByteArray();
        } catch (java.io.IOException impossible) {
            throw new IllegalStateException("stub class generation failed", impossible);
        }
    }

    /**
     * P0-2: decrypts one class body through the runtime, which does it inside the DLL.
     *
     * <p>The 32-byte class key never reaches this process's Java heap any more: it used to be
     * returned by {@code deriveClassKey()} and cached in a static field, which made "reflect once,
     * decrypt 1156 bodies offline" a 60-line script on any licensed machine. Only the plaintext
     * crosses the boundary now.</p>
     *
     * <p>Halts (exit 4) when no reachable runtime can decrypt: a protected class that cannot be
     * decrypted must never be handed to the JVM as ciphertext.</p>
     */
    static byte[] decryptBody(byte[] blob, String internalName) {
        long started = System.nanoTime();
        // Hot path: one call per protected class (1156 on this build). The Method is cached because
        // resolving it re-scans Instrumentation.getAllLoadedClasses(), which measurably tripled
        // startup (62s -> 176s) when it ran per class.
        java.lang.reflect.Method cached = decryptMethod;
        if (cached != null) {
            try {
                Object plain = cached.invoke(null, blob, internalName);
                if (plain instanceof byte[] bytes && bytes.length > 0) {
                    noteDecryptCost(internalName, started);
                    return bytes;
                }
            } catch (Throwable ignored) {
                // fall through to the slow resolve path (handle replaced, class unloaded, ...)
            }
        }
        for (int attempt = 0; attempt < 40; attempt++) {
            for (Class<?> runtime : runtimeCandidates(ATTACH_INSTRUMENTATION)) {
                try {
                    java.lang.reflect.Method method = runtime.getMethod("decryptClassBody",
                            byte[].class, String.class);
                    Object plain = method.invoke(null, blob, internalName);
                    if (plain instanceof byte[] bytes && bytes.length > 0) {
                        decryptMethod = method;
                        if (!decryptReady) {
                            decryptReady = true;
                            diagAlways("class bodies decrypt inside native (no key in Java)");
                        }
                        noteDecryptCost(internalName, started);
                        return bytes;
                    }
                } catch (Throwable failure) {
                    if (attempt == 0) {
                        diagAlways("class body decrypt failed on " + runtime.getClassLoader()
                                + ": " + failure);
                    }
                }
            }
            if (decryptReady) {
                // The runtime works, so a failure here is a bad blob/name - not a race with the gate.
                break;
            }
            try {
                Thread.sleep(250L);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        diagAlways("class body decrypt unavailable: halting (no licence / no native handle)");
        Runtime.getRuntime().halt(4);
        throw new IllegalStateException("chimera: class body decrypt unavailable (fail closed)");
    }

    /**
     * #19: the per-licence watermark constant, or {@code null} when the runtime cannot produce one.
     *
     * <p>Resolved through the same loader-ordered candidate list as the decryption path: the gate
     * owns the session, and the copy of {@code ChimeraRuntime} that has the licence context is the
     * one the gate loaded. Negative results are not cached - the first protected class can be
     * decrypted before the gate has finished, and the watermark must appear once the context
     * exists.</p>
     */
    static String watermarkPayload() {
        String current = watermark;
        if (current != null) {
            return current;
        }
        for (Class<?> runtime : runtimeCandidates(ATTACH_INSTRUMENTATION)) {
            try {
                Object candidate = runtime.getMethod(WATERMARK).invoke(null);
                if (candidate instanceof String text && !text.isEmpty()) {
                    watermark = text;
                    diag("watermark resolved (" + text.length() + " chars)");
                    return text;
                }
            } catch (Throwable ignored) {
                // no context yet (or an older runtime without #19): try the next candidate
            }
        }
        return null;
    }

    /** Diagnostic: surfaces per-class decrypt cost (startup regression hunting). */
    private static void noteDecryptCost(String internalName, long startedNanos) {        if (!DIAG) {
            return;
        }
        long millis = (System.nanoTime() - startedNanos) / 1_000_000L;
        decryptTotalMillis += millis;
        decryptCalls++;
        if (millis >= 50) {
            diag("slow decrypt " + internalName + " " + millis + "ms");
        }
        if (decryptCalls % 200 == 0) {
            diag("decrypt stats: " + decryptCalls + " classes, " + decryptTotalMillis + "ms total");
        }
    }

    private static long decryptTotalMillis;
    private static int decryptCalls;

    /**
     * A2: internal name of the {@code ChimeraRuntime} copy that the gate actually loaded.
     *
     * <p>Runtime classes are renamed by the pipeline ({@code q/xxx}), so the injected
     * {@code invokestatic} has to use the live name, not the source name. Resolved once; a null
     * result disables gating rather than risking a NoClassDefFoundError in a licensed launch.</p>
     */
    static String runtimeInternalName() {
        String cached = runtimeInternal;
        if (cached != null) {
            return cached;
        }
        for (Class<?> type : runtimeCandidates(ATTACH_INSTRUMENTATION)) {
            String name = type.getName().replace('.', '/');
            runtimeInternal = name;
            return name;
        }
        return null;
    }

    private static volatile String runtimeInternal;

    private AttachAgent() {
    }

    public static void agentmain(String args, Instrumentation instrumentation) throws Exception {
        try {
            // LAZY decryption (2026-10-22): attach is triggered from the mixin plugin <clinit>,
            // which Fabric runs BEFORE preLaunch entrypoints. Decryption needs the native handle
            // that the gate installs, so nothing is decrypted here; the first protected class
            // resolves it through the runtime (see decryptBody) and fails closed without a handle.
            ATTACH_INSTRUMENTATION = instrumentation;
            instrumentation.addTransformer(new ClassDecryptTransformer(), true);
            // The Fabric byte-reader hook needs ASM at agentmain time; on a plain classpath
            // (bootstrap mode: no shaded ASM visible to the agent class loader) registering it
            // would fail the whole agent. Only register when ASM is actually resolvable; the
            // hook is pointless without Fabric's Knot classes anyway.
            if (asmAvailable()) {
                instrumentation.addTransformer(new FabricByteHookTransformer(), true);
            } else {
                diag("fabric hook skipped: no ASM on agent classpath");
            }
            AgentState.installed = true;
            diagAlways("attached (class bodies decrypt lazily through native on first class)");
            patchAlreadyLoaded(instrumentation);
        } catch (Throwable failure) {
            diagAlways("agentmain failed: " + failure);
            throw failure;
        }
    }

    private static boolean asmAvailable() {
        try {
            Class.forName("org.objectweb.asm.ClassVisitor", false,
                    AttachAgent.class.getClassLoader());
            return true;
        } catch (Throwable missing) {
            return false;
        }
    }

    private static void patchAlreadyLoaded(Instrumentation instrumentation) {
        for (String name : new String[]{DELEGATE, KNOT}) {
            try {
                Class<?> type = Class.forName(name, false, ClassLoader.getSystemClassLoader());
                instrumentation.retransformClasses(type);
                diag("retransformed " + name);
            } catch (Throwable failure) {
                diag("retransform skipped " + name + " -> " + failure);
            }
        }
    }

    /**
     * Every place the runtime class could live. The Fabric (Knot) loader is not a child of the
     * system loader, so parent delegation cannot reach it; {@code Class.forName} covers plain and
     * bootstrap launches and the instrumentation view is loader-agnostic. Duplicates are harmless:
     * a copy without a live handle simply yields no key.
     */
    private static java.util.List<Class<?>> runtimeCandidates(Instrumentation instrumentation) {
        java.util.List<Class<?>> found = new java.util.ArrayList<>(3);
        java.util.List<Class<?>> systemCopies = new java.util.ArrayList<>(1);
        // SECURITY (red-team #4): the system loader is consulted LAST. A launcher-supplied -cp jar
        // can shadow dev.chimera.runtime.ChimeraRuntime with a class whose deriveClassKey()
        // returns attacker-chosen bytes, and that copy's static nativeHandle field is not the one
        // the gate installed. The instance that matters is whichever loader owns the gate (Knot),
        // so the instrumentation view wins and system-loader copies are only a last resort.
        ClassLoader system = ClassLoader.getSystemClassLoader();
        if (instrumentation != null) {
            try {
                for (Class<?> loaded : instrumentation.getAllLoadedClasses()) {
                    if (!RUNTIME.equals(loaded.getName()) || found.contains(loaded)
                            || systemCopies.contains(loaded)) {
                        continue;
                    }
                    if (loaded.getClassLoader() == system) {
                        systemCopies.add(loaded);
                    } else {
                        found.add(loaded);
                    }
                }
            } catch (Throwable ignored) {
                // fall through to the loader probes
            }
        }
        for (ClassLoader loader : new ClassLoader[]{Thread.currentThread().getContextClassLoader(),
                system}) {
            if (loader == null) {
                continue;
            }
            try {
                Class<?> type = Class.forName(RUNTIME, false, loader);
                if (found.contains(type) || systemCopies.contains(type)) {
                    continue;
                }
                if (type.getClassLoader() == system) {
                    systemCopies.add(type);
                } else {
                    found.add(type);
                }
            } catch (Throwable ignored) {
                // try the next loader
            }
        }
        found.addAll(systemCopies);
        return found;
    }

    /**
     * P0-3a ciphertext-mandatory set: every internal name whose body was encrypted in this build.
     *
     * <p>Absent for dev builds, in which case the agent keeps the old lenient behaviour. When the
     * resource is present, a listed class that arrives as plaintext is proof that decrypted bodies
     * were dumped and pasted back into the jar, so the process is halted instead of running.</p>
     */
    private static volatile java.util.Set<String> protectedNames;

    static java.util.Set<String> protectedNames() {
        java.util.Set<String> current = protectedNames;
        if (current != null) {
            return current;
        }
        java.util.Set<String> loaded = java.util.Set.of();
        try (InputStream in = AttachAgent.class.getResourceAsStream("/chimera/attach/protected.txt")) {
            if (in != null) {
                java.util.Set<String> set = new java.util.HashSet<>();
                for (String line : new String(in.readAllBytes(),
                        java.nio.charset.StandardCharsets.UTF_8).split("\\R")) {
                    String name = line.trim();
                    if (!name.isEmpty()) {
                        set.add(name);
                    }
                }
                loaded = java.util.Collections.unmodifiableSet(set);
            }
        } catch (Throwable ignored) {
            loaded = java.util.Set.of();
        }
        protectedNames = loaded;
        if (!loaded.isEmpty()) {
            diagAlways("ciphertext-mandatory set loaded: " + loaded.size() + " classes");
        }
        return loaded;
    }

    /**
     * True when {@code internalName} must arrive as CHENC1 ciphertext in this build.
     *
     * <p>The resource holds 128-bit SHA-256 digests, not names, so the file itself does not reveal
     * which classes are protected.</p>
     */
    static boolean mustBeCiphertext(String internalName) {
        if (internalName == null) {
            return false;
        }
        java.util.Set<String> set = protectedNames();
        if (set.isEmpty()) {
            return false;
        }
        try {
            byte[] h = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(internalName.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(32);
            for (int i = 0; i < 16; i++) {
                hex.append(Character.forDigit((h[i] >> 4) & 0xF, 16));
                hex.append(Character.forDigit(h[i] & 0xF, 16));
            }
            return set.contains(hex.toString());
        } catch (Throwable ignored) {
            return false;
        }
    }

    /**
     * Ciphertext-mandatory enforcement: a protected class that arrives as plaintext means the jar
     * was rebuilt from dumped bodies. Halt rather than fall back to the plaintext.
     */
    static void enforceCiphertext(String internalName, byte[] bytes) {
        if (bytes == null || !mustBeCiphertext(internalName)) {
            return;
        }
        if (AgentCipher.isEncrypted(bytes)) {
            return;
        }
        diagAlways("PLAINTEXT-CONTAMINATION " + internalName + " len=" + bytes.length
                + " (protected class arrived unencrypted; halting)");
        Runtime.getRuntime().halt(4);
    }

    /**
     * Per-class diagnostics are OFF by default (#48): the decrypt transformer runs for every one of
     * the ~1300 classes, and an open+append+close on {@code %TEMP%} per class (plus the Windows AV
     * scan it triggers) was a measurable part of the protected startup time. Set
     * {@code -Dchimera.agent.diag=true} to get the detailed {@code chimera-agent.log} back.
     */
    private static final boolean DIAG = Boolean.getBoolean("chimera.agent.diag");

    /** Detailed diagnostics: only with {@code -Dchimera.agent.diag=true}. */
    static void diag(String line) {
        if (!DIAG) {
            return;
        }
        write(line);
    }

    /** Lifecycle diagnostics (a handful per launch) that support scripts rely on. */
    static void diagAlways(String line) {
        write(line);
    }

    private static void write(String line) {
        try {
            Path path = Path.of(System.getProperty("java.io.tmpdir", "."), "chimera-agent.log");
            Files.writeString(path, line + System.lineSeparator(), StandardCharsets.UTF_8,
                    java.nio.file.StandardOpenOption.CREATE,
                    java.nio.file.StandardOpenOption.APPEND);
        } catch (Throwable ignored) {
            // diagnostics only
        }
    }
}
