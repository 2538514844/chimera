package dev.chimera.attach;

/**
 * Called from patched Fabric loader byte-read methods: returns the plaintext for CHENC1 entries so
 * Fabric's own ASM passes (class tweakers, interface injection) see valid class files.
 */
public final class FabricHook {

    /** Classes this process has already decrypted (plaintext re-reads are then expected). */
    private static final java.util.Set<String> DECRYPTED =
            java.util.concurrent.ConcurrentHashMap.newKeySet();

    /** Fabric passes entry paths ({@code a/b/C.class}) while the AAD is the internal name. */
    private static String normalize(String name) {
        String internal = name == null ? "" : name;
        if (internal.startsWith("/")) {
            internal = internal.substring(1);
        }
        if (internal.endsWith(".class")) {
            internal = internal.substring(0, internal.length() - 6);
        }
        return internal;
    }

    private FabricHook() {
    }

    /** Decrypts {@code bytes} when it is a CHENC1 payload; otherwise returns it unchanged. */
    public static byte[] decrypt(String className, byte[] bytes) {
        if (bytes == null) {
            return bytes;
        }
        String internal = normalize(className);
        // VM mode: every mod class becomes an empty stub, so Fabric and Mixin see a valid but inert
        // artifact (see AttachAgent.emptyStub).
        if (AttachAgent.vmStubMode() && AttachAgent.isModClass(internal)) {
            return AttachAgent.emptyStub(internal);
        }
        if (!AgentCipher.isEncrypted(bytes)) {
            // P0-3a: plaintext for a protected class is only legitimate when WE produced it.
            // Fabric re-reads entries it already had decrypted, so a class we have decrypted
            // before is expected to come back plaintext. Anything else means the jar on disk was
            // rebuilt from dumped bodies -> halt.
            if (AttachAgent.mustBeCiphertext(internal) && !DECRYPTED.contains(internal)) {
                AttachAgent.enforceCiphertext(internal, bytes);
            }
            return bytes;
        }
        // Fail closed: ciphertext with no key must halt, never pass through to the JVM. The key is
        // resolved lazily because attach runs from the mixin plugin, before the gate installs the
        // native handle the key is derived from.
        // Red-team #2: the ciphertext-mandatory set used to fail open when protected.txt was
        // deleted (empty set => every membership test false => no enforcement at all). Encrypted
        // bytes prove this is a class-encrypt build, so an empty set can only mean the list was
        // stripped -> halt instead of silently downgrading.
        if (AttachAgent.protectedNames().isEmpty()) {
            AttachAgent.diagAlways("ciphertext-mandatory list missing/empty while CHENC1 bodies are"
                    + " present (" + internal + "); halting");
            Runtime.getRuntime().halt(4);
        }
        try {
            byte[] plain = AttachAgent.decryptBody(bytes, internal);
            DECRYPTED.add(internal);
            AgentState.decrypted++;
            // #19: this is the path Fabric actually uses for mod classes, so the watermark has to
            // be injected HERE as well. ClassDecryptTransformer never sees these bodies (it gets
            // the already-plaintext bytes back from the loader and returns null), so injecting only
            // there would leave every mod class unmarked - measured gap from the red-team review.
            byte[] marked = WatermarkInjector.inject(plain, AttachAgent.watermarkPayload());
            // A2: baked at build time now - see dev.chimera.transform.gate.ClassGateInjector.
            byte[] gated = marked;
            AttachAgent.diag("fabric-hook decrypted " + className
                    + (marked != plain ? " wm=on" : ""));
            return gated;
        } catch (Throwable failure) {
            AgentState.failures++;
            AttachAgent.diag("fabric-hook failed " + className + " -> " + failure);
            throw new IllegalStateException("chimera: fabric byte hook failed: " + className, failure);
        }
    }
}
