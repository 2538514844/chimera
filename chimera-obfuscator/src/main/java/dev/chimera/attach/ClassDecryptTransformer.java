package dev.chimera.attach;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

/** Replaces CHENC1 class bodies with their plaintext at JVM definition time. */
public final class ClassDecryptTransformer implements ClassFileTransformer {

    public ClassDecryptTransformer() {
    }

    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain, byte[] classfileBuffer) {
        if (className == null || classfileBuffer == null) {
            return null;
        }
        // VM mode: hand the JVM an empty class instead of the real body. The mod stays loaded (its
        // metadata is untouched) but has no features and nothing worth dumping.
        if (AttachAgent.vmStubMode() && AttachAgent.isModClass(className)) {
            return AttachAgent.emptyStub(className);
        }
        // P0-3a enforcement deliberately lives in FabricHook (the jar-read boundary), NOT here:
        // this transformer also runs on retransformation and on already-decrypted bytes, where a
        // plaintext buffer is normal (measured false positive: dev/idhammai/.../HUD).
        if (!AgentCipher.isEncrypted(classfileBuffer)) {
            return null;
        }
        try {
            // Red-team #2: encrypted bytes with an empty ciphertext-mandatory set means the list
            // was stripped, not that nothing is protected. Fail closed on both decrypt paths.
            if (AttachAgent.protectedNames().isEmpty()) {
                AttachAgent.diagAlways("ciphertext-mandatory list missing/empty while CHENC1 bodies"
                        + " are present (" + className + "); halting");
                Runtime.getRuntime().halt(4);
            }
            byte[] plain = AttachAgent.decryptBody(classfileBuffer, className);
            AgentState.decrypted++;
            // #19: per-licence watermark, best effort. Runs only on freshly decrypted bodies, so
            // plaintext/mixin classes (which return earlier) never get extra instructions.
            byte[] watermarked = WatermarkInjector.inject(plain, AttachAgent.watermarkPayload());
            // A2: the gate is no longer injected here. It is baked into the encrypted class body at
            // build time (dev.chimera.transform.gate.ClassGateInjector), because a runtime-injected
            // gate leaves the shipped bytes ungated - an offline dump then yields ungated classes
            // and a repack never calls nativeGateCheck (red team round 4, measured).
            byte[] gated = watermarked;
            AttachAgent.diag("decrypted " + className + " len=" + plain.length
                    + (watermarked != plain ? " wm=on" : ""));
            return gated;
        } catch (Throwable failure) {
            AgentState.failures++;
            AttachAgent.diag("decrypt failed " + className + " len=" + classfileBuffer.length
                    + " -> " + failure);
            throw new IllegalStateException("chimera: class decrypt failed: " + className, failure);
        }
    }
}
