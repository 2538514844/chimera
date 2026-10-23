package dev.chimera.runtime;

/**
 * SECURITY (audit 2026-10-22 #3/#5): build-time constants that decide whether the test seams and
 * the mandatory native payload apply.
 *
 * <p>Both fields are deliberately <b>non-final</b>: {@code javac} folds reads of a
 * {@code static final boolean} compile-time constant, which would leave the engine nothing to
 * rewrite. {@code dev.chimera.core.RuntimeSeamPatch} rewrites the {@code <clinit>} stores while the
 * runtime classes are copied into an artifact that carries a native payload
 * ({@code --embed-dll} / {@code --payload-stealth}), so a shipped artifact ships
 * {@code TEST_SEAMS=false} / {@code PAYLOAD_REQUIRED=true}. The class is covered by the CHR1
 * runtime-hash self-check and by the HMAC'd resource manifest, so flipping the values back in a
 * shipped jar is tampering and halts(4).</p>
 *
 * <p>This class must stay free of static initialisation side effects: the preLaunch gate reads it
 * before the native image is loaded, and initialising {@link ChimeraRuntime} at that point would
 * make it miss the staged DLL.</p>
 */
final class ChimeraBuildFlags {

    /** Test seams ({@code *ForTests} methods/fields) are usable. False in payload artifacts. */
    private static boolean TEST_SEAMS = true;

    /** The artifact must carry {@code /chimera/embedded.dll} or {@code /chimera/res/native.dat}. */
    private static boolean PAYLOAD_REQUIRED = false;

    private ChimeraBuildFlags() {
    }

    /** True when the diagnostic/test seams may influence behaviour in this process. */
    static boolean testSeams() {
        return TEST_SEAMS;
    }

    /** True when a missing native payload means "tampered artifact" instead of "dev build". */
    static boolean payloadRequired() {
        return PAYLOAD_REQUIRED;
    }
}
