package dev.chimera.core;

/**
 * Metadata for a generated JNI implementation template.
 *
 * <p>{@code headerDecl} is the full {@code extern "C" JNIEXPORT ...;} declaration, {@code cppBody}
 * is the transpiled C++ function body (only when {@code supported} is true), and {@code supported}
 * tells the writer whether a real implementation was produced or a TODO stub is required.</p>
 */
public record NativeTemplate(
        String classInternalName,
        String methodName,
        String descriptor,
        boolean isStatic,
        boolean supported,
        String cppBody,
        String headerDecl) {

    /** Backward-compatible constructor: unsupported TODO template. */
    public NativeTemplate(String classInternalName, String methodName, String descriptor, boolean isStatic) {
        this(classInternalName, methodName, descriptor, isStatic, false, null, null);
    }
}
