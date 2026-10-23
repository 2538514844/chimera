package dev.chimera.transform.sink;

import org.objectweb.asm.tree.MethodNode;

/**
 * One method that was moved into the native sink.
 *
 * <p>{@code original} is the untouched pre-transform {@link MethodNode}: its instruction list,
 * try/catch blocks, local variables and annotations are kept so the caller can audit or migrate
 * them. The node inside the transformed class has already been replaced by an empty native stub,
 * so the two objects must never be confused.</p>
 *
 * <p>{@code symbol} is the JNI symbol produced by
 * {@link dev.chimera.nativecode.compile.NativeBodyCompiler} and {@code cppSource} is the complete
 * generated JNI function (not only the body).</p>
 */
public record SinkSelectedMethod(
        String owner,
        String name,
        String descriptor,
        String signature,
        int originalAccess,
        boolean isStatic,
        long weight,
        String symbol,
        MethodNode original,
        String cppSource) {

    public SinkSelectedMethod {
        if (owner == null || owner.isEmpty()) {
            throw new IllegalArgumentException("owner is required");
        }
        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("name is required for " + owner);
        }
        if (descriptor == null || descriptor.isEmpty()) {
            throw new IllegalArgumentException("descriptor is required for " + owner + "." + name);
        }
        if (original == null) {
            throw new IllegalArgumentException("original MethodNode is required for " + owner + "." + name);
        }
        if (symbol == null || symbol.isEmpty()) {
            throw new IllegalArgumentException("JNI symbol is required for " + owner + "." + name);
        }
        if (cppSource == null || cppSource.isBlank()) {
            throw new IllegalArgumentException("generated C++ source is required for " + owner + "." + name);
        }
    }

    /** {@code owner.name + descriptor}; unique inside a class file. */
    public String displayName() {
        return owner + "." + name + descriptor;
    }
}
