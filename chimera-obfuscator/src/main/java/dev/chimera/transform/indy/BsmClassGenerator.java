package dev.chimera.transform.indy;

import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Handle;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * G8: build-time generator for the dispersed bootstrap owners.
 *
 * <p>{@code IndyIntegration} ships {@link #DEFAULT_COUNT} structurally identical classes
 * {@code chimera/indy/Bsm0} .. {@code chimera/indy/Bsm15}. Each one exposes exactly the
 * {@link ChimeraBootstrap#BSM_DESC} bootstrap method and delegates to
 * {@link ChimeraBootstrap#bootstrap} - no logic is duplicated, only the constant-pool owner name
 * differs. Call sites select one of these owners with
 * {@code (classId ^ siteIndex) & (DEFAULT_COUNT - 1)}, so a single hook/link failure cannot be
 * attributed to one well-known bootstrap owner (G8 BSM dispersion).</p>
 *
 * <p>The generated classes are ordinary Java 17 class files; they are returned as
 * {@code byEntryName} entries (e.g. {@code chimera/indy/Bsm7.class}) and do not depend on ASM at
 * runtime. They are also present in {@link IndyIntegration.Result#classes()} so existing engine
 * wiring packages them without extra glue; {@link IndyIntegration.Result#extraClasses()} exposes
 * the generated subset explicitly for callers that inject runtime support separately.</p>
 */
public final class BsmClassGenerator {

    /** Number of equivalent bootstrap owners generated (power of two, masked by the rotation). */
    public static final int DEFAULT_COUNT = 16;

    /** Internal-name prefix of the generated owners. */
    public static final String OWNER_PREFIX = "chimera/indy/Bsm";

    private BsmClassGenerator() {
    }

    /** Internal name of owner {@code index}: {@code chimera/indy/Bsm<index>}. */
    public static String owner(int index) {
        checkIndex(index);
        return OWNER_PREFIX + index;
    }

    /** Resource entry name of owner {@code index}: {@code chimera/indy/Bsm<index>.class}. */
    public static String entryName(int index) {
        return owner(index) + ".class";
    }

    /** INVOKESTATIC handle to the bootstrap method of owner {@code index}. */
    public static Handle handle(int index) {
        return new Handle(Opcodes.H_INVOKESTATIC, owner(index),
                ChimeraBootstrap.BSM_NAME, ChimeraBootstrap.BSM_DESC, false);
    }

    /** Generates all {@link #DEFAULT_COUNT} owners, keyed by resource entry name. */
    public static Map<String, byte[]> generate() {
        return generate(DEFAULT_COUNT);
    }

    /**
     * Generates {@code count} owners (1..DEFAULT_COUNT, power of two because call sites mask the
     * rotation with {@code count - 1}).
     */
    public static Map<String, byte[]> generate(int count) {
        if (count < 1 || count > DEFAULT_COUNT || (count & (count - 1)) != 0) {
            throw new IllegalArgumentException(
                    "bsm owner count must be a power of two in [1, " + DEFAULT_COUNT + "]: " + count);
        }
        Map<String, byte[]> out = new LinkedHashMap<>();
        for (int i = 0; i < count; i++) {
            out.put(entryName(i), generateClass(i));
        }
        return Collections.unmodifiableMap(out);
    }

    /** Generates the class file of owner {@code index} (delegates to {@link ChimeraBootstrap}). */
    public static byte[] generateClass(int index) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER,
                owner(index), null, "java/lang/Object", null);
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                ChimeraBootstrap.BSM_NAME, ChimeraBootstrap.BSM_DESC, null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitVarInsn(Opcodes.ALOAD, 1);
        mv.visitVarInsn(Opcodes.ALOAD, 2);
        mv.visitVarInsn(Opcodes.LLOAD, 3);
        mv.visitVarInsn(Opcodes.LLOAD, 5);
        mv.visitVarInsn(Opcodes.ILOAD, 7);
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, ChimeraBootstrap.OWNER,
                ChimeraBootstrap.BSM_NAME, ChimeraBootstrap.BSM_DESC, false);
        mv.visitInsn(Opcodes.ARETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    private static void checkIndex(int index) {
        if (index < 0 || index >= DEFAULT_COUNT) {
            throw new IllegalArgumentException("bsm owner index out of range: " + index);
        }
    }
}
