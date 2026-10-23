package dev.chimera.core;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.MethodNode;

/**
 * SECURITY (audit 2026-10-22 #3/#5): rewrites the build-time seam constants of the injected
 * runtime classes so a shipped artifact cannot be talked back into dev semantics.
 *
 * <p>{@code ChimeraBuildFlags.TEST_SEAMS} / {@code PAYLOAD_REQUIRED} are non-final fields written
 * once from {@code <clinit>}; this pass replaces the pushed int constant in front of the
 * {@code PUTSTATIC} with the build-time value. Every artifact that carries a native payload ships
 * {@code TEST_SEAMS=false, PAYLOAD_REQUIRED=true}, which is what makes the {@code *ForTests} seams
 * inert for third-party mods and a deleted payload fatal instead of a silent dev downgrade.</p>
 *
 * <p>The rewrite happens before the class is hashed into {@code /chimera/runtime.hash}, so the
 * emitted artifact is self-consistent: patching the flag back in a shipped jar fails the CHR1
 * self-check.</p>
 */
final class RuntimeSeamPatch {

    private static final String TEST_SEAMS = "TEST_SEAMS";
    private static final String PAYLOAD_REQUIRED = "PAYLOAD_REQUIRED";

    private RuntimeSeamPatch() {
    }

    /**
     * Returns the class bytes with the seam constants set to {@code testSeams} /
     * {@code payloadRequired}. Classes without those fields are returned untouched.
     */
    static byte[] apply(byte[] classBytes, boolean testSeams, boolean payloadRequired) {
        ClassNode node = new ClassNode();
        new ClassReader(classBytes).accept(node, 0);
        boolean patched = false;
        for (MethodNode method : node.methods) {
            if (!"<clinit>".equals(method.name) || method.instructions.size() == 0) {
                continue;
            }
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                 insn = insn.getNext()) {
                if (!(insn instanceof FieldInsnNode field)
                        || field.getOpcode() != Opcodes.PUTSTATIC
                        || !node.name.equals(field.owner)) {
                    continue;
                }
                boolean value;
                if (TEST_SEAMS.equals(field.name)) {
                    value = testSeams;
                } else if (PAYLOAD_REQUIRED.equals(field.name)) {
                    value = payloadRequired;
                } else {
                    continue;
                }
                AbstractInsnNode push = previousReal(insn);
                if (push == null || push.getOpcode() < Opcodes.ICONST_0
                        || push.getOpcode() > Opcodes.ICONST_1) {
                    throw new IllegalStateException("cannot rewrite build flag " + field.name
                            + " in " + node.name + ": unexpected initialiser");
                }
                method.instructions.set(push,
                        new InsnNode(value ? Opcodes.ICONST_1 : Opcodes.ICONST_0));
                patched = true;
            }
        }
        if (!patched) {
            return classBytes;
        }
        ClassWriter writer = new ClassWriter(0);
        node.accept(writer);
        return writer.toByteArray();
    }

    /** Skips labels, line numbers and frames so the value push can be found. */
    private static AbstractInsnNode previousReal(AbstractInsnNode node) {
        AbstractInsnNode current = node == null ? null : node.getPrevious();
        while (current != null && current.getOpcode() < 0) {
            current = current.getPrevious();
        }
        return current;
    }
}
