package dev.chimera.transform;

import dev.chimera.core.TransformContext;
import dev.chimera.core.Transformer;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;

import java.util.HashMap;
import java.util.Map;

/**
 * Replaces LDC string constants with {@code ChimeraRuntime.decryptStr(id)} calls.
 *
 * <p>Methods containing a {@code tableswitch}/{@code lookupswitch} are skipped entirely:
 * several compilers implement {@code switch} over strings by hashing the string and then
 * switching on the hash, so rewriting the LDC in such a method could change the control
 * flow. Non-String constants (Type/Handle/ConstantDynamic/numbers) are left untouched.
 * The transformer only mutates the {@link ClassNode}; the encrypted table is produced
 * later by {@link TransformContext#encodeStringTable()}.</p>
 */
public final class StringEncryptTransformer implements Transformer {
    private static final String RUNTIME_OWNER = "dev/chimera/runtime/ChimeraRuntime";
    private static final String DECRYPT_METHOD = "decryptStr";
    private static final String DECRYPT_DESCRIPTOR = "(I)Ljava/lang/String;";

    /** Per-instance dedup: identical strings are registered only once per build. */
    private final Map<String, Integer> ids = new HashMap<>();

    @Override
    public void transform(String internalName, ClassNode node, TransformContext ctx) {
        if (!ctx.config.encryptStrings) {
            return;
        }
        for (MethodNode method : node.methods) {
            if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) {
                continue;
            }
            if (containsSwitch(method)) {
                continue;
            }
            transformMethod(method, ctx);
        }
    }

    private static boolean containsSwitch(MethodNode method) {
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof TableSwitchInsnNode || insn instanceof LookupSwitchInsnNode) {
                return true;
            }
        }
        return false;
    }

    private void transformMethod(MethodNode method, TransformContext ctx) {
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; ) {
            AbstractInsnNode next = insn.getNext();
            if (insn instanceof LdcInsnNode && ((LdcInsnNode) insn).cst instanceof String) {
                String value = (String) ((LdcInsnNode) insn).cst;
                int id = ids.computeIfAbsent(value, ctx::registerString);
                method.instructions.insert(insn, new MethodInsnNode(Opcodes.INVOKESTATIC,
                        RUNTIME_OWNER, DECRYPT_METHOD, DECRYPT_DESCRIPTOR, false));
                method.instructions.set(insn, new LdcInsnNode(id));
                ctx.stats.stringsEncrypted++;
            }
            insn = next;
        }
    }
}
