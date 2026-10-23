package dev.chimera.transform;

import dev.chimera.core.ChimeraConfig;
import dev.chimera.core.ClassPool;
import dev.chimera.core.Stats;
import dev.chimera.core.TransformContext;
import dev.chimera.crypto.Crypto;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StringEncryptTransformerTest {

    private static TransformContext context(boolean encryptStrings) {
        ChimeraConfig config = new ChimeraConfig();
        config.encryptStrings = encryptStrings;
        config.keyMaterial = new byte[32];
        return new TransformContext(config, Crypto.random(16), Crypto.random(32),
                new ClassPool(Map.of()), (name, data) -> {
                }, new Stats(), "test-build");
    }

    private static ClassNode classNode(String name) {
        ClassNode node = new ClassNode();
        node.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, name, null, "java/lang/Object", null);
        return node;
    }

    private static MethodNode method(String name, String descriptor, int access) {
        return new MethodNode(access, name, descriptor, null, null);
    }

    private static List<AbstractInsnNode> instructions(MethodNode method) {
        List<AbstractInsnNode> out = new ArrayList<>();
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            out.add(insn);
        }
        return out;
    }

    @Test
    void replacesStringConstantsAndDeduplicatesIds() {
        TransformContext ctx = context(true);
        ClassNode node = classNode("pkg/Test");
        MethodNode m = method("m", "()V", Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC);
        m.instructions.add(new LdcInsnNode("hello"));
        m.instructions.add(new LdcInsnNode("hello"));
        m.instructions.add(new LdcInsnNode("world"));
        m.instructions.add(new LdcInsnNode(Type.getType("Ljava/lang/String;")));
        node.methods.add(m);

        new StringEncryptTransformer().transform("pkg/Test", node, ctx);

        assertEquals(3, ctx.stats.stringsEncrypted);
        assertEquals(2, ctx.strings().size());
        List<AbstractInsnNode> insns = instructions(m);
        assertEquals(7, insns.size());

        int helloId = firstId(insns, 0);
        assertEquals(helloId, firstId(insns, 2));
        int worldId = firstId(insns, 4);
        assertNotEquals(helloId, worldId);
        assertEquals("hello", ctx.strings().get(helloId));
        assertEquals("world", ctx.strings().get(worldId));

        assertDecryptCall(insns.get(1));
        assertDecryptCall(insns.get(3));
        assertDecryptCall(insns.get(5));
        assertInstanceOf(Type.class, ((LdcInsnNode) insns.get(6)).cst);
    }

    private static int firstId(List<AbstractInsnNode> insns, int index) {
        LdcInsnNode ldc = assertInstanceOf(LdcInsnNode.class, insns.get(index));
        return (Integer) assertInstanceOf(Integer.class, ldc.cst);
    }

    private static void assertDecryptCall(AbstractInsnNode insn) {
        MethodInsnNode call = assertInstanceOf(MethodInsnNode.class, insn);
        assertEquals(Opcodes.INVOKESTATIC, call.getOpcode());
        assertEquals("dev/chimera/runtime/ChimeraRuntime", call.owner);
        assertEquals("decryptStr", call.name);
        assertEquals("(I)Ljava/lang/String;", call.desc);
        assertEquals(false, call.itf);
    }

    @Test
    void skipsMethodsContainingSwitches() {
        TransformContext ctx = context(true);
        ClassNode node = classNode("pkg/Sw");
        MethodNode withSwitch = method("sw", "(I)V", Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC);
        LabelNode defaultLabel = new LabelNode();
        LabelNode caseLabel = new LabelNode();
        withSwitch.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        withSwitch.instructions.add(new LookupSwitchInsnNode(defaultLabel, new int[]{0}, new LabelNode[]{caseLabel}));
        withSwitch.instructions.add(new LdcInsnNode("keep-me"));
        node.methods.add(withSwitch);

        MethodNode normal = method("n", "()V", Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC);
        normal.instructions.add(new LdcInsnNode("encrypt-me"));
        node.methods.add(normal);

        new StringEncryptTransformer().transform("pkg/Sw", node, ctx);

        assertEquals(1, ctx.stats.stringsEncrypted);
        assertEquals(1, ctx.strings().size());
        LdcInsnNode kept = assertInstanceOf(LdcInsnNode.class, withSwitch.instructions.getLast());
        assertEquals("keep-me", kept.cst);
        assertTrue(instructions(normal).stream().anyMatch(i -> i instanceof MethodInsnNode));
    }

    @Test
    void skipsAbstractAndNativeMethods() {
        TransformContext ctx = context(true);
        ClassNode node = classNode("pkg/Abs");
        node.methods.add(method("a", "()V", Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT));
        node.methods.add(method("n", "()V", Opcodes.ACC_PUBLIC | Opcodes.ACC_NATIVE));
        MethodNode concrete = method("c", "()V", Opcodes.ACC_PUBLIC);
        concrete.instructions.add(new LdcInsnNode("value"));
        node.methods.add(concrete);

        new StringEncryptTransformer().transform("pkg/Abs", node, ctx);

        assertEquals(1, ctx.stats.stringsEncrypted);
    }

    @Test
    void respectsEncryptStringsFlag() {
        TransformContext ctx = context(false);
        ClassNode node = classNode("pkg/Off");
        MethodNode m = method("m", "()V", Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC);
        m.instructions.add(new LdcInsnNode("untouched"));
        node.methods.add(m);

        new StringEncryptTransformer().transform("pkg/Off", node, ctx);

        assertEquals(0, ctx.stats.stringsEncrypted);
        assertEquals(0, ctx.strings().size());
        LdcInsnNode ldc = assertInstanceOf(LdcInsnNode.class, m.instructions.getFirst());
        assertEquals("untouched", ldc.cst);
    }

    @Test
    void deduplicatesAcrossClassesWithSameTransformerInstance() {
        TransformContext ctx = context(true);
        StringEncryptTransformer transformer = new StringEncryptTransformer();

        for (String className : new String[]{"pkg/One", "pkg/Two"}) {
            ClassNode node = classNode(className);
            MethodNode m = method("m", "()V", Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC);
            m.instructions.add(new LdcInsnNode("shared"));
            node.methods.add(m);
            transformer.transform(className, node, ctx);
        }

        assertEquals(2, ctx.stats.stringsEncrypted);
        assertEquals(1, ctx.strings().size());
        assertEquals("shared", ctx.strings().values().iterator().next());
    }
}
