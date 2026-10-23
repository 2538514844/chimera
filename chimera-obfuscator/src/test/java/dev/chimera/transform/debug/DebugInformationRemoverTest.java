package dev.chimera.transform.debug;

import dev.chimera.core.ChimeraConfig;
import dev.chimera.core.ClassPool;
import dev.chimera.core.Stats;
import dev.chimera.core.TransformContext;
import dev.chimera.crypto.Crypto;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.LineNumberNode;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** A9: debug metadata removal must not change behaviour and must never touch Mixin classes. */
class DebugInformationRemoverTest {

    private static final String SUBJECT = "fixtures/DebugSubject";

    @Test
    void stripsLineNumbersAndSourceFileButKeepsBehaviour() throws Exception {
        ClassNode node = subject();
        assertNotNull(node.sourceFile, "fixture must carry SourceFile for this test");
        assertEquals(2, countLineNumbers(node));

        DebugInformationRemover remover = new DebugInformationRemover(false);
        remover.transform(node.name, node, context());

        // A9: SourceFile is normalised to the constant "x" instead of being removed: Minecraft's
        // stack-trace walker dereferences it, and a constant leaks strictly less than the real file
        // name while keeping stack traces printable.
        assertEquals("x", node.sourceFile, "SourceFile must be normalised to the constant");
        assertNull(node.sourceDebug, "SourceDebugExtension must be removed");
        assertEquals(0, countLineNumbers(node), "LineNumberTable must be removed");
        for (var method : node.methods) {
            assertNull(method.localVariables, "LocalVariableTable must be removed");
            assertNull(method.parameters, "MethodParameters must be removed");
        }
        assertEquals(1, remover.classesStripped());

        assertEquals(7, invokeLabel(write(node)), "behaviour must be unchanged");
    }

    @Test
    void mixinClassesAreSkippedByteForByte() {
        ClassNode mixin = subject();
        mixin.visibleAnnotations = new ArrayList<>();
        mixin.visibleAnnotations.add(new AnnotationNode("Lorg/spongepowered/asm/mixin/Mixin;"));
        ClassNode node = read(write(mixin));

        DebugInformationRemover remover = new DebugInformationRemover(true);
        remover.transform(node.name, node, context());

        assertEquals(0, remover.classesStripped());
        assertEquals(1, remover.classesSkipped());
        assertNotNull(node.sourceFile, "Mixin SourceFile must be preserved");
        assertEquals(2, countLineNumbers(node), "Mixin LineNumberTable must be preserved");
    }

    @Test
    void signatureStrippingIsOptIn() {
        ClassNode kept = read(write(subjectWithSignature()));
        new DebugInformationRemover(false).transform(kept.name, kept, context());
        ClassNode stripped = read(write(subjectWithSignature()));
        new DebugInformationRemover(true).transform(stripped.name, stripped, context());
        assertNull(stripped.signature, "class Signature must be removed when enabled");
        assertNotNull(kept.signature, "class Signature must be kept by default");
    }

    @Test
    void runtimePackagesAreSkipped() {
        ClassNode runtime = subject();
        runtime.name = "dev/chimera/runtime/HiddenThing";
        DebugInformationRemover remover = new DebugInformationRemover(false);
        remover.transform(runtime.name, runtime, context());
        assertEquals(0, remover.classesStripped());
        assertNotNull(runtime.sourceFile);
    }

    private static ClassNode subjectWithSignature() {
        ClassNode node = subject();
        node.signature = "Ljava/lang/Object;";
        return node;
    }

    private static int countLineNumbers(ClassNode node) {
        int count = 0;
        for (var method : node.methods) {
            if (method.instructions == null) continue;
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn instanceof LineNumberNode) count++;
            }
        }
        return count;
    }

    private static int invokeLabel(byte[] classBytes) throws Exception {
        class Loader extends ClassLoader {
            Class<?> define(String name, byte[] bytes) {
                return defineClass(name, bytes, 0, bytes.length);
            }
        }
        Class<?> type = new Loader().define("fixtures.DebugSubject", classBytes);
        return (Integer) type.getMethod("value").invoke(null);
    }

    private static ClassNode subject() {
        ClassNode node = new ClassNode();
        node.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, SUBJECT, null, "java/lang/Object", null);
        node.visitSource("DebugSubject.java", null);
        MethodVisitor mv = node.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "value", "()I", null, null);
        mv.visitCode();
        Label first = new Label();
        mv.visitLabel(first);
        mv.visitLineNumber(11, first);
        mv.visitIntInsn(Opcodes.BIPUSH, 7);
        Label second = new Label();
        mv.visitLabel(second);
        mv.visitLineNumber(12, second);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(1, 0);
        mv.visitEnd();
        node.visitEnd();
        return node;
    }

    private static ClassNode read(byte[] bytes) {
        ClassNode node = new ClassNode();
        new ClassReader(bytes).accept(node, 0);
        return node;
    }

    private static byte[] write(ClassNode node) {
        ClassWriter writer = new ClassWriter(0);
        node.accept(writer);
        return writer.toByteArray();
    }

    private static TransformContext context() {
        ChimeraConfig config = new ChimeraConfig();
        byte[] key = Crypto.sha256("a9-test".getBytes(StandardCharsets.UTF_8));
        return new TransformContext(config, new byte[16], key, new ClassPool(Map.of()),
                (name, data) -> { }, new Stats(), "a9-test");
    }
}
