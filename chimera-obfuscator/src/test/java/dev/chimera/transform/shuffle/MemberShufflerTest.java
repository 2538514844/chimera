package dev.chimera.transform.shuffle;

import dev.chimera.core.ChimeraConfig;
import dev.chimera.core.ClassPool;
import dev.chimera.core.Stats;
import dev.chimera.core.TransformContext;
import dev.chimera.crypto.Crypto;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MemberShufflerTest {

    private static final String SUBJECT = "fixtures/ShuffleSubject";

    @Test
    void shufflesOrderKeepsMembersAndBehaviour() throws Exception {
        ClassNode node = subject();
        List<String> fieldsBefore = names(node.fields.stream().map(f -> f.name).toList());
        List<String> methodsBefore = names(node.methods.stream().map(m -> m.name).toList());
        int initIndex = indexOf(node.methods, "<init>");
        int clinitIndex = indexOf(node.methods, "<clinit>");

        MemberShuffler shuffler = new MemberShuffler(true, true);
        shuffler.transform(node.name, node, context());

        assertEquals(fieldsBefore, names(node.fields.stream().map(f -> f.name).toList()),
                "the same fields must remain");
        assertEquals(methodsBefore, names(node.methods.stream().map(m -> m.name).toList()),
                "the same methods must remain");
        assertNotEquals(fieldsBefore, node.fields.stream().map(f -> f.name).toList(),
                "field order must change");
        assertNotEquals(methodsBefore, node.methods.stream().map(m -> m.name).toList(),
                "method order must change");
        assertEquals(initIndex, indexOf(node.methods, "<init>"), "<init> keeps its slot");
        assertEquals(clinitIndex, indexOf(node.methods, "<clinit>"), "<clinit> keeps its slot");
        assertTrue(shuffler.fieldsMoved() > 0);
        assertTrue(shuffler.methodsMoved() > 0);

        assertEquals(42, invoke(node));
    }

    @Test
    void orderIsDeterministicPerClass() {
        ClassNode first = read(write(subject()));
        ClassNode second = read(write(subject()));
        MemberShuffler a = new MemberShuffler(true, true);
        MemberShuffler b = new MemberShuffler(true, true);
        a.transform(first.name, first, context());
        b.transform(second.name, second, context());
        assertEquals(names(first.fields.stream().map(f -> f.name).toList()),
                names(second.fields.stream().map(f -> f.name).toList()));
        assertEquals(names(first.methods.stream().map(m -> m.name).toList()),
                names(second.methods.stream().map(m -> m.name).toList()));
    }

    @Test
    void mixinAndRecordAndInterfaceAreSkipped() {
        ClassNode mixin = subject();
        mixin.visibleAnnotations = new ArrayList<>();
        mixin.visibleAnnotations.add(new AnnotationNode("Lorg/spongepowered/asm/mixin/Mixin;"));
        MemberShuffler shuffler = new MemberShuffler(true, true);
        shuffler.transform(mixin.name, mixin, context());
        assertEquals(1, shuffler.classesSkipped());

        ClassNode record = subject();
        record.access |= Opcodes.ACC_RECORD;
        MemberShuffler second = new MemberShuffler(true, true);
        second.transform(record.name, record, context());
        assertEquals(1, second.classesSkipped());

        ClassNode itf = subject();
        itf.access |= Opcodes.ACC_INTERFACE;
        MemberShuffler third = new MemberShuffler(true, true);
        third.transform(itf.name, itf, context());
        assertEquals(1, third.classesSkipped());
    }

    private static int indexOf(List<org.objectweb.asm.tree.MethodNode> methods, String name) {
        for (int i = 0; i < methods.size(); i++) {
            if (methods.get(i).name.equals(name)) return i;
        }
        return -1;
    }

    private static List<String> names(List<String> list) {
        List<String> sorted = new ArrayList<>(list);
        java.util.Collections.sort(sorted);
        return sorted;
    }

    private static int invoke(ClassNode node) throws Exception {
        class Loader extends ClassLoader {
            Class<?> define(String name, byte[] bytes) {
                return defineClass(name, bytes, 0, bytes.length);
            }
        }
        Class<?> type = new Loader().define("fixtures.ShuffleSubject", write(node));
        return (Integer) type.getMethod("value").invoke(null);
    }

    private static ClassNode subject() {
        ClassNode node = new ClassNode();
        node.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, SUBJECT, null, "java/lang/Object", null);
        for (int i = 0; i < 6; i++) {
            node.visitField(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, "f" + i, "I", null, i).visitEnd();
        }
        MethodVisitor init = node.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitCode();
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(1, 1);
        init.visitEnd();
        MethodVisitor clinit = node.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        clinit.visitCode();
        clinit.visitInsn(Opcodes.RETURN);
        clinit.visitMaxs(0, 0);
        clinit.visitEnd();
        for (int i = 0; i < 6; i++) {
            MethodVisitor mv = node.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                    "m" + i, "()I", null, null);
            mv.visitCode();
            mv.visitIntInsn(Opcodes.BIPUSH, 42);
            mv.visitInsn(Opcodes.IRETURN);
            mv.visitMaxs(1, 0);
            mv.visitEnd();
        }
        MethodVisitor value = node.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "value", "()I", null, null);
        value.visitCode();
        value.visitIntInsn(Opcodes.BIPUSH, 42);
        value.visitInsn(Opcodes.IRETURN);
        value.visitMaxs(1, 0);
        value.visitEnd();
        node.visitEnd();
        return node;
    }

    private static ClassNode read(byte[] bytes) {
        ClassNode node = new ClassNode();
        new ClassReader(bytes).accept(node, 0);
        return node;
    }

    private static byte[] write(ClassNode node) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        node.accept(writer);
        return writer.toByteArray();
    }

    private static TransformContext context() {
        ChimeraConfig config = new ChimeraConfig();
        byte[] key = Crypto.sha256("shuffle-test".getBytes(StandardCharsets.UTF_8));
        return new TransformContext(config, new byte[16], key, new ClassPool(Map.of()),
                (name, data) -> { }, new Stats(), "shuffle-test");
    }
}
