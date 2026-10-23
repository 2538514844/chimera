package dev.chimera.transform.naming;

import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** G1: short names must remove the original identifier while keeping behaviour. */
class M13ShortNamesTest {

    @Test
    void shortNamesRemoveOriginalIdentifiersAndKeepBehaviour() throws Exception {
        Map<String, byte[]> classes = new LinkedHashMap<>();
        classes.put("fixtures/ShortHelper.class", helper());
        classes.put("fixtures/ShortMain.class", main());

        InvisibleNameTransformer.Options options = InvisibleNameTransformer.Options.defaults();
        options.shortClassNames = true;
        options.shortMemberNames = true;
        InvisibleNameTransformer.Result result = InvisibleNameTransformer.apply(classes,
                new LinkedHashMap<>(), options);

        assertTrue(result.classesRenamed() >= 2, "both classes must be renamed");
        for (String entry : result.classes().keySet()) {
            assertFalse(entry.contains("ShortHelper") || entry.contains("ShortMain"),
                    "original class name must not survive in the jar entry: " + entry);
            String simple = InvisibleNames.simpleName(entry.substring(0, entry.length() - 6));
            String visible = simple.replaceAll("[\\u200E\\u200F\\u2060\\u0000]", "");
            assertTrue(visible.length() <= 2, "visible simple name must be <= 2 chars: " + simple);
        }

        // Behaviour: load by the new names and invoke the renamed compute() method.
        ClassLoader loader = new ClassLoader() {
            @Override
            protected Class<?> findClass(String name) throws ClassNotFoundException {
                byte[] bytes = result.classes().get(name.replace('.', '/') + ".class");
                if (bytes == null) throw new ClassNotFoundException(name);
                return defineClass(name, bytes, 0, bytes.length);
            }
        };
        int executed = 0;
        for (String entry : result.classes().keySet()) {
            String binary = entry.substring(0, entry.length() - 6).replace('/', '.');
            Class<?> type = Class.forName(binary, true, loader);
            for (var method : type.getDeclaredMethods()) {
                if (method.getParameterCount() == 0 && method.getReturnType() == int.class) {
                    method.setAccessible(true);
                    Object value = method.invoke(null);
                    assertEquals(54, value, "renamed method must keep behaviour");
                    executed++;
                }
            }
        }
        assertTrue(executed >= 2, "expected both renamed entry methods to run, got " + executed);
    }

    @Test
    void mixinClassesStillKeepNames() {
        Map<String, byte[]> classes = new LinkedHashMap<>();
        classes.put("fixtures/mixin/KeepMixin.class", mixin());
        classes.put("fixtures/PlainTarget.class", helper());

        InvisibleNameTransformer.Options options = InvisibleNameTransformer.Options.defaults();
        options.shortClassNames = true;
        options.shortMemberNames = true;
        InvisibleNameTransformer.Result result = InvisibleNameTransformer.apply(classes,
                new LinkedHashMap<>(), options);
        assertTrue(result.classes().containsKey("fixtures/mixin/KeepMixin.class"),
                "Mixin class must be byte-identical and keep its entry name");
    }

    @Test
    void shortTokenIsStableAndUnique() {
        assertNotNull(InvisibleNameTransformer.shortToken(0));
        String first = InvisibleNameTransformer.shortToken(0);
        assertEquals("a", first);
        assertEquals("b", InvisibleNameTransformer.shortToken(1));
        assertEquals("aa", InvisibleNameTransformer.shortToken(26));
        assertEquals("ab", InvisibleNameTransformer.shortToken(27));
    }

    private static byte[] helper() {
        ClassNode node = new ClassNode();
        node.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixtures/ShortHelper", null, "java/lang/Object", null);
        MethodVisitor mv = node.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "compute", "()I", null, null);
        mv.visitCode();
        mv.visitIntInsn(Opcodes.BIPUSH, 54);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(1, 0);
        mv.visitEnd();
        node.visitEnd();
        return write(node);
    }

    private static byte[] main() {
        ClassNode node = new ClassNode();
        node.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixtures/ShortMain", null, "java/lang/Object", null);
        MethodVisitor mv = node.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "compute", "()I", null, null);
        mv.visitCode();
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "fixtures/ShortHelper", "compute", "()I", false);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(1, 0);
        mv.visitEnd();
        node.visitEnd();
        return write(node);
    }

    private static byte[] mixin() {
        ClassNode node = new ClassNode();
        node.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixtures/mixin/KeepMixin", null,
                "java/lang/Object", null);
        node.visibleAnnotations = new ArrayList<>();
        node.visibleAnnotations.add(new AnnotationNode("Lorg/spongepowered/asm/mixin/Mixin;"));
        node.visitEnd();
        return write(node);
    }

    private static byte[] write(ClassNode node) {
        ClassWriter writer = new ClassWriter(0);
        node.accept(writer);
        return writer.toByteArray();
    }
}
