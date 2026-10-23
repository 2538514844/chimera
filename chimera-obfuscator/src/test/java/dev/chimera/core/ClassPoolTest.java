package dev.chimera.core;

import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.lang.reflect.Method;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClassPoolTest {
    private static final int PUBLIC = Opcodes.ACC_PUBLIC;
    private static final int INTERFACE = Opcodes.ACC_PUBLIC | Opcodes.ACC_INTERFACE | Opcodes.ACC_ABSTRACT;

    private static byte[] classBytes(String name, String superName, String[] interfaces, int access) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, access, name, null, superName, interfaces);
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static ClassPool samplePool() {
        Map<String, byte[]> classes = new LinkedHashMap<>();
        // Keys use the engine's "pkg/C.class" form; ClassPool must normalize them.
        classes.put("pkg/Base.class", classBytes("pkg/Base", "java/lang/Object", null, PUBLIC));
        classes.put("pkg/Middle.class", classBytes("pkg/Middle", "pkg/Base", null, PUBLIC));
        classes.put("pkg/Impl.class", classBytes("pkg/Impl", "pkg/Middle", new String[]{"pkg/IChild"}, PUBLIC));
        classes.put("pkg/Other.class", classBytes("pkg/Other", "java/lang/Object", null, PUBLIC));
        classes.put("pkg/IFace.class", classBytes("pkg/IFace", "java/lang/Object", null, INTERFACE));
        classes.put("pkg/IChild.class", classBytes("pkg/IChild", "java/lang/Object", new String[]{"pkg/IFace"}, INTERFACE));
        return new ClassPool(classes);
    }

    @Test
    void normalizesKeysAndParsesHeaders() {
        ClassPool pool = samplePool();
        assertTrue(pool.has("pkg/Base"));
        assertTrue(pool.has("pkg/Impl"));
        assertFalse(pool.has("pkg/Missing"));
        assertEquals("pkg/Base", pool.superName("pkg/Middle"));
        assertEquals("pkg/IChild", pool.interfaces("pkg/Impl").get(0));
        assertEquals(List.of("pkg/IFace"), pool.interfaces("pkg/IChild"));
        assertTrue(pool.interfaces("pkg/Base").isEmpty());
    }

    @Test
    void resolvesJdkHierarchyWithoutInitializingClasses() {
        ClassPool pool = samplePool();
        assertTrue(pool.has("java/lang/String"));
        assertNull(pool.superName("java/lang/Object"));
        assertEquals("java/lang/Object", pool.superName("java/lang/String"));
        assertEquals("java/util/AbstractList", pool.superName("java/util/ArrayList"));
        assertTrue(pool.isAssignable("java/util/ArrayList", "java/util/List"));
        assertTrue(pool.isAssignable("java/util/ArrayList", "java/lang/Iterable"));
        assertTrue(pool.isAssignable("java/lang/String", "java/io/Serializable"));
        assertFalse(pool.has("does/not/Exist"));
        assertFalse(pool.isAssignable("java/lang/String", "java/util/List"));
    }

    @Test
    void assignabilityFollowsSuperclassAndInterfaceChains() {
        ClassPool pool = samplePool();
        assertTrue(pool.isAssignable("pkg/Impl", "pkg/Impl"));
        assertTrue(pool.isAssignable("pkg/Impl", "pkg/Middle"));
        assertTrue(pool.isAssignable("pkg/Impl", "pkg/Base"));
        assertTrue(pool.isAssignable("pkg/Impl", "java/lang/Object"));
        assertTrue(pool.isAssignable("pkg/Impl", "pkg/IChild"));
        assertTrue(pool.isAssignable("pkg/Impl", "pkg/IFace"));
        assertTrue(pool.isAssignable("pkg/IChild", "pkg/IFace"));
        assertFalse(pool.isAssignable("pkg/Base", "pkg/Impl"));
        assertFalse(pool.isAssignable("pkg/IFace", "pkg/IChild"));
        assertFalse(pool.isAssignable("pkg/Other", "pkg/Base"));
        assertFalse(pool.isAssignable(null, "pkg/Base"));
        assertFalse(pool.isAssignable("pkg/Base", null));
    }

    @Test
    void commonSuperClassUsesHierarchyAndInterfaces() {
        ClassPool pool = samplePool();
        assertEquals("pkg/Impl", pool.commonSuperClass("pkg/Impl", "pkg/Impl"));
        assertEquals("pkg/Middle", pool.commonSuperClass("pkg/Impl", "pkg/Middle"));
        assertEquals("pkg/Middle", pool.commonSuperClass("pkg/Middle", "pkg/Impl"));
        assertEquals("pkg/Base", pool.commonSuperClass("pkg/Middle", "pkg/Base"));
        assertEquals("java/lang/Object", pool.commonSuperClass("pkg/Impl", "pkg/Other"));
        assertEquals("java/lang/Object", pool.commonSuperClass("pkg/IChild", "pkg/Base"));
        assertEquals("java/lang/Object", pool.commonSuperClass("pkg/Impl", "missing/Type"));
        assertEquals("java/lang/Object", pool.commonSuperClass("missing/Type", "missing/Other"));
        assertEquals("java/util/AbstractList",
                pool.commonSuperClass("java/util/ArrayList", "java/util/LinkedList"));
    }

    @Test
    void handlesArrayTypes() {
        ClassPool pool = samplePool();
        assertEquals("[Ljava/lang/Object;", pool.commonSuperClass("[Ljava/lang/String;", "[Ljava/lang/Integer;"));
        assertEquals("java/lang/Object", pool.commonSuperClass("[Ljava/lang/String;", "java/lang/Object"));
        assertTrue(pool.isAssignable("[Ljava/lang/String;", "java/lang/Object"));
        assertTrue(pool.isAssignable("[Ljava/lang/String;", "java/lang/Cloneable"));
        assertTrue(pool.isAssignable("[Ljava/lang/String;", "[Ljava/lang/CharSequence;"));
        assertTrue(pool.isAssignable("[[Ljava/lang/String;", "[[Ljava/lang/Object;"));
        assertFalse(pool.isAssignable("java/lang/String", "[Ljava/lang/Object;"));
        assertFalse(pool.isAssignable("[I", "[J"));
        assertEquals("java/lang/Object", pool.commonSuperClass("[I", "[J"));
    }

    @Test
    void classWriterDelegatesToPool() {
        ClassPool pool = samplePool();
        ChimeraClassWriter writer = new ChimeraClassWriter(0, pool);
        assertEquals("pkg/Middle", writer.getCommonSuperClass("pkg/Impl", "pkg/Middle"));
        assertEquals("java/lang/Object", writer.getCommonSuperClass("pkg/Impl", "pkg/Other"));
    }

    private static byte[] bean(String name) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V17, PUBLIC, name, null, "java/lang/Object", null);
        MethodVisitor mv = writer.visitMethod(PUBLIC, "<init>", "()V", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(1, 1);
        mv.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] mergeClass(ClassPool pool) {
        ClassWriter writer = new ChimeraClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS, pool);
        writer.visit(Opcodes.V17, PUBLIC, "pkg/Merge", null, "java/lang/Object", null);
        MethodVisitor mv = writer.visitMethod(PUBLIC | Opcodes.ACC_STATIC, "pick", "(Z)Ljava/lang/Object;", null, null);
        mv.visitCode();
        Label elseLabel = new Label();
        Label endLabel = new Label();
        mv.visitVarInsn(Opcodes.ILOAD, 0);
        mv.visitJumpInsn(Opcodes.IFEQ, elseLabel);
        mv.visitTypeInsn(Opcodes.NEW, "pkg/A");
        mv.visitInsn(Opcodes.DUP);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "pkg/A", "<init>", "()V", false);
        mv.visitJumpInsn(Opcodes.GOTO, endLabel);
        mv.visitLabel(elseLabel);
        mv.visitTypeInsn(Opcodes.NEW, "pkg/B");
        mv.visitInsn(Opcodes.DUP);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "pkg/B", "<init>", "()V", false);
        mv.visitLabel(endLabel);
        mv.visitInsn(Opcodes.ARETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    @Test
    void classWriterComputesFramesUsingPoolHierarchy() throws Exception {
        byte[] a = bean("pkg/A");
        byte[] b = bean("pkg/B");
        Map<String, byte[]> classes = new LinkedHashMap<>();
        classes.put("pkg/A.class", a);
        classes.put("pkg/B.class", b);
        ClassPool pool = new ClassPool(classes);

        Map<String, byte[]> definitions = new LinkedHashMap<>();
        definitions.put("pkg/A", a);
        definitions.put("pkg/B", b);
        definitions.put("pkg/Merge", mergeClass(pool));

        ClassLoader loader = new ClassLoader(ClassPoolTest.class.getClassLoader()) {
            @Override
            protected Class<?> findClass(String name) throws ClassNotFoundException {
                byte[] bytes = definitions.get(name.replace('.', '/'));
                if (bytes == null) {
                    return super.findClass(name);
                }
                return defineClass(name, bytes, 0, bytes.length);
            }
        };

        Class<?> mergeType = Class.forName("pkg.Merge", true, loader);
        Method pick = mergeType.getMethod("pick", boolean.class);
        Object left = pick.invoke(null, true);
        Object right = pick.invoke(null, false);
        assertEquals("pkg.A", left.getClass().getName());
        assertEquals("pkg.B", right.getClass().getName());
        assertTrue(left.getClass().getClassLoader() == loader);
    }
}
