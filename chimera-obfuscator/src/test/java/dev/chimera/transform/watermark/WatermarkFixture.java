package dev.chimera.transform.watermark;

import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.util.LinkedHashMap;
import java.util.Map;

/** Small ASM-generated classes used by the watermark tests. */
final class WatermarkFixture implements Opcodes {

    static final String ALPHA = "com/example/Alpha";
    static final String BETA = "com/example/Beta";
    static final String GAMMA = "com/example/Gamma";
    static final String MIXIN_TARGET = "com/example/MixinTarget";

    private WatermarkFixture() {
    }

    static Map<String, byte[]> classes() {
        Map<String, byte[]> classes = new LinkedHashMap<>();
        classes.put(ALPHA + ".class", createClass(ALPHA, false, true, true));
        classes.put(BETA + ".class", createClass(BETA, false, true, false));
        classes.put(GAMMA + ".class", createClass(GAMMA, false, false, false));
        classes.put(MIXIN_TARGET + ".class", createClass(MIXIN_TARGET, true, true, false));
        return classes;
    }

    private static byte[] createClass(String name, boolean mixin, boolean rich, boolean generic) {
        ClassWriter writer = new ClassWriter(0);
        String signature = mixin ? "<T:Ljava/lang/Object;>Ljava/lang/Object;"
                : (generic ? "<T:Ljava/lang/Object;>Ljava/lang/Object;" : null);
        writer.visit(V17, ACC_PUBLIC | ACC_SUPER, name, signature,
                "java/lang/Object", null);
        writer.visitSource(simpleName(name) + ".java", null);
        if (mixin) {
            AnnotationVisitor annotation = writer.visitAnnotation(
                    "Lorg/spongepowered/asm/mixin/Mixin;", true);
            annotation.visit("value", "com/example/Target");
            annotation.visitEnd();
        }

        if (rich) {
            writer.visitField(ACC_PRIVATE, "zeta", "I", null, null).visitEnd();
            writer.visitField(ACC_PRIVATE, "alpha", "Ljava/lang/String;", null, null).visitEnd();
            writer.visitField(ACC_PROTECTED, "middle", "J", null, null).visitEnd();
        } else {
            writer.visitField(ACC_PRIVATE, "zeta", "I", null, null).visitEnd();
        }
        if (mixin) {
            writer.visitField(ACC_PUBLIC, "target", "I", null, null).visitEnd();
        }

        writeConstructor(writer);
        if (rich) {
            writeIntMethod(writer, "zeta", 7, 11);
            writeIntMethod(writer, "alpha", 3, 12);
            writeMiddle(writer);
            writeCompute(writer);
        } else {
            writeIntMethod(writer, "only", 1, 13);
        }
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static void writeConstructor(ClassWriter writer) {
        MethodVisitor method = writer.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null);
        method.visitCode();
        Label start = new Label();
        method.visitLabel(start);
        method.visitLineNumber(1, start);
        method.visitVarInsn(ALOAD, 0);
        method.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        method.visitInsn(RETURN);
        Label end = new Label();
        method.visitLabel(end);
        method.visitLocalVariable("this", "L" + "java/lang/Object" + ";", null, start, end, 0);
        method.visitMaxs(1, 1);
        method.visitEnd();
    }

    private static void writeIntMethod(ClassWriter writer, String name, int value, int line) {
        MethodVisitor method = writer.visitMethod(ACC_PUBLIC, name, "()I", null, null);
        method.visitCode();
        Label start = new Label();
        method.visitLabel(start);
        method.visitLineNumber(line, start);
        method.visitIntInsn(BIPUSH, value);
        method.visitInsn(IRETURN);
        method.visitMaxs(1, 1);
        method.visitEnd();
    }

    private static void writeMiddle(ClassWriter writer) {
        MethodVisitor method = writer.visitMethod(ACC_PUBLIC, "middle", "(I)I", null, null);
        method.visitCode();
        Label start = new Label();
        Label end = new Label();
        method.visitLabel(start);
        method.visitLineNumber(42, start);
        method.visitVarInsn(ILOAD, 1);
        method.visitInsn(ICONST_1);
        method.visitInsn(IADD);
        method.visitInsn(IRETURN);
        method.visitLabel(end);
        method.visitLocalVariable("x", "I", null, start, end, 1);
        method.visitMaxs(2, 2);
        method.visitEnd();
    }

    private static void writeCompute(ClassWriter writer) {
        MethodVisitor method = writer.visitMethod(ACC_PUBLIC, "compute",
                "(Ljava/lang/String;)Ljava/lang/String;", null, null);
        method.visitCode();
        Label start = new Label();
        method.visitLabel(start);
        method.visitLineNumber(77, start);
        method.visitVarInsn(ALOAD, 1);
        method.visitInsn(ARETURN);
        method.visitMaxs(1, 2);
        method.visitEnd();
    }

    private static String simpleName(String internalName) {
        int slash = internalName.lastIndexOf('/');
        return slash < 0 ? internalName : internalName.substring(slash + 1);
    }
}
