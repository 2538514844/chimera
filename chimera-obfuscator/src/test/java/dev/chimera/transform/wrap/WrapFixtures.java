package dev.chimera.transform.wrap;

import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;

import java.util.ArrayList;
import java.util.List;

/** ASM fixtures for {@link InvokeWrapperTest}; package-private and build-time only. */
final class WrapFixtures implements Opcodes {

    static final String MATH = "fixtures/wrap/MathApi";
    static final String CALC = "fixtures/wrap/Calc";
    static final String SUBJECT = "fixtures/wrap/Subject";
    static final String MIXIN = "fixtures/wrap/MixinSubject";
    static final String INTERFACE = "fixtures/wrap/WrapInterface";
    static final String PRIMITIVE_API = "fixtures/wrap/PrimitiveApi";
    static final String PRIMITIVE_SUBJECT = "fixtures/wrap/PrimitiveSubject";

    private WrapFixtures() {
    }

    static byte[] mathApi() {
        ClassNode node = begin(MATH, ACC_PUBLIC | ACC_SUPER | ACC_FINAL);
        node.visitField(ACC_PRIVATE | ACC_STATIC, "counter", "I", null, null).visitEnd();

        binary(node, "add", "(II)I", IADD);
        binary(node, "mul", "(II)I", IMUL);

        MethodVisitor ladd = node.visitMethod(ACC_PUBLIC | ACC_STATIC, "ladd", "(JJ)J", null, null);
        ladd.visitCode();
        ladd.visitVarInsn(LLOAD, 0);
        ladd.visitVarInsn(LLOAD, 2);
        ladd.visitInsn(LADD);
        ladd.visitInsn(LRETURN);
        ladd.visitMaxs(0, 0);
        ladd.visitEnd();

        MethodVisitor dadd = node.visitMethod(ACC_PUBLIC | ACC_STATIC, "dadd", "(DD)D", null, null);
        dadd.visitCode();
        dadd.visitVarInsn(DLOAD, 0);
        dadd.visitVarInsn(DLOAD, 2);
        dadd.visitInsn(DADD);
        dadd.visitInsn(DRETURN);
        dadd.visitMaxs(0, 0);
        dadd.visitEnd();

        MethodVisitor touch = node.visitMethod(ACC_PUBLIC | ACC_STATIC, "touch", "()V", null, null);
        touch.visitCode();
        touch.visitFieldInsn(GETSTATIC, MATH, "counter", "I");
        touch.visitInsn(ICONST_1);
        touch.visitInsn(IADD);
        touch.visitFieldInsn(PUTSTATIC, MATH, "counter", "I");
        touch.visitInsn(RETURN);
        touch.visitMaxs(0, 0);
        touch.visitEnd();

        MethodVisitor counter = node.visitMethod(ACC_PUBLIC | ACC_STATIC, "counter", "()I", null, null);
        counter.visitCode();
        counter.visitFieldInsn(GETSTATIC, MATH, "counter", "I");
        counter.visitInsn(IRETURN);
        counter.visitMaxs(0, 0);
        counter.visitEnd();

        MethodVisitor fail = node.visitMethod(ACC_PUBLIC | ACC_STATIC, "fail", "(I)I", null, null);
        fail.visitCode();
        Label ok = new Label();
        fail.visitVarInsn(ILOAD, 0);
        fail.visitJumpInsn(IFGE, ok);
        fail.visitTypeInsn(NEW, "java/lang/IllegalStateException");
        fail.visitInsn(DUP);
        fail.visitLdcInsn("math-negative");
        fail.visitMethodInsn(INVOKESPECIAL, "java/lang/IllegalStateException", "<init>",
                "(Ljava/lang/String;)V", false);
        fail.visitInsn(ATHROW);
        fail.visitLabel(ok);
        fail.visitVarInsn(ILOAD, 0);
        fail.visitInsn(IRETURN);
        fail.visitMaxs(0, 0);
        fail.visitEnd();

        return write(node);
    }

    private static void binary(ClassNode node, String name, String descriptor, int opcode) {
        MethodVisitor mv = node.visitMethod(ACC_PUBLIC | ACC_STATIC, name, descriptor, null, null);
        mv.visitCode();
        mv.visitVarInsn(ILOAD, 0);
        mv.visitVarInsn(ILOAD, 1);
        mv.visitInsn(opcode);
        mv.visitInsn(IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
    }

    static byte[] calc() {
        ClassNode node = begin(CALC, ACC_PUBLIC | ACC_SUPER);
        node.visitField(ACC_PRIVATE, "base", "I", null, null).visitEnd();

        MethodVisitor ctor = node.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null);
        ctor.visitCode();
        ctor.visitVarInsn(ALOAD, 0);
        ctor.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        ctor.visitVarInsn(ALOAD, 0);
        ctor.visitInsn(ICONST_3);
        ctor.visitFieldInsn(PUTFIELD, CALC, "base", "I");
        ctor.visitInsn(RETURN);
        ctor.visitMaxs(0, 0);
        ctor.visitEnd();

        MethodVisitor twice = node.visitMethod(ACC_PUBLIC, "twice", "(I)I", null, null);
        twice.visitCode();
        twice.visitVarInsn(ILOAD, 1);
        twice.visitInsn(ICONST_2);
        twice.visitInsn(IMUL);
        twice.visitInsn(IRETURN);
        twice.visitMaxs(0, 0);
        twice.visitEnd();

        MethodVisitor addTo = node.visitMethod(ACC_PUBLIC, "addTo", "(II)I", null, null);
        addTo.visitCode();
        addTo.visitVarInsn(ILOAD, 1);
        addTo.visitVarInsn(ILOAD, 2);
        addTo.visitInsn(IADD);
        addTo.visitVarInsn(ALOAD, 0);
        addTo.visitFieldInsn(GETFIELD, CALC, "base", "I");
        addTo.visitInsn(IADD);
        addTo.visitInsn(IRETURN);
        addTo.visitMaxs(0, 0);
        addTo.visitEnd();

        MethodVisitor failOn = node.visitMethod(ACC_PUBLIC, "failOn", "(I)I", null, null);
        failOn.visitCode();
        Label ok = new Label();
        failOn.visitVarInsn(ILOAD, 1);
        failOn.visitJumpInsn(IFGE, ok);
        failOn.visitTypeInsn(NEW, "java/lang/IllegalStateException");
        failOn.visitInsn(DUP);
        failOn.visitLdcInsn("calc-negative");
        failOn.visitMethodInsn(INVOKESPECIAL, "java/lang/IllegalStateException", "<init>",
                "(Ljava/lang/String;)V", false);
        failOn.visitInsn(ATHROW);
        failOn.visitLabel(ok);
        failOn.visitVarInsn(ILOAD, 1);
        failOn.visitInsn(ICONST_3);
        failOn.visitInsn(IMUL);
        failOn.visitInsn(IRETURN);
        failOn.visitMaxs(0, 0);
        failOn.visitEnd();

        MethodVisitor name = node.visitMethod(ACC_PUBLIC, "name", "()Ljava/lang/String;", null, null);
        name.visitCode();
        name.visitLdcInsn("calc");
        name.visitInsn(ARETURN);
        name.visitMaxs(0, 0);
        name.visitEnd();

        return write(node);
    }

    static byte[] subject() {
        ClassNode node = begin(SUBJECT, ACC_PUBLIC | ACC_SUPER);

        MethodVisitor ctor = node.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null);
        ctor.visitCode();
        ctor.visitVarInsn(ALOAD, 0);
        ctor.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        ctor.visitInsn(ICONST_2);
        ctor.visitInsn(ICONST_3);
        ctor.visitMethodInsn(INVOKESTATIC, MATH, "mul", "(II)I", false);
        ctor.visitInsn(POP);
        ctor.visitInsn(RETURN);
        ctor.visitMaxs(0, 0);
        ctor.visitEnd();

        MethodVisitor clinit = node.visitMethod(ACC_STATIC, "<clinit>", "()V", null, null);
        clinit.visitCode();
        clinit.visitInsn(ICONST_1);
        clinit.visitInsn(ICONST_2);
        clinit.visitMethodInsn(INVOKESTATIC, MATH, "add", "(II)I", false);
        clinit.visitInsn(POP);
        clinit.visitInsn(RETURN);
        clinit.visitMaxs(0, 0);
        clinit.visitEnd();

        MethodVisitor staticPath = node.visitMethod(ACC_PUBLIC | ACC_STATIC, "staticPath",
                "(II)I", null, null);
        staticPath.visitCode();
        staticPath.visitVarInsn(ILOAD, 0);
        staticPath.visitVarInsn(ILOAD, 1);
        staticPath.visitMethodInsn(INVOKESTATIC, MATH, "add", "(II)I", false);
        staticPath.visitVarInsn(ILOAD, 0);
        staticPath.visitVarInsn(ILOAD, 1);
        staticPath.visitInsn(ISUB);
        staticPath.visitMethodInsn(INVOKESTATIC, "java/lang/Math", "abs", "(I)I", false);
        staticPath.visitInsn(IADD);
        staticPath.visitInsn(IRETURN);
        staticPath.visitMaxs(0, 0);
        staticPath.visitEnd();

        MethodVisitor virtualPath = node.visitMethod(ACC_PUBLIC | ACC_STATIC, "virtualPath",
                "(L" + CALC + ";I)I", null, null);
        virtualPath.visitCode();
        virtualPath.visitVarInsn(ALOAD, 0);
        virtualPath.visitVarInsn(ILOAD, 1);
        virtualPath.visitMethodInsn(INVOKEVIRTUAL, CALC, "twice", "(I)I", false);
        virtualPath.visitVarInsn(ALOAD, 0);
        virtualPath.visitVarInsn(ILOAD, 1);
        virtualPath.visitInsn(ICONST_1);
        virtualPath.visitMethodInsn(INVOKEVIRTUAL, CALC, "addTo", "(II)I", false);
        virtualPath.visitInsn(IADD);
        virtualPath.visitInsn(IRETURN);
        virtualPath.visitMaxs(0, 0);
        virtualPath.visitEnd();

        MethodVisitor branchy = node.visitMethod(ACC_PUBLIC | ACC_STATIC, "branchy", "(I)I", null, null);
        branchy.visitCode();
        Label negative = new Label();
        branchy.visitVarInsn(ILOAD, 0);
        branchy.visitJumpInsn(IFLE, negative);
        branchy.visitVarInsn(ILOAD, 0);
        branchy.visitInsn(ICONST_2);
        branchy.visitMethodInsn(INVOKESTATIC, MATH, "mul", "(II)I", false);
        branchy.visitInsn(IRETURN);
        branchy.visitLabel(negative);
        branchy.visitVarInsn(ILOAD, 0);
        branchy.visitInsn(ICONST_3);
        branchy.visitMethodInsn(INVOKESTATIC, MATH, "add", "(II)I", false);
        branchy.visitInsn(IRETURN);
        branchy.visitMaxs(0, 0);
        branchy.visitEnd();

        MethodVisitor loopy = node.visitMethod(ACC_PUBLIC | ACC_STATIC, "loopy", "(I)I", null, null);
        loopy.visitCode();
        loopy.visitInsn(ICONST_0);
        loopy.visitVarInsn(ISTORE, 1);
        loopy.visitInsn(ICONST_0);
        loopy.visitVarInsn(ISTORE, 2);
        Label loop = new Label();
        Label end = new Label();
        loopy.visitLabel(loop);
        loopy.visitVarInsn(ILOAD, 1);
        loopy.visitVarInsn(ILOAD, 0);
        loopy.visitJumpInsn(IF_ICMPGE, end);
        loopy.visitVarInsn(ILOAD, 2);
        loopy.visitVarInsn(ILOAD, 1);
        loopy.visitMethodInsn(INVOKESTATIC, MATH, "add", "(II)I", false);
        loopy.visitVarInsn(ISTORE, 2);
        loopy.visitIincInsn(1, 1);
        loopy.visitJumpInsn(GOTO, loop);
        loopy.visitLabel(end);
        loopy.visitVarInsn(ILOAD, 2);
        loopy.visitInsn(IRETURN);
        loopy.visitMaxs(0, 0);
        loopy.visitEnd();

        MethodVisitor exceptionPath = node.visitMethod(ACC_PUBLIC | ACC_STATIC, "exceptionPath",
                "(L" + CALC + ";I)Ljava/lang/String;", null, null);
        exceptionPath.visitCode();
        exceptionPath.visitVarInsn(ALOAD, 0);
        exceptionPath.visitVarInsn(ILOAD, 1);
        exceptionPath.visitMethodInsn(INVOKEVIRTUAL, CALC, "failOn", "(I)I", false);
        exceptionPath.visitMethodInsn(INVOKESTATIC, "java/lang/String", "valueOf",
                "(I)Ljava/lang/String;", false);
        exceptionPath.visitInsn(ARETURN);
        exceptionPath.visitMaxs(0, 0);
        exceptionPath.visitEnd();

        MethodVisitor selfPath = node.visitMethod(ACC_PUBLIC | ACC_STATIC, "selfPath", "(I)I", null, null);
        selfPath.visitCode();
        selfPath.visitVarInsn(ILOAD, 0);
        selfPath.visitMethodInsn(INVOKESTATIC, SUBJECT, "helper", "(I)I", false);
        selfPath.visitInsn(ICONST_5);
        selfPath.visitInsn(IADD);
        selfPath.visitInsn(IRETURN);
        selfPath.visitMaxs(0, 0);
        selfPath.visitEnd();

        MethodVisitor helper = node.visitMethod(ACC_PUBLIC | ACC_STATIC, "helper", "(I)I", null, null);
        helper.visitCode();
        helper.visitVarInsn(ILOAD, 0);
        helper.visitInsn(ICONST_1);
        helper.visitInsn(IADD);
        helper.visitInsn(IRETURN);
        helper.visitMaxs(0, 0);
        helper.visitEnd();

        MethodVisitor reflectionPath = node.visitMethod(ACC_PUBLIC | ACC_STATIC, "reflectionPath",
                "(Ljava/lang/String;)I", null, null);
        reflectionPath.visitCode();
        reflectionPath.visitLdcInsn("java.lang.String");
        reflectionPath.visitMethodInsn(INVOKESTATIC, "java/lang/Class", "forName",
                "(Ljava/lang/String;)Ljava/lang/Class;", false);
        reflectionPath.visitInsn(POP);
        reflectionPath.visitInsn(ICONST_0);
        reflectionPath.visitInsn(IRETURN);
        reflectionPath.visitMaxs(0, 0);
        reflectionPath.visitEnd();

        MethodVisitor longPath = node.visitMethod(ACC_PUBLIC | ACC_STATIC, "longPath",
                "(JJ)J", null, null);
        longPath.visitCode();
        longPath.visitVarInsn(LLOAD, 0);
        longPath.visitVarInsn(LLOAD, 2);
        longPath.visitMethodInsn(INVOKESTATIC, MATH, "ladd", "(JJ)J", false);
        longPath.visitInsn(LRETURN);
        longPath.visitMaxs(0, 0);
        longPath.visitEnd();

        MethodVisitor doublePath = node.visitMethod(ACC_PUBLIC | ACC_STATIC, "doublePath",
                "(DD)D", null, null);
        doublePath.visitCode();
        doublePath.visitVarInsn(DLOAD, 0);
        doublePath.visitVarInsn(DLOAD, 2);
        doublePath.visitMethodInsn(INVOKESTATIC, MATH, "dadd", "(DD)D", false);
        doublePath.visitInsn(DRETURN);
        doublePath.visitMaxs(0, 0);
        doublePath.visitEnd();

        MethodVisitor voidPath = node.visitMethod(ACC_PUBLIC | ACC_STATIC, "voidPath", "()V", null, null);
        voidPath.visitCode();
        voidPath.visitMethodInsn(INVOKESTATIC, MATH, "touch", "()V", false);
        voidPath.visitInsn(RETURN);
        voidPath.visitMaxs(0, 0);
        voidPath.visitEnd();

        return write(node);
    }

    static byte[] mixinSubject() {
        ClassNode node = begin(MIXIN, ACC_PUBLIC | ACC_SUPER);
        node.visibleAnnotations = new ArrayList<>(List.of(
                new AnnotationNode("Lorg/spongepowered/asm/mixin/Mixin;")));

        MethodVisitor call = node.visitMethod(ACC_PUBLIC | ACC_STATIC, "call", "(I)I", null, null);
        call.visitCode();
        call.visitVarInsn(ILOAD, 0);
        call.visitInsn(ICONST_1);
        call.visitMethodInsn(INVOKESTATIC, MATH, "add", "(II)I", false);
        call.visitInsn(IRETURN);
        call.visitMaxs(0, 0);
        call.visitEnd();

        MethodVisitor callCalc = node.visitMethod(ACC_PUBLIC | ACC_STATIC, "callCalc",
                "(L" + CALC + ";I)I", null, null);
        callCalc.visitCode();
        callCalc.visitVarInsn(ALOAD, 0);
        callCalc.visitVarInsn(ILOAD, 1);
        callCalc.visitMethodInsn(INVOKEVIRTUAL, CALC, "twice", "(I)I", false);
        callCalc.visitInsn(IRETURN);
        callCalc.visitMaxs(0, 0);
        callCalc.visitEnd();

        return write(node);
    }

    static byte[] wrapInterface() {
        ClassNode node = begin(INTERFACE, ACC_PUBLIC | ACC_INTERFACE | ACC_ABSTRACT);
        MethodVisitor viaStatic = node.visitMethod(ACC_PUBLIC | ACC_STATIC, "viaStatic", "(I)I", null, null);
        viaStatic.visitCode();
        viaStatic.visitVarInsn(ILOAD, 0);
        viaStatic.visitInsn(ICONST_2);
        viaStatic.visitMethodInsn(INVOKESTATIC, MATH, "mul", "(II)I", false);
        viaStatic.visitInsn(IRETURN);
        viaStatic.visitMaxs(0, 0);
        viaStatic.visitEnd();
        return write(node);
    }

    static byte[] primitiveApi() {
        ClassNode node = begin(PRIMITIVE_API, ACC_PUBLIC | ACC_SUPER | ACC_FINAL);

        MethodVisitor flag = node.visitMethod(ACC_PUBLIC | ACC_STATIC, "flag", "(I)Z", null, null);
        flag.visitCode();
        Label notPositive = new Label();
        flag.visitVarInsn(ILOAD, 0);
        flag.visitJumpInsn(IFLE, notPositive);
        flag.visitInsn(ICONST_1);
        flag.visitInsn(IRETURN);
        flag.visitLabel(notPositive);
        flag.visitInsn(ICONST_0);
        flag.visitInsn(IRETURN);
        flag.visitMaxs(0, 0);
        flag.visitEnd();

        MethodVisitor not = node.visitMethod(ACC_PUBLIC | ACC_STATIC, "not", "(Z)Z", null, null);
        not.visitCode();
        Label wasFalse = new Label();
        not.visitVarInsn(ILOAD, 0);
        not.visitJumpInsn(IFEQ, wasFalse);
        not.visitInsn(ICONST_0);
        not.visitInsn(IRETURN);
        not.visitLabel(wasFalse);
        not.visitInsn(ICONST_1);
        not.visitInsn(IRETURN);
        not.visitMaxs(0, 0);
        not.visitEnd();

        identity(node, "byteValue", "(B)B", ILOAD);
        identity(node, "charValue", "(C)C", ILOAD);
        identity(node, "shortValue", "(S)S", ILOAD);
        return write(node);
    }

    private static void identity(ClassNode node, String name, String descriptor, int loadOpcode) {
        MethodVisitor mv = node.visitMethod(ACC_PUBLIC | ACC_STATIC, name, descriptor, null, null);
        mv.visitCode();
        mv.visitVarInsn(loadOpcode, 0);
        mv.visitInsn(IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
    }

    static byte[] primitiveSubject() {
        ClassNode node = begin(PRIMITIVE_SUBJECT, ACC_PUBLIC | ACC_SUPER);
        primitivePath(node, "flagPath", "(I)Z", "flag", "(I)Z", ILOAD);
        primitivePath(node, "notPath", "(Z)Z", "not", "(Z)Z", ILOAD);
        primitivePath(node, "bytePath", "(B)B", "byteValue", "(B)B", ILOAD);
        primitivePath(node, "charPath", "(C)C", "charValue", "(C)C", ILOAD);
        primitivePath(node, "shortPath", "(S)S", "shortValue", "(S)S", ILOAD);
        return write(node);
    }

    private static void primitivePath(ClassNode node, String name, String descriptor,
                                      String target, String targetDescriptor, int loadOpcode) {
        MethodVisitor mv = node.visitMethod(ACC_PUBLIC | ACC_STATIC, name, descriptor, null, null);
        mv.visitCode();
        mv.visitVarInsn(loadOpcode, 0);
        mv.visitMethodInsn(INVOKESTATIC, PRIMITIVE_API, target, targetDescriptor, false);
        mv.visitInsn(IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
    }

    private static ClassNode begin(String name, int access) {
        ClassNode node = new ClassNode();
        node.visit(V17, access, name, null, "java/lang/Object", null);
        return node;
    }

    private static byte[] write(ClassNode node) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        node.accept(writer);
        return writer.toByteArray();
    }
}
