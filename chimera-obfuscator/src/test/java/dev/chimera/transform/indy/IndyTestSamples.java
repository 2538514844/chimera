package dev.chimera.transform.indy;

import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * ASM-built fixtures for M10 tests. No bytecode is hand-copied from javac output: every class is
 * generated explicitly so the expected invoke-site statistics are auditable.
 */
final class IndyTestSamples implements Opcodes {

    static final String MATH = "sample/MathOps";
    static final String CALC_API = "sample/CalcApi";
    static final String CALC = "sample/Calc";
    static final String SUBJECT = "sample/Subject";
    static final String BRIDGE_SUBJECT = "sample/BridgeSubject";
    static final String OBJECT = "java/lang/Object";

    private IndyTestSamples() {
    }

    static Map<String, byte[]> originalClasses() {
        Map<String, byte[]> classes = new LinkedHashMap<>();
        classes.put(MATH, mathOps());
        classes.put(CALC_API, calcApi());
        classes.put(CALC, calc());
        classes.put(SUBJECT, subject());
        return classes;
    }

    static byte[] mathOps() {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(V17, ACC_PUBLIC | ACC_FINAL | ACC_SUPER, MATH, null, OBJECT, null);
        cw.visitField(ACC_PUBLIC | ACC_STATIC | ACC_FINAL, "SEED", "I", null, Integer.valueOf(11))
                .visitEnd();
        constructor(cw);
        MethodVisitor mv = cw.visitMethod(ACC_PUBLIC | ACC_STATIC, "add", "(II)I", null, null);
        mv.visitCode();
        mv.visitVarInsn(ILOAD, 0);
        mv.visitVarInsn(ILOAD, 1);
        mv.visitInsn(IADD);
        mv.visitIntInsn(BIPUSH, 7);
        mv.visitInsn(IADD);
        mv.visitInsn(IRETURN);
        mv.visitMaxs(2, 2);
        mv.visitEnd();

        mv = cw.visitMethod(ACC_PUBLIC | ACC_STATIC, "mul", "(II)I", null, null);
        mv.visitCode();
        mv.visitVarInsn(ILOAD, 0);
        mv.visitVarInsn(ILOAD, 1);
        mv.visitInsn(IMUL);
        mv.visitIntInsn(BIPUSH, 3);
        mv.visitInsn(ISUB);
        mv.visitInsn(IRETURN);
        mv.visitMaxs(2, 2);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    static byte[] calcApi() {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(V17, ACC_PUBLIC | ACC_ABSTRACT | ACC_INTERFACE, CALC_API, null, OBJECT, null);
        MethodVisitor mv = cw.visitMethod(ACC_PUBLIC | ACC_ABSTRACT, "twice", "(I)I", null, null);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    static byte[] calc() {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(V17, ACC_PUBLIC | ACC_FINAL | ACC_SUPER, CALC, null, OBJECT,
                new String[]{CALC_API});
        constructor(cw);
        MethodVisitor mv = cw.visitMethod(ACC_PUBLIC, "twice", "(I)I", null, null);
        mv.visitCode();
        mv.visitVarInsn(ILOAD, 1);
        mv.visitInsn(ICONST_2);
        mv.visitInsn(IMUL);
        mv.visitInsn(IRETURN);
        mv.visitMaxs(2, 2);
        mv.visitEnd();

        mv = cw.visitMethod(ACC_PUBLIC | ACC_STATIC, "make", "()L" + CALC + ";", null, null);
        mv.visitCode();
        mv.visitTypeInsn(NEW, CALC);
        mv.visitInsn(DUP);
        mv.visitMethodInsn(INVOKESPECIAL, CALC, "<init>", "()V", false);
        mv.visitInsn(ARETURN);
        mv.visitMaxs(2, 0);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    static byte[] subject() {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(V17, ACC_PUBLIC | ACC_FINAL | ACC_SUPER, SUBJECT, null, OBJECT, null);

        // <init>: one Object.<init> special call + one static MathOps.add call.
        MethodVisitor mv = cw.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null);
        mv.visitCode();
        mv.visitVarInsn(ALOAD, 0);
        mv.visitMethodInsn(INVOKESPECIAL, OBJECT, "<init>", "()V", false);
        mv.visitInsn(ICONST_1);
        mv.visitInsn(ICONST_2);
        mv.visitMethodInsn(INVOKESTATIC, MATH, "add", "(II)I", false);
        mv.visitInsn(POP);
        mv.visitInsn(RETURN);
        mv.visitMaxs(2, 1);
        mv.visitEnd();

        // <clinit>: one static call.
        mv = cw.visitMethod(ACC_STATIC, "<clinit>", "()V", null, null);
        mv.visitCode();
        mv.visitInsn(ICONST_3);
        mv.visitInsn(ICONST_4);
        mv.visitMethodInsn(INVOKESTATIC, MATH, "add", "(II)I", false);
        mv.visitInsn(POP);
        mv.visitInsn(RETURN);
        mv.visitMaxs(2, 0);
        mv.visitEnd();

        // staticPath: two rewrite-eligible static calls.
        mv = cw.visitMethod(ACC_PUBLIC | ACC_STATIC, "staticPath", "(II)I", null, null);
        mv.visitCode();
        mv.visitVarInsn(ILOAD, 0);
        mv.visitVarInsn(ILOAD, 1);
        mv.visitMethodInsn(INVOKESTATIC, MATH, "add", "(II)I", false);
        mv.visitInsn(ICONST_2);
        mv.visitMethodInsn(INVOKESTATIC, MATH, "mul", "(II)I", false);
        mv.visitInsn(IRETURN);
        mv.visitMaxs(2, 2);
        mv.visitEnd();

        // ctorPath: constructor call (skipped) + virtual call (rewritten).
        mv = cw.visitMethod(ACC_PUBLIC | ACC_STATIC, "ctorPath", "(I)I", null, null);
        mv.visitCode();
        mv.visitTypeInsn(NEW, CALC);
        mv.visitInsn(DUP);
        mv.visitMethodInsn(INVOKESPECIAL, CALC, "<init>", "()V", false);
        mv.visitVarInsn(ASTORE, 1);
        mv.visitVarInsn(ALOAD, 1);
        mv.visitVarInsn(ILOAD, 0);
        mv.visitMethodInsn(INVOKEVIRTUAL, CALC, "twice", "(I)I", false);
        mv.visitInsn(IRETURN);
        mv.visitMaxs(2, 2);
        mv.visitEnd();

        // interfacePath: invokeinterface (rewritten).
        mv = cw.visitMethod(ACC_PUBLIC | ACC_STATIC, "interfacePath", "(L" + CALC_API + ";I)I", null, null);
        mv.visitCode();
        mv.visitVarInsn(ALOAD, 0);
        mv.visitVarInsn(ILOAD, 1);
        mv.visitMethodInsn(INVOKEINTERFACE, CALC_API, "twice", "(I)I", true);
        mv.visitInsn(IRETURN);
        mv.visitMaxs(2, 2);
        mv.visitEnd();

        // reflectionPath: reflection-sensitive target (skipped).
        mv = cw.visitMethod(ACC_PUBLIC | ACC_STATIC, "reflectionPath", "(Ljava/lang/String;)I", null, null);
        mv.visitCode();
        mv.visitVarInsn(ALOAD, 0);
        mv.visitMethodInsn(INVOKESTATIC, "java/lang/Class", "forName",
                "(Ljava/lang/String;)Ljava/lang/Class;", false);
        mv.visitInsn(POP);
        mv.visitInsn(ICONST_5);
        mv.visitInsn(IRETURN);
        mv.visitMaxs(1, 1);
        mv.visitEnd();

        // superPath: non-constructor invokespecial (skipped as SPECIAL_CALL).
        mv = cw.visitMethod(ACC_PUBLIC, "superPath", "()Ljava/lang/String;", null, null);
        mv.visitCode();
        mv.visitVarInsn(ALOAD, 0);
        mv.visitMethodInsn(INVOKESPECIAL, OBJECT, "toString", "()Ljava/lang/String;", false);
        mv.visitInsn(ARETURN);
        mv.visitMaxs(1, 1);
        mv.visitEnd();

        // selfPath: static self call (rewritten).
        mv = cw.visitMethod(ACC_PUBLIC | ACC_STATIC, "selfPath", "(I)I", null, null);
        mv.visitCode();
        mv.visitVarInsn(ILOAD, 0);
        mv.visitInsn(ICONST_3);
        mv.visitMethodInsn(INVOKESTATIC, SUBJECT, "staticPath", "(II)I", false);
        mv.visitInsn(IRETURN);
        mv.visitMaxs(2, 1);
        mv.visitEnd();

        // instancePath: static self call from an instance method (rewritten).
        mv = cw.visitMethod(ACC_PUBLIC, "instancePath", "(I)I", null, null);
        mv.visitCode();
        mv.visitVarInsn(ILOAD, 1);
        mv.visitInsn(ICONST_3);
        mv.visitMethodInsn(INVOKESTATIC, SUBJECT, "staticPath", "(II)I", false);
        mv.visitInsn(IRETURN);
        mv.visitMaxs(2, 2);
        mv.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }

    /**
     * Mixin-annotated class: every invoke site must be skipped. Carries a class Signature,
     * SourceFile, LineNumberTable and LocalVariableTable so the tests can prove that Mixin bytes
     * are preserved verbatim (Signature/debug attributes must survive for Mixin runtime processing).
     */
    static byte[] bridgeSubject() {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(V17, ACC_PUBLIC | ACC_SUPER, BRIDGE_SUBJECT,
                "Ljava/lang/Object;", OBJECT, null);
        cw.visitSource("BridgeSubject.java", null);
        cw.visitAnnotation("Lorg/spongepowered/asm/mixin/Mixin;", true).visitEnd();
        MethodVisitor mv = cw.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null);
        mv.visitCode();
        org.objectweb.asm.Label ctorStart = new org.objectweb.asm.Label();
        org.objectweb.asm.Label ctorEnd = new org.objectweb.asm.Label();
        mv.visitLabel(ctorStart);
        mv.visitLineNumber(1, ctorStart);
        mv.visitVarInsn(ALOAD, 0);
        mv.visitMethodInsn(INVOKESPECIAL, OBJECT, "<init>", "()V", false);
        mv.visitInsn(RETURN);
        mv.visitLabel(ctorEnd);
        mv.visitLocalVariable("this", "L" + BRIDGE_SUBJECT + ";", null, ctorStart, ctorEnd, 0);
        mv.visitMaxs(1, 1);
        mv.visitEnd();
        mv = cw.visitMethod(ACC_PUBLIC | ACC_STATIC, "run", "()I", null, null);
        mv.visitCode();
        org.objectweb.asm.Label runStart = new org.objectweb.asm.Label();
        org.objectweb.asm.Label runEnd = new org.objectweb.asm.Label();
        mv.visitLabel(runStart);
        mv.visitLineNumber(2, runStart);
        mv.visitIntInsn(BIPUSH, 4);
        mv.visitIntInsn(BIPUSH, 5);
        mv.visitMethodInsn(INVOKESTATIC, MATH, "add", "(II)I", false);
        mv.visitInsn(IRETURN);
        mv.visitLabel(runEnd);
        mv.visitLocalVariable("unused", "I", null, runStart, runEnd, 0);
        mv.visitMaxs(2, 0);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    private static void constructor(ClassWriter cw) {
        MethodVisitor mv = cw.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null);
        mv.visitCode();
        mv.visitVarInsn(ALOAD, 0);
        mv.visitMethodInsn(INVOKESPECIAL, OBJECT, "<init>", "()V", false);
        mv.visitInsn(RETURN);
        mv.visitMaxs(1, 1);
        mv.visitEnd();
    }
}
