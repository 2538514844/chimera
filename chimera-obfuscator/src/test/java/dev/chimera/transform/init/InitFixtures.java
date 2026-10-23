package dev.chimera.transform.init;

import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;

import java.util.ArrayList;
import java.util.List;

/** ASM fixtures for {@link FieldInitSinkTest}; package-private and build-time only. */
final class InitFixtures implements Opcodes {

    static final String SUBJECT = "fixtures/init/Subject";
    static final String ORDER = "fixtures/init/OrderSubject";
    static final String FINAL = "fixtures/init/FinalSubject";
    static final String TRY_CATCH = "fixtures/init/TryCatchSubject";
    static final String MIXIN = "fixtures/init/MixinSubject";
    static final String RECORD = "fixtures/init/RecordSubject";
    static final String ENUM = "fixtures/init/EnumSubject";
    static final String INTERFACE = "fixtures/init/InterfaceSubject";
    static final String BRANCH_CTOR = "fixtures/init/BranchCtorSubject";
    static final String STATIC_BRANCH = "fixtures/init/StaticBranchSubject";

    private InitFixtures() {
    }

    static byte[] subject() {
        ClassNode node = begin(SUBJECT, ACC_PUBLIC | ACC_SUPER);
        node.visitField(ACC_PRIVATE, "a", "I", null, null).visitEnd();
        node.visitField(ACC_PRIVATE, "b", "I", null, null).visitEnd();
        node.visitField(ACC_PRIVATE, "s", "Ljava/lang/String;", null, null).visitEnd();
        node.visitField(ACC_PRIVATE, "l", "J", null, null).visitEnd();
        node.visitField(ACC_PRIVATE, "d", "D", null, null).visitEnd();
        node.visitField(ACC_PRIVATE, "argument", "I", null, null).visitEnd();
        node.visitField(ACC_PRIVATE | ACC_FINAL, "fixed", "I", null, null).visitEnd();
        node.visitField(ACC_PRIVATE | ACC_STATIC, "sa", "I", null, null).visitEnd();
        node.visitField(ACC_PRIVATE | ACC_STATIC, "ss", "Ljava/lang/String;", null, null).visitEnd();
        node.visitField(ACC_PRIVATE | ACC_STATIC | ACC_FINAL, "SF", "I", null, null).visitEnd();
        node.visitField(ACC_PRIVATE | ACC_STATIC, "snapshot", "I", null, null).visitEnd();

        MethodVisitor ctor = node.visitMethod(ACC_PUBLIC, "<init>", "(I)V", null, null);
        ctor.visitCode();
        ctor.visitVarInsn(ALOAD, 0);
        ctor.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        putInstanceInt(ctor, SUBJECT, "a", 1);
        ctor.visitVarInsn(ALOAD, 0);
        ctor.visitIntInsn(BIPUSH, 42);
        ctor.visitFieldInsn(PUTFIELD, SUBJECT, "b", "I");
        ctor.visitVarInsn(ALOAD, 0);
        ctor.visitLdcInsn("hello");
        ctor.visitFieldInsn(PUTFIELD, SUBJECT, "s", "Ljava/lang/String;");
        ctor.visitVarInsn(ALOAD, 0);
        ctor.visitLdcInsn(1234567890123L);
        ctor.visitFieldInsn(PUTFIELD, SUBJECT, "l", "J");
        ctor.visitVarInsn(ALOAD, 0);
        ctor.visitLdcInsn(1.5d);
        ctor.visitFieldInsn(PUTFIELD, SUBJECT, "d", "D");
        ctor.visitVarInsn(ALOAD, 0);
        ctor.visitVarInsn(ILOAD, 1);
        ctor.visitFieldInsn(PUTFIELD, SUBJECT, "argument", "I");
        putInstanceInt(ctor, SUBJECT, "fixed", 7);
        ctor.visitInsn(RETURN);
        ctor.visitMaxs(0, 0);
        ctor.visitEnd();

        MethodVisitor clinit = node.visitMethod(ACC_STATIC, "<clinit>", "()V", null, null);
        clinit.visitCode();
        clinit.visitInsn(ICONST_5);
        clinit.visitFieldInsn(PUTSTATIC, SUBJECT, "sa", "I");
        clinit.visitLdcInsn("static");
        clinit.visitFieldInsn(PUTSTATIC, SUBJECT, "ss", "Ljava/lang/String;");
        clinit.visitInsn(ICONST_3);
        clinit.visitFieldInsn(PUTSTATIC, SUBJECT, "SF", "I");
        clinit.visitFieldInsn(GETSTATIC, SUBJECT, "sa", "I");
        clinit.visitFieldInsn(GETSTATIC, SUBJECT, "SF", "I");
        clinit.visitInsn(IADD);
        clinit.visitFieldInsn(PUTSTATIC, SUBJECT, "snapshot", "I");
        clinit.visitInsn(RETURN);
        clinit.visitMaxs(0, 0);
        clinit.visitEnd();

        sum(node);
        branch(node);
        throwing(node);
        getter(node, "text", "()Ljava/lang/String;", "s", "Ljava/lang/String;", ARETURN, false);
        getterInt(node, "getA", "a", false);
        getterInt(node, "getB", "b", false);
        getterInt(node, "getArgument", "argument", false);
        getterInt(node, "getFixed", "fixed", false);
        getterInt(node, "getSa", "sa", true);
        getterInt(node, "getSnapshot", "snapshot", true);
        getter(node, "getSs", "()Ljava/lang/String;", "ss", "Ljava/lang/String;", ARETURN, true);
        getter(node, "getSf", "()I", "SF", "I", IRETURN, true);

        MethodVisitor longValue = node.visitMethod(ACC_PUBLIC, "longValue", "()J", null, null);
        longValue.visitCode();
        longValue.visitVarInsn(ALOAD, 0);
        longValue.visitFieldInsn(GETFIELD, SUBJECT, "l", "J");
        longValue.visitVarInsn(ALOAD, 0);
        longValue.visitFieldInsn(GETFIELD, SUBJECT, "a", "I");
        longValue.visitInsn(I2L);
        longValue.visitInsn(LADD);
        longValue.visitInsn(LRETURN);
        longValue.visitMaxs(0, 0);
        longValue.visitEnd();

        MethodVisitor doubleValue = node.visitMethod(ACC_PUBLIC, "doubleValue", "()D", null, null);
        doubleValue.visitCode();
        doubleValue.visitVarInsn(ALOAD, 0);
        doubleValue.visitFieldInsn(GETFIELD, SUBJECT, "d", "D");
        doubleValue.visitInsn(DCONST_1);
        doubleValue.visitInsn(DADD);
        doubleValue.visitInsn(DRETURN);
        doubleValue.visitMaxs(0, 0);
        doubleValue.visitEnd();

        return write(node);
    }

    private static void sum(ClassNode node) {
        MethodVisitor mv = node.visitMethod(ACC_PUBLIC, "sum", "(I)I", null, null);
        mv.visitCode();
        mv.visitInsn(ICONST_0);
        mv.visitVarInsn(ISTORE, 2);
        mv.visitInsn(ICONST_0);
        mv.visitVarInsn(ISTORE, 3);
        Label loop = new Label();
        Label end = new Label();
        mv.visitLabel(loop);
        mv.visitVarInsn(ILOAD, 2);
        mv.visitVarInsn(ILOAD, 1);
        mv.visitJumpInsn(IF_ICMPGE, end);
        mv.visitVarInsn(ILOAD, 3);
        mv.visitVarInsn(ALOAD, 0);
        mv.visitFieldInsn(GETFIELD, SUBJECT, "a", "I");
        mv.visitVarInsn(ALOAD, 0);
        mv.visitFieldInsn(GETFIELD, SUBJECT, "b", "I");
        mv.visitInsn(IADD);
        mv.visitVarInsn(ALOAD, 0);
        mv.visitFieldInsn(GETFIELD, SUBJECT, "argument", "I");
        mv.visitInsn(IADD);
        mv.visitInsn(IADD);
        mv.visitVarInsn(ISTORE, 3);
        mv.visitIincInsn(2, 1);
        mv.visitJumpInsn(GOTO, loop);
        mv.visitLabel(end);
        mv.visitVarInsn(ILOAD, 3);
        mv.visitInsn(IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
    }

    private static void branch(ClassNode node) {
        MethodVisitor mv = node.visitMethod(ACC_PUBLIC, "branch", "(I)I", null, null);
        mv.visitCode();
        Label positive = new Label();
        mv.visitVarInsn(ILOAD, 1);
        mv.visitJumpInsn(IFGT, positive);
        mv.visitVarInsn(ALOAD, 0);
        mv.visitFieldInsn(GETFIELD, SUBJECT, "b", "I");
        mv.visitVarInsn(ILOAD, 1);
        mv.visitInsn(ISUB);
        mv.visitInsn(IRETURN);
        mv.visitLabel(positive);
        mv.visitVarInsn(ALOAD, 0);
        mv.visitFieldInsn(GETFIELD, SUBJECT, "a", "I");
        mv.visitVarInsn(ILOAD, 1);
        mv.visitInsn(IADD);
        mv.visitInsn(IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
    }

    private static void throwing(ClassNode node) {
        MethodVisitor mv = node.visitMethod(ACC_PUBLIC, "throwing", "(I)I", null, null);
        mv.visitCode();
        Label ok = new Label();
        mv.visitVarInsn(ILOAD, 1);
        mv.visitJumpInsn(IFGE, ok);
        mv.visitTypeInsn(NEW, "java/lang/IllegalArgumentException");
        mv.visitInsn(DUP);
        mv.visitLdcInsn("negative");
        mv.visitMethodInsn(INVOKESPECIAL, "java/lang/IllegalArgumentException", "<init>",
                "(Ljava/lang/String;)V", false);
        mv.visitInsn(ATHROW);
        mv.visitLabel(ok);
        mv.visitVarInsn(ILOAD, 1);
        mv.visitVarInsn(ALOAD, 0);
        mv.visitFieldInsn(GETFIELD, SUBJECT, "fixed", "I");
        mv.visitInsn(IADD);
        mv.visitInsn(IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
    }

    static byte[] orderSubject() {
        ClassNode node = begin(ORDER, ACC_PUBLIC | ACC_SUPER);
        node.visitField(ACC_PRIVATE, "a", "I", null, null).visitEnd();
        node.visitField(ACC_PRIVATE, "b", "I", null, null).visitEnd();
        node.visitField(ACC_PRIVATE, "c", "I", null, null).visitEnd();
        node.visitField(ACC_PRIVATE | ACC_STATIC, "observedA", "I", null, null).visitEnd();
        node.visitField(ACC_PRIVATE | ACC_STATIC, "observedB", "I", null, null).visitEnd();
        node.visitField(ACC_PRIVATE | ACC_STATIC, "observedC", "I", null, null).visitEnd();

        MethodVisitor ctor = node.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null);
        ctor.visitCode();
        ctor.visitVarInsn(ALOAD, 0);
        ctor.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        putInstanceInt(ctor, ORDER, "a", 1);
        putInstanceInt(ctor, ORDER, "b", 2);
        observe(ctor, ORDER, "a", "observedA");
        observe(ctor, ORDER, "b", "observedB");
        putInstanceInt(ctor, ORDER, "c", 9);
        observe(ctor, ORDER, "c", "observedC");
        ctor.visitInsn(RETURN);
        ctor.visitMaxs(0, 0);
        ctor.visitEnd();

        getterInt(node, "getA", "a", false);
        getterInt(node, "getB", "b", false);
        getterInt(node, "getC", "c", false);
        getterInt(node, "getObservedA", "observedA", true);
        getterInt(node, "getObservedB", "observedB", true);
        getterInt(node, "getObservedC", "observedC", true);
        return write(node);
    }

    static byte[] finalSubject() {
        ClassNode node = begin(FINAL, ACC_PUBLIC | ACC_SUPER);
        node.visitField(ACC_PRIVATE | ACC_FINAL, "v", "I", null, null).visitEnd();
        node.visitField(ACC_PRIVATE | ACC_VOLATILE, "vv", "I", null, null).visitEnd();
        node.visitField(ACC_PRIVATE | ACC_STATIC | ACC_FINAL, "K", "I", null, null).visitEnd();

        MethodVisitor ctor = node.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null);
        ctor.visitCode();
        ctor.visitVarInsn(ALOAD, 0);
        ctor.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        putInstanceInt(ctor, FINAL, "v", 5);
        putInstanceInt(ctor, FINAL, "vv", 11);
        ctor.visitInsn(RETURN);
        ctor.visitMaxs(0, 0);
        ctor.visitEnd();

        MethodVisitor clinit = node.visitMethod(ACC_STATIC, "<clinit>", "()V", null, null);
        clinit.visitCode();
        clinit.visitIntInsn(BIPUSH, 7);
        clinit.visitFieldInsn(PUTSTATIC, FINAL, "K", "I");
        clinit.visitInsn(RETURN);
        clinit.visitMaxs(0, 0);
        clinit.visitEnd();

        getterInt(node, "getV", "v", false);
        getterInt(node, "getVv", "vv", false);
        getterInt(node, "getK", "K", true);
        return write(node);
    }

    static byte[] tryCatchSubject() {
        ClassNode node = begin(TRY_CATCH, ACC_PUBLIC | ACC_SUPER);
        node.visitField(ACC_PRIVATE, "a", "I", null, null).visitEnd();
        node.visitField(ACC_PRIVATE, "b", "I", null, null).visitEnd();

        MethodVisitor ctor = node.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null);
        ctor.visitCode();
        ctor.visitVarInsn(ALOAD, 0);
        ctor.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        putInstanceInt(ctor, TRY_CATCH, "a", 1);
        Label start = new Label();
        Label end = new Label();
        Label handler = new Label();
        Label done = new Label();
        ctor.visitLabel(start);
        putInstanceInt(ctor, TRY_CATCH, "b", 2);
        ctor.visitLabel(end);
        ctor.visitJumpInsn(GOTO, done);
        ctor.visitLabel(handler);
        ctor.visitVarInsn(ASTORE, 1);
        putInstanceInt(ctor, TRY_CATCH, "b", 9);
        ctor.visitLabel(done);
        ctor.visitInsn(RETURN);
        ctor.visitTryCatchBlock(start, end, handler, "java/lang/RuntimeException");
        ctor.visitMaxs(0, 0);
        ctor.visitEnd();

        getterInt(node, "getA", "a", false);
        getterInt(node, "getB", "b", false);
        return write(node);
    }

    static byte[] mixinSubject() {
        ClassNode node = begin(MIXIN, ACC_PUBLIC | ACC_SUPER);
        node.visibleAnnotations = new ArrayList<>(List.of(
                new AnnotationNode("Lorg/spongepowered/asm/mixin/Mixin;")));
        node.visitField(ACC_PRIVATE, "x", "I", null, null).visitEnd();
        MethodVisitor ctor = node.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null);
        ctor.visitCode();
        ctor.visitVarInsn(ALOAD, 0);
        ctor.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        putInstanceInt(ctor, MIXIN, "x", 11);
        ctor.visitInsn(RETURN);
        ctor.visitMaxs(0, 0);
        ctor.visitEnd();
        return write(node);
    }

    static byte[] recordSubject() {
        ClassNode node = begin(RECORD, ACC_PUBLIC | ACC_SUPER | ACC_RECORD | ACC_FINAL);
        node.visitField(ACC_PRIVATE, "x", "I", null, null).visitEnd();
        ctorWithConstant(node, RECORD, "x");
        return write(node);
    }

    static byte[] enumSubject() {
        ClassNode node = begin(ENUM, ACC_PUBLIC | ACC_SUPER | ACC_ENUM | ACC_FINAL);
        node.visitField(ACC_PRIVATE, "x", "I", null, null).visitEnd();
        ctorWithConstant(node, ENUM, "x");
        return write(node);
    }

    static byte[] interfaceSubject() {
        ClassNode node = begin(INTERFACE, ACC_PUBLIC | ACC_INTERFACE | ACC_ABSTRACT);
        node.visitField(ACC_PUBLIC | ACC_STATIC | ACC_FINAL, "X", "I", null, null).visitEnd();
        MethodVisitor clinit = node.visitMethod(ACC_STATIC, "<clinit>", "()V", null, null);
        clinit.visitCode();
        clinit.visitIntInsn(BIPUSH, 13);
        clinit.visitFieldInsn(PUTSTATIC, INTERFACE, "X", "I");
        clinit.visitInsn(RETURN);
        clinit.visitMaxs(0, 0);
        clinit.visitEnd();
        return write(node);
    }

    static byte[] branchCtorSubject() {
        ClassNode node = begin(BRANCH_CTOR, ACC_PUBLIC | ACC_SUPER);
        node.visitField(ACC_PRIVATE, "a", "I", null, null).visitEnd();
        node.visitField(ACC_PRIVATE, "b", "I", null, null).visitEnd();

        MethodVisitor ctor = node.visitMethod(ACC_PUBLIC, "<init>", "(I)V", null, null);
        ctor.visitCode();
        ctor.visitVarInsn(ALOAD, 0);
        ctor.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        Label other = new Label();
        Label after = new Label();
        ctor.visitVarInsn(ILOAD, 1);
        ctor.visitJumpInsn(IFLE, other);
        putInstanceInt(ctor, BRANCH_CTOR, "a", 1);
        ctor.visitJumpInsn(GOTO, after);
        ctor.visitLabel(other);
        putInstanceInt(ctor, BRANCH_CTOR, "a", 2);
        ctor.visitLabel(after);
        putInstanceInt(ctor, BRANCH_CTOR, "b", 3);
        ctor.visitInsn(RETURN);
        ctor.visitMaxs(0, 0);
        ctor.visitEnd();

        getterInt(node, "getA", "a", false);
        getterInt(node, "getB", "b", false);
        return write(node);
    }

    static byte[] staticBranchSubject(int flagValue) {
        ClassNode node = begin(STATIC_BRANCH, ACC_PUBLIC | ACC_SUPER);
        node.visitField(ACC_PRIVATE | ACC_STATIC, "flag", "I", null, Integer.valueOf(flagValue)).visitEnd();
        node.visitField(ACC_PRIVATE | ACC_STATIC, "a", "I", null, null).visitEnd();
        node.visitField(ACC_PRIVATE | ACC_STATIC, "b", "Ljava/lang/String;", null, null).visitEnd();

        MethodVisitor clinit = node.visitMethod(ACC_STATIC, "<clinit>", "()V", null, null);
        clinit.visitCode();
        Label merge = new Label();
        clinit.visitFieldInsn(GETSTATIC, STATIC_BRANCH, "flag", "I");
        clinit.visitJumpInsn(IFEQ, merge);
        clinit.visitInsn(ICONST_1);
        clinit.visitFieldInsn(PUTSTATIC, STATIC_BRANCH, "a", "I");
        clinit.visitLabel(merge);
        clinit.visitLdcInsn("x");
        clinit.visitFieldInsn(PUTSTATIC, STATIC_BRANCH, "b", "Ljava/lang/String;");
        clinit.visitInsn(RETURN);
        clinit.visitMaxs(0, 0);
        clinit.visitEnd();

        getterInt(node, "getFlag", "flag", true);
        getterInt(node, "getA", "a", true);
        getter(node, "getB", "()Ljava/lang/String;", "b", "Ljava/lang/String;", ARETURN, true);
        return write(node);
    }

    // ------------------------------------------------------------------ helpers

    private static ClassNode begin(String name, int access) {
        ClassNode node = new ClassNode();
        node.visit(V17, access, name, null, "java/lang/Object", null);
        return node;
    }

    private static void ctorWithConstant(ClassNode node, String owner, String field) {
        MethodVisitor ctor = node.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null);
        ctor.visitCode();
        ctor.visitVarInsn(ALOAD, 0);
        ctor.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        putInstanceInt(ctor, owner, field, 3);
        ctor.visitInsn(RETURN);
        ctor.visitMaxs(0, 0);
        ctor.visitEnd();
    }

    private static void putInstanceInt(MethodVisitor mv, String owner, String field, int value) {
        mv.visitVarInsn(ALOAD, 0);
        pushInt(mv, value);
        mv.visitFieldInsn(PUTFIELD, owner, field, "I");
    }

    private static void observe(MethodVisitor mv, String owner, String field, String target) {
        mv.visitVarInsn(ALOAD, 0);
        mv.visitFieldInsn(GETFIELD, owner, field, "I");
        mv.visitFieldInsn(PUTSTATIC, owner, target, "I");
    }

    private static void pushInt(MethodVisitor mv, int value) {
        if (value >= -1 && value <= 5) {
            mv.visitInsn(ICONST_0 + value);
        } else if (value >= Byte.MIN_VALUE && value <= Byte.MAX_VALUE) {
            mv.visitIntInsn(BIPUSH, value);
        } else {
            mv.visitIntInsn(SIPUSH, value);
        }
    }

    private static void getterInt(ClassNode node, String name, String field, boolean isStatic) {
        MethodVisitor mv = node.visitMethod(ACC_PUBLIC | (isStatic ? ACC_STATIC : 0),
                name, "()I", null, null);
        mv.visitCode();
        if (isStatic) {
            mv.visitFieldInsn(GETSTATIC, node.name, field, "I");
        } else {
            mv.visitVarInsn(ALOAD, 0);
            mv.visitFieldInsn(GETFIELD, node.name, field, "I");
        }
        mv.visitInsn(IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
    }

    private static void getter(ClassNode node, String name, String descriptor, String field,
                               String fieldDescriptor, int returnOpcode, boolean isStatic) {
        MethodVisitor mv = node.visitMethod(ACC_PUBLIC | (isStatic ? ACC_STATIC : 0),
                name, descriptor, null, null);
        mv.visitCode();
        if (isStatic) {
            mv.visitFieldInsn(GETSTATIC, node.name, field, fieldDescriptor);
        } else {
            mv.visitVarInsn(ALOAD, 0);
            mv.visitFieldInsn(GETFIELD, node.name, field, fieldDescriptor);
        }
        mv.visitInsn(returnOpcode);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
    }

    private static byte[] write(ClassNode node) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        node.accept(writer);
        return writer.toByteArray();
    }
}
