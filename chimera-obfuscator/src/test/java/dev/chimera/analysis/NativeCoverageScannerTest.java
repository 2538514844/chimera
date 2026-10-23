package dev.chimera.analysis;

import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.ClassNode;

import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NativeCoverageScannerTest {

    private static ClassNode node(byte[] bytes) {
        ClassNode cn = new ClassNode();
        new ClassReader(bytes).accept(cn, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        return cn;
    }

    private static Map<String, NativeCoverageScanner.Tier> tiers(ClassNode cn) {
        return NativeCoverageScanner.scanClass(cn).methods().stream()
                .collect(Collectors.toMap(NativeCoverageScanner.MethodReport::name,
                        NativeCoverageScanner.MethodReport::tier));
    }

    private static ClassWriter writer(int access, String name) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, access, name, null, "java/lang/Object", null);
        return cw;
    }

    @Test
    void classifiesPurePrimitiveMethodsAsTierA() {
        ClassWriter cw = writer(Opcodes.ACC_PUBLIC, "demo/Pure");
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "add", "(II)I", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ILOAD, 0);
        mv.visitVarInsn(Opcodes.ILOAD, 1);
        mv.visitInsn(Opcodes.IADD);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "clamp", "(DDD)D", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.DLOAD, 0);
        mv.visitVarInsn(Opcodes.DLOAD, 2);
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Math", "max", "(DD)D", false);
        mv.visitVarInsn(Opcodes.DLOAD, 4);
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Math", "min", "(DD)D", false);
        mv.visitInsn(Opcodes.DRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        cw.visitEnd();

        Map<String, NativeCoverageScanner.Tier> tiers = tiers(node(cw.toByteArray()));
        assertEquals(NativeCoverageScanner.Tier.A, tiers.get("add"));
        assertEquals(NativeCoverageScanner.Tier.B, tiers.get("clamp"));
    }

    @Test
    void classifiesStaticFieldAndNonMathCallAsTierBOrC() {
        ClassWriter cw = writer(Opcodes.ACC_PUBLIC, "demo/Fields");
        cw.visitField(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "CNT", "I", null, null).visitEnd();
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "read", "()I", null, null);
        mv.visitCode();
        mv.visitFieldInsn(Opcodes.GETSTATIC, "demo/Fields", "CNT", "I");
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "callOther", "(I)I", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ILOAD, 0);
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "demo/Helper", "twice", "(I)I", false);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        cw.visitEnd();

        Map<String, NativeCoverageScanner.Tier> tiers = tiers(node(cw.toByteArray()));
        assertEquals(NativeCoverageScanner.Tier.B, tiers.get("read"));
        assertEquals(NativeCoverageScanner.Tier.C, tiers.get("callOther"));
    }

    @Test
    void classifiesObjectsExceptionsAndTryCatchAsTierD() {
        ClassWriter cw = writer(Opcodes.ACC_PUBLIC, "demo/Objects");
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "name", "()Ljava/lang/String;", null, null);
        mv.visitCode();
        mv.visitLdcInsn("x");
        mv.visitInsn(Opcodes.ARETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "allocate", "()Ljava/lang/Object;", null, null);
        mv.visitCode();
        mv.visitTypeInsn(Opcodes.NEW, "java/lang/Object");
        mv.visitInsn(Opcodes.DUP);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        mv.visitInsn(Opcodes.ARETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "guard", "(I)I", null, null);
        mv.visitCode();
        org.objectweb.asm.Label start = new org.objectweb.asm.Label();
        org.objectweb.asm.Label end = new org.objectweb.asm.Label();
        org.objectweb.asm.Label handler = new org.objectweb.asm.Label();
        mv.visitTryCatchBlock(start, end, handler, "java/lang/RuntimeException");
        mv.visitLabel(start);
        mv.visitVarInsn(Opcodes.ILOAD, 0);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitLabel(end);
        mv.visitLabel(handler);
        mv.visitInsn(Opcodes.ICONST_M1);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        cw.visitEnd();

        Map<String, NativeCoverageScanner.Tier> tiers = tiers(node(cw.toByteArray()));
        assertEquals(NativeCoverageScanner.Tier.D, tiers.get("name"));
        assertEquals(NativeCoverageScanner.Tier.D, tiers.get("allocate"));
        assertEquals(NativeCoverageScanner.Tier.D, tiers.get("guard"));
    }

    @Test
    void classifiesHardCasesAsTierE() {
        ClassWriter cw = writer(Opcodes.ACC_PUBLIC, "demo/Hard");
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "indy", "()Ljava/lang/Runnable;", null, null);
        mv.visitCode();
        mv.visitInvokeDynamicInsn("run", "()Ljava/lang/Runnable;",
                new org.objectweb.asm.Handle(org.objectweb.asm.Opcodes.H_INVOKESTATIC,
                        "java/lang/invoke/LambdaMetafactory", "metafactory",
                        "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;"
                                + "Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodType;)"
                                + "Ljava/lang/invoke/CallSite;", false),
                org.objectweb.asm.Type.getType("()V"),
                new org.objectweb.asm.Handle(org.objectweb.asm.Opcodes.H_INVOKESTATIC, "demo/Hard", "impl", "()V", false),
                org.objectweb.asm.Type.getType("()V"));
        mv.visitInsn(Opcodes.ARETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_NATIVE, "nativeMethod", "()V", null, null);
        mv.visitEnd();
        mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_SYNCHRONIZED, "sync", "()V", null, null);
        mv.visitCode();
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        cw.visitEnd();

        Map<String, NativeCoverageScanner.Tier> tiers = tiers(node(cw.toByteArray()));
        assertEquals(NativeCoverageScanner.Tier.E, tiers.get("indy"));
        assertEquals(NativeCoverageScanner.Tier.E, tiers.get("nativeMethod"));
        assertEquals(NativeCoverageScanner.Tier.E, tiers.get("sync"));
        assertEquals(NativeCoverageScanner.Tier.E, tiers.get("<init>"));
    }

    @Test
    void classifiesMixinClassesAsTierE() {
        ClassWriter cw = writer(Opcodes.ACC_PUBLIC, "demo/MixinDemo");
        cw.visitAnnotation("Lorg/spongepowered/asm/mixin/Mixin;", true).visitEnd();
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "onTick", "()V", null, null);
        mv.visitCode();
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        cw.visitEnd();

        ClassNode cn = node(cw.toByteArray());
        NativeCoverageScanner.ClassReport report = NativeCoverageScanner.scanClass(cn);
        assertTrue(report.mixin());
        assertEquals(NativeCoverageScanner.Tier.E, report.methods().get(0).tier());
        assertTrue(report.methods().get(0).reasons().contains("MIXIN_CLASS"));
    }
}
