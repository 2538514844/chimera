package dev.chimera.nativecode.compile;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class NativeBodyCompilerTest {

    private static ClassNode fixture() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "demo/Fixture", null, "java/lang/Object", null);

        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "add", "(II)I", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ILOAD, 0);
        mv.visitVarInsn(Opcodes.ILOAD, 1);
        mv.visitInsn(Opcodes.IADD);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "gcd", "(II)I", null, null);
        mv.visitCode();
        Label loop = new Label();
        Label done = new Label();
        mv.visitLabel(loop);
        mv.visitVarInsn(Opcodes.ILOAD, 1);
        mv.visitJumpInsn(Opcodes.IFEQ, done);
        mv.visitVarInsn(Opcodes.ILOAD, 0);
        mv.visitVarInsn(Opcodes.ILOAD, 1);
        mv.visitInsn(Opcodes.IREM);
        mv.visitVarInsn(Opcodes.ISTORE, 2);
        mv.visitVarInsn(Opcodes.ILOAD, 1);
        mv.visitVarInsn(Opcodes.ISTORE, 0);
        mv.visitVarInsn(Opcodes.ILOAD, 2);
        mv.visitVarInsn(Opcodes.ISTORE, 1);
        mv.visitJumpInsn(Opcodes.GOTO, loop);
        mv.visitLabel(done);
        mv.visitVarInsn(Opcodes.ILOAD, 0);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "pick", "(I)I", null, null);
        mv.visitCode();
        Label l0 = new Label();
        Label l1 = new Label();
        Label l2 = new Label();
        Label dflt = new Label();
        mv.visitVarInsn(Opcodes.ILOAD, 0);
        mv.visitTableSwitchInsn(0, 1, dflt, l0, l1);
        mv.visitLabel(l0);
        mv.visitIntInsn(Opcodes.BIPUSH, 10);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitLabel(l1);
        mv.visitIntInsn(Opcodes.SIPUSH, 300);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitLabel(l2);
        mv.visitInsn(Opcodes.ICONST_M1);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitLabel(dflt);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "divGuard", "(II)I", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ILOAD, 0);
        mv.visitVarInsn(Opcodes.ILOAD, 1);
        mv.visitInsn(Opcodes.IDIV);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "asLong", "(I)J", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ILOAD, 0);
        mv.visitInsn(Opcodes.I2L);
        mv.visitInsn(Opcodes.LRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        cw.visitEnd();
        ClassNode cn = new ClassNode();
        new ClassReader(cw.toByteArray()).accept(cn, 0);
        return cn;
    }

    private static List<MethodNode> methods(ClassNode cn) {
        return new ArrayList<>(cn.methods);
    }

    @Test
    void compilesTierAMethodsAndEmitsJniSymbols() {
        ClassNode cn = fixture();
        String unit = NativeBodyCompiler.compileUnit(cn.name, methods(cn), Set.of());
        assertTrue(unit.contains("Java_demo_Fixture_add("), "symbol for add missing:\n" + unit);
        assertTrue(unit.contains("Java_demo_Fixture_gcd("), "symbol for gcd missing");
        assertTrue(unit.contains("switch (st[sp].i)"), "tableswitch not lowered");
        assertTrue(unit.contains("java/lang/ArithmeticException"), "division guard missing");
        assertTrue(unit.contains("INT32_MIN"), "integer overflow corner not handled");
        assertFalse(unit.contains("GETSTATIC"), "no field ops expected");
    }

    @Test
    void overloadedMethodsUseLongJniNameWithParameterDescriptor() {
        ClassNode cn = fixture();
        String unit = NativeBodyCompiler.compileUnit(cn.name, methods(cn),
                Set.of("add(II)I", "gcd(II)I"));
        assertTrue(unit.contains("Java_demo_Fixture_add__II"), "long JNI name for overloaded add missing:\n" + unit);
        assertTrue(unit.contains("Java_demo_Fixture_gcd__II"), "long JNI name for overloaded gcd missing");
    }

    @Test
    void rejectsUnsupportedOpcodes() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "demo/Bad", null, "java/lang/Object", null);
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "multi", "()[[I", null, null);
        mv.visitCode();
        mv.visitInsn(Opcodes.ICONST_2);
        mv.visitInsn(Opcodes.ICONST_2);
        mv.visitMultiANewArrayInsn("[[I", 2);
        mv.visitInsn(Opcodes.ARETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        cw.visitEnd();
        ClassNode cn = new ClassNode();
        new ClassReader(cw.toByteArray()).accept(cn, 0);

        NativeBodyCompiler.UnsupportedInstruction ex = assertThrows(
                NativeBodyCompiler.UnsupportedInstruction.class,
                () -> NativeBodyCompiler.compile(cn.name, cn.methods.get(0), false));
        assertEquals(Opcodes.MULTIANEWARRAY, ex.opcode());
    }

    @Test
    void generatedUnitCompilesWithGxx(@TempDir Path tmp) throws Exception {
        assumeTrue(hasGxx(), "g++ not on PATH; skipping C++ syntax check");
        ClassNode cn = fixture();
        String unit = NativeBodyCompiler.compileUnit(cn.name, methods(cn), Set.of());
        Path cpp = tmp.resolve("fixture.cpp");
        Files.writeString(cpp, unit, StandardCharsets.UTF_8);

        Path jdkInclude = Path.of(System.getProperty("java.home"), "include");
        assumeTrue(Files.isDirectory(jdkInclude), "JDK include dir missing");

        List<String> cmd = new ArrayList<>(List.of("g++", "-std=c++17", "-fsyntax-only",
                "-I", jdkInclude.toString()));
        Path win32 = jdkInclude.resolve("win32");
        if (Files.isDirectory(win32)) {
            cmd.add("-I");
            cmd.add(win32.toString());
        }
        cmd.add(cpp.toString());

        Process process = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        boolean finished = process.waitFor(120, TimeUnit.SECONDS);
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (!finished) {
            process.destroyForcibly();
        }
        assertTrue(finished, "g++ timed out");
        assertEquals(0, process.exitValue(), "g++ rejected generated C++:\n" + output);
    }

    private static boolean hasGxx() {
        try {
            Process p = new ProcessBuilder("g++", "--version").redirectErrorStream(true).start();
            return p.waitFor(20, TimeUnit.SECONDS) && p.exitValue() == 0;
        } catch (IOException | InterruptedException e) {
            return false;
        }
    }

    @Test
    void generatesD1FieldArrayStringAndTryCatch() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "demo/D1", null, "java/lang/Object", null);
        cw.visitField(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "C", "I", null, null).visitEnd();

        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "getC", "()I", null, null);
        mv.visitCode();
        mv.visitFieldInsn(Opcodes.GETSTATIC, "demo/D1", "C", "I");
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "sum", "([I)I", null, null);
        mv.visitCode();
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitVarInsn(Opcodes.ISTORE, 1);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitVarInsn(Opcodes.ISTORE, 2);
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitInsn(Opcodes.ARRAYLENGTH);
        mv.visitVarInsn(Opcodes.ISTORE, 3);
        mv.visitVarInsn(Opcodes.ILOAD, 2);
        mv.visitVarInsn(Opcodes.ILOAD, 3);
        mv.visitJumpInsn(Opcodes.IF_ICMPGE, new Label());
        mv.visitVarInsn(Opcodes.ILOAD, 1);
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitVarInsn(Opcodes.ILOAD, 2);
        mv.visitInsn(Opcodes.IALOAD);
        mv.visitInsn(Opcodes.IADD);
        mv.visitVarInsn(Opcodes.ISTORE, 1);
        mv.visitIincInsn(2, 1);
        mv.visitVarInsn(Opcodes.ILOAD, 1);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "mkArr", "(I)[I", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ILOAD, 0);
        mv.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_INT);
        mv.visitInsn(Opcodes.ARETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "hello", "()Ljava/lang/String;", null, null);
        mv.visitCode();
        mv.visitLdcInsn("hi");
        mv.visitInsn(Opcodes.ARETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "tryDiv", "(II)I", null, null);
        mv.visitCode();
        Label start = new Label();
        Label end = new Label();
        Label handler = new Label();
        mv.visitTryCatchBlock(start, end, handler, "java/lang/ArithmeticException");
        mv.visitLabel(start);
        mv.visitVarInsn(Opcodes.ILOAD, 0);
        mv.visitVarInsn(Opcodes.ILOAD, 1);
        mv.visitInsn(Opcodes.IDIV);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitLabel(end);
        mv.visitLabel(handler);
        mv.visitVarInsn(Opcodes.ASTORE, 2);
        mv.visitInsn(Opcodes.ICONST_M1);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        cw.visitEnd();

        ClassNode cn = new ClassNode();
        new ClassReader(cw.toByteArray()).accept(cn, 0);
        String unit = NativeBodyCompiler.compileUnit(cn.name, methods(cn), Set.of());
        assertTrue(unit.contains("GetStaticIntField"), "static field codegen missing:\n" + unit);
        assertTrue(unit.contains("GetIntArrayRegion"), "array load codegen missing");
        assertTrue(unit.contains("NewIntArray"), "NewArray codegen missing");
        assertTrue(unit.contains("NewStringUTF(\"hi\")"), "string constant codegen missing");
        assertTrue(unit.contains("ExceptionOccurred()"), "try-catch exception routing missing");
        assertTrue(unit.contains("goto L"), "handler jump missing");
    }


    @Test
    void generatesD2NewInvokeAndTypeChecks() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "demo/D2", null, "java/lang/Object", null);
        cw.visitField(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "OBJ", "Ljava/lang/Object;", null, null).visitEnd();

        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "make", "()Ljava/lang/Object;", null, null);
        mv.visitCode();
        mv.visitTypeInsn(Opcodes.NEW, "java/lang/Object");
        mv.visitInsn(Opcodes.DUP);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        mv.visitInsn(Opcodes.ARETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "len", "(Ljava/lang/String;)I", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "length", "()I", false);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "check", "(Ljava/lang/Object;)Z", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitTypeInsn(Opcodes.INSTANCEOF, "java/lang/String");
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        ClassNode cn = new ClassNode();
        new ClassReader(cw.toByteArray()).accept(cn, 0);
        String unit = NativeBodyCompiler.compileUnit(cn.name, methods(cn), Set.of());
        assertTrue(unit.contains("AllocObject"), "NEW codegen missing:\n" + unit);
        assertTrue(unit.contains("GetMethodID"), "method id cache missing");
        assertTrue(unit.contains("CallNonvirtualVoidMethodA"), "constructor call missing");
        assertTrue(unit.contains("CallIntMethodA"), "virtual call missing");
        assertTrue(unit.contains("IsInstanceOf"), "instanceof missing");
    }

}
