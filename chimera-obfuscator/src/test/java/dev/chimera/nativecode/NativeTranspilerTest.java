package dev.chimera.nativecode;

import dev.chimera.core.NativeTemplate;
import dev.chimera.core.NativeTemplateWriter;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Verifies the M4 bytecode -> C++ translator including branches/loops and the .h/.cpp pair. */
class NativeTranspilerTest {

    private static ClassNode classNode(String name) {
        ClassNode cn = new ClassNode();
        cn.version = Opcodes.V17;
        cn.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL;
        cn.name = name;
        cn.superName = "java/lang/Object";
        return cn;
    }

    private static MethodNode method(ClassNode owner, int access, String name, String desc) {
        MethodNode m = new MethodNode(Opcodes.ASM9, access, name, desc, null, null);
        m.maxStack = 8;
        m.maxLocals = 8;
        owner.methods.add(m);
        return m;
    }

    private static NativeTemplate template(ClassNode owner, MethodNode m, NativeTranspiler.TranspileResult r) {
        return new NativeTemplate(owner.name, m.name, m.desc,
                (m.access & Opcodes.ACC_STATIC) != 0, r.supported(), r.cppBody(), r.headerDecl());
    }

    private static ClassNode addClass() {
        ClassNode owner = classNode("demo/Math");
        MethodNode m = method(owner, Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "add", "(II)I");
        InsnList il = m.instructions;
        il.add(new VarInsnNode(Opcodes.ILOAD, 0));
        il.add(new VarInsnNode(Opcodes.ILOAD, 1));
        il.add(new InsnNode(Opcodes.IADD));
        il.add(new InsnNode(Opcodes.IRETURN));
        return owner;
    }

    private static ClassNode mixClass() {
        ClassNode owner = classNode("demo/Math");
        MethodNode m = method(owner, Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "mix", "(ID)D");
        InsnList il = m.instructions;
        il.add(new VarInsnNode(Opcodes.ILOAD, 0));
        il.add(new InsnNode(Opcodes.I2D));
        il.add(new VarInsnNode(Opcodes.DLOAD, 1));
        il.add(new InsnNode(Opcodes.DADD));
        il.add(new InsnNode(Opcodes.DRETURN));
        return owner;
    }

    /** if (x == 0) return 1; else return 0; */
    private static ClassNode branchClass() {
        ClassNode owner = classNode("demo/Branchy");
        MethodNode m = method(owner, Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "pick", "(I)I");
        LabelNode otherwise = new LabelNode();
        m.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        m.instructions.add(new JumpInsnNode(Opcodes.IFEQ, otherwise));
        m.instructions.add(new InsnNode(Opcodes.ICONST_1));
        m.instructions.add(new InsnNode(Opcodes.IRETURN));
        m.instructions.add(otherwise);
        m.instructions.add(new InsnNode(Opcodes.ICONST_0));
        m.instructions.add(new InsnNode(Opcodes.IRETURN));
        return owner;
    }

    /** int sum = 0; for (int i = 0; i < n; i++) sum += i; return sum; */
    private static ClassNode loopClass() {
        ClassNode owner = classNode("demo/Loopy");
        MethodNode m = method(owner, Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "sum", "(I)I");
        LabelNode loop = new LabelNode();
        LabelNode end = new LabelNode();
        m.instructions.add(new InsnNode(Opcodes.ICONST_0));
        m.instructions.add(new VarInsnNode(Opcodes.ISTORE, 1));
        m.instructions.add(new InsnNode(Opcodes.ICONST_0));
        m.instructions.add(new VarInsnNode(Opcodes.ISTORE, 2));
        m.instructions.add(loop);
        m.instructions.add(new VarInsnNode(Opcodes.ILOAD, 2));
        m.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        m.instructions.add(new JumpInsnNode(Opcodes.IF_ICMPGE, end));
        m.instructions.add(new VarInsnNode(Opcodes.ILOAD, 1));
        m.instructions.add(new VarInsnNode(Opcodes.ILOAD, 2));
        m.instructions.add(new InsnNode(Opcodes.IADD));
        m.instructions.add(new VarInsnNode(Opcodes.ISTORE, 1));
        m.instructions.add(new IincInsnNode(2, 1));
        m.instructions.add(new JumpInsnNode(Opcodes.GOTO, loop));
        m.instructions.add(end);
        m.instructions.add(new VarInsnNode(Opcodes.ILOAD, 1));
        m.instructions.add(new InsnNode(Opcodes.IRETURN));
        return owner;
    }

    @Test
    void transpilesStaticIntAdd() {
        ClassNode owner = addClass();
        MethodNode m = owner.methods.get(0);
        var r = NativeTranspiler.transpile(owner, m);
        assertTrue(r.supported(), "static int add should be supported");
        assertNotNull(r.cppBody());
        assertTrue(r.cppBody().contains("jint lv0_i = a0;"), r.cppBody());
        assertTrue(r.cppBody().contains("jint lv1_i = a1;"), r.cppBody());
        assertTrue(r.cppBody().contains("jint s0_i;"), r.cppBody());
        assertTrue(r.cppBody().contains("(chimera_u32)s0_i + (chimera_u32)s1_i"), r.cppBody());
        assertTrue(r.cppBody().contains("return s0_i;"), r.cppBody());
        assertTrue(r.headerDecl().startsWith("extern \"C\" JNIEXPORT jint JNICALL"), r.headerDecl());
        assertTrue(r.headerDecl().contains("Java_demo_Math_add"), r.headerDecl());
        assertTrue(r.headerDecl().contains("jclass clazz"), r.headerDecl());
        assertTrue(r.headerDecl().contains("jint a0, jint a1"), r.headerDecl());
    }

    @Test
    void manglesJniNamesPerSpec() {
        ClassNode owner = classNode("demo/My_Math$Inner");
        MethodNode m = method(owner, Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run", "()D");
        m.instructions.add(new InsnNode(Opcodes.DCONST_1));
        m.instructions.add(new InsnNode(Opcodes.DRETURN));
        var r = NativeTranspiler.transpile(owner, m);
        assertTrue(r.supported());
        assertTrue(r.headerDecl().contains("Java_demo_My_1Math_00024Inner_run"), r.headerDecl());
    }

    @Test
    void transpilesStaticDoubleMix() {
        ClassNode owner = mixClass();
        MethodNode m = owner.methods.get(0);
        var r = NativeTranspiler.transpile(owner, m);
        assertTrue(r.supported(), "static int,double mix should be supported");
        assertTrue(r.cppBody().contains("jdouble lv1_d = a1;"), r.cppBody());
        assertTrue(r.cppBody().contains("(jdouble)s0_i"), r.cppBody());
        assertTrue(r.cppBody().contains("s0_d = s0_d + s1_d;"), r.cppBody());
        assertTrue(r.cppBody().contains("return s0_d;"), r.cppBody());
        assertTrue(r.headerDecl().contains("JNIEXPORT jdouble JNICALL"), r.headerDecl());
        assertTrue(r.headerDecl().contains("jdouble a1"), r.headerDecl());
    }

    @Test
    void transpilesBranches() {
        ClassNode owner = branchClass();
        MethodNode m = owner.methods.get(0);
        var r = NativeTranspiler.transpile(owner, m);
        assertTrue(r.supported(), "if/else must be transpiled to goto");
        assertTrue(r.cppBody().contains("if (s0_i == 0) goto L"), r.cppBody());
        assertNotNull(r.headerDecl());
    }

    @Test
    void transpilesLoops() {
        ClassNode owner = loopClass();
        MethodNode m = owner.methods.get(0);
        var r = NativeTranspiler.transpile(owner, m);
        assertTrue(r.supported(), "for loop must be transpiled to labels/goto");
        assertTrue(r.cppBody().contains("goto L"), r.cppBody());
        assertTrue(r.cppBody().contains("if ("), r.cppBody());
        assertTrue(r.cppBody().contains("lv2_i = (jint)((chimera_u32)lv2_i + (chimera_u32)1);"), r.cppBody());
    }

    @Test
    void overloadedMethodsGetDistinctJniLongNamesAndFiles() {
        ClassNode owner = classNode("demo/Overload");
        MethodNode ints = method(owner, Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "add", "(II)I");
        ints.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        ints.instructions.add(new VarInsnNode(Opcodes.ILOAD, 1));
        ints.instructions.add(new InsnNode(Opcodes.IADD));
        ints.instructions.add(new InsnNode(Opcodes.IRETURN));

        MethodNode mixed = method(owner, Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "add", "(ID)D");
        mixed.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        mixed.instructions.add(new InsnNode(Opcodes.I2D));
        mixed.instructions.add(new VarInsnNode(Opcodes.DLOAD, 1));
        mixed.instructions.add(new InsnNode(Opcodes.DADD));
        mixed.instructions.add(new InsnNode(Opcodes.DRETURN));

        NativeTranspiler.TranspileResult intsResult = NativeTranspiler.transpile(owner, ints);
        NativeTranspiler.TranspileResult mixedResult = NativeTranspiler.transpile(owner, mixed);
        assertTrue(intsResult.supported());
        assertTrue(mixedResult.supported());
        assertTrue(intsResult.headerDecl().contains("Java_demo_Overload_add__II"),
                intsResult.headerDecl());
        assertTrue(mixedResult.headerDecl().contains("Java_demo_Overload_add__ID"),
                mixedResult.headerDecl());

        NativeTemplate intsTemplate = template(owner, ints, intsResult);
        NativeTemplate mixedTemplate = template(owner, mixed, mixedResult);
        assertNotEquals(NativeTemplateWriter.fileBase(intsTemplate),
                NativeTemplateWriter.fileBase(mixedTemplate),
                "overloaded natives must not overwrite the same .h/.cpp");
    }

    @Test
    void transpilesPureMathCalls() {
        ClassNode owner = classNode("demo/MathCalls");
        MethodNode m = method(owner, Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "calc", "(DD)D");
        m.instructions.add(new VarInsnNode(Opcodes.DLOAD, 0));
        m.instructions.add(new VarInsnNode(Opcodes.DLOAD, 2));
        m.instructions.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Math", "max", "(DD)D", false));
        m.instructions.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Math", "sqrt", "(D)D", false));
        m.instructions.add(new InsnNode(Opcodes.DRETURN));
        NativeTranspiler.TranspileResult r = NativeTranspiler.transpile(owner, m);
        assertTrue(r.supported(), r.headerDecl());
        assertTrue(r.cppBody().contains("std::fmax("), r.cppBody());
        assertTrue(r.cppBody().contains("std::sqrt("), r.cppBody());
    }

    @Test
    void rejectsObjectParametersAndNonStaticMethods() {
        ClassNode owner = classNode("demo/Hwid");
        MethodNode objectArg = method(owner, Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "hash", "(Ljava/lang/String;)Ljava/lang/String;");
        objectArg.instructions.add(new InsnNode(Opcodes.ACONST_NULL));
        objectArg.instructions.add(new InsnNode(Opcodes.ARETURN));
        assertFalse(NativeTranspiler.transpile(owner, objectArg).supported());

        ClassNode owner2 = classNode("demo/Instance");
        MethodNode instance = method(owner2, Opcodes.ACC_PUBLIC, "calc", "(I)I");
        instance.instructions.add(new VarInsnNode(Opcodes.ILOAD, 1));
        instance.instructions.add(new InsnNode(Opcodes.IRETURN));
        assertFalse(NativeTranspiler.transpile(owner2, instance).supported());
    }

    @Test
    void rejectsExceptionTables() {
        ClassNode owner = classNode("demo/Throwing");
        MethodNode m = method(owner, Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "one", "()I");
        m.instructions.add(new InsnNode(Opcodes.ICONST_1));
        m.instructions.add(new InsnNode(Opcodes.IRETURN));
        LabelNode start = new LabelNode();
        LabelNode end = new LabelNode();
        LabelNode handler = new LabelNode();
        m.tryCatchBlocks.add(new TryCatchBlockNode(start, end, handler, "java/lang/RuntimeException"));
        assertFalse(NativeTranspiler.transpile(owner, m).supported());
    }

    @Test
    void transpilesIntegerDivisionWithJavaSemanticsGuard() {
        ClassNode owner = classNode("demo/Div");
        MethodNode m = method(owner, Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "div", "(II)I");
        m.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        m.instructions.add(new VarInsnNode(Opcodes.ILOAD, 1));
        m.instructions.add(new InsnNode(Opcodes.IDIV));
        m.instructions.add(new InsnNode(Opcodes.IRETURN));
        var r = NativeTranspiler.transpile(owner, m);
        assertTrue(r.supported());
        assertTrue(r.cppBody().contains("chimera_idiv(s0_i, s1_i)"), r.cppBody());
    }

    @Test
    void writerEmitsHeaderAndSource() {
        ClassNode owner = addClass();
        NativeTranspiler.TranspileResult r = NativeTranspiler.transpile(owner, owner.methods.get(0));
        NativeTemplate t = template(owner, owner.methods.get(0), r);

        String header = NativeTemplateWriter.generateHeader(t);
        assertTrue(header.contains("#pragma once"), header);
        assertTrue(header.contains("#include <jni.h>"), header);
        assertTrue(header.contains("chimera_d2i"), header);
        assertTrue(header.contains(r.headerDecl()), header);

        String source = NativeTemplateWriter.generateSource(t);
        assertTrue(source.contains("#include \"demo_Math_add.h\""), source);
        assertTrue(source.contains("#include <cmath>"), source);
        assertTrue(source.contains("return s0_i;"), source);

        NativeTemplate todo = new NativeTemplate("demo/Hwid", "hash",
                "(Ljava/lang/String;)Ljava/lang/String;", true);
        String todoSource = NativeTemplateWriter.generateSource(todo);
        assertTrue(todoSource.contains("// TODO: implement hash"), todoSource);
        assertTrue(todoSource.contains("return nullptr;"), todoSource);
    }

    @Test
    void generatedSourcesPassGccSyntaxCheck() throws Exception {
        Path gcc = findOnPath("gcc");
        Assumptions.assumeTrue(gcc != null, "gcc not installed; skipping native C++ syntax smoke test");
        Path javaHome = Path.of(System.getProperty("java.home"));
        Path include = javaHome.resolve("include");
        Path platformInclude = include.resolve(platformDir());
        Assumptions.assumeTrue(Files.isDirectory(include) && Files.isDirectory(platformInclude),
                "JNI headers missing under " + javaHome);

        Path dir = Files.createTempDirectory("chimera-native-smoke");
        List<NativeTemplate> templates = new ArrayList<>();
        for (ClassNode owner : List.of(addClass(), mixClass(), branchClass(), loopClass())) {
            NativeTranspiler.TranspileResult r = NativeTranspiler.transpile(owner, owner.methods.get(0));
            assertTrue(r.supported(), "fixture must be supported: " + owner.methods.get(0).name);
            templates.add(template(owner, owner.methods.get(0), r));
        }
        templates.add(new NativeTemplate("demo/Hwid", "hash",
                "(Ljava/lang/String;)Ljava/lang/String;", true));
        for (NativeTemplate t : templates) {
            write(dir, t);
        }

        for (NativeTemplate t : templates) {
            Path cpp = dir.resolve(NativeTemplateWriter.fileBase(t) + ".cpp");
            List<String> command = new ArrayList<>();
            command.add(gcc.toString());
            command.add("-x");
            command.add("c++");
            command.add("-std=c++17");
            command.add("-fsyntax-only");
            command.add("-I" + include);
            command.add("-I" + platformInclude);
            command.add(cpp.toString());
            ProcessResult pr = run(command, 30);
            assertTrue(pr.exit == 0,
                    "gcc syntax check failed for " + cpp + "\ncommand: " + String.join(" ", command)
                            + "\noutput:\n" + pr.output);
        }
    }

    private static void write(Path dir, NativeTemplate t) throws IOException {
        Files.writeString(dir.resolve(NativeTemplateWriter.fileBase(t) + ".h"),
                NativeTemplateWriter.generateHeader(t), StandardCharsets.UTF_8);
        Files.writeString(dir.resolve(NativeTemplateWriter.fileBase(t) + ".cpp"),
                NativeTemplateWriter.generateSource(t), StandardCharsets.UTF_8);
    }

    private static Path findOnPath(String executable) {
        String path = System.getenv("PATH");
        if (path == null) return null;
        for (String element : path.split(java.io.File.pathSeparator)) {
            if (element.isBlank()) continue;
            for (String candidate : List.of(executable, executable + ".exe", executable + ".bat")) {
                Path p = Path.of(element, candidate);
                if (Files.isRegularFile(p)) return p;
            }
        }
        return null;
    }

    private static String platformDir() {
        String os = System.getProperty("os.name", "").toLowerCase();
        if (os.contains("win")) return "win32";
        if (os.contains("mac")) return "darwin";
        return "linux";
    }

    private record ProcessResult(int exit, String output) {
    }

    private static ProcessResult run(List<String> command, int timeoutSeconds) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        Process process = pb.start();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (InputStream in = process.getInputStream()) {
            in.transferTo(out);
        }
        boolean finished = process.waitFor(timeoutSeconds, java.util.concurrent.TimeUnit.SECONDS);
        if (!finished) {
            process.destroyForcibly();
            return new ProcessResult(-1, "timeout after " + timeoutSeconds + "s");
        }
        return new ProcessResult(process.exitValue(), out.toString(StandardCharsets.UTF_8));
    }
}
