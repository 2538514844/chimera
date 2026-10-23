package dev.chimera.transform.sink;

import dev.chimera.core.ChimeraConfig;
import dev.chimera.core.ClassPool;
import dev.chimera.core.Stats;
import dev.chimera.core.TransformContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Acceptance tests for {@link NativeSinkTransformer}: selection rules, original-body collection,
 * native stub shape, Mixin byte preservation, RegisterNatives symbols and determinism.
 */
class NativeSinkTransformerTest {

    private static final String FIXTURE = "demo/SinkFixture";
    private static final String MIXIN = "demo/SinkTarget";
    private static final String INTERFACE = "demo/SinkItf";
    private static final String WEIGHT = "demo/SinkWeight";
    private static final String OTHER = "demo/SinkOther";
    private static final String EXCLUDED = "dev/chimera/SinkExcluded";
    private static final String ANNOTATED = "demo/SinkAnnotated";

    /**
     * B-2 product decision: reference-returning methods ({@code identity(Object)Object}) are NOT
     * sunk. The native body cannot return the object the Java contract expects on every path (the
     * first real-machine attempt returned null and surfaced as an NPE inside the mod), so the sink
     * policy only takes void/primitive-returning methods and leaves reference returns in Java.
     * Coverage is unchanged in practice: 256 of the 256 selected PeakHack methods are primitive.
     */
    private static final Set<String> EXPECTED_SELECTED = Set.of(
            "add(II)I",
            "scale(I)I",
            "loop(I)I",
            "branched(I)I",
            "tryCatch(II)I",
            "over(I)I",
            "over(II)I");

    @Test
    void selectsSupportedMethodsAndLeavesNativeStubs() throws Exception {
        ClassNode node = read(fixtureBytes());
        Map<String, MethodNode> before = index(node);
        TransformContext ctx = context();
        NativeSinkTransformer transformer = new NativeSinkTransformer(options());

        transformer.transform(FIXTURE, node, ctx);

        SinkResult result = transformer.result();
        Set<String> selected = new HashSet<>();
        for (SinkSelectedMethod method : result.selectedMethods()) {
            selected.add(method.name() + method.descriptor());
            MethodNode stub = find(node, method.name(), method.descriptor());
            assertNotNull(stub, "native stub missing for " + method.displayName());
            assertNotSame(method.original(), stub);
            assertEquals(Opcodes.ACC_NATIVE, stub.access & Opcodes.ACC_NATIVE,
                    method.displayName() + " must be native");
            assertEquals(0, stub.instructions.size(), "native stub must have no code");
            assertTrue(stub.tryCatchBlocks.isEmpty(), "native stub must have no try/catch");
            assertEquals(0, stub.maxStack);
            assertEquals(0, stub.maxLocals);
            assertEquals((method.original().access & Opcodes.ACC_STATIC) != 0,
                    (stub.access & Opcodes.ACC_STATIC) != 0,
                    "static/instance kind must be preserved for " + method.displayName());
            assertSame(before.get(method.name() + method.descriptor()), method.original(),
                    "collected node must be the untouched original");
            assertTrue(method.original().instructions.size() > 0, "original body must be collected");
        }
        assertEquals(EXPECTED_SELECTED, selected);

        SinkSelectedMethod loop = selected(result, "loop", "(I)I");
        assertTrue(hasOpcode(loop.original(), Opcodes.GOTO), "loop body must be kept with its back edge");
        SinkSelectedMethod tryCatch = selected(result, "tryCatch", "(II)I");
        assertEquals(1, tryCatch.original().tryCatchBlocks.size(), "try/catch metadata must be collected");
        SinkSelectedMethod scale = selected(result, "scale", "(I)I");
        assertTrue(hasOpcode(scale.original(), Opcodes.GETFIELD), "instance field access must be kept");
        assertFalse(scale.isStatic());
        assertTrue(selected(result, "add", "(II)I").isStatic());

        MethodNode identity = find(node, "identity", "(Ljava/lang/Object;)Ljava/lang/Object;");
        assertEquals(0, identity.access & Opcodes.ACC_NATIVE,
                "reference-returning method must keep its Java body (B-2 product decision)");
        assertTrue(identity.instructions.size() > 0);
        assertEquals("<T:Ljava/lang/Object;>(TT;)TT;", identity.signature,
                "skipped method must keep its generic Signature");
        assertNotNull(identity.visibleAnnotations);
        assertTrue(identity.visibleAnnotations.stream()
                .anyMatch(annotation -> "Ldemo/Marker;".equals(annotation.desc)),
                "skipped method must keep its annotations");

        NativeSinkTransformer.Stats stats = transformer.stats();
        assertEquals(7, stats.selected());
        assertEquals(7, stats.generatedFunctions());
        assertEquals(14, stats.methodsVisited());
        assertEquals(stats.selected() + stats.skipped(), stats.methodsVisited());
        assertEquals(1, stats.skipCount(NativeSinkTransformer.SkipReason.CONSTRUCTOR));
        assertEquals(1, stats.skipCount(NativeSinkTransformer.SkipReason.CLASS_INITIALIZER));
        assertEquals(1, stats.skipCount(NativeSinkTransformer.SkipReason.SYNCHRONIZED));
        assertEquals(1, stats.skipCount(NativeSinkTransformer.SkipReason.NATIVE));
        assertEquals(1, stats.skipCount(NativeSinkTransformer.SkipReason.BRIDGE));
        assertEquals(2, stats.skipCount(NativeSinkTransformer.SkipReason.UNSUPPORTED_BYTECODE),
                "identity(Object)Object is rejected by NativeBodyCompiler reference-return rule");
        assertEquals(0, stats.skipCount(NativeSinkTransformer.SkipReason.CLASS_BUDGET));
        assertEquals(7, ctx.stats.methodsNativeStubbed,
                "sink methods must feed the existing core native counter");

        assertEquals(7, result.generatedFunctions());
        for (SinkSelectedMethod method : result.selectedMethods()) {
            assertTrue(method.cppSource().contains(method.symbol()),
                    "generated C++ must define its JNI symbol: " + method.displayName());
            assertTrue(method.cppSource().contains("JNIEXPORT"));
        }
    }

    @Test
    void leavesUnselectedMethodsAndMixinsByteIdentical() throws Exception {
        ClassNode node = read(fixtureBytes());
        Map<String, String> before = dumps(node);
        Map<String, Integer> accessBefore = access(node);
        NativeSinkTransformer transformer = new NativeSinkTransformer(options());
        transformer.transform(FIXTURE, node, context());

        for (String key : List.of("<init>()V", "<clinit>()V", "sync()V", "raw(I)I", "multi()[[I",
                "bridge(Ljava/lang/Object;)Ljava/lang/Object;")) {
            MethodNode method = find(node, key.substring(0, key.indexOf('(')),
                    key.substring(key.indexOf('(')));
            assertNotNull(method, "skipped method missing: " + key);
            assertEquals(before.get(key), dump(method), "skipped method body changed: " + key);
            assertEquals(accessBefore.get(key), method.access, "skipped method access changed: " + key);
        }

        ClassNode mixinNode = read(mixinBytes());
        byte[] mixinBefore = write(mixinNode);
        Map<String, String> mixinDumps = dumps(mixinNode);
        NativeSinkTransformer mixinTransformer = new NativeSinkTransformer(options());
        mixinTransformer.transform(MIXIN, mixinNode, context());
        byte[] mixinAfter = write(mixinNode);

        assertArrayEquals(mixinBefore, mixinAfter, "Mixin class bytes must not change");
        assertEquals("Ljava/lang/Object;", mixinNode.signature, "class Signature must survive");
        assertEquals(mixinDumps, dumps(mixinNode), "Mixin method bodies must not change");
        assertEquals(0, mixinTransformer.stats().selected());
        assertEquals(1, mixinTransformer.stats().mixinClassesSkipped());
        assertEquals(1, mixinTransformer.stats().skipCount(NativeSinkTransformer.SkipReason.MIXIN_CLASS));
        MethodNode injected = mixinNode.methods.get(0);
        assertFalse((injected.access & Opcodes.ACC_NATIVE) != 0);
        assertNotNull(injected.localVariables);
        assertFalse(injected.localVariables.isEmpty(), "Mixin debug locals must survive");
        // The fixture (like a real @Inject) uses CLASS retention, which ASM reads into
        // invisibleAnnotations. Requiring a RuntimeVisibleAnnotations attribute here would
        // contradict the byte-identity assertion above: adding that attribute changes the bytes.
        assertNotNull(injected.invisibleAnnotations);
        assertTrue(injected.invisibleAnnotations.stream()
                .anyMatch(annotation -> annotation.desc.startsWith("Lorg/spongepowered/asm/mixin/")));
    }

    @Test
    void skipsMethodsOwnedByOtherChimeraStages() throws Exception {
        ClassNode node = read(annotatedBytes());
        NativeSinkTransformer transformer = new NativeSinkTransformer(options());
        transformer.transform(ANNOTATED, node, context());

        assertEquals(1, transformer.stats().selected(), "only the unannotated method may be sunk");
        assertEquals(2, transformer.stats().skipCount(NativeSinkTransformer.SkipReason.CHIMERA_ANNOTATION),
                "both visible and invisible Chimera annotations must block the sink");
        assertEquals(3, transformer.stats().methodsVisited());

        assertFalse((find(node, "vmEntry", "(I)I").access & Opcodes.ACC_NATIVE) != 0,
                "@ChimeraVM body must stay in Java for the VM stage");
        assertTrue(find(node, "vmEntry", "(I)I").instructions.size() > 0);
        assertFalse((find(node, "entangled", "(I)I").access & Opcodes.ACC_NATIVE) != 0,
                "@ChimeraEntangle body must stay in Java for the entangle stage");
        assertTrue(find(node, "entangled", "(I)I").instructions.size() > 0);
        MethodNode kept = find(node, "kept", "(I)I");
        assertNotNull(kept);
        assertEquals(Opcodes.ACC_NATIVE, kept.access & Opcodes.ACC_NATIVE);
        assertEquals(0, kept.instructions.size());
        assertEquals(ANNOTATED + "\tkept\t(I)I\t\n", transformer.encodeSinkManifest());
    }

    @Test
    void skipsInterfaceDefaultMethods() throws Exception {
        ClassNode node = read(interfaceBytes());
        byte[] before = write(node);
        NativeSinkTransformer transformer = new NativeSinkTransformer(options());
        transformer.transform(INTERFACE, node, context());

        assertEquals(0, transformer.stats().selected());
        assertEquals(1, transformer.stats().skipCount(NativeSinkTransformer.SkipReason.INTERFACE_METHOD));
        assertEquals(1, transformer.stats().skipCount(NativeSinkTransformer.SkipReason.ABSTRACT));
        assertEquals(2, transformer.stats().methodsVisited());
        assertArrayEquals(before, write(node), "interface class must be untouched");
    }

    @Test
    void generatesRegisterNativesSnippetWithExactSymbols() throws Exception {
        NativeSinkTransformer transformer = transformFixture();
        String snippet = transformer.registerNativesSnippet();

        assertTrue(snippet.contains("extern \"C\" JNIEXPORT jint JNICALL JNI_OnLoad"), snippet);
        assertTrue(snippet.contains("chimera_sink_register_all"));
        assertTrue(snippet.contains("chimera_sink_methods_0"));
        assertTrue(snippet.contains("chimera_sink_resolve(env, \"demo/SinkFixture\")"),
                "C-3: host classes must be resolved through the load-only resolver");
        assertFalse(snippet.contains("FindClass(\"demo/SinkFixture\")"),
                "C-3: env->FindClass links the host class and must not be used");
        assertTrue(snippet.contains("chimera_sink_register_all_with_host"),
                "C-3: the registering class must be captured as the resolution host");
        assertTrue(snippet.contains("return failed =="),
                "C-3: all-groups-failed must be distinguishable from partial failure");
        assertTrue(snippet.contains("RegisterNatives"));
        assertTrue(snippet.contains("return JNI_ERR;"), "JNI_OnLoad must fail closed");
        assertTrue(snippet.contains("JNI_VERSION_1_8"));
        assertTrue(snippet.contains("&Java_demo_SinkFixture_add)"));
        assertTrue(snippet.contains("&Java_demo_SinkFixture_over__I)"),
                "overloaded method must use the long JNI name");
        assertTrue(snippet.contains("&Java_demo_SinkFixture_over__II)"));
        assertFalse(snippet.contains("&Java_demo_SinkFixture_over)"),
                "short JNI name must not be used for an overloaded method");

        String unit = transformer.cppUnit();
        assertTrue(unit.contains("#include <jni.h>"));
        for (SinkSelectedMethod method : transformer.result().selectedMethods()) {
            assertTrue(unit.contains(method.symbol()), "missing function for " + method.displayName());
        }
        assertTrue(unit.contains("RegisterNatives"));

        String withoutOnLoad = transformer.registerNativesSnippet(false);
        assertFalse(withoutOnLoad.contains("JNI_OnLoad"));
        assertTrue(withoutOnLoad.contains("chimera_sink_register_all"));

        String manifest = transformer.encodeSinkManifest();
        String[] lines = manifest.split("\n", -1);
        assertEquals(8, lines.length, "7 manifest lines + trailing newline");
        assertEquals(7, Arrays.stream(lines).filter(line -> !line.isEmpty()).count());
        for (String line : lines) {
            if (line.isEmpty()) {
                continue;
            }
            String[] columns = line.split("\t", -1);
            assertEquals(4, columns.length, "manifest columns: " + line);
            assertEquals(FIXTURE, columns[0]);
        }
        assertFalse(Arrays.stream(lines).anyMatch(line -> line.startsWith(FIXTURE + "\tidentity\t")),
                "reference-returning method must not appear in the sink manifest");
        String addLine = Arrays.stream(lines)
                .filter(line -> line.startsWith(FIXTURE + "\tadd\t"))
                .findFirst().orElseThrow();
        assertEquals("", addLine.split("\t", -1)[3], "absent Signature must encode as an empty column");
        String[] nonEmpty = Arrays.stream(lines).filter(line -> !line.isEmpty()).toArray(String[]::new);
        String[] sortedLines = Arrays.copyOf(nonEmpty, nonEmpty.length);
        Arrays.sort(sortedLines);
        assertArrayEquals(sortedLines, nonEmpty, "manifest must be canonically sorted");
    }

    @Test
    void artifactsAreDeterministicAcrossClassOrder() throws Exception {
        NativeSinkTransformer first = new NativeSinkTransformer(options());
        ClassNode fixture = read(fixtureBytes());
        first.transform(FIXTURE, fixture, context());
        ClassNode other = read(otherBytes());
        first.transform(OTHER, other, context());

        NativeSinkTransformer second = new NativeSinkTransformer(options());
        ClassNode other2 = read(otherBytes());
        second.transform(OTHER, other2, context());
        ClassNode fixture2 = read(fixtureBytes());
        second.transform(FIXTURE, fixture2, context());

        assertEquals(first.encodeSinkManifest(), second.encodeSinkManifest());
        assertEquals(first.registerNativesSnippet(), second.registerNativesSnippet());
        assertEquals(first.cppUnit(), second.cppUnit());

        // Same batch and same visitation order as "first": a fresh instance must reproduce the
        // artifacts bit-for-bit. (Compare against the identical batch; a single-class transformer
        // legitimately emits fewer functions than a two-class one.)
        NativeSinkTransformer third = new NativeSinkTransformer(options());
        ClassNode fixture3 = read(fixtureBytes());
        third.transform(FIXTURE, fixture3, context());
        ClassNode other3 = read(otherBytes());
        third.transform(OTHER, other3, context());
        assertEquals(first.encodeSinkManifest(), third.encodeSinkManifest());
        assertEquals(first.cppUnit(), third.cppUnit());
    }

    @Test
    void appliesInstructionThresholdsAndWeightPriority() throws Exception {
        NativeSinkTransformer.Options weightOptions = new NativeSinkTransformer.Options(
                true, 8192, 1, 400, 1, 256, 1, 0, 0, 0,
                NativeSinkTransformer.Options.DEFAULT_EXCLUDED_PREFIXES);
        NativeSinkTransformer weighted = new NativeSinkTransformer(weightOptions);
        weighted.transform(WEIGHT, read(weightBytes()), context());
        assertEquals(1, weighted.stats().selected());
        assertEquals("heavy()I", weighted.result().selectedMethods().get(0).name()
                + weighted.result().selectedMethods().get(0).descriptor());
        assertEquals(1, weighted.stats().skipCount(NativeSinkTransformer.SkipReason.CLASS_BUDGET));

        NativeSinkTransformer.Options smallOptions = new NativeSinkTransformer.Options(
                true, 8192, 1, 5, 16, 256, 1, 1, 1, 1,
                NativeSinkTransformer.Options.DEFAULT_EXCLUDED_PREFIXES);
        NativeSinkTransformer small = new NativeSinkTransformer(smallOptions);
        small.transform(WEIGHT, read(weightBytes()), context());
        assertEquals(1, small.stats().selected());
        assertEquals("light()I", small.result().selectedMethods().get(0).name()
                + small.result().selectedMethods().get(0).descriptor());
        assertEquals(1, small.stats().skipCount(NativeSinkTransformer.SkipReason.TOO_MANY_INSTRUCTIONS));

        NativeSinkTransformer.Options byteOptions = new NativeSinkTransformer.Options(
                true, 1, 1, 400, 16, 256, 1, 1, 1, 1,
                NativeSinkTransformer.Options.DEFAULT_EXCLUDED_PREFIXES);
        NativeSinkTransformer tiny = new NativeSinkTransformer(byteOptions);
        tiny.transform(WEIGHT, read(weightBytes()), context());
        assertEquals(0, tiny.stats().selected());
        assertEquals(2, tiny.stats().skipCount(NativeSinkTransformer.SkipReason.TOO_LARGE));
    }

    @Test
    void failsClosedOnInvalidInputAndSkipsExcludedClasses() throws Exception {
        NativeSinkTransformer transformer = new NativeSinkTransformer(options());
        ClassNode node = read(fixtureBytes());
        assertThrows(IllegalArgumentException.class,
                () -> transformer.transform("demo/Other", node, context()),
                "owner mismatch must fail the build");
        assertThrows(IllegalArgumentException.class,
                () -> transformer.transform(FIXTURE, null, context()));
        assertThrows(IllegalArgumentException.class,
                () -> transformer.transform(FIXTURE, node, null));
        assertThrows(IllegalArgumentException.class,
                () -> new NativeSinkTransformer.Options(true, -1, 1, 400, 16, 256, 1, 1, 1, 1,
                        NativeSinkTransformer.Options.DEFAULT_EXCLUDED_PREFIXES));

        NativeSinkTransformer excluded = new NativeSinkTransformer(options());
        excluded.transform(EXCLUDED, read(simpleBytes(EXCLUDED, "calc")), context());
        assertEquals(0, excluded.stats().selected());
        assertEquals(1, excluded.stats().skipCount(NativeSinkTransformer.SkipReason.EXCLUDED_CLASS));
        assertEquals(0, excluded.result().selectedMethods().size());
    }

    @Test
    void generatedCppCompilesWithGxx(@TempDir Path tmp) throws Exception {
        assumeTrue(hasGxx(), "g++ not on PATH; skipping C++ syntax check");
        Path jdkInclude = Path.of(System.getProperty("java.home"), "include");
        assumeTrue(Files.isDirectory(jdkInclude), "JDK include directory missing");

        NativeSinkTransformer transformer = transformFixture();
        Path cpp = tmp.resolve("sink.cpp");
        Files.writeString(cpp, transformer.cppUnit(), StandardCharsets.UTF_8);

        List<String> command = new ArrayList<>(List.of("g++", "-std=c++17", "-fsyntax-only",
                "-I", jdkInclude.toString()));
        Path win32 = jdkInclude.resolve("win32");
        if (Files.isDirectory(win32)) {
            command.add("-I");
            command.add(win32.toString());
        }
        command.add(cpp.toString());

        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        boolean finished = process.waitFor(180, TimeUnit.SECONDS);
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (!finished) {
            process.destroyForcibly();
        }
        assertTrue(finished, "g++ timed out");
        assertEquals(0, process.exitValue(), "g++ rejected generated native sink unit:\n" + output);
    }

    // ---------------------------------------------------------------- fixtures

    private static byte[] fixtureBytes() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, FIXTURE, null,
                "java/lang/Object", null);
        cw.visitField(Opcodes.ACC_PRIVATE, "factor", "I", null, null).visitEnd();
        cw.visitField(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "hits", "I", null, null).visitEnd();

        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitIntInsn(Opcodes.BIPUSH, 3);
        mv.visitFieldInsn(Opcodes.PUTFIELD, FIXTURE, "factor", "I");
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        mv = cw.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        mv.visitCode();
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitFieldInsn(Opcodes.PUTSTATIC, FIXTURE, "hits", "I");
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "add", "(II)I", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ILOAD, 0);
        mv.visitVarInsn(Opcodes.ILOAD, 1);
        mv.visitInsn(Opcodes.IADD);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "scale", "(I)I", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitFieldInsn(Opcodes.GETFIELD, FIXTURE, "factor", "I");
        mv.visitVarInsn(Opcodes.ILOAD, 1);
        mv.visitInsn(Opcodes.IMUL);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        Label loop = new Label();
        Label done = new Label();
        mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "loop", "(I)I", null, null);
        mv.visitCode();
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitVarInsn(Opcodes.ISTORE, 1);
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitVarInsn(Opcodes.ISTORE, 2);
        mv.visitLabel(loop);
        mv.visitVarInsn(Opcodes.ILOAD, 2);
        mv.visitVarInsn(Opcodes.ILOAD, 0);
        mv.visitJumpInsn(Opcodes.IF_ICMPGT, done);
        mv.visitVarInsn(Opcodes.ILOAD, 1);
        mv.visitVarInsn(Opcodes.ILOAD, 2);
        mv.visitInsn(Opcodes.IADD);
        mv.visitVarInsn(Opcodes.ISTORE, 1);
        mv.visitIincInsn(2, 1);
        mv.visitJumpInsn(Opcodes.GOTO, loop);
        mv.visitLabel(done);
        mv.visitVarInsn(Opcodes.ILOAD, 1);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        Label negative = new Label();
        mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "branched", "(I)I", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ILOAD, 0);
        mv.visitJumpInsn(Opcodes.IFLE, negative);
        mv.visitVarInsn(Opcodes.ILOAD, 0);
        mv.visitInsn(Opcodes.ICONST_2);
        mv.visitInsn(Opcodes.IMUL);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitLabel(negative);
        mv.visitInsn(Opcodes.ICONST_M1);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        Label start = new Label();
        Label end = new Label();
        Label handler = new Label();
        mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "tryCatch", "(II)I", null, null);
        mv.visitCode();
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

        mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "identity",
                "(Ljava/lang/Object;)Ljava/lang/Object;",
                "<T:Ljava/lang/Object;>(TT;)TT;", null);
        mv.visitAnnotation("Ldemo/Marker;", true).visitEnd();
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitInsn(Opcodes.ARETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "over", "(I)I", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ILOAD, 0);
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitInsn(Opcodes.IADD);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "over", "(II)I", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ILOAD, 0);
        mv.visitVarInsn(Opcodes.ILOAD, 1);
        mv.visitInsn(Opcodes.IADD);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_SYNCHRONIZED, "sync", "()V", null, null);
        mv.visitCode();
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_NATIVE, "raw", "(I)I", null, null);
        mv.visitEnd();

        mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "multi", "()[[I", null, null);
        mv.visitCode();
        mv.visitInsn(Opcodes.ICONST_2);
        mv.visitInsn(Opcodes.ICONST_2);
        mv.visitMultiANewArrayInsn("[[I", 2);
        mv.visitInsn(Opcodes.ARETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_BRIDGE | Opcodes.ACC_SYNTHETIC,
                "bridge", "(Ljava/lang/Object;)Ljava/lang/Object;", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ALOAD, 1);
        mv.visitInsn(Opcodes.ARETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }

    private static byte[] mixinBytes() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, MIXIN, "Ljava/lang/Object;",
                "java/lang/Object", null);
        cw.visitAnnotation("Lorg/spongepowered/asm/mixin/Mixin;", true).visitEnd();

        Label start = new Label();
        Label end = new Label();
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "inject", "(I)I", "(I)I", null);
        mv.visitAnnotation("Lorg/spongepowered/asm/mixin/injection/Inject;", false).visitEnd();
        mv.visitCode();
        mv.visitLabel(start);
        mv.visitLineNumber(7, start);
        mv.visitVarInsn(Opcodes.ILOAD, 1);
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitInsn(Opcodes.IADD);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitLabel(end);
        mv.visitLocalVariable("this", "Ldemo/SinkTarget;", null, start, end, 0);
        mv.visitLocalVariable("x", "I", null, start, end, 1);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }

    private static byte[] interfaceBytes() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_INTERFACE | Opcodes.ACC_ABSTRACT,
                INTERFACE, null, "java/lang/Object", null);

        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "twice", "(I)I", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ILOAD, 1);
        mv.visitInsn(Opcodes.ICONST_2);
        mv.visitInsn(Opcodes.IMUL);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT, "raw", "(I)I", null, null);
        mv.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }

    private static byte[] weightBytes() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, WEIGHT, null,
                "java/lang/Object", null);

        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "heavy", "()I", null, null);
        mv.visitCode();
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitVarInsn(Opcodes.ISTORE, 0);
        mv.visitVarInsn(Opcodes.ILOAD, 0);
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitInsn(Opcodes.IADD);
        mv.visitVarInsn(Opcodes.ISTORE, 0);
        mv.visitVarInsn(Opcodes.ILOAD, 0);
        mv.visitInsn(Opcodes.ICONST_2);
        mv.visitInsn(Opcodes.IADD);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "light", "()I", null, null);
        mv.visitCode();
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }

    private static byte[] annotatedBytes() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, ANNOTATED, null,
                "java/lang/Object", null);

        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "kept", "(I)I", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ILOAD, 0);
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitInsn(Opcodes.IADD);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "vmEntry", "(I)I", null, null);
        mv.visitAnnotation("Ldev/chimera/annotations/ChimeraVM;", false).visitEnd();
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ILOAD, 0);
        mv.visitInsn(Opcodes.ICONST_2);
        mv.visitInsn(Opcodes.IMUL);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "entangled", "(I)I", null, null);
        mv.visitAnnotation("Ldev/chimera/annotations/ChimeraEntangle;", true).visitEnd();
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ILOAD, 0);
        mv.visitInsn(Opcodes.ICONST_3);
        mv.visitInsn(Opcodes.IADD);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }

    private static byte[] otherBytes() {
        return simpleBytes(OTHER, "other");
    }

    private static byte[] simpleBytes(String owner, String method) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, owner, null,
                "java/lang/Object", null);
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, method, "(I)I", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ILOAD, 0);
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitInsn(Opcodes.IADD);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    // ----------------------------------------------------------------- helpers

    private static NativeSinkTransformer.Options options() {
        return new NativeSinkTransformer.Options(true, 8192, 1, 400, 16, 256, 1, 4, 2, 3,
                NativeSinkTransformer.Options.DEFAULT_EXCLUDED_PREFIXES);
    }

    private static NativeSinkTransformer transformFixture() throws Exception {
        NativeSinkTransformer transformer = new NativeSinkTransformer(options());
        transformer.transform(FIXTURE, read(fixtureBytes()), context());
        return transformer;
    }

    private static TransformContext context() {
        ChimeraConfig config = new ChimeraConfig();
        config.keyMaterial = new byte[32];
        config.resourceKeyMaterial = new byte[32];
        return new TransformContext(config, new byte[16], new byte[32], new ClassPool(Map.of()),
                (name, data) -> {
                }, new Stats(), "sink-test");
    }

    private static ClassNode read(byte[] bytes) {
        ClassNode node = new ClassNode();
        new ClassReader(bytes).accept(node, 0);
        return node;
    }

    private static byte[] write(ClassNode node) {
        ClassWriter writer = new ClassWriter(0);
        node.accept(writer);
        return writer.toByteArray();
    }

    private static MethodNode find(ClassNode node, String name, String desc) {
        for (MethodNode method : node.methods) {
            if (method.name.equals(name) && method.desc.equals(desc)) {
                return method;
            }
        }
        return null;
    }

    private static SinkSelectedMethod selected(SinkResult result, String name, String desc) {
        for (SinkSelectedMethod method : result.selectedMethods()) {
            if (method.name().equals(name) && method.descriptor().equals(desc)) {
                return method;
            }
        }
        throw new AssertionError("not selected: " + name + desc);
    }

    private static Map<String, MethodNode> index(ClassNode node) {
        Map<String, MethodNode> out = new LinkedHashMap<>();
        for (MethodNode method : node.methods) {
            out.put(method.name + method.desc, method);
        }
        return out;
    }

    private static Map<String, String> dumps(ClassNode node) {
        Map<String, String> out = new LinkedHashMap<>();
        for (MethodNode method : node.methods) {
            out.put(method.name + method.desc, dump(method));
        }
        return out;
    }

    private static Map<String, Integer> access(ClassNode node) {
        Map<String, Integer> out = new LinkedHashMap<>();
        for (MethodNode method : node.methods) {
            out.put(method.name + method.desc, method.access);
        }
        return out;
    }

    private static String dump(MethodNode method) {
        StringBuilder sb = new StringBuilder();
        for (AbstractInsnNode insn : method.instructions) {
            sb.append(insn.getOpcode()).append('@').append(insn.getClass().getSimpleName()).append(';');
        }
        sb.append("tryCatch=").append(method.tryCatchBlocks.size());
        return sb.toString();
    }

    private static boolean hasOpcode(MethodNode method, int opcode) {
        for (AbstractInsnNode insn : method.instructions) {
            if (insn.getOpcode() == opcode) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasGxx() {
        try {
            Process process = new ProcessBuilder("g++", "--version").redirectErrorStream(true).start();
            return process.waitFor(20, TimeUnit.SECONDS) && process.exitValue() == 0;
        } catch (IOException | InterruptedException e) {
            return false;
        }
    }
}
