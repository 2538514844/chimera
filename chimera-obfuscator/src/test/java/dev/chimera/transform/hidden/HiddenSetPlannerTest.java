package dev.chimera.transform.hidden;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * S5 hidden-set planning: candidates, structural keeps, reflective strings, excludes,
 * determinism and fail-closed input handling.
 */
class HiddenSetPlannerTest {

    private static final int V = Opcodes.V17;

    private static final String MIXIN = "Lorg/spongepowered/asm/mixin/Mixin;";
    private static final String NATIVE = "Ldev/chimera/annotations/ChimeraNative;";
    private static final String VM = "Ldev/chimera/annotations/ChimeraVM;";

    // ------------------------------------------------------------------
    // ASM helpers
    // ------------------------------------------------------------------

    private static byte[] cls(String name, int access, String superName, String[] interfaces,
                              java.util.function.Consumer<ClassWriter> body) {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(V, access, name, null, superName, interfaces);
        body.accept(cw);
        cw.visitEnd();
        return cw.toByteArray();
    }

    private static byte[] simple(String name) {
        return cls(name, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, "java/lang/Object", null, cw -> {
            ctor(cw, "java/lang/Object");
        });
    }

    private static void ctor(ClassWriter cw, String superName) {
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, superName, "<init>", "()V", false);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(1, 1);
        mv.visitEnd();
    }

    private static void method(ClassWriter cw, int access, String name, String desc,
                               java.util.function.Consumer<MethodVisitor> body) {
        MethodVisitor mv = cw.visitMethod(access, name, desc, null, null);
        mv.visitCode();
        body.accept(mv);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(4, 4);
        mv.visitEnd();
    }

    private static void classAnnotation(ClassWriter cw, String desc,
                                        java.util.function.Consumer<AnnotationVisitor> body) {
        AnnotationVisitor av = cw.visitAnnotation(desc, false);
        body.accept(av);
        av.visitEnd();
    }

    private static void methodAnnotation(MethodVisitor mv, String desc) {
        AnnotationVisitor av = mv.visitAnnotation(desc, false);
        av.visitEnd();
    }

    // ------------------------------------------------------------------
    // Fixture: 20+ synthetic classes covering every rule
    // ------------------------------------------------------------------

    private static Map<String, byte[]> fixture() {
        Map<String, byte[]> classes = new LinkedHashMap<>();

        // app: entrypoint references one same-package and one cross-package class.
        classes.put("app/Main", cls("app/Main", Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                "java/lang/Object", null, cw -> {
                    cw.visitField(Opcodes.ACC_PUBLIC, "service", "Llib/Impl;", null, null).visitEnd();
                    ctor(cw, "java/lang/Object");
                    method(cw, Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "helper",
                            "(Lapp/Helper;)V", mv -> {
                            });
                }));
        classes.put("app/Helper", cls("app/Helper", Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                "java/lang/Object", null, cw -> {
                    ctor(cw, "java/lang/Object");
                    method(cw, Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "deep",
                            "(Lapp/Deep;)V", mv -> {
                            });
                }));
        classes.put("app/Deep", simple("app/Deep"));

        // lib: cross-package reference from the kept entrypoint forces the first class to stay.
        classes.put("lib/Impl", cls("lib/Impl", Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                "java/lang/Object", null, cw -> {
                    ctor(cw, "java/lang/Object");
                    method(cw, Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "ok",
                            "(Llib/Ok;)V", mv -> {
                            });
                }));
        classes.put("lib/Ok", simple("lib/Ok"));

        // demo: self-contained cluster (mutual references), plus reflective targets.
        classes.put("demo/Pair", cls("demo/Pair", Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                "java/lang/Object", null, cw -> {
                    cw.visitField(Opcodes.ACC_PUBLIC, "partner", "Ldemo/Partner;", null, null).visitEnd();
                    ctor(cw, "java/lang/Object");
                }));
        classes.put("demo/Partner", cls("demo/Partner", Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                "java/lang/Object", null, cw -> {
                    cw.visitField(Opcodes.ACC_PUBLIC, "pair", "Ldemo/Pair;", null, null).visitEnd();
                    ctor(cw, "java/lang/Object");
                }));
        classes.put("demo/Anon", cls("demo/Anon", Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                "java/lang/Object", null, cw -> {
                    ctor(cw, "java/lang/Object");
                    method(cw, Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "use",
                            "(Ldemo/Pair;)V", mv -> {
                            });
                }));
        classes.put("demo/Reflector", cls("demo/Reflector", Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                "java/lang/Object", null, cw -> {
                    ctor(cw, "java/lang/Object");
                    method(cw, Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "load", "()V", mv -> {
                        mv.visitLdcInsn("demo.ReflectTarget");
                        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Class", "forName",
                                "(Ljava/lang/String;)Ljava/lang/Class;", false);
                        mv.visitInsn(Opcodes.POP);
                    });
                }));
        classes.put("demo/ReflectTarget", simple("demo/ReflectTarget"));
        classes.put("demo/MemberReflector", cls("demo/MemberReflector",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, "java/lang/Object", null, cw -> {
                    ctor(cw, "java/lang/Object");
                    method(cw, Opcodes.ACC_PUBLIC, "call", "()V", mv -> {
                        mv.visitLdcInsn(Type.getType("Ldemo/MemberReflector;"));
                        mv.visitLdcInsn("secret");
                        mv.visitInsn(Opcodes.ACONST_NULL);
                        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getDeclaredMethod",
                                "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false);
                        mv.visitInsn(Opcodes.POP);
                    });
                    method(cw, Opcodes.ACC_PUBLIC, "secret", "()V", mv -> {
                    });
                }));

        // api: structural class kinds.
        classes.put("api/Contract", cls("api/Contract",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_INTERFACE | Opcodes.ACC_ABSTRACT,
                "java/lang/Object", null, cw -> {
                }));
        classes.put("api/ContractImpl", cls("api/ContractImpl", Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                "java/lang/Object", new String[]{"api/Contract"}, cw -> {
                    ctor(cw, "java/lang/Object");
                }));
        classes.put("api/Color", cls("api/Color",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_ENUM | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER,
                "java/lang/Enum", null, cw -> {
                    cw.visitField(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_ENUM | Opcodes.ACC_FINAL,
                            "RED", "Lapi/Color;", null, null).visitEnd();
                }));
        classes.put("api/Point", cls("api/Point",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER | Opcodes.ACC_RECORD,
                "java/lang/Record", null, cw -> {
                    cw.visitRecordComponent("x", "I", null).visitEnd();
                    ctor(cw, "java/lang/Record");
                }));
        classes.put("api/Marker", cls("api/Marker",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_ANNOTATION | Opcodes.ACC_INTERFACE | Opcodes.ACC_ABSTRACT,
                "java/lang/Object", new String[]{"java/lang/annotation/Annotation"}, cw -> {
                }));

        // mixin: the mixin and its in-jar target must both stay.
        classes.put("mix/Mixer", cls("mix/Mixer", Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                "java/lang/Object", null, cw -> {
                    classAnnotation(cw, MIXIN, av -> {
                        AnnotationVisitor array = av.visitArray("targets");
                        array.visit(null, "mix.Target");
                        array.visitEnd();
                    });
                    ctor(cw, "java/lang/Object");
                }));
        classes.put("mix/Target", simple("mix/Target"));

        // native / VM owners.
        classes.put("native/Calc", cls("native/Calc", Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                "java/lang/Object", null, cw -> {
                    MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                            "calc", "(I)I", null, null);
                    methodAnnotation(mv, NATIVE);
                    mv.visitCode();
                    mv.visitVarInsn(Opcodes.ILOAD, 0);
                    mv.visitInsn(Opcodes.IRETURN);
                    mv.visitMaxs(1, 1);
                    mv.visitEnd();
                }));
        classes.put("vm/Program", cls("vm/Program", Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                "java/lang/Object", null, cw -> {
                    MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                            "run", "()V", null, null);
                    methodAnnotation(mv, VM);
                    mv.visitCode();
                    mv.visitInsn(Opcodes.RETURN);
                    mv.visitMaxs(0, 0);
                    mv.visitEnd();
                }));

        // excludes / implicit keeps.
        classes.put("dev/chimera/runtime/ChimeraRun", simple("dev/chimera/runtime/ChimeraRun"));
        classes.put("demo/Generated$chimera$1", simple("demo/Generated$chimera$1"));
        classes.put("demo/Excluded", simple("demo/Excluded"));
        classes.put("demo/Prefixed/Thing", simple("demo/Prefixed/Thing"));

        return classes;
    }

    private static HiddenSetOptions options() {
        return new HiddenSetOptions(Set.of("app.Main"), Set.of("demo/Excluded"),
                Set.of("demo/Prefixed"), true);
    }

    private static HiddenSetOptions strictOptions() {
        return new HiddenSetOptions(Set.of("app.Main"), Set.of("demo/Excluded"),
                Set.of("demo/Prefixed"), false);
    }

    // ------------------------------------------------------------------
    // Report invariants / structural rules
    // ------------------------------------------------------------------

    @Test
    void reportCountsAreConsistentAndDisjoint() {
        Map<String, byte[]> classes = fixture();
        Report report = HiddenSetPlanner.plan(classes, options());

        assertEquals(classes.size(), report.scannedClasses());
        assertEquals(report.hiddenCandidates().size(), report.hiddenCandidateCount());
        assertEquals(classes.size(), report.keptCount() + report.hiddenCandidateCount());
        assertEquals(classes.size(), report.keepReasons().size() + report.hiddenCandidates().size());
        for (String candidate : report.hiddenCandidates()) {
            assertFalse(report.keepReasons().containsKey(candidate), "kept and hidden: " + candidate);
            assertNull(report.reasonFor(candidate));
            assertTrue(report.isHiddenCandidate(candidate));
        }
        for (Map.Entry<String, String> entry : report.keepReasons().entrySet()) {
            assertFalse(entry.getValue().isBlank(), "blank reason for " + entry.getKey());
            assertFalse(entry.getValue().contains("\n"), "multiline reason for " + entry.getKey());
        }
        assertTrue(report.reflectiveHits() >= 2, "expected reflective hits, got " + report.reflectiveHits());
    }

    @Test
    void structuralKindsAreKeptWithReasons() {
        Report report = HiddenSetPlanner.plan(fixture(), options());

        assertEquals("interface", report.reasonFor("api/Contract"));
        assertEquals("enum", report.reasonFor("api/Color"));
        assertEquals("record", report.reasonFor("api/Point"));
        assertEquals("annotation type", report.reasonFor("api/Marker"));
        assertEquals("Mixin class", report.reasonFor("mix/Mixer"));
        assertEquals("Mixin target of mix/Mixer", report.reasonFor("mix/Target"));
        assertEquals("@ChimeraNative owner", report.reasonFor("native/Calc"));
        assertEquals("@ChimeraVM owner", report.reasonFor("vm/Program"));
        assertEquals("chimera package (dev/chimera)", report.reasonFor("dev/chimera/runtime/ChimeraRun"));
        assertTrue(report.reasonFor("demo/Generated$chimera$1").contains("$chimera$"));
        assertTrue(report.reasonFor("demo/Excluded").contains("forced keep"));
        assertTrue(report.reasonFor("demo/Prefixed/Thing").contains("forced keep prefix"));
        assertEquals("entrypoint (fabric.mod.json / mixin config)", report.reasonFor("app/Main"));
    }

    @Test
    void reflectiveClassStringKeepsTargetAndIsCounted() {
        Report report = HiddenSetPlanner.plan(fixture(), options());

        assertTrue(report.reasonFor("demo/ReflectTarget").contains("reflective class string"));
        assertTrue(report.reasonFor("demo/ReflectTarget").contains("demo.ReflectTarget"));
        assertTrue(report.isHiddenCandidate("demo/Reflector"), "the caller itself stays hideable");
    }

    @Test
    void reflectiveMemberLookupKeepsCaller() {
        Report report = HiddenSetPlanner.plan(fixture(), options());

        String reason = report.reasonFor("demo/MemberReflector");
        assertNotNull(reason, "getDeclaredMethod(\"secret\") must keep the caller");
        assertTrue(reason.contains("reflective member lookup"));
        assertTrue(reason.contains("secret"));
    }

    @Test
    void crossPackageKeptReferenceForcesKeep() {
        Report report = HiddenSetPlanner.plan(fixture(), options());

        String reason = report.reasonFor("lib/Impl");
        assertNotNull(reason, "lib/Impl is named by kept app/Main across packages");
        assertTrue(reason.startsWith("referenced by kept app/Main"));
        assertTrue(reason.contains("field descriptor"));
        assertFalse(report.isHiddenCandidate("lib/Impl"));
    }

    @Test
    void samePackageReferenceIsPermittedByDefaultButBlockedInStrictMode() {
        Report relaxed = HiddenSetPlanner.plan(fixture(), options());
        assertTrue(relaxed.isHiddenCandidate("app/Helper"),
                "same-package reference from a kept class is permitted by default (S5 rewrite)");
        assertTrue(relaxed.isHiddenCandidate("app/Deep"));

        Report strict = HiddenSetPlanner.plan(fixture(), strictOptions());
        assertFalse(strict.isHiddenCandidate("app/Helper"));
        assertTrue(strict.reasonFor("app/Helper").contains("app/Main"));
        assertFalse(strict.isHiddenCandidate("app/Deep"),
                "the strict closure follows kept references transitively");
    }

    @Test
    void selfContainedCandidateClusterIsHidden() {
        Report report = HiddenSetPlanner.plan(fixture(), options());

        assertTrue(report.isHiddenCandidate("demo/Pair"));
        assertTrue(report.isHiddenCandidate("demo/Partner"));
        assertTrue(report.isHiddenCandidate("demo/Anon"));
        assertFalse(report.isHiddenCandidate("lib/Impl"));
    }

    // ------------------------------------------------------------------
    // Reference kinds
    // ------------------------------------------------------------------

    @Test
    void everyReferenceKindKeepsItsTargetAcrossPackages() {
        Map<String, byte[]> classes = new LinkedHashMap<>();
        classes.put("ref/Anno", cls("ref/Anno",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_ANNOTATION | Opcodes.ACC_INTERFACE | Opcodes.ACC_ABSTRACT,
                "java/lang/Object", new String[]{"java/lang/annotation/Annotation"}, cw -> {
                }));
        classes.put("ref/Host", referenceHost());
        classes.put("ref/Rec", recordHolder());
        for (String target : List.of(
                "far/Super", "far/Itf", "far/OuterType", "far/NestHost", "far/NestMate",
                "far/Permitted", "far/InnerType", "far/AnnoType", "far/FieldType", "far/SigType",
                "far/MethodArg", "far/CatchType", "far/LdcType", "far/HandleType", "far/IndyType",
                "far/FrameType", "far/RecComp")) {
            classes.put(target, simple(target));
        }

        HiddenSetOptions options = HiddenSetOptions.ofEntrypoints("ref/Host", "ref/Rec");
        Report report = HiddenSetPlanner.plan(classes, options);

        for (String target : List.of(
                "far/Super", "far/Itf", "far/OuterType", "far/NestHost", "far/NestMate",
                "far/Permitted", "far/InnerType", "far/AnnoType", "far/FieldType", "far/SigType",
                "far/MethodArg", "far/CatchType", "far/LdcType", "far/HandleType", "far/IndyType",
                "far/FrameType", "far/RecComp")) {
            assertFalse(report.isHiddenCandidate(target), target + " is referenced by a kept class");
            String reason = report.reasonFor(target);
            assertNotNull(reason, target);
            assertTrue(reason.startsWith("referenced by kept ref/"), target + " -> " + reason);
        }
        assertTrue(report.reasonFor("far/Super").contains("superclass"));
        assertTrue(report.reasonFor("far/Itf").contains("interface"));
        assertTrue(report.reasonFor("far/FieldType").contains("field descriptor"));
        assertTrue(report.reasonFor("far/MethodArg").contains("method descriptor"));
        assertTrue(report.reasonFor("far/SigType").contains("signature"));
        assertTrue(report.reasonFor("far/AnnoType").contains("annotation"));
        assertTrue(report.reasonFor("far/CatchType").contains("try-catch"));
        assertTrue(report.reasonFor("far/LdcType").contains("ldc"));
        assertTrue(report.reasonFor("far/HandleType").contains("ldc"));
        assertTrue(report.reasonFor("far/IndyType").contains("invokedynamic"));
        assertTrue(report.reasonFor("far/FrameType").contains("stack map"));
        assertTrue(report.reasonFor("far/InnerType").contains("inner class"));
        assertTrue(report.reasonFor("far/NestHost").contains("nest host"));
        assertTrue(report.reasonFor("far/NestMate").contains("nest member"));
        assertTrue(report.reasonFor("far/Permitted").contains("permitted subclass"));
        assertTrue(report.reasonFor("far/OuterType").contains("outer class"));
        assertTrue(report.reasonFor("far/RecComp").contains("record component"));
    }

    private static byte[] referenceHost() {
        return cls("ref/Host", Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, "far/Super",
                new String[]{"far/Itf"}, cw -> {
                    cw.visitOuterClass("far/OuterType", "m", "()V");
                    cw.visitNestHost("far/NestHost");
                    cw.visitNestMember("far/NestMate");
                    cw.visitPermittedSubclass("far/Permitted");
                    cw.visitInnerClass("far/InnerType", "ref/Host", "InnerType", Opcodes.ACC_STATIC);
                    classAnnotation(cw, "Lref/Anno;", av -> av.visit("type", Type.getType("Lfar/AnnoType;")));
                    cw.visitField(Opcodes.ACC_PUBLIC, "field", "Lfar/FieldType;", null, null).visitEnd();
                    cw.visitField(Opcodes.ACC_PUBLIC, "generic", "Ljava/util/List;",
                            "Ljava/util/List<Lfar/SigType;>;", null).visitEnd();
                    ctor(cw, "far/Super");
                    method(cw, Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "params", "(Lfar/MethodArg;)V",
                            mv -> {
                            });
                    MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                            "refs", "()V", null, null);
                    mv.visitCode();
                    Label start = new Label();
                    Label end = new Label();
                    Label handler = new Label();
                    mv.visitTryCatchBlock(start, end, handler, "far/CatchType");
                    mv.visitLabel(start);
                    mv.visitLdcInsn(Type.getType("Lfar/LdcType;"));
                    mv.visitInsn(Opcodes.POP);
                    mv.visitLdcInsn(new Handle(Opcodes.H_INVOKESTATIC, "far/HandleType", "run", "()V", false));
                    mv.visitInsn(Opcodes.POP);
                    mv.visitInvokeDynamicInsn("x", "()V",
                            new Handle(Opcodes.H_INVOKESTATIC, "java/lang/invoke/LambdaMetafactory",
                                    "metafactory", "()Ljava/lang/invoke/CallSite;", false),
                            new Handle(Opcodes.H_INVOKESTATIC, "far/IndyType", "run", "()V", false));
                    mv.visitLabel(end);
                    mv.visitInsn(Opcodes.RETURN);
                    mv.visitLabel(handler);
                    mv.visitInsn(Opcodes.RETURN);
                    mv.visitMaxs(2, 0);
                    mv.visitEnd();
                    MethodVisitor frames = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                            "frames", "()V", null, null);
                    frames.visitCode();
                    Label frameLabel = new Label();
                    frames.visitLabel(frameLabel);
                    frames.visitFrame(Opcodes.F_NEW, 0, new Object[0], 1,
                            new Object[]{"far/FrameType"});
                    frames.visitInsn(Opcodes.RETURN);
                    frames.visitMaxs(1, 0);
                    frames.visitEnd();
                });
    }

    private static byte[] recordHolder() {
        return cls("ref/Rec", Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER | Opcodes.ACC_RECORD,
                "java/lang/Record", null, cw -> {
                    cw.visitRecordComponent("c", "Lfar/RecComp;", null).visitEnd();
                    ctor(cw, "java/lang/Record");
                });
    }

    // ------------------------------------------------------------------
    // Determinism / output
    // ------------------------------------------------------------------

    @Test
    void determinismAcrossInsertionOrder() {
        Map<String, byte[]> forward = fixture();
        List<String> keys = new ArrayList<>(forward.keySet());
        Map<String, byte[]> reverse = new LinkedHashMap<>();
        for (int i = keys.size() - 1; i >= 0; i--) {
            reverse.put(keys.get(i), forward.get(keys.get(i)));
        }

        Report first = HiddenSetPlanner.plan(forward, options());
        Report second = HiddenSetPlanner.plan(reverse, options());

        assertEquals(first, second);
        assertEquals(new ArrayList<>(first.hiddenCandidates()), new ArrayList<>(second.hiddenCandidates()));
        assertTrue(new ArrayList<>(first.keepReasons().keySet()).equals(
                new ArrayList<>(second.keepReasons().keySet())));
    }

    @Test
    void writeCandidateListIsSortedAndComplete(@TempDir Path tempDir) throws IOException {
        Report report = HiddenSetPlanner.plan(fixture(), options());
        Path file = tempDir.resolve("out/candidates.txt");

        Path written = HiddenSetPlanner.writeCandidateList(report, file);

        assertEquals(file.toAbsolutePath().normalize(), written);
        String text = Files.readString(file, StandardCharsets.UTF_8);
        assertFalse(text.contains("\r"), "must use LF line endings");
        List<String> lines = text.isEmpty() ? List.of() : List.of(text.split("\n", -1));
        List<String> nonEmpty = new ArrayList<>();
        for (String line : lines) {
            if (!line.isEmpty()) {
                nonEmpty.add(line);
            }
        }
        assertEquals(new ArrayList<>(report.hiddenCandidates()), nonEmpty);
        List<String> sorted = new ArrayList<>(nonEmpty);
        sorted.sort(String::compareTo);
        assertEquals(sorted, nonEmpty);
        assertTrue(text.endsWith("\n"));
    }

    @Test
    void writeCandidateListHandlesEmptyReport(@TempDir Path tempDir) throws IOException {
        Report report = HiddenSetPlanner.plan(Map.of(), HiddenSetOptions.defaults());
        Path file = tempDir.resolve("nested/dir/list.txt");

        HiddenSetPlanner.writeCandidateList(report, file);

        assertTrue(Files.exists(file));
        assertEquals(0, Files.size(file));
        assertTrue(report.hiddenCandidates().isEmpty());
    }

    @Test
    void emptyInputProducesEmptyReport() {
        Report report = HiddenSetPlanner.plan(Map.of(), HiddenSetOptions.defaults());

        assertEquals(0, report.scannedClasses());
        assertEquals(0, report.hiddenCandidateCount());
        assertEquals(0, report.keptCount());
        assertEquals(0, report.reflectiveHits());
        assertTrue(report.keepReasons().isEmpty());
        assertTrue(report.hiddenCandidates().isEmpty());
    }

    @Test
    void planDoesNotMutateInputBytes() {
        Map<String, byte[]> classes = fixture();
        Map<String, byte[]> copies = new LinkedHashMap<>();
        for (Map.Entry<String, byte[]> entry : classes.entrySet()) {
            copies.put(entry.getKey(), entry.getValue().clone());
        }

        HiddenSetPlanner.plan(classes, options());

        assertEquals(copies.keySet(), classes.keySet());
        for (Map.Entry<String, byte[]> entry : classes.entrySet()) {
            assertTrue(Arrays.equals(copies.get(entry.getKey()), entry.getValue()),
                    "input bytes changed for " + entry.getKey());
        }
    }

    @Test
    void normalizesDottedAndClassSuffixKeys() {
        byte[] bytes = simple("dots/A");
        Report dotted = HiddenSetPlanner.plan(Map.of("dots.A", bytes), HiddenSetOptions.defaults());
        Report suffixed = HiddenSetPlanner.plan(Map.of("dots/A.class", bytes), HiddenSetOptions.defaults());

        assertEquals(1, dotted.scannedClasses());
        assertTrue(dotted.isHiddenCandidate("dots/A"));
        assertEquals(dotted, suffixed);
    }

    // ------------------------------------------------------------------
    // Fail-closed
    // ------------------------------------------------------------------

    @Test
    void failClosedOnMalformedClassBytes() {
        assertThrows(IllegalArgumentException.class,
                () -> HiddenSetPlanner.plan(Map.of("bad/Bytes", new byte[]{1, 2, 3}),
                        HiddenSetOptions.defaults()));
    }

    @Test
    void failClosedOnKeyNameMismatch() {
        assertThrows(IllegalArgumentException.class,
                () -> HiddenSetPlanner.plan(Map.of("wrong/Name", simple("right/Name")),
                        HiddenSetOptions.defaults()));
    }

    @Test
    void failClosedOnNullInputs() {
        assertThrows(IllegalArgumentException.class,
                () -> HiddenSetPlanner.plan(null, HiddenSetOptions.defaults()));
        assertThrows(IllegalArgumentException.class,
                () -> HiddenSetPlanner.plan(Map.of(), null));
        assertThrows(IllegalArgumentException.class,
                () -> HiddenSetPlanner.writeCandidateList(null, Path.of("x.txt")));
        assertThrows(IllegalArgumentException.class,
                () -> HiddenSetPlanner.writeCandidateList(
                        HiddenSetPlanner.plan(Map.of(), HiddenSetOptions.defaults()), null));
    }

    @Test
    void failClosedOnDuplicateClassAfterNormalization() {
        Map<String, byte[]> conflicting = new LinkedHashMap<>();
        conflicting.put("dup/A", simple("dup/A"));
        conflicting.put("dup/A.class", simple("dup/A"));
        assertThrows(IllegalArgumentException.class,
                () -> HiddenSetPlanner.plan(conflicting, HiddenSetOptions.defaults()));
    }

    @Test
    void ignoresExternalAndUnknownNames() {
        Map<String, byte[]> classes = new LinkedHashMap<>();
        classes.put("keep/Entry", cls("keep/Entry", Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                "java/lang/Object", new String[]{"java/lang/Runnable"}, cw -> {
                    cw.visitField(Opcodes.ACC_PUBLIC, "f", "Ljava/util/List;", null, null).visitEnd();
                    ctor(cw, "java/lang/Object");
                }));
        classes.put("keep/Free", simple("keep/Free"));

        Report report = HiddenSetPlanner.plan(classes, HiddenSetOptions.ofEntrypoints("keep/Entry"));

        assertEquals(2, report.scannedClasses());
        assertFalse(report.keepReasons().containsKey("java/lang/Object"));
        assertFalse(report.keepReasons().containsKey("java/util/List"));
        assertNotNull(report.reasonFor("keep/Entry"));
        assertTrue(report.isHiddenCandidate("keep/Free"));
    }
}
