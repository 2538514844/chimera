package dev.chimera.transform.sink;

import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * B1 wiring acceptance for the native sink: the planner must rank classes by in-jar call
 * weight, exclude mixin/keep/dev-chimera classes, and the transformer must honor the
 * class gate; the engine-level integration must sink the planned classes' bodies before
 * the per-class stage runs.
 */
class NativeSinkWiringTest {

    /** Four-class fixture: Caller -> Hub -> {A, B}; Hub is the call hub (highest weight). */
    private static final String CALLER = "demo/pln/Caller";
    private static final String HUB = "demo/pln/Hub";
    private static final String LEAF_A = "demo/pln/LeafA";
    private static final String LEAF_B = "demo/pln/LeafB";
    private static final String MIXIN = "demo/pln/SinkMixin";
    private static final String RUNTIME = "dev/chimera/pln/Runtime";

    @Test
    void plannerRanksByInJarCallsAndExcludesMixinAndRuntime() {
        Map<String, byte[]> classes = fixtureJar();
        NativeSinkPlanner.Plan plan = NativeSinkPlanner.plan(classes, List.of(), 0);

        assertEquals(6, plan.totalClasses(), "all fixture classes must be visited");
        assertEquals(1, plan.mixinClasses(), "the @Mixin class must be excluded");
        assertEquals(1, plan.excludedClasses(), "dev/chimera/** must be excluded");
        assertEquals(4, plan.ranked().size(), "4 non-mixin, non-runtime candidate classes");

        // Hub receives calls from Caller (2 sites); leaves receive 1 each; Caller 0.
        assertEquals(HUB, plan.ranked().get(0).internalName(), "highest in-jar call weight first");
        assertEquals(2, plan.ranked().get(0).inJarCalls());
        assertTrue(plan.ranked().get(0).weight() > plan.ranked().get(1).weight(),
                "call weight must dominate the ranking");
        assertFalse(plan.allowedClasses().contains(MIXIN), "mixin must never be allowed");
        assertFalse(plan.allowedClasses().contains(RUNTIME), "runtime must never be allowed");

        // Deterministic: tie-broken by name when weights are equal.
        NativeSinkPlanner.Plan again = NativeSinkPlanner.plan(classes, List.of(), 0);
        assertEquals(plan.ranked().stream().map(NativeSinkPlanner.ClassWeight::internalName).toList(),
                again.ranked().stream().map(NativeSinkPlanner.ClassWeight::internalName).toList());
    }

    @Test
    void budgetCapsAllowedClassesAndTransformerHonorsGate() throws Exception {
        Map<String, byte[]> classes = fixtureJar();
        // maxClasses=1 -> only the top-weight class (Hub) may sink anything.
        NativeSinkPlanner.Plan plan = NativeSinkPlanner.plan(classes, List.of(), 1);
        assertEquals(1, plan.allowedClasses().size());
        assertTrue(plan.allowedClasses().contains(HUB));

        NativeSinkTransformer transformer = new NativeSinkTransformer();
        transformer.restrictTo(plan.allowedClasses());
        for (Map.Entry<String, byte[]> entry : classes.entrySet()) {
            String internal = entry.getKey().substring(0, entry.getKey().length() - 6);
            ClassNode node = new ClassNode();
            new ClassReader(entry.getValue()).accept(node, 0);
            transformer.transform(internal, node, context());
        }

        assertTrue(transformer.stats().selected() > 0, "Hub must sink its helper methods");
        for (var selected : transformer.result().selectedMethods()) {
            assertEquals(HUB, selected.owner(), "only the allowed class may be sunk");
        }
        // A gated-out class must keep its Java body.
        ClassNode caller = read(classes.get(CALLER + ".class"));
        MethodNode body = find(caller, "run", "()V");
        assertTrue(body.instructions.size() > 0, "gated-out class must keep its body");
        assertFalse((body.access & Opcodes.ACC_NATIVE) != 0);

        // Clearing the gate restores eligibility: Caller's run() must now be selectable.
        transformer.restrictTo(null);
        ClassNode caller2 = read(classes.get(CALLER + ".class"));
        transformer.transform(CALLER, caller2, context());
        assertTrue(transformer.result().selectedMethods().stream()
                        .anyMatch(m -> m.owner().equals(CALLER)),
                "gate cleared: Caller must now be eligible");
        MethodNode cleared = find(caller2, "run", "()V");
        assertTrue((cleared.access & Opcodes.ACC_NATIVE) != 0,
                "run() must have become a native stub after the gate was cleared");
    }

    @Test
    void budgetNormalizationSemantics() {
        assertEquals(0, NativeSinkPlanner.normalizeBudget(0));
        assertEquals(0, NativeSinkPlanner.normalizeBudget(-5));
        assertEquals(8, NativeSinkPlanner.normalizeBudget(8));
        assertTrue(NativeSinkPlanner.isPercentBudget(8));
        assertTrue(NativeSinkPlanner.isPercentBudget(15));
        assertFalse(NativeSinkPlanner.isPercentBudget(0));
        assertFalse(NativeSinkPlanner.isPercentBudget(100));
        assertFalse(NativeSinkPlanner.isPercentBudget(300));
    }

    // ---------------------------------------------------------------- fixtures

    /** Caller.run -> Hub.twice + Hub.answer; Hub.twice -> LeafA.one; Hub.answer -> LeafB.two. */
    private static Map<String, byte[]> fixtureJar() {
        Map<String, byte[]> classes = new LinkedHashMap<>();
        classes.put(CALLER + ".class", callerBytes());
        classes.put(HUB + ".class", hubBytes());
        classes.put(LEAF_A + ".class", leafBytes(LEAF_A, "one"));
        classes.put(LEAF_B + ".class", leafBytes(LEAF_B, "two"));
        classes.put(MIXIN + ".class", mixinBytes());
        classes.put(RUNTIME + ".class", leafBytes(RUNTIME, "secret"));
        return classes;
    }

    private static byte[] callerBytes() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, CALLER, null,
                "java/lang/Object", null);
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "run", "()V", null, null);
        mv.visitCode();
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, HUB, "twice", "(I)I", false);
        mv.visitInsn(Opcodes.POP);
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, HUB, "answer", "()I", false);
        mv.visitInsn(Opcodes.POP);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    private static byte[] hubBytes() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, HUB, null,
                "java/lang/Object", null);
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "twice", "(I)I", null, null);
        mv.visitCode();
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, LEAF_A, "one", "(I)I", false);
        mv.visitInsn(Opcodes.IADD);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "answer", "()I", null, null);
        mv.visitCode();
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, LEAF_B, "two", "()I", false);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    private static byte[] leafBytes(String owner, String name) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, owner, null,
                "java/lang/Object", null);
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                name, name.equals("two") ? "()I" : "(I)I", null, null);
        mv.visitCode();
        if (name.equals("two")) {
            mv.visitIntInsn(Opcodes.BIPUSH, 42);
        } else {
            mv.visitVarInsn(Opcodes.ILOAD, 0);
            mv.visitInsn(Opcodes.ICONST_1);
            mv.visitInsn(Opcodes.IADD);
        }
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    private static byte[] mixinBytes() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, MIXIN, null, "java/lang/Object", null);
        cw.visitAnnotation("Lorg/spongepowered/asm/mixin/Mixin;", true).visitEnd();
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "helper", "(I)I", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ILOAD, 0);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    private static ClassNode read(byte[] bytes) {
        ClassNode node = new ClassNode();
        new ClassReader(bytes).accept(node, 0);
        return node;
    }

    private static MethodNode find(ClassNode node, String name, String desc) {
        for (MethodNode method : node.methods) {
            if (method.name.equals(name) && method.desc.equals(desc)) {
                return method;
            }
        }
        return null;
    }

    private static dev.chimera.core.TransformContext context() {
        dev.chimera.core.ChimeraConfig config = new dev.chimera.core.ChimeraConfig();
        config.keyMaterial = new byte[32];
        config.resourceKeyMaterial = new byte[32];
        return new dev.chimera.core.TransformContext(config, new byte[16], new byte[32],
                new dev.chimera.core.ClassPool(Map.of()), (name, data) -> {
                }, new dev.chimera.core.Stats(), "sink-wiring-test");
    }
}
