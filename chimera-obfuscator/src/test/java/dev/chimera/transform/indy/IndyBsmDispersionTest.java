package dev.chimera.transform.indy;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.util.CheckClassAdapter;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.InvocationTargetException;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * G8 acceptance: {@link IndyIntegration#prepare} generates 16 equivalent bootstrap owners and
 * rotates call sites with {@code (classId ^ siteIndex) & 15}; the generated owners are loadable and
 * behave exactly like the single {@link ChimeraBootstrap} owner. A per-site {@link CheckHook} can
 * deny one site without affecting the others.
 */
public class IndyBsmDispersionTest implements Opcodes {

    private static final String SPREAD = "sample/BsmSpread";
    private static final String PARTIAL = "sample/PartialSubject";
    private static final String MATH = IndyTestSamples.MATH;
    private static final String OBJECT = "java/lang/Object";

    @BeforeEach
    void reset() {
        MemberIdRegistry.clearForTests();
        ChimeraBootstrap.installCheckHook(CheckHook.DENY);
    }

    @Test
    void prepareGeneratesSixteenEquivalentOwnersAndRotatesCallSites() throws Exception {
        Map<String, byte[]> originals = new LinkedHashMap<>(IndyTestSamples.originalClasses());
        originals.put(SPREAD, bsmSpread());
        IndyIntegration.Result result =
                IndyIntegration.prepare(originals, IndyIntegration.Options.AGGRESSIVE);

        assertEquals(BsmClassGenerator.DEFAULT_COUNT, result.extraClasses().size());
        for (int i = 0; i < BsmClassGenerator.DEFAULT_COUNT; i++) {
            String entryName = "chimera/indy/Bsm" + i + ".class";
            assertTrue(result.extraClasses().containsKey(entryName), entryName);
            byte[] generated = result.extraClasses().get(entryName);
            assertNotNull(generated);
            // classes() mirrors the input key convention (these fixtures use "a/B", no .class).
            assertArrayEquals(generated, result.classes().get("chimera/indy/Bsm" + i),
                    "generated owners must also be packaged through classes()");
        }
        assertEquals(BsmClassGenerator.DEFAULT_COUNT, result.distinctBsmOwners());

        // Rotation: site i selects owner ((classId ^ i) & 15); 40 spread sites cover all 16.
        long classId = MemberIdRegistry.classId(MATH);
        Set<String> expectedOwners = new LinkedHashSet<>();
        for (int i = 0; i < 40; i++) {
            expectedOwners.add(BsmClassGenerator.owner((int) ((classId ^ (long) i) & 15)));
        }
        assertEquals(BsmClassGenerator.DEFAULT_COUNT, expectedOwners.size());

        ClassNode rewritten = readNode(result.classes().get(SPREAD));
        Set<String> usedOwners = new LinkedHashSet<>();
        int indySites = 0;
        for (MethodNode method : rewritten.methods) {
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn instanceof InvokeDynamicInsnNode indy) {
                    indySites++;
                    usedOwners.add(indy.bsm.getOwner());
                    assertEquals(ChimeraBootstrap.BSM_NAME, indy.bsm.getName());
                    assertEquals(ChimeraBootstrap.BSM_DESC, indy.bsm.getDesc());
                }
            }
        }
        assertEquals(40, indySites);
        assertEquals(expectedOwners, usedOwners);
        assertEquals(BsmClassGenerator.DEFAULT_COUNT, usedOwners.size());

        for (int i = 0; i < BsmClassGenerator.DEFAULT_COUNT; i++) {
            ClassNode owner = readNode(result.extraClasses().get("chimera/indy/Bsm" + i + ".class"));
            assertEquals("chimera/indy/Bsm" + i, owner.name);
            assertEquals(1, owner.methods.size(), "each owner carries exactly the bootstrap method");
            MethodNode bootstrap = owner.methods.get(0);
            assertEquals(ChimeraBootstrap.BSM_NAME, bootstrap.name);
            assertEquals(ChimeraBootstrap.BSM_DESC, bootstrap.desc);
            assertTrue((bootstrap.access & ACC_PUBLIC) != 0);
            assertTrue((bootstrap.access & ACC_STATIC) != 0);
            MethodInsnNode delegate = firstMethodInsn(bootstrap);
            assertNotNull(delegate);
            assertEquals(ChimeraBootstrap.OWNER, delegate.owner);
            assertEquals(ChimeraBootstrap.BSM_NAME, delegate.name);
            assertEquals(ChimeraBootstrap.BSM_DESC, delegate.desc);
        }

        TestByteLoader loader = new TestByteLoader(result.classes(), getClass().getClassLoader());
        MemberIdRegistry.clearForTests();
        MemberIdRegistry.loadMemberTable(result.memberTable(), loader, true);
        AtomicInteger links = new AtomicInteger();
        ChimeraBootstrap.installCheckHook(request -> {
            links.incrementAndGet();
            return true;
        });

        Class<?> spread = Class.forName(SPREAD.replace('/', '.'), true, loader);
        // sum(i + 7, i = 0..39) = 780 + 280.
        assertEquals(1060, invokeInt(spread, "run", 0));
        assertEquals(40, links.get(), "each dispersed site links exactly once");
        assertEquals(40, MemberIdRegistry.memberLookups(), "member resolution is cached per site");

        StringWriter diagnostics = new StringWriter();
        CheckClassAdapter.verify(new ClassReader(result.classes().get(SPREAD)), loader, false,
                new PrintWriter(diagnostics));
        assertEquals("", diagnostics.toString().trim(), "ASM data-flow verification must pass");
    }

    @Test
    void oneDeniedSiteDoesNotAffectOtherSites() throws Exception {
        Map<String, byte[]> originals = new LinkedHashMap<>();
        originals.put(MATH, IndyTestSamples.mathOps());
        originals.put(PARTIAL, partialSubject());
        IndyIntegration.Result result =
                IndyIntegration.prepare(originals, IndyIntegration.Options.AGGRESSIVE);
        assertEquals(2, result.stats().rewritten());

        TestByteLoader loader = new TestByteLoader(result.classes(), getClass().getClassLoader());
        MemberIdRegistry.clearForTests();
        MemberIdRegistry.loadMemberTable(result.memberTable(), loader, true);

        AtomicInteger attempts = new AtomicInteger();
        Set<String> names = new LinkedHashSet<>();
        Set<Integer> kinds = new LinkedHashSet<>();
        ChimeraBootstrap.installCheckHook(request -> {
            attempts.incrementAndGet();
            synchronized (names) {
                names.add(request.callSiteName());
                kinds.add(request.kind());
            }
            return "add".equals(request.callSiteName());
        });

        Class<?> partial = Class.forName(PARTIAL.replace('/', '.'), true, loader);
        // Allowed site links and executes.
        assertEquals(13, invokeInt(partial, "allowed", 5));
        // Denied site fails closed, but only that site.
        InvocationTargetException denied = assertThrows(InvocationTargetException.class,
                () -> invokeInt(partial, "denied", 5));
        assertTrue(hasBootstrapMethodError(denied.getCause()),
                "denied link must throw BootstrapMethodError, got " + denied.getCause());

        assertEquals(2, attempts.get(), "one check per attempted site");
        assertEquals(Set.of("add", "mul"), names);
        assertEquals(Set.of(Integer.valueOf(ChimeraBootstrap.KIND_STATIC)), kinds);

        // The already-linked site keeps working and never re-checks.
        assertEquals(13, invokeInt(partial, "allowed", 5));
        assertEquals(15, invokeInt(partial, "allowed", 7));
        assertEquals(2, attempts.get());
    }

    @Test
    void dispersionCanBeDisabledForTheLegacyContract() {
        Map<String, byte[]> originals = new LinkedHashMap<>(IndyTestSamples.originalClasses());
        IndyIntegration.Result result = IndyIntegration.prepare(originals,
                new IndyIntegration.Options(true, true, false));

        assertTrue(result.extraClasses().isEmpty());
        assertEquals(0, result.distinctBsmOwners());
        assertEquals(9, result.stats().rewritten());

        ClassNode subject = readNode(result.classes().get(IndyTestSamples.SUBJECT));
        int indySites = 0;
        for (MethodNode method : subject.methods) {
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn instanceof InvokeDynamicInsnNode indy) {
                    indySites++;
                    assertEquals(ChimeraBootstrap.OWNER, indy.bsm.getOwner());
                }
            }
        }
        assertEquals(9, indySites);
    }

    // ------------------------------------------------------------------ fixtures

    static byte[] bsmSpread() {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(V17, ACC_PUBLIC | ACC_FINAL | ACC_SUPER, SPREAD, null, OBJECT, null);
        constructor(cw);
        MethodVisitor mv = cw.visitMethod(ACC_PUBLIC | ACC_STATIC, "run", "(I)I", null, null);
        mv.visitCode();
        for (int i = 0; i < 40; i++) {
            mv.visitVarInsn(ILOAD, 0);
            mv.visitIntInsn(BIPUSH, i);
            mv.visitMethodInsn(INVOKESTATIC, MATH, "add", "(II)I", false);
            mv.visitVarInsn(ISTORE, 0);
        }
        mv.visitVarInsn(ILOAD, 0);
        mv.visitInsn(IRETURN);
        mv.visitMaxs(2, 1);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    static byte[] partialSubject() {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(V17, ACC_PUBLIC | ACC_FINAL | ACC_SUPER, PARTIAL, null, OBJECT, null);
        constructor(cw);
        MethodVisitor mv = cw.visitMethod(ACC_PUBLIC | ACC_STATIC, "allowed", "(I)I", null, null);
        mv.visitCode();
        mv.visitVarInsn(ILOAD, 0);
        mv.visitInsn(ICONST_1);
        mv.visitMethodInsn(INVOKESTATIC, MATH, "add", "(II)I", false);
        mv.visitInsn(IRETURN);
        mv.visitMaxs(2, 1);
        mv.visitEnd();

        mv = cw.visitMethod(ACC_PUBLIC | ACC_STATIC, "denied", "(I)I", null, null);
        mv.visitCode();
        mv.visitVarInsn(ILOAD, 0);
        mv.visitInsn(ICONST_1);
        mv.visitMethodInsn(INVOKESTATIC, MATH, "mul", "(II)I", false);
        mv.visitInsn(IRETURN);
        mv.visitMaxs(2, 1);
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

    // ------------------------------------------------------------------ helpers

    private static MethodInsnNode firstMethodInsn(MethodNode method) {
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof MethodInsnNode call) {
                return call;
            }
        }
        return null;
    }

    private static ClassNode readNode(byte[] bytes) {
        ClassNode node = new ClassNode();
        new ClassReader(bytes).accept(node, 0);
        return node;
    }

    private static int invokeInt(Class<?> type, String name, int argument) throws Exception {
        return ((Number) type.getMethod(name, int.class).invoke(null, argument)).intValue();
    }

    private static boolean hasBootstrapMethodError(Throwable throwable) {
        Throwable current = throwable;
        while (current != null) {
            if (current instanceof BootstrapMethodError) {
                return true;
            }
            current = current.getCause();
        }
        return false;
    }
}
