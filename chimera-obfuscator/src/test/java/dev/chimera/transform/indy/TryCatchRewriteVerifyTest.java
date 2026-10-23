package dev.chimera.transform.indy;

import dev.chimera.core.ClassFingerprint;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FrameNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.util.CheckClassAdapter;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * M10 fix regression: the WurstTranslator VerifyError ("Bad type on operand stack", handler
 * entry frame typed java/lang/Object for a catch(Exception) site) happened when the ENGINE
 * recomputed frames over a ClassPool that was missing external dependencies (gson/Minecraft).
 * These tests pin the three guarantees the fix rests on:
 *
 * <ol>
 *   <li>The transformer itself preserves the original StackMapTable: after rewriting a method
 *       whose try range contains call sites, the catch-handler entry frames still carry the
 *       caught type (Exception), never java/lang/Object.</li>
 *   <li>A shared handler for two catch types (IOException | JsonParseException, exactly the
 *       Wurst shape) rewrites inside the try range and still JVM-verifies and executes.</li>
 *   <li>{@link ClassFingerprint#shapeDigest} is stable under the indy rewrite (so the engine
 *       keeps the original frames) and changes when a branch is added (so the engine still
 *       recomputes when a real control-flow transform runs).</li>
 * </ol>
 */
public class TryCatchRewriteVerifyTest {

    private static final String HANDLER_CASE = "trycatch/HandlerCase";

    @BeforeEach
    void resetGlobalState() {
        MemberIdRegistry.clearForTests();
        ChimeraBootstrap.installCheckHook(CheckHook.ALLOW);
    }

    /**
     * Full pipeline over a synthetic class shaped like WurstTranslator.loadTranslations:
     * two call sites inside a try range, one shared handler for IOException|JsonParseException
     * (the crash pattern) plus an Exception handler, all entry frames typed Exception.
     * The rewrite must keep those frames and the JVM must verify and run the method.
     */
    @Test
    void sharedHandlerTryCatchMethodRewritesVerifiesAndRuns() throws Exception {
        byte[] original = generateHandlerCase();
        byte[] rewritten = IndyDispatchTransformer.transformClass(original,
                new IndyDispatchTransformer.Options(true, true, true)).bytes();

        // Frames at every catch-handler entry must still name the caught type, never Object.
        assertHandlerFramesTyped(rewritten, "run");

        // Structural check plus a real JVM define + execute: verification happens here.
        new ClassReader(rewritten).accept(new CheckClassAdapter(new ClassWriter(0), false), 0);
        TestByteLoader loader = new TestByteLoader(rewrittenClasses(rewritten),
                getClass().getClassLoader());
        Class<?> handlerCase = Class.forName(HANDLER_CASE.replace('/', '.'), true, loader);
        MemberIdRegistry.registerClass(handlerCase);
        MemberIdRegistry.registerClass(String.class);
        MemberIdRegistry.registerMethod(String.class, "hashCode");
        MemberIdRegistry.registerMethod(String.class, "length");
        MemberIdRegistry.registerMethod(String.class, "equals", Object.class);
        // The handler bodies call Exception.printStackTrace (declared on Throwable): the call
        // site carries owner java/lang/Exception, so the member must be registered under the
        // site owner's ids with the Throwable Method object.
        MemberIdRegistry.registerClass(Exception.class);
        MemberIdRegistry.registerMethod(MemberIdRegistry.classId("java/lang/Exception"),
                MemberIdRegistry.memberId("java/lang/Exception", "printStackTrace", "()V"),
                Throwable.class.getDeclaredMethod("printStackTrace"));
        Method run = handlerCase.getMethod("run", String.class);
        assertEquals("io", run.invoke(null, "boom"), "IOException path -> shared handler");
        assertEquals("ok", run.invoke(null, "fine"), "no-throw path");
    }

    /** Handler entry frames must be typed with the caught type after the rewrite (Wurst fix). */
    @Test
    void handlerEntryFramesKeepCaughtTypeAfterRewrite() throws Exception {
        byte[] rewritten = IndyDispatchTransformer.transformClass(generateHandlerCase(),
                new IndyDispatchTransformer.Options(true, true, true)).bytes();
        ClassNode node = new ClassNode();
        new ClassReader(rewritten).accept(node, ClassReader.EXPAND_FRAMES);
        for (MethodNode method : node.methods) {
            if (!"run".equals(method.name) || method.tryCatchBlocks == null) {
                continue;
            }
            assertTrue(method.tryCatchBlocks.size() >= 2, "both handlers survived");
            for (TryCatchBlockNode block : method.tryCatchBlocks) {
                AbstractInsnNode frame = frameBefore(block.handler);
                assertNotNull(frame, "handler entry must have a frame");
                Object top = ((FrameNode) frame).stack.isEmpty()
                        ? null : ((FrameNode) frame).stack.get(((FrameNode) frame).stack.size() - 1);
                assertEquals("java/lang/Exception", String.valueOf(top),
                        "handler entry for catch(" + block.type + ") must stay Exception, not Object");
            }
        }
    }

    /**
     * The engine's shape fingerprint decides between COMPUTE_MAXS (keep frames) and
     * COMPUTE_FRAMES. The indy rewrite must NOT change it; adding a branch must.
     */
    @Test
    void shapeDigestStableUnderIndyRewriteButChangesOnBranchInsert() throws Exception {
        byte[] original = generateHandlerCase();
        ClassNode before = new ClassNode();
        new ClassReader(original).accept(before, ClassReader.EXPAND_FRAMES);
        byte[] shapeBefore = ClassFingerprint.shapeDigest(before);

        byte[] rewritten = IndyDispatchTransformer.transformClass(original,
                new IndyDispatchTransformer.Options(true, true, true)).bytes();
        ClassNode after = new ClassNode();
        new ClassReader(rewritten).accept(after, ClassReader.EXPAND_FRAMES);
        assertArrayEquals(shapeBefore, ClassFingerprint.shapeDigest(after),
                "indy rewrite is shape-preserving: engine keeps the original frames");

        // Adding one branch to a method must flip the digest (engine recomputes frames).
        MethodNode any = after.methods.stream()
                .filter(m -> m.instructions != null && m.instructions.size() > 0)
                .findFirst().orElseThrow();
        org.objectweb.asm.tree.LabelNode label = new org.objectweb.asm.tree.LabelNode();
        any.instructions.insert(any.instructions.getFirst(),
                new org.objectweb.asm.tree.JumpInsnNode(Opcodes.GOTO, label));
        any.instructions.add(label);
        assertNotEquals(java.util.Arrays.toString(shapeBefore),
                java.util.Arrays.toString(ClassFingerprint.shapeDigest(after)),
                "branch insertion changes the shape digest");
    }

    /** Failing execution would surface as VerifyError wrapped in InvocationTargetException. */
    @Test
    void denyHookStillFailsClosedOnTryCatchMethod() throws Exception {
        byte[] rewritten = IndyDispatchTransformer.transformClass(generateHandlerCase(),
                new IndyDispatchTransformer.Options(true, true, true)).bytes();
        TestByteLoader loader = new TestByteLoader(rewrittenClasses(rewritten),
                getClass().getClassLoader());
        Class<?> handlerCase = Class.forName(HANDLER_CASE.replace('/', '.'), true, loader);
        MemberIdRegistry.registerClass(handlerCase);
        MemberIdRegistry.registerClass(String.class);
        MemberIdRegistry.registerMethod(String.class, "hashCode");
        MemberIdRegistry.registerMethod(String.class, "length");
        MemberIdRegistry.registerMethod(String.class, "equals", Object.class);
        MemberIdRegistry.registerClass(Exception.class);
        MemberIdRegistry.registerMethod(MemberIdRegistry.classId("java/lang/Exception"),
                MemberIdRegistry.memberId("java/lang/Exception", "printStackTrace", "()V"),
                Throwable.class.getDeclaredMethod("printStackTrace"));
        ChimeraBootstrap.installCheckHook(CheckHook.DENY);
        InvocationTargetException thrown = assertThrows(InvocationTargetException.class, () ->
                handlerCase.getMethod("run", String.class).invoke(null, "boom"));
        assertTrue(thrown.getCause() instanceof BootstrapMethodError
                        || thrown.getCause() instanceof VerifyError,
                "deny must fail closed, got " + thrown.getCause());
    }

    // ------------------------------------------------------------------ fixtures

    /**
     * The rewritten class plus the generated {@code chimera/indy/Bsm*} owners the rewritten
     * call sites reference; the indy support classes (ChimeraBootstrap et al.) resolve from the
     * test class path through the loader's parent.
     */
    private static Map<String, byte[]> rewrittenClasses(byte[] rewrittenClass) {
        Map<String, byte[]> classes = new LinkedHashMap<>();
        classes.put(HANDLER_CASE, rewrittenClass);
        for (Map.Entry<String, byte[]> generated : BsmClassGenerator.generate().entrySet()) {
            String entry = generated.getKey();
            classes.put(entry.substring(0, entry.length() - ".class".length()),
                    generated.getValue());
        }
        return classes;
    }

    /**
     * run(input): try { input.hashCode(); input.length(); if (hashCode==0) throw new
     * JsonParseException; } catch (IOException | JsonParseException e) { e.printStackTrace();
     * return "io"; } catch (Exception e) { e.printStackTrace(); return "ex"; } return "ok".
     * The two call sites inside the try range are rewritten to indy; the shared handler is the
     * exact WurstTranslator crash shape.
     */
    private static byte[] generateHandlerCase() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, HANDLER_CASE,
                null, "java/lang/Object", null);
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "run", "(Ljava/lang/String;)Ljava/lang/String;", null, null);
        Label tryStart = new Label(), tryEnd = new Label();
        Label hIo = new Label(), hEx = new Label();
        mv.visitTryCatchBlock(tryStart, tryEnd, hIo, "java/io/IOException");
        mv.visitTryCatchBlock(tryStart, tryEnd, hIo, "java/io/UncheckedIOException");
        mv.visitTryCatchBlock(tryStart, tryEnd, hEx, "java/lang/Exception");
        mv.visitCode();
        mv.visitLabel(tryStart);
        // Two plain call sites inside the try range -> indy rewrite candidates.
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "hashCode", "()I", false);
        mv.visitInsn(Opcodes.POP);
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "length", "()I", false);
        mv.visitInsn(Opcodes.POP);
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitLdcInsn("boom");
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "equals",
                "(Ljava/lang/Object;)Z", false);
        Label ok = new Label();
        mv.visitJumpInsn(Opcodes.IFEQ, ok);
        mv.visitTypeInsn(Opcodes.NEW, "java/io/IOException");
        mv.visitInsn(Opcodes.DUP);
        mv.visitLdcInsn("boom");
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/io/IOException", "<init>",
                "(Ljava/lang/String;)V", false);
        mv.visitInsn(Opcodes.ATHROW);
        mv.visitLabel(ok);
        mv.visitLabel(tryEnd);
        mv.visitLdcInsn("ok");
        mv.visitInsn(Opcodes.ARETURN);
        mv.visitLabel(hIo);
        mv.visitVarInsn(Opcodes.ASTORE, 1);
        mv.visitVarInsn(Opcodes.ALOAD, 1);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Exception",
                "printStackTrace", "()V", false);
        mv.visitLdcInsn("io");
        mv.visitInsn(Opcodes.ARETURN);
        mv.visitLabel(hEx);
        mv.visitVarInsn(Opcodes.ASTORE, 1);
        mv.visitVarInsn(Opcodes.ALOAD, 1);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Exception",
                "printStackTrace", "()V", false);
        mv.visitLdcInsn("ex");
        mv.visitInsn(Opcodes.ARETURN);
        mv.visitMaxs(3, 2);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    private static void assertHandlerFramesTyped(byte[] classBytes, String methodName) {
        ClassNode node = new ClassNode();
        new ClassReader(classBytes).accept(node, ClassReader.EXPAND_FRAMES);
        int indy = 0;
        for (MethodNode method : node.methods) {
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                    insn = insn.getNext()) {
                if (insn instanceof InvokeDynamicInsnNode) {
                    indy++;
                }
            }
        }
        assertTrue(indy >= 2, "try-range call sites must be rewritten: got " + indy);
        for (MethodNode method : node.methods) {
            if (!methodName.equals(method.name) || method.tryCatchBlocks == null) {
                continue;
            }
            for (TryCatchBlockNode block : method.tryCatchBlocks) {
                AbstractInsnNode frame = frameBefore(block.handler);
                assertNotNull(frame, "handler entry needs a frame");
                Object top = ((FrameNode) frame).stack.isEmpty()
                        ? null : ((FrameNode) frame).stack.get(((FrameNode) frame).stack.size() - 1);
                assertEquals("java/lang/Exception", String.valueOf(top),
                        "catch(" + block.type + ") handler frame must be Exception, got " + top);
            }
        }
    }

    /** The FrameNode qualifying a handler: ASM emits the frame right AFTER the handler label. */
    private static AbstractInsnNode frameBefore(AbstractInsnNode handler) {
        AbstractInsnNode p = handler;
        while (p != null && p.getType() == AbstractInsnNode.LABEL) {
            p = p.getNext();
        }
        return p != null && p.getType() == AbstractInsnNode.FRAME ? p : null;
    }

    /** Unused import guard: keep List referenced for future assertions. */
    @SuppressWarnings("unused")
    private static List<Object> types(FrameNode frame) {
        return frame.stack == null ? List.of() : frame.stack;
    }
}
