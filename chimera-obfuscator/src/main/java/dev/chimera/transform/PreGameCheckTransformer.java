package dev.chimera.transform;

import dev.chimera.core.TransformContext;
import dev.chimera.core.Transformer;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * M7/Module 4: automatic {@code @ChimeraPreGameCheck} enforcement.
 *
 * <p>Injects the following prologue at the start of every annotated method, so a developer cannot
 * forget the call:</p>
 *
 * <pre>{@code
 * if (!ChimeraRuntime.preGameCheckWithFallback(account, password, hwid)) {
 *     return <type-neutral default>;
 * }
 * }</pre>
 *
 * <p>The checker never throws: on integrity/activation failure it poisons the runtime, so the
 * protected body is skipped and in-game values degrade to negative/NaN instead of a catchable
 * exception. Constructors, abstract methods, and methods already annotated with
 * {@code @ChimeraVM}/{@code @ChimeraNative} are rejected at build time (their bodies are
 * generated/replaced, so the prologue would be lost or duplicated).</p>
 */
public final class PreGameCheckTransformer implements Transformer {

    public static final String ANNOTATION_DESC = "Ldev/chimera/annotations/ChimeraPreGameCheck;";
    private static final String VM_ANNOTATION = "Ldev/chimera/annotations/ChimeraVM;";
    private static final String NATIVE_ANNOTATION = "Ldev/chimera/annotations/ChimeraNative;";
    private static final String RUNTIME_CLASS = "dev/chimera/runtime/ChimeraRuntime";
    private static final String RUNTIME_METHOD = "preGameCheckWithFallback";
    private static final String RUNTIME_DESC =
            "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z";
    /** No-argument variant: keeps credentials out of the constant pool for the common case. */
    private static final String PROPERTIES_METHOD = "preGameCheckFromProperties";
    private static final String PROPERTIES_DESC = "()Z";

    /**
     * B1 audit: a boolean @ChimeraPreGameCheck return must never be consumed as a security
     * decision. If any call site branches on it (IFEQ/IFNE), fail the build and require the
     * caller to use the SessionHandle validity check / void entry instead.
     */
    public static void auditBooleanPgcSecurity(Map<String, byte[]> classes) {
        Map<String, String> booleanMethods = new HashMap<>();
        for (Map.Entry<String, byte[]> entry : classes.entrySet()) {
            if (!entry.getKey().endsWith(".class")) continue;
            ClassNode node = new ClassNode();
            new ClassReader(entry.getValue()).accept(node, ClassReader.SKIP_FRAMES);
            for (MethodNode method : node.methods) {
                if (findAnnotation(method) == null) continue;
                if (Type.getReturnType(method.desc).getSort() == Type.BOOLEAN) {
                    booleanMethods.put(node.name + "." + method.name + method.desc,
                            node.name + "." + method.name);
                }
            }
        }
        if (booleanMethods.isEmpty()) {
            return;
        }
        List<String> violations = new ArrayList<>();
        for (Map.Entry<String, byte[]> entry : classes.entrySet()) {
            if (!entry.getKey().endsWith(".class")) continue;
            ClassNode node = new ClassNode();
            new ClassReader(entry.getValue()).accept(node, ClassReader.SKIP_FRAMES);
            for (MethodNode method : node.methods) {
                if (method.instructions == null) continue;
                for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null;
                        insn = insn.getNext()) {
                    if (!(insn instanceof MethodInsnNode call)
                            || call.getOpcode() != Opcodes.INVOKESTATIC
                            || !booleanMethods.containsKey(call.owner + "." + call.name + call.desc)) {
                        continue;
                    }
                    AbstractInsnNode next = nextRealInsn(insn.getNext());
                    if (next != null && next instanceof JumpInsnNode jump
                            && (jump.getOpcode() == Opcodes.IFEQ || jump.getOpcode() == Opcodes.IFNE)) {
                        violations.add(node.name + "." + method.name + method.desc
                                + " branches on boolean PGC " + booleanMethods.get(
                                call.owner + "." + call.name + call.desc));
                    }
                }
            }
        }
        if (!violations.isEmpty()) {
            throw new IllegalArgumentException("B1 boolean PGC audit failed: boolean @ChimeraPreGameCheck "
                    + "return values are used as security branches: " + violations
                    + ". Fix: make the entry method void/int and gate the business logic with the "
                    + "SessionHandle validity check (nativeCheckHandle) instead of a boolean result.");
        }
    }

    private static AbstractInsnNode nextRealInsn(AbstractInsnNode insn) {
        while (insn != null && (insn instanceof LabelNode
                || insn instanceof org.objectweb.asm.tree.LineNumberNode
                || insn.getOpcode() < 0)) {
            insn = insn.getNext();
        }
        return insn;
    }

    @Override
    public void transform(String internalName, ClassNode node, TransformContext ctx) {
        if (node.methods == null) {
            return;
        }
        for (MethodNode method : node.methods) {
            AnnotationNode annotation = findAnnotation(method);
            if (annotation == null) {
                continue;
            }
            if (internalName.startsWith("dev/chimera/runtime/")) {
                continue;
            }
            if ("<init>".equals(method.name) || "<clinit>".equals(method.name)) {
                throw new IllegalArgumentException("@ChimeraPreGameCheck cannot be placed on "
                        + internalName + "." + method.name + " (constructors/class initializers "
                        + "must not return early)");
            }
            if ((method.access & Opcodes.ACC_ABSTRACT) != 0) {
                throw new IllegalArgumentException("@ChimeraPreGameCheck cannot be placed on the "
                        + "abstract method " + internalName + "." + method.name
                        + "; annotate its concrete call site instead");
            }
            if (hasAnnotation(method, VM_ANNOTATION) || hasAnnotation(method, NATIVE_ANNOTATION)) {
                throw new IllegalArgumentException("@ChimeraPreGameCheck cannot be combined with "
                        + "@ChimeraVM/@ChimeraNative on " + internalName + "." + method.name
                        + " (the body is virtualized/replaced after injection); annotate the "
                        + "Java caller instead");
            }
            String account = stringValue(annotation, "account");
            String password = stringValue(annotation, "password");
            String hwid = stringValue(annotation, "hwid");
            inject(node, method, account, password, hwid);
            if (ctx != null) {
                ctx.stats.pregameInjections++;
            }
        }
    }

    private static void inject(ClassNode owner, MethodNode method,
                               String account, String password, String hwid) {
        InsnList prologue = new InsnList();
        if (account.isEmpty() && password.isEmpty() && hwid.isEmpty()) {
            // Common case: zero string constants, so the check also works before the content
            // key exists and nothing credential-shaped is embedded in the jar.
            prologue.add(new MethodInsnNode(Opcodes.INVOKESTATIC, RUNTIME_CLASS,
                    PROPERTIES_METHOD, PROPERTIES_DESC, false));
        } else {
            prologue.add(new LdcInsnNode(account));
            prologue.add(new LdcInsnNode(password));
            prologue.add(new LdcInsnNode(hwid));
            prologue.add(new MethodInsnNode(Opcodes.INVOKESTATIC, RUNTIME_CLASS, RUNTIME_METHOD,
                    RUNTIME_DESC, false));
        }
        LabelNode proceed = new LabelNode();
        prologue.add(new JumpInsnNode(Opcodes.IFNE, proceed));
        appendDefaultReturn(prologue, method);
        prologue.add(proceed);
        method.instructions.insert(prologue);
        method.maxStack = Math.max(method.maxStack, 4);
    }

    private static void appendDefaultReturn(InsnList list, MethodNode method) {
        Type returnType = Type.getReturnType(method.desc);
        switch (returnType.getSort()) {
            case Type.VOID -> list.add(new InsnNode(Opcodes.RETURN));
            // A3: boolean must stay false. Returning a poisoned non-zero int would be interpreted
            // as "true" by the caller (unlock instead of degrade). This is the one type where the
            // M2 numeric shape is not applicable; documented in docs/PHASE-A-SEMANTICS.md.
            case Type.BOOLEAN -> {
                list.add(new InsnNode(Opcodes.ICONST_0));
                list.add(new InsnNode(Opcodes.IRETURN));
            }
            case Type.BYTE, Type.CHAR, Type.SHORT, Type.INT -> {
                list.add(new MethodInsnNode(Opcodes.INVOKESTATIC, RUNTIME_CLASS,
                        "pregamePoisonInt", "()I", false));
                list.add(new InsnNode(Opcodes.IRETURN));
            }
            case Type.LONG -> {
                list.add(new MethodInsnNode(Opcodes.INVOKESTATIC, RUNTIME_CLASS,
                        "pregamePoisonLong", "()J", false));
                list.add(new InsnNode(Opcodes.LRETURN));
            }
            case Type.FLOAT -> {
                list.add(new MethodInsnNode(Opcodes.INVOKESTATIC, RUNTIME_CLASS,
                        "pregamePoisonFloat", "()F", false));
                list.add(new InsnNode(Opcodes.FRETURN));
            }
            case Type.DOUBLE -> {
                list.add(new MethodInsnNode(Opcodes.INVOKESTATIC, RUNTIME_CLASS,
                        "pregamePoisonDouble", "()D", false));
                list.add(new InsnNode(Opcodes.DRETURN));
            }
            default -> {
                // Reference types cannot carry a universal sentinel; null is verifier-safe and
                // the session is poisoned. Documented residual distinguishability (A3).
                list.add(new InsnNode(Opcodes.ACONST_NULL));
                list.add(new InsnNode(Opcodes.ARETURN));
            }
        }
    }

    private static AnnotationNode findAnnotation(MethodNode method) {
        AnnotationNode found = find(method.visibleAnnotations);
        return found != null ? found : find(method.invisibleAnnotations);
    }

    private static AnnotationNode find(List<AnnotationNode> annotations) {
        if (annotations == null) {
            return null;
        }
        for (AnnotationNode annotation : annotations) {
            if (annotation.desc != null && annotation.desc.equals(ANNOTATION_DESC)) {
                return annotation;
            }
        }
        return null;
    }

    private static boolean hasAnnotation(MethodNode method, String descriptor) {
        return contains(method.visibleAnnotations, descriptor)
                || contains(method.invisibleAnnotations, descriptor);
    }

    private static boolean contains(List<AnnotationNode> annotations, String descriptor) {
        if (annotations == null) {
            return false;
        }
        for (AnnotationNode annotation : annotations) {
            if (annotation.desc != null && annotation.desc.equals(descriptor)) {
                return true;
            }
        }
        return false;
    }

    private static String stringValue(AnnotationNode annotation, String key) {
        if (annotation.values == null) {
            return "";
        }
        for (int i = 0; i + 1 < annotation.values.size(); i += 2) {
            if (key.equals(annotation.values.get(i))) {
                Object value = annotation.values.get(i + 1);
                return value instanceof String text ? text : "";
            }
        }
        return "";
    }
}
