package dev.chimera.transform;

import dev.chimera.core.NativeTemplate;
import dev.chimera.core.TransformContext;
import dev.chimera.core.Transformer;
import dev.chimera.nativecode.NativeTranspiler;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.ArrayList;
import java.util.List;

/** Turns @ChimeraNative methods into native stubs and records C++ template metadata. */
public final class NativeStubTransformer implements Transformer {
    private static final String DESC = "Ldev/chimera/annotations/ChimeraNative;";

    @Override
    public void transform(String internalName, ClassNode node, TransformContext ctx) {
        if (!ctx.config.nativeStubs) return;
        for (MethodNode m : node.methods) {
            if (!hasAnnotation(m.invisibleAnnotations) && !hasAnnotation(m.visibleAnnotations)) continue;
            if ((m.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) continue;
            if (ctx.config.strictFabric) {
                FabricSafetyGuard.check(node, m, "@ChimeraNative");
            }
            enforceBusinessReturnType(internalName, m);
            NativeTranspiler.TranspileResult transpiled = NativeTranspiler.transpile(node, m);
            removeAnnotations(m);
            m.access |= Opcodes.ACC_NATIVE;
            m.instructions.clear();
            m.tryCatchBlocks.clear();
            if (m.localVariables != null) m.localVariables.clear();
            m.maxStack = 0;
            m.maxLocals = 0;
            ctx.stats.methodsNativeStubbed++;
            ctx.addNative(new NativeTemplate(internalName, m.name, m.desc,
                    (m.access & Opcodes.ACC_STATIC) != 0,
                    transpiled.supported(), transpiled.cppBody(), transpiled.headerDecl()));
        }
    }

    /**
     * Task 3: a JNI method must return a business value (double/float/long/object), never a
     * boolean or a judgment int. Otherwise a one-instruction patch (mov eax,1; ret) would unlock
     * the feature, so this is rejected at build time.
     */
    private static void enforceBusinessReturnType(String internalName, MethodNode m) {
        Type returnType = Type.getReturnType(m.desc);
        int sort = returnType.getSort();
        if (sort == Type.BOOLEAN || sort == Type.INT || sort == Type.SHORT
                || sort == Type.BYTE || sort == Type.CHAR || sort == Type.VOID) {
            throw new IllegalArgumentException(
                    "@ChimeraNative method " + internalName + "." + m.name + m.desc
                            + " returns " + returnType.getClassName()
                            + "; native methods must return a business value (double/float/long/object), "
                            + "not boolean/int/void (a 'return 1' patch must break arithmetic, not unlock logic)");
        }
    }

    private static boolean hasAnnotation(List<AnnotationNode> anns) {
        if (anns == null) return false;
        for (AnnotationNode a : anns) if (DESC.equals(a.desc)) return true;
        return false;
    }

    private static void removeAnnotations(MethodNode m) {
        if (m.invisibleAnnotations != null) {
            m.invisibleAnnotations = new ArrayList<>(m.invisibleAnnotations);
            m.invisibleAnnotations.removeIf(a -> DESC.equals(a.desc));
        }
        if (m.visibleAnnotations != null) {
            m.visibleAnnotations = new ArrayList<>(m.visibleAnnotations);
            m.visibleAnnotations.removeIf(a -> DESC.equals(a.desc));
        }
    }
}
