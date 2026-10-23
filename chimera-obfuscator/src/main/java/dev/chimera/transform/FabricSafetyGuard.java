package dev.chimera.transform;

import org.objectweb.asm.ConstantDynamic;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.MultiANewArrayInsnNode;
import org.objectweb.asm.tree.TypeInsnNode;

import java.util.List;

/**
 * Production remap safety gate for {@code @ChimeraNative} / {@code @ChimeraVM} methods (M4 P0).
 *
 * <p>Fabric/Forge remap Minecraft classes at runtime: a method body or descriptor that references
 * {@code net.minecraft.*}/{@code net.fabricmc.*} is fine in a normal mod class (the loader
 * remaps it), but a native JNI body or a VM instruction stream is generated at build time and
 * cannot be remapped. In game such a method fails with {@code NoClassDefFoundError} or links
 * against a class name that does not exist in production.</p>
 *
 * <p>This guard rejects those references at build time with an actionable message, forcing the
 * developer to move the algorithm into a pure-logic class (no Minecraft types) and call it from
 * the game-facing code. It only inspects the annotated method: its descriptor, signature,
 * declared exceptions, referenced classes/fields/methods and string constants.</p>
 */
public final class FabricSafetyGuard {

    /** Package prefixes that are rewritten by the mod loader at runtime. */
    private static final String[] REMAPPED_PREFIXES = {
            "net/minecraft/",
            "net/fabricmc/",
            "com/mojang/"
    };

    /** Human-readable form used in error messages. */
    private static final String[] REMAPPED_NAMES = {
            "net.minecraft.*",
            "net.fabricmc.*",
            "com.mojang.*"
    };

    /** Every Sponge Mixin annotation starts with this descriptor prefix. */
    private static final String MIXIN_ANNOTATION_PREFIX = "Lorg/spongepowered/asm/mixin/";

    private FabricSafetyGuard() {
    }

    /**
     * Scans one annotated method and throws {@link IllegalArgumentException} when it references a
     * runtime-remapped Minecraft/Fabric type. {@code annotation} is the annotation simple name used
     * in the error message ({@code @ChimeraNative} / {@code @ChimeraVM}).
     *
     * @return {@code null} when safe, otherwise the first offending reference (for diagnostics)
     */
    public static String check(ClassNode owner, MethodNode method, String annotation) {
        String classIssue = inspectClass(owner);
        if (classIssue != null) {
            throw new IllegalArgumentException(remapError(owner, method, annotation, classIssue));
        }
        String offending = inspect(method);
        if (offending == null) {
            return null;
        }
        throw new IllegalArgumentException(remapError(owner, method, annotation, offending));
    }

    private static String remapError(ClassNode owner, MethodNode method, String annotation,
                                     String offending) {
        return "Fabric production remap check failed: " + annotation + " method "
                        + owner.name + "." + method.name + method.desc
                        + " references " + offending + ".\n"
                        + "Fabric remaps Minecraft/Fabric classes at runtime, but " + annotation
                        + " bodies are generated at build time and cannot be remapped; this would fail"
                        + " with NoClassDefFoundError/UnsatisfiedLinkError in production.\n"
                        + "Fix: move the algorithm into a standalone pure-logic class that has no "
                        + "net.minecraft.* / net.fabricmc.* references and is not a Mixin class "
                        + "(Mixin merges/renames methods into the target class, so JNI/VM bodies "
                        + "cannot follow); call it from the game-facing class.\n"
                        + "Escape hatch for non-production experiments only: --no-fabric-check "
                        + "(chimera.strictFabric = false); never ship such a build.";
    }

    /** Class-level remap/Mixin risks (checked once per annotated method). */
    public static String inspectClass(ClassNode owner) {
        if (owner == null) {
            return null;
        }
        String className = findInDescriptor(owner.name);
        if (className != null) {
            return "class name " + owner.name + " -> " + className;
        }
        if (owner.superName != null) {
            String superName = findInDescriptor(owner.superName);
            if (superName != null) {
                return "superclass " + owner.superName + " -> " + superName;
            }
        }
        if (owner.interfaces != null) {
            for (String interfaceName : owner.interfaces) {
                String found = findInDescriptor(interfaceName);
                if (found != null) {
                    return "interface " + interfaceName + " -> " + found;
                }
            }
        }
        String classMixin = findMixinAnnotation(owner.visibleAnnotations, "class");
        if (classMixin == null) {
            classMixin = findMixinAnnotation(owner.invisibleAnnotations, "class");
        }
        return classMixin;
    }

    private static String findMixinAnnotation(List<AnnotationNode> annotations, String where) {
        if (annotations == null) {
            return null;
        }
        for (AnnotationNode annotation : annotations) {
            if (annotation.desc != null && annotation.desc.startsWith(MIXIN_ANNOTATION_PREFIX)) {
                return "Mixin annotation " + annotation.desc + " on " + where;
            }
        }
        return null;
    }

    /** Returns {@code null} when the method is safe, otherwise the offending reference. */
    public static String inspect(MethodNode method) {
        String methodMixin = findMixinAnnotation(method.visibleAnnotations, "method");
        if (methodMixin == null) {
            methodMixin = findMixinAnnotation(method.invisibleAnnotations, "method");
        }
        if (methodMixin != null) {
            return methodMixin;
        }
        String fromDescriptor = findInDescriptor(method.desc);
        if (fromDescriptor != null) {
            return "descriptor " + method.desc + " -> " + fromDescriptor;
        }
        if (method.signature != null) {
            String fromSignature = findInDescriptor(method.signature);
            if (fromSignature != null) {
                return "generic signature " + method.signature + " -> " + fromSignature;
            }
        }
        if (method.exceptions != null) {
            for (String exception : method.exceptions) {
                String found = findInDescriptor(exception);
                if (found != null) {
                    return "declared exception " + exception + " -> " + found;
                }
            }
        }
        if (method.tryCatchBlocks != null) {
            for (TryCatchBlockNode block : method.tryCatchBlocks) {
                if (block.type != null) {
                    String found = findInDescriptor(block.type);
                    if (found != null) {
                        return "try/catch type " + block.type + " -> " + found;
                    }
                }
            }
        }
        String annotationIssue = inspectAnnotations(method.visibleAnnotations, "method annotation");
        if (annotationIssue == null) {
            annotationIssue = inspectAnnotations(method.invisibleAnnotations, "method annotation");
        }
        if (annotationIssue != null) {
            return annotationIssue;
        }
        if (method.instructions == null) {
            return null;
        }
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            String offending = inspectInstruction(insn);
            if (offending != null) {
                return offending;
            }
        }
        return null;
    }

    private static String inspectInstruction(AbstractInsnNode insn) {
        if (insn instanceof TypeInsnNode type) {
            return findInDescriptor(type.desc);
        }
        if (insn instanceof FieldInsnNode field) {
            String owner = findInDescriptor(field.owner);
            if (owner != null) {
                return "field owner " + field.owner;
            }
            return findInDescriptor(field.desc);
        }
        if (insn instanceof MethodInsnNode call) {
            String owner = findInDescriptor(call.owner);
            if (owner != null) {
                return "method owner " + call.owner;
            }
            return findInDescriptor(call.desc);
        }
        if (insn instanceof InvokeDynamicInsnNode indy) {
            String found = findInDescriptor(indy.desc);
            if (found != null) {
                return "invokedynamic descriptor " + indy.desc;
            }
            if (indy.bsmArgs != null) {
                for (Object argument : indy.bsmArgs) {
                    if (argument instanceof Type type) {
                        String typeRef = findInDescriptor(type.getDescriptor());
                        if (typeRef != null) {
                            return "invokedynamic bootstrap argument " + typeRef;
                        }
                    }
                }
            }
            return null;
        }
        if (insn instanceof MultiANewArrayInsnNode array) {
            return findInDescriptor(array.desc);
        }
        if (insn instanceof LdcInsnNode ldc) {
            if (ldc.cst instanceof Type type) {
                String typeRef = findInDescriptor(type.getDescriptor());
                if (typeRef != null) {
                    return "class constant " + typeRef;
                }
            } else if (ldc.cst instanceof String text) {
                return findInText(text);
            } else if (ldc.cst instanceof Handle handle) {
                return inspectHandle(handle);
            } else if (ldc.cst instanceof ConstantDynamic dynamic) {
                return inspectConstantDynamic(dynamic);
            }
        }
        return null;
    }

    private static String inspectHandle(Handle handle) {
        if (handle == null) {
            return null;
        }
        String owner = findInDescriptor(handle.getOwner());
        if (owner != null) {
            return "method handle owner " + handle.getOwner() + " -> " + owner;
        }
        return findInDescriptor(handle.getDesc());
    }

    private static String inspectConstantDynamic(ConstantDynamic dynamic) {
        if (dynamic == null) {
            return null;
        }
        String fromDescriptor = findInDescriptor(dynamic.getDescriptor());
        if (fromDescriptor != null) {
            return "constant dynamic descriptor -> " + fromDescriptor;
        }
        String fromBootstrap = inspectHandle(dynamic.getBootstrapMethod());
        if (fromBootstrap != null) {
            return "constant dynamic bootstrap " + fromBootstrap;
        }
        for (int i = 0; i < dynamic.getBootstrapMethodArgumentCount(); i++) {
            Object argument = dynamic.getBootstrapMethodArgument(i);
            String found = inspectAnnotationValue(argument);
            if (found != null) {
                return "constant dynamic argument " + found;
            }
        }
        return null;
    }

    private static String inspectAnnotations(List<AnnotationNode> annotations, String where) {
        if (annotations == null) {
            return null;
        }
        for (AnnotationNode annotation : annotations) {
            if (annotation.values == null) {
                continue;
            }
            for (int i = 0; i + 1 < annotation.values.size(); i += 2) {
                String found = inspectAnnotationValue(annotation.values.get(i + 1));
                if (found != null) {
                    return where + " " + annotation.desc + " -> " + found;
                }
            }
        }
        return null;
    }

    private static String inspectAnnotationValue(Object value) {
        if (value instanceof Type type) {
            return findInDescriptor(type.getDescriptor());
        }
        if (value instanceof String text) {
            return findInText(text);
        }
        if (value instanceof Handle handle) {
            return inspectHandle(handle);
        }
        if (value instanceof ConstantDynamic dynamic) {
            return inspectConstantDynamic(dynamic);
        }
        if (value instanceof List<?> list) {
            for (Object item : list) {
                String found = inspectAnnotationValue(item);
                if (found != null) {
                    return found;
                }
            }
        }
        if (value instanceof Object[] array) {
            for (Object item : array) {
                String found = inspectAnnotationValue(item);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    /** Checks a raw descriptor/name list for a remapped prefix. */
    public static String findInDescriptor(String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        for (String prefix : REMAPPED_PREFIXES) {
            if (value.contains(prefix)) {
                return prefix;
            }
        }
        for (String name : REMAPPED_NAMES) {
            if (value.contains(name)) {
                return name;
            }
        }
        return null;
    }

    /** String constants that name a remapped class are also flagged (e.g. reflection use). */
    public static String findInText(String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        for (String name : REMAPPED_NAMES) {
            if (value.contains(name)) {
                return "string constant \"" + name + "\"";
            }
        }
        for (String prefix : REMAPPED_PREFIXES) {
            if (value.contains(prefix)) {
                return "string constant \"" + prefix + "\"";
            }
        }
        return null;
    }

    /** True when the method body/descriptor touches runtime-remapped Minecraft/Fabric types. */
    public static boolean referencesRemappedTypes(MethodNode method) {
        return inspect(method) != null;
    }
}
