package dev.chimera.transform.harden;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;

import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

/** M11/M12 共用的安全判定与随机名工具。 */
final class HardenSupport {

    private static final String MIXIN_PREFIX = "Lorg/spongepowered/asm/mixin/";
    private static final String MIXIN_EXTRAS_PREFIX = "Lcom/llamalad7/mixinextras/";

    private HardenSupport() {
    }

    /** Mixin 类对字节码结构非常敏感（Signature/调试信息），必须整体跳过。 */
    static boolean isMixinClass(ClassNode cn) {
        if (cn.name != null && (cn.name.contains("/mixin/") || cn.name.startsWith("mixin/"))) {
            return true;
        }
        return hasAnnotation(cn.visibleAnnotations, MIXIN_PREFIX)
                || hasAnnotation(cn.invisibleAnnotations, MIXIN_PREFIX)
                || hasAnnotation(cn.visibleAnnotations, MIXIN_EXTRAS_PREFIX)
                || hasAnnotation(cn.invisibleAnnotations, MIXIN_EXTRAS_PREFIX);
    }

    private static boolean hasAnnotation(List<AnnotationNode> annotations, String prefix) {
        if (annotations == null) {
            return false;
        }
        for (AnnotationNode an : annotations) {
            if (an.desc != null && an.desc.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    /** 类版本是否允许私有接口方法（Java 9+）。 */
    static boolean supportsPrivateInterfaceMethods(ClassNode cn) {
        return (cn.access & Opcodes.ACC_INTERFACE) == 0 || cn.version >= Opcodes.V9;
    }

    static String randomIdentifier(String prefix, int length) {
        String alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        StringBuilder sb = new StringBuilder(prefix);
        ThreadLocalRandom rnd = ThreadLocalRandom.current();
        for (int i = 0; i < length; i++) {
            sb.append(alphabet.charAt(rnd.nextInt(alphabet.length())));
        }
        return sb.toString();
    }
}
