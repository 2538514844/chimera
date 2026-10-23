package dev.chimera.transform.harden;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.Collection;
import java.util.concurrent.ThreadLocalRandom;

/**
 * M11：结构下毒。对齐 Hachimi 的实测特征：
 * <ul>
 *   <li>非法 Signature 属性（JVM 不校验、javap/JD 强校验 -> 工具崩）；</li>
 *   <li>伪常量池引用（不存在的内部类名）；</li>
 *   <li>垃圾 synthetic 方法；</li>
 *   <li>常量池膨胀（大量 LDC 字符串常量）。</li>
 * </ul>
 *
 * <p>红线：Mixin 类整体跳过（实测删 Signature 会让 Mixin apply 直接崩）。</p>
 */
public final class StructuralPoisonTransformer {

    public record Options(
            boolean invalidSignature,
            boolean fakeClassRefs,
            int dummyMethodsPerClass,
            int constantsPerClass,
            String fakeClassPrefix) {

        public static Options defaults() {
            return new Options(true, true, 8, 24, "chimera/fake/");
        }
    }

    public record Stats(
            int classes,
            int skippedMixin,
            int skippedInterfaceVersion,
            int invalidSignatures,
            int fakeRefs,
            int dummyMethods,
            int constants) {
    }

    private StructuralPoisonTransformer() {
    }

    private static final String INVALID_SIGNATURE = "!!";

    public static Stats transform(Collection<ClassNode> classes, Options options) {
        int skippedMixin = 0;
        int skippedInterfaceVersion = 0;
        int invalidSignatures = 0;
        int fakeRefs = 0;
        int dummyMethods = 0;
        int constants = 0;
        int visited = 0;
        for (ClassNode cn : classes) {
            if (HardenSupport.isMixinClass(cn)) {
                skippedMixin++;
                continue;
            }
            if (!HardenSupport.supportsPrivateInterfaceMethods(cn)) {
                skippedInterfaceVersion++;
                continue;
            }
            visited++;
            boolean changed = false;

            if (options.invalidSignature()) {
                // 对齐 Hachimi：类、每个方法（含构造器）、每个字段都写非法 Signature，
                // 让 javap/JD/Procyon 在解析泛型签名时确定性失败。
                cn.signature = INVALID_SIGNATURE;
                invalidSignatures++;
                changed = true;
                for (MethodNode method : cn.methods) {
                    method.signature = INVALID_SIGNATURE;
                    invalidSignatures++;
                }
                for (FieldNode field : cn.fields) {
                    field.signature = INVALID_SIGNATURE;
                    invalidSignatures++;
                }
            }

            if (options.fakeClassRefs()) {
                String fakeName = options.fakeClassPrefix() + HardenSupport.randomIdentifier("Fake", 6);
                MethodNode dead = syntheticMethod(cn, "dead");
                InsnList insns = new InsnList();
                insns.add(new LdcInsnNode(Type.getObjectType(fakeName)));
                insns.add(new InsnNode(Opcodes.POP));
                insns.add(new InsnNode(Opcodes.RETURN));
                dead.instructions = insns;
                dead.maxStack = 1;
                dead.maxLocals = 0;
                fakeRefs++;
                changed = true;
            }

            for (int i = 0; i < options.dummyMethodsPerClass(); i++) {
                MethodNode dummy = syntheticMethod(cn, "junk" + i);
                InsnList insns = new InsnList();
                insns.add(new InsnNode(Opcodes.RETURN));
                dummy.instructions = insns;
                dummy.maxStack = 0;
                dummy.maxLocals = 0;
                dummyMethods++;
                changed = true;
            }

            if (options.constantsPerClass() > 0) {
                MethodNode pool = syntheticMethod(cn, "consts");
                InsnList insns = new InsnList();
                ThreadLocalRandom rnd = ThreadLocalRandom.current();
                for (int i = 0; i < options.constantsPerClass(); i++) {
                    String value = randomConstant(rnd);
                    insns.add(new LdcInsnNode(value));
                    insns.add(new InsnNode(Opcodes.POP));
                    constants++;
                }
                insns.add(new InsnNode(Opcodes.RETURN));
                pool.instructions = insns;
                pool.maxStack = 1;
                pool.maxLocals = 0;
                changed = true;
            }

            if (changed && cn.sourceFile != null) {
                // 保留 sourceFile（M11 不负责删调试信息），避免与 S6 重叠。
            }
        }
        return new Stats(visited, skippedMixin, skippedInterfaceVersion,
                invalidSignatures, fakeRefs, dummyMethods, constants);
    }

    private static MethodNode syntheticMethod(ClassNode cn, String tag) {
        int access = Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC;
        if ((cn.access & Opcodes.ACC_INTERFACE) != 0) {
            access = Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC | Opcodes.ACC_PUBLIC;
        }
        String name = "chimera$" + tag + "$" + HardenSupport.randomIdentifier("", 5);
        MethodNode mn = new MethodNode(access, name, "()V", null, null);
        cn.methods.add(mn);
        return mn;
    }

    private static String randomConstant(ThreadLocalRandom rnd) {
        String alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        StringBuilder sb = new StringBuilder(16);
        for (int i = 0; i < 16; i++) {
            sb.append(alphabet.charAt(rnd.nextInt(alphabet.length())));
        }
        return "chimera$" + sb;
    }
}