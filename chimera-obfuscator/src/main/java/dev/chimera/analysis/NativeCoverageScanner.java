package dev.chimera.analysis;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * S1：把 Wurst（或任意 mod jar）的方法按"能否 native codegen"分级，
 * 输出 CSV 与汇总，用于决定 JNI codegen 的覆盖范围与排期。
 *
 * <p>分级：
 * <ul>
 *   <li>A —— 纯原始类型（含分支/循环/switch/算术），无需 JNI 对象操作</li>
 *   <li>B —— A + 原始类型静态字段 + 字符串常量 + java/lang/Math|StrictMath</li>
 *   <li>C —— 原始类型实例/静态字段 + 原始类型调用（需 FieldID/MethodID 缓存）</li>
 *   <li>D —— 对象/数组/异常/try-catch/对象调用（需完整 JNI codegen）</li>
 *   <li>E —— 不可 codegen：Mixin/构造器/&lt;clinit&gt;/native/abstract/synchronized/indy/monitor/jsr</li>
 * </ul>
 */
public final class NativeCoverageScanner {

    public enum Tier { A, B, C, D, E }

    public record MethodReport(
            String owner,
            String name,
            String desc,
            int access,
            Tier tier,
            List<String> reasons,
            int insns,
            int calls,
            int fieldRefs,
            int arrayOps,
            int stringConstants,
            boolean tryCatch,
            boolean switchInsn,
            boolean indy) {
    }

    public record ClassReport(String name, boolean mixin, List<MethodReport> methods) {
    }

    public record Summary(
            int classes,
            int mixinClasses,
            int methods,
            int codegenCandidates,
            int hardSkipped,
            Map<Tier, Integer> tierCounts,
            Map<String, Integer> reasonCounts) {
    }

    private static final String MIXIN_PREFIX = "Lorg/spongepowered/asm/mixin/";
    private static final String MIXIN_EXTRAS_PREFIX = "Lcom/llamalad7/mixinextras/";

    private NativeCoverageScanner() {
    }

    public static List<ClassReport> scan(Path jar) throws IOException {
        List<ClassReport> reports = new ArrayList<>();
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            List<? extends ZipEntry> entries = zip.stream()
                    .filter(e -> !e.isDirectory() && e.getName().endsWith(".class"))
                    .sorted(Comparator.comparing(ZipEntry::getName))
                    .toList();
            for (ZipEntry entry : entries) {
                byte[] bytes = zip.getInputStream(entry).readAllBytes();
                ClassNode cn = new ClassNode();
                new ClassReader(bytes).accept(cn, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
                reports.add(scanClass(cn));
            }
        }
        return reports;
    }

    static ClassReport scanClass(ClassNode cn) {
        boolean mixin = hasMixinAnnotation(cn.visibleAnnotations)
                || hasMixinAnnotation(cn.invisibleAnnotations);
        List<MethodReport> methods = new ArrayList<>(cn.methods.size());
        for (MethodNode mn : cn.methods) {
            methods.add(scanMethod(cn, mn, mixin));
        }
        return new ClassReport(cn.name, mixin, methods);
    }

    private static boolean hasMixinAnnotation(List<AnnotationNode> annotations) {
        if (annotations == null) {
            return false;
        }
        for (AnnotationNode an : annotations) {
            if (an.desc != null && an.desc.startsWith(MIXIN_PREFIX) && an.desc.endsWith("/Mixin;")) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasMemberMixinAnnotation(List<AnnotationNode> visible, List<AnnotationNode> invisible) {
        return anyMemberMixin(visible) || anyMemberMixin(invisible);
    }

    private static boolean anyMemberMixin(List<AnnotationNode> annotations) {
        if (annotations == null) {
            return false;
        }
        for (AnnotationNode an : annotations) {
            if (an.desc == null) {
                continue;
            }
            if (an.desc.startsWith(MIXIN_PREFIX) || an.desc.startsWith(MIXIN_EXTRAS_PREFIX)) {
                return true;
            }
        }
        return false;
    }

    static MethodReport scanMethod(ClassNode cn, MethodNode mn, boolean classIsMixin) {
        List<String> reasons = new ArrayList<>();
        boolean hard = false;

        if (classIsMixin) {
            reasons.add("MIXIN_CLASS");
            hard = true;
        }
        if ("<init>".equals(mn.name)) {
            reasons.add("CONSTRUCTOR");
            hard = true;
        }
        if ("<clinit>".equals(mn.name)) {
            reasons.add("CLINIT");
            hard = true;
        }
        if ((mn.access & Opcodes.ACC_NATIVE) != 0) {
            reasons.add("NATIVE");
            hard = true;
        }
        if ((mn.access & Opcodes.ACC_ABSTRACT) != 0) {
            reasons.add("ABSTRACT");
            hard = true;
        }
        if ((mn.access & Opcodes.ACC_SYNCHRONIZED) != 0) {
            reasons.add("SYNCHRONIZED");
            hard = true;
        }
        if (hasMemberMixinAnnotation(mn.visibleAnnotations, mn.invisibleAnnotations)) {
            reasons.add("MIXIN_MEMBER");
            hard = true;
        }

        boolean primitiveOnly = primitiveDescriptor(mn.desc);
        // objectLevel = 出现了"必须用 JNI 对象 API"的形态（对象描述符/分配/对象成员/数组/异常/lambda）
        boolean objectLevel = !primitiveOnly;
        boolean usesStaticField = false;
        boolean usesInstanceField = false;
        boolean usesCall = false;
        boolean usesNonMathCall = false;
        boolean usesString = false;
        boolean usesSwitch = false;
        boolean indy = false;
        int insns = 0;
        int calls = 0;
        int fieldRefs = 0;
        int arrayOps = 0;
        int stringConstants = 0;

        for (AbstractInsnNode insn : mn.instructions) {
            int op = insn.getOpcode();
            if (op < 0) {
                continue;
            }
            insns++;
            if (op == Opcodes.INVOKEDYNAMIC) {
                indy = true;
                hard = true;
                reasons.add("INDY");
                objectLevel = true;
            } else if (insn instanceof MethodInsnNode mi) {
                calls++;
                usesCall = true;
                if (!primitiveDescriptor(mi.desc)) {
                    objectLevel = true;
                }
                boolean mathCall = "java/lang/Math".equals(mi.owner) || "java/lang/StrictMath".equals(mi.owner);
                if (!mathCall) {
                    usesNonMathCall = true;
                }
            } else if (insn instanceof FieldInsnNode fi) {
                fieldRefs++;
                if (!primitiveTypeDescriptor(fi.desc)) {
                    objectLevel = true;
                }
                if (op == Opcodes.GETSTATIC || op == Opcodes.PUTSTATIC) {
                    usesStaticField = true;
                } else {
                    usesInstanceField = true;
                }
            } else if (insn instanceof LdcInsnNode ld) {
                Object cst = ld.cst;
                if (cst instanceof String) {
                    stringConstants++;
                    usesString = true;
                } else if (cst instanceof Type t) {
                    if (t.getSort() != Type.INT && t.getSort() != Type.FLOAT
                            && t.getSort() != Type.LONG && t.getSort() != Type.DOUBLE) {
                        objectLevel = true;
                    }
                } else if (cst instanceof org.objectweb.asm.Handle
                        || cst instanceof org.objectweb.asm.ConstantDynamic) {
                    objectLevel = true;
                }
            } else if (op == Opcodes.MONITORENTER || op == Opcodes.MONITOREXIT) {
                hard = true;
                reasons.add("MONITOR");
            } else if (op == Opcodes.JSR || op == Opcodes.RET) {
                hard = true;
                reasons.add("JSR");
            } else if (op == Opcodes.TABLESWITCH || op == Opcodes.LOOKUPSWITCH) {
                usesSwitch = true;
            } else if (op == Opcodes.NEW || op == Opcodes.ANEWARRAY || op == Opcodes.MULTIANEWARRAY
                    || op == Opcodes.CHECKCAST || op == Opcodes.INSTANCEOF || op == Opcodes.ATHROW) {
                objectLevel = true;
            } else if (op == Opcodes.NEWARRAY || op == Opcodes.ARRAYLENGTH
                    || (op >= Opcodes.IALOAD && op <= Opcodes.SALOAD)
                    || (op >= Opcodes.IASTORE && op <= Opcodes.SASTORE)) {
                arrayOps++;
                objectLevel = true;
            }
        }

        boolean tryCatch = mn.tryCatchBlocks != null && !mn.tryCatchBlocks.isEmpty();
        if (tryCatch) {
            reasons.add("TRY_CATCH");
        }
        if (!primitiveOnly) {
            reasons.add("OBJECT_DESC");
        }

        Tier tier;
        if (hard) {
            tier = Tier.E;
        } else if (primitiveOnly && !objectLevel && !usesCall && !usesStaticField && !usesString && !tryCatch) {
            tier = Tier.A;
        } else if (primitiveOnly && !objectLevel && !tryCatch && !usesInstanceField
                && !usesNonMathCall && !usesString) {
            tier = Tier.B;
        } else if (primitiveOnly && !objectLevel && !tryCatch) {
            tier = Tier.C;
        } else {
            tier = Tier.D;
        }

        if (tier == Tier.B) {
            reasons.add("STATIC_FIELD_OR_CONST");
        }
        if (tier == Tier.C) {
            reasons.add("PRIMITIVE_MEMBER_ACCESS");
        }
        if (tier == Tier.D) {
            reasons.add("FULL_JNI");
        }
        return new MethodReport(cn.name, mn.name, mn.desc, mn.access, tier, List.copyOf(reasons),
                insns, calls, fieldRefs, arrayOps, stringConstants, tryCatch, usesSwitch, indy);
    }

    static boolean primitiveDescriptor(String methodDesc) {
        Type type = Type.getMethodType(methodDesc);
        if (!primitiveType(type.getReturnType())) {
            return false;
        }
        for (Type arg : type.getArgumentTypes()) {
            if (!primitiveType(arg)) {
                return false;
            }
        }
        return true;
    }

    private static boolean primitiveTypeDescriptor(String desc) {
        return primitiveType(Type.getType(desc));
    }

    private static boolean primitiveType(Type type) {
        return switch (type.getSort()) {
            case Type.VOID, Type.BOOLEAN, Type.CHAR, Type.BYTE, Type.SHORT,
                 Type.INT, Type.FLOAT, Type.LONG, Type.DOUBLE -> true;
            default -> false;
        };
    }

    public static Summary summarize(List<ClassReport> reports) {
        Map<Tier, Integer> counts = new EnumMap<>(Tier.class);
        for (Tier t : Tier.values()) {
            counts.put(t, 0);
        }
        Map<String, Integer> reasonCounts = new TreeMap<>();
        int classes = 0;
        int mixinClasses = 0;
        int methods = 0;
        int candidates = 0;
        int hard = 0;
        for (ClassReport cr : reports) {
            classes++;
            if (cr.mixin()) {
                mixinClasses++;
            }
            for (MethodReport mr : cr.methods()) {
                methods++;
                counts.merge(mr.tier(), 1, Integer::sum);
                if (mr.tier() == Tier.E) {
                    hard++;
                } else {
                    candidates++;
                }
                for (String reason : mr.reasons()) {
                    reasonCounts.merge(reason, 1, Integer::sum);
                }
            }
        }
        return new Summary(classes, mixinClasses, methods, candidates, hard,
                Map.copyOf(counts), Map.copyOf(reasonCounts));
    }

    public static void writeCsv(List<ClassReport> reports, Path out) throws IOException {
        Files.createDirectories(out.getParent());
        try (PrintWriter pw = new PrintWriter(Files.newBufferedWriter(out, StandardCharsets.UTF_8))) {
            pw.println("owner,name,desc,access,tier,reasons,insns,calls,fieldRefs,arrayOps,stringConstants,tryCatch,switch,indy");
            for (ClassReport cr : reports) {
                for (MethodReport mr : cr.methods()) {
                    pw.printf("%s,%s,%s,0x%04x,%s,%s,%d,%d,%d,%d,%d,%b,%b,%b%n",
                            csv(mr.owner()), csv(mr.name()), csv(mr.desc()), mr.access(), mr.tier(),
                            csv(String.join(";", mr.reasons())), mr.insns(), mr.calls(), mr.fieldRefs(),
                            mr.arrayOps(), mr.stringConstants(), mr.tryCatch(), mr.switchInsn(), mr.indy());
                }
            }
        }
    }

    private static String csv(String value) {
        if (value.indexOf(',') < 0 && value.indexOf('"') < 0 && value.indexOf('\n') < 0) {
            return value;
        }
        return '"' + value.replace("\"", "\"\"") + '"';
    }

    public static String summarizeHuman(Summary summary) {
        StringBuilder sb = new StringBuilder();
        sb.append("classes=").append(summary.classes())
                .append(" mixinClasses=").append(summary.mixinClasses())
                .append(" methods=").append(summary.methods())
                .append(" codegenCandidates=").append(summary.codegenCandidates())
                .append(" hardSkipped=").append(summary.hardSkipped())
                .append('\n');
        long total = summary.methods();
        for (Tier tier : Tier.values()) {
            int count = summary.tierCounts().getOrDefault(tier, 0);
            sb.append(String.format(Locale.ROOT, "  %s: %6d  (%5.1f%%)%n",
                    tier, count, total == 0 ? 0.0 : 100.0 * count / total));
        }
        List<Map.Entry<String, Integer>> reasons = new ArrayList<>(summary.reasonCounts().entrySet());
        reasons.sort(Map.Entry.<String, Integer>comparingByValue().reversed());
        sb.append("reasons:\n");
        for (Map.Entry<String, Integer> e : reasons) {
            sb.append(String.format(Locale.ROOT, "  %-24s %6d%n", e.getKey(), e.getValue()));
        }
        return sb.toString();
    }

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("usage: NativeCoverageScanner <jar> [out.csv]");
            System.exit(2);
        }
        Path jar = Path.of(args[0]);
        List<ClassReport> reports = scan(jar);
        Summary summary = summarize(reports);
        System.out.print(summarizeHuman(summary));
        if (args.length >= 2) {
            Path out = Path.of(args[1]);
            writeCsv(reports, out);
            System.out.println("csv=" + out.toAbsolutePath());
        }
    }
}
