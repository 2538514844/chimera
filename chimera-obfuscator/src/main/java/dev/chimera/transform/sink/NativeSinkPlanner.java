package dev.chimera.transform.sink;

import dev.chimera.transform.indy.IndyDispatchTransformer;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * B1 选类策略：按"调用权重"选出允许下沉的类（Hachimi 对照：只下沉核心逻辑类，3.5%~15% 方法）。
 *
 * <p>权重模型（类级）：</p>
 * <ul>
 *   <li>inJar（jar 内其他类对它的静态调用数）×3 —— 入口可达性 / 被引用强度；</li>
 *   <li>indy 改写引用数 ×1 —— 被改写引用多的类优先（这些类的调用面大，是核心逻辑）；</li>
 *   <li>方法体指令数总和 —— 大类优先，单次下沉收益更高。</li>
 * </ul>
 *
 * <p>排除集与 indy / ClassEncryptor 对齐：mixin 类（{@link IndyDispatchTransformer#isMixinClass}，
 * 运行时被 Mixin 重写）、keep/exclude 前缀（{@code config.excludes}）、{@code dev/chimera/} 运行时
 * 自身。预算按"类权重降序"分配：先选中的类，其全部可编译方法都可参与方法级筛选
 * （{@link NativeSinkTransformer} 的 per-class budget 与 build budget 再约束方法数）。</p>
 *
 * <p>纯规划器：只产出类名集合与统计，不改任何字节。确定性：所有排序带稳定 tiebreaker。</p>
 */
public final class NativeSinkPlanner {

    /** 默认：无预算上限（保持旧行为，方法数由 Options.maxMethodsPerBuild 控制）。 */
    public static final int UNLIMITED = 0;

    private static final String RUNTIME_PREFIX = "dev/chimera/";

    private NativeSinkPlanner() {
    }

    /** 一个候选类的权重与统计。 */
    public record ClassWeight(String internalName, long weight, int inJarCalls, int methodCount,
                              int instructionBytes) {
    }

    /** 规划结果：允许下沉的类集合（内部名）+ 权重明细（按权重降序）。 */
    public record Plan(Set<String> allowedClasses,
                       List<ClassWeight> ranked,
                       int totalClasses,
                       int excludedClasses,
                       int mixinClasses,
                       int budgetCapClasses) {
    }

    /**
     * 解析预算参数。
     *
     * @param budgetValue {@code <=0} = 不限；{@code 1..99} = 方法数百分比上限（3..99）；
     *                    {@code >=100} = 绝对最大方法数
     */
    public static int normalizeBudget(int budgetValue) {
        return budgetValue < 0 ? UNLIMITED : budgetValue;
    }

    /** true 当预算语义是"百分比"；此时调用方需要先估计可编译方法总数。 */
    public static boolean isPercentBudget(int normalizedBudget) {
        return normalizedBudget > 0 && normalizedBudget < 100;
    }

    /**
     * 计算类权重并选出预算内允许下沉的类集合。
     *
     * @param classes       jar 内全部类（entryName "a/B.class" -> bytes），值不可为 null
     * @param excludes      排除前缀（与 indy / ClassEncryptor keep 语义一致，前缀匹配）
     * @param maxClasses    {@code <=0} = 不限类数（仅按权重排序全选）
     */
    public static Plan plan(Map<String, byte[]> classes, List<String> excludes, int maxClasses) {
        Set<String> excludePrefixes = new TreeSet<>();
        if (excludes != null) {
            excludePrefixes.addAll(excludes);
        }

        // Pass 1: parse every class once, collect method info + count cross-class calls.
        Map<String, ClassNode> parsed = new LinkedHashMap<>();
        for (Map.Entry<String, byte[]> entry : classes.entrySet()) {
            String key = entry.getKey();
            byte[] bytes = entry.getValue();
            if (key == null || bytes == null || bytes.length < 10 || !key.endsWith(".class")) {
                continue;
            }
            try {
                ClassNode node = new ClassNode();
                new ClassReader(bytes).accept(node, ClassReader.SKIP_DEBUG);
                parsed.put(key, node);
            } catch (Throwable unreadable) {
                // The main pipeline reports unreadable classes later; the planner just ignores them.
            }
        }

        // Pass 2: in-jar incoming call counts (callee class -> count of INVOKE* sites from other
        // jar classes). This is the reachability/centrality signal.
        Map<String, Integer> incomingCalls = new HashMap<>();
        for (ClassNode node : parsed.values()) {
            if (IndyDispatchTransformer.isMixinClass(node)) {
                // Mixin classes are excluded anyway; do not let their (rewritten-at-runtime)
                // call sites inflate other classes' weight.
                continue;
            }
            if (node.methods == null) {
                continue;
            }
            for (var method : node.methods) {
                if (method.instructions == null) {
                    continue;
                }
                for (AbstractInsnNode insn : method.instructions) {
                    if (insn instanceof MethodInsnNode call
                            && call.owner != null
                            && !call.owner.equals(node.name)) {
                        String ownerEntry = call.owner + ".class";
                        if (parsed.containsKey(ownerEntry)) {
                            incomingCalls.merge(call.owner, 1, Integer::sum);
                        }
                    }
                }
            }
        }

        // Pass 3: score and rank candidate classes.
        List<ClassWeight> candidates = new ArrayList<>();
        int mixinCount = 0;
        int excludedCount = 0;
        for (Map.Entry<String, ClassNode> entry : parsed.entrySet()) {
            ClassNode node = entry.getValue();
            String internal = node.name;
            if (internal == null) {
                continue;
            }
            if (IndyDispatchTransformer.isMixinClass(node)) {
                mixinCount++;
                continue;
            }
            if (isExcluded(internal, excludePrefixes)) {
                excludedCount++;
                continue;
            }
            int methodCount = node.methods == null ? 0 : node.methods.size();
            int instructionBytes = 0;
            for (var method : node.methods) {
                if (method.instructions != null) {
                    instructionBytes += method.instructions.size();
                }
            }
            int incoming = incomingCalls.getOrDefault(internal, 0);
            long weight = (long) incoming * 3L + (long) methodCount + (long) (instructionBytes / 8);
            candidates.add(new ClassWeight(internal, weight, incoming, methodCount, instructionBytes));
        }

        // Deterministic order: weight desc, then name asc.
        candidates.sort(Comparator
                .comparingLong(ClassWeight::weight).reversed()
                .thenComparing(ClassWeight::internalName));

        int cap = maxClasses > 0 ? Math.min(maxClasses, candidates.size()) : candidates.size();
        Set<String> allowed = new TreeSet<>();
        List<ClassWeight> ranked = new ArrayList<>(candidates.size());
        for (int i = 0; i < candidates.size(); i++) {
            ClassWeight cw = candidates.get(i);
            ranked.add(cw);
            if (i < cap) {
                allowed.add(cw.internalName());
            }
        }
        return new Plan(allowed, List.copyOf(ranked), parsed.size(), excludedCount,
                mixinCount, cap);
    }

    private static boolean isExcluded(String internalName, Set<String> prefixes) {
        if (internalName.startsWith(RUNTIME_PREFIX)) {
            return true;
        }
        for (String prefix : prefixes) {
            if (!prefix.isEmpty() && internalName.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    /** Convenience for logging: top-N weights as a compact string. */
    public static String describeTop(Plan plan, int top) {
        StringBuilder sb = new StringBuilder();
        List<ClassWeight> ranked = plan.ranked();
        for (int i = 0; i < Math.min(top, ranked.size()); i++) {
            if (i > 0) {
                sb.append(", ");
            }
            ClassWeight cw = ranked.get(i);
            sb.append(cw.internalName()).append("(w=").append(cw.weight())
                    .append(",in=").append(cw.inJarCalls())
                    .append(",m=").append(cw.methodCount()).append(')');
        }
        return sb.toString();
    }

    /** Maps selected method owners to their share of the total instruction weight (reporting helper). */
    public static Map<String, Integer> selectedByOwner(List<SinkSelectedMethod> selected) {
        Map<String, Integer> byOwner = new TreeMap<>();
        for (SinkSelectedMethod method : selected) {
            byOwner.merge(method.owner(), 1, Integer::sum);
        }
        return byOwner;
    }
}
