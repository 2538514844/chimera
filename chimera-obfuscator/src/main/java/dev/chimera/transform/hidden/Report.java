package dev.chimera.transform.hidden;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * {@link HiddenSetPlanner#plan(Map, HiddenSetOptions)} 的纯分析结果。
 *
 * <p>不变量（构造时 fail-closed 校验）：</p>
 * <ul>
 *   <li>{@code keepReasons} 与 {@code hiddenCandidates} 不相交；</li>
 *   <li>{@code hiddenCandidateCount == hiddenCandidates.size()}；</li>
 *   <li>名字非空、无换行；理由非空、无换行（{@link #writeCandidateList} 可直接按行写文件）。</li>
 * </ul>
 *
 * <p>集合/映射都按字典序保存为不可变副本，保证同一输入多次规划、不同输入顺序下结果一致。</p>
 *
 * @param keepReasons 保留类 -&gt; 原因（结构类型、entrypoint、反射字符串、被保留类按名引用...）
 * @param hiddenCandidates 可隐藏候选（仅分析结论；本类不修改任何字节）
 * @param scannedClasses 参与扫描的 jar 内类数量
 * @param reflectiveHits 被反射字符串命中的类数量（去重后的类数，不是字符串数）
 * @param hiddenCandidateCount {@code hiddenCandidates.size()} 的冗余计数，便于日志/Stats
 */
public record Report(
        Map<String, String> keepReasons,
        Set<String> hiddenCandidates,
        int scannedClasses,
        int reflectiveHits,
        int hiddenCandidateCount) {

    public Report {
        keepReasons = copyReasons(keepReasons);
        hiddenCandidates = copyNames(hiddenCandidates);
        if (scannedClasses < 0) {
            throw new IllegalArgumentException("scannedClasses must be >= 0");
        }
        if (reflectiveHits < 0) {
            throw new IllegalArgumentException("reflectiveHits must be >= 0");
        }
        if (hiddenCandidateCount != hiddenCandidates.size()) {
            throw new IllegalArgumentException("hiddenCandidateCount must equal hiddenCandidates.size()");
        }
        if (hiddenCandidateCount > scannedClasses || keepReasons.size() > scannedClasses) {
            throw new IllegalArgumentException("counts exceed scannedClasses");
        }
        if (keepReasons.size() + hiddenCandidateCount > scannedClasses) {
            throw new IllegalArgumentException("keepReasons and hiddenCandidates overlap scannedClasses bounds");
        }
        for (String name : hiddenCandidates) {
            if (keepReasons.containsKey(name)) {
                throw new IllegalArgumentException("class is both kept and hidden: " + name);
            }
        }
    }

    /** 保留类数量。 */
    public int keptCount() {
        return keepReasons.size();
    }

    /** 该内部名是否在隐藏候选中。 */
    public boolean isHiddenCandidate(String internalName) {
        return hiddenCandidates.contains(internalName);
    }

    /** 该内部名的保留原因；隐藏候选或未知类返回 {@code null}。 */
    public String reasonFor(String internalName) {
        return keepReasons.get(internalName);
    }

    private static Map<String, String> copyReasons(Map<String, String> reasons) {
        if (reasons == null) {
            throw new IllegalArgumentException("keepReasons must not be null");
        }
        Map<String, String> copy = new TreeMap<>();
        for (Map.Entry<String, String> entry : reasons.entrySet()) {
            String name = requireName(entry.getKey(), "keepReasons key");
            String reason = entry.getValue();
            if (reason == null || reason.isBlank()) {
                throw new IllegalArgumentException("empty keep reason for " + name);
            }
            if (reason.indexOf('\n') >= 0 || reason.indexOf('\r') >= 0) {
                throw new IllegalArgumentException("keep reason must be single-line: " + name);
            }
            copy.put(name, reason);
        }
        return Collections.unmodifiableMap(copy);
    }

    private static Set<String> copyNames(Set<String> names) {
        if (names == null) {
            throw new IllegalArgumentException("hiddenCandidates must not be null");
        }
        Set<String> copy = new TreeSet<>();
        for (String name : names) {
            copy.add(requireName(name, "hiddenCandidates element"));
        }
        return Collections.unmodifiableSet(copy);
    }

    private static String requireName(String name, String label) {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException(label + " must be a non-blank internal name");
        }
        if (name.indexOf('\n') >= 0 || name.indexOf('\r') >= 0) {
            throw new IllegalArgumentException(label + " must be single-line: " + name);
        }
        return name;
    }
}
