package dev.chimera.transform.hidden;

import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;

/**
 * {@link HiddenSetPlanner} 的输入规则。
 *
 * <p>本类型刻意不依赖 {@code ChimeraConfig}：CLI/Gradle 配置与 {@code fabric.mod.json}
 * entrypoints 由 Lead 在接线层映射进来。规划器只读字节、不改产物。</p>
 *
 * <p>所有集合都会归一化为 internal name（{@code a/b/C}）并排序；也接受点号形式
 * （{@code a.b.C}）或 {@code .class} 后缀。集合中不允许 null、空串或带空白字符的名字。</p>
 *
 * @param entrypoints 不可隐藏的入口类（{@code fabric.mod.json} entrypoints、mixins 配置等）
 * @param forcedKeep 额外强制保留的类
 * @param forcedKeepPrefixes 额外强制保留的类名前缀（匹配 {@code p} 本身或 {@code p/...}）
 * @param samePackageReferencesPermitHiding 同包按名引用是否不阻止被引用类进入隐藏集。
 *        默认 {@code true}，与 S5「引用间接化 / 同包重写」配套；没有该前置能力时置
 *        {@code false}，只允许封闭引用分量被隐藏（更保守）。
 */
public record HiddenSetOptions(
        Set<String> entrypoints,
        Set<String> forcedKeep,
        Set<String> forcedKeepPrefixes,
        boolean samePackageReferencesPermitHiding) {

    public HiddenSetOptions {
        entrypoints = normalizeNames(entrypoints, "entrypoints");
        forcedKeep = normalizeNames(forcedKeep, "forcedKeep");
        forcedKeepPrefixes = normalizePrefixes(forcedKeepPrefixes);
    }

    /** 保守默认：无额外规则，同包引用豁免开启（与 S5 引用间接化配套）。 */
    public static HiddenSetOptions defaults() {
        return new HiddenSetOptions(Set.of(), Set.of(), Set.of(), true);
    }

    /** 只声明入口类的便捷工厂。 */
    public static HiddenSetOptions ofEntrypoints(String... entrypoints) {
        if (entrypoints == null) {
            throw new IllegalArgumentException("entrypoints must not be null");
        }
        Set<String> names = new TreeSet<>();
        for (String entrypoint : entrypoints) {
            names.add(entrypoint);
        }
        return new HiddenSetOptions(names, Set.of(), Set.of(), true);
    }

    private static Set<String> normalizeNames(Set<String> values, String label) {
        if (values == null) {
            throw new IllegalArgumentException(label + " must not be null");
        }
        Set<String> normalized = new TreeSet<>();
        for (String value : values) {
            normalized.add(normalizeName(value, label));
        }
        return Collections.unmodifiableSet(normalized);
    }

    private static Set<String> normalizePrefixes(Set<String> values) {
        if (values == null) {
            throw new IllegalArgumentException("forcedKeepPrefixes must not be null");
        }
        Set<String> normalized = new TreeSet<>();
        for (String value : values) {
            String prefix = normalizeName(value, "forcedKeepPrefixes");
            while (prefix.endsWith("/")) {
                prefix = prefix.substring(0, prefix.length() - 1);
            }
            if (prefix.isEmpty()) {
                throw new IllegalArgumentException("forcedKeepPrefixes contains an empty prefix");
            }
            normalized.add(prefix);
        }
        return Collections.unmodifiableSet(normalized);
    }

    private static String normalizeName(String raw, String label) {
        if (raw == null) {
            throw new IllegalArgumentException(label + " contains a null class name");
        }
        String name = raw.trim().replace('\\', '/');
        if (name.endsWith(".class")) {
            name = name.substring(0, name.length() - ".class".length());
        }
        name = name.replace('.', '/');
        while (name.startsWith("/")) {
            name = name.substring(1);
        }
        if (name.isEmpty()) {
            throw new IllegalArgumentException(label + " contains an empty class name");
        }
        for (int i = 0; i < name.length(); i++) {
            if (Character.isWhitespace(name.charAt(i))) {
                throw new IllegalArgumentException(label + " contains a name with whitespace: " + raw);
            }
        }
        return name;
    }
}
