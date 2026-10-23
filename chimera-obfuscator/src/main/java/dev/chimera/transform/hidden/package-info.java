/**
 * S5 隐藏集合规划（纯分析，不修改产物字节）。
 *
 * <p>{@link dev.chimera.transform.hidden.HiddenSetPlanner} 扫描整个 jar 的引用图，输出
 * {@link dev.chimera.transform.hidden.Report}：哪些类可以进入隐藏集、哪些类必须保留以及原因
 * （Mixin/接口/enum/record/annotation、entrypoint、{@code @ChimeraNative}/{@code @ChimeraVM}
 * owner、{@code dev/chimera}、{@code $chimera$}、反射字符串命中、被保留类按名引用）。</p>
 *
 * <p>设计约束：</p>
 * <ul>
 *   <li>只依赖 ASM 与 JDK，不依赖 {@code ChimeraConfig}/{@code ChimeraEngine}/{@code Stats}；</li>
 *   <li>所有解析/输入失败路径 fail-closed：抛 {@link java.lang.IllegalArgumentException}
 *       中止规划，绝不返回“部分安全”的隐藏集合；</li>
 *   <li>结果确定性：所有 Map/Set 按 internal name 字典序保存；</li>
 *   <li>若后续阶段没有实现「保留类对隐藏类的按名引用间接化」，同包引用豁免是唯一不安全点，
 *       此时应使用 {@link dev.chimera.transform.hidden.HiddenSetOptions#samePackageReferencesPermitHiding()}
 *       = {@code false} 的严格模式。</li>
 * </ul>
 */
package dev.chimera.transform.hidden;
