# M4 — JNIC：Java 字节码到 C++ 的自动转译（基础运算版）

## 1. 范围

M4 把 `@ChimeraNative` 方法从“只有签名 + TODO 的模板”升级为可编译的原生实现：

- **NativeTranspiler**：读取 ASM `ClassNode + MethodNode`，对**直线运算 + 条件分支 + 循环**的 int/long/double 字节码生成 C++ 函数体（v2，见 §7）；
- **NativeTemplateWriter**：生成成对的 `<Class>_<method>.h` 与 `.cpp`；
- **ChimeraEngine.writeNativeTemplates**：混淆时把 `.h + .cpp` 写到 `nativeOutDir`；
- **Gradle `chimeraNativeCompile`**：调用 gcc/clang 把 `.cpp` 编成 `.dll/.so/.dylib`；
- **JUnit**：转译结果断言 + 真实 `gcc -fsyntax-only` 冒烟（gcc 不存在时用 Assumptions 跳过，不伪造）。

不改变现有的 `--no-native` 行为：关闭后既不生成 stub，也不写模板。

## 2. 生成产物

每个方法生成两个文件（`<Class>_<method>` 为文件名 stem）：

```
out/native/demo_Math_add.h
out/native/demo_Math_add.cpp
```

`.h`：

```c
#pragma once
#include <jni.h>

// Exact Java narrowing semantics (saturating, NaN -> 0) for d2i / d2l.
static inline jint chimera_d2i(jdouble v) { ... }
static inline jlong chimera_d2l(jdouble v) { ... }

extern "C" JNIEXPORT jint JNICALL Java_demo_Math_add(JNIEnv* env, jclass clazz, jint a0, jint a1);
```

`.cpp`：

```c
#include "demo_Math_add.h"
#include <cmath>

extern "C" JNIEXPORT jint JNICALL Java_demo_Math_add(JNIEnv* env, jclass clazz, jint a0, jint a1) {
    jint v0 = a0;
    jint v1 = a1;
    return (v0 + v1);
}
```

JNI 符号名按 JNI 规范生成：`Java_` + 类名/方法名 mangling（`/`、`.` → `_`；原名中的 `_` → `_1`；
`$` 等非字母数字 → `_0xxxx`）。注意：历史实现把已替换的包分隔符又当成字面 `_` 转义成 `_5f_`
（`Java_demo_5f_Hwid_hash`），JVM 永远查不到该符号，加载库后调用必抛 `UnsatisfiedLinkError`；
本版已修正为 `Java_demo_Hwid_hash`（文件名 stem 仍保持 `<Class>_<method>`，产物路径不变）。

## 3. 支持的字节码子集

| 类别 | 指令 |
|---|---|
| 常量 | `ICONST_M1..ICONST_5`, `BIPUSH`, `SIPUSH`, `LCONST_0/1`, `DCONST_0/1`, `LDC`（int/long/double，有限值） |
| 局部变量 | `ILOAD/LLOAD/DLOAD`, `ISTORE/LSTORE/DSTORE` |
| int 运算 | `IADD ISUB IMUL IDIV IREM INEG` |
| long 运算 | `LADD LSUB LMUL LDIV LREM LNEG` |
| double 运算 | `DADD DSUB DMUL DDIV DREM`（`DREM` 用 `std::fmod`） |
| 转换 | `I2L I2D L2I L2D D2I D2L`，窄化 `I2B I2C I2S` |
| 位运算/移位 | `IAND IOR IXOR LAND LOR LXOR`，`ISHL ISHR IUSHR LSHL LSHR LUSHR`（移位计数按 Java 掩码） |
| 比较 | `LCMP DCMPG DCMPL`（产生 int 再分支） |
| 控制流 | `IFEQ IFNE IFLT IFGE IFGT IFLE`、`IF_ICMPEQ/NE/LT/GE/GT/LE`、`GOTO`、`IINC` |
| 返回 | `IRETURN LRETURN DRETURN` |

方法约束：**static**，参数/返回类型只允许 `int/long/double`（void 与对象/数组不支持）。
类/方法上的 `@ChimeraNative` 生命周期不变：`NativeStubTransformer` 把方法改成 native、清空 Code，
并在清空之前调用 `NativeTranspiler` 保存转译结果。

### 不支持的输入（自动回退为 TODO stub，不生成错误代码）

- switch（`TABLESWITCH`, `LOOKUPSWITCH`）
- 字段访问（`GETFIELD/PUTFIELD/GETSTATIC/PUTSTATIC`）
- 方法调用（`INVOKEVIRTUAL/INVOKESTATIC/INVOKESPECIAL/INVOKEINTERFACE/INVOKEDYNAMIC`）
- 对象/数组/异常/监视器/类型检查（`NEW`, `ANEWARRAY`, `CHECKCAST`, `ATHROW`, `MONITORENTER`…）
- 异常表非空、非 static、float 运算、`LDC` 的 NaN/Infinity
- 不可达字节码（ASM Analyzer 的 frame 为 null）、方法末尾没有 return

回退时 `.cpp` 保留：

```c
// TODO: implement hash(Ljava/lang/String;)Ljava/lang/String;
return nullptr;
```

## 4. Gradle 使用

```groovy
plugins { id 'dev.chimera' }

chimera {
    inputJar      = file("build/libs/app.jar")
    outputJar     = file("build/libs/app-obf.jar")
    contentKey    = "demo-content-key"
    nativeOutDir  = file("build/native")
    nativeLibDir  = file("build/native-lib")  // 默认 build/native-lib
    nativeCompiler = "gcc"                    // 默认 gcc；可填绝对路径或 clang
}
```

```bash
# 先生成模板，再编译 native 库
./gradlew chimeraObfuscate chimeraNativeCompile
```

`chimeraNativeCompile` 会：

1. 遍历 `nativeOutDir` 下所有 `.cpp`；
2. 用 `<JAVA_HOME>/include` 与平台子目录（win32/linux/darwin）作为 JNI 头路径；
3. 执行 `gcc -shared -O2 -std=c++17 -I... -o <name>.dll|.so|.dylib <name>.cpp`（非 Windows 加 `-fPIC`）；
4. 失败时抛出 `GradleException` 并带上编译器输出；没有 `.cpp` 时打印提示并跳过。

Windows PowerShell 手工等价命令（MinGW gcc）：

```powershell
$JAVA_HOME = "C:\Program Files\Eclipse Adoptium\jdk-21.0.12.101-hotspot"
gcc -shared -O2 -std=c++17 `
    -I"$JAVA_HOME\include" -I"$JAVA_HOME\include\win32" `
    -o build\native-lib\demo_Math_add.dll build\native\demo_Math_add.cpp
```

Linux：

```bash
gcc -shared -O2 -std=c++17 -fPIC \
    -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/linux" \
    -o build/native-lib/libdemo_Math_add.so build/native/demo_Math_add.cpp
```

加载：`System.loadLibrary("demo_Math_add")` 或 `System.load(absolutePath)`；未加载时调用 native 方法
仍会抛 `UnsatisfiedLinkError`（与 M1/M2 行为一致）。

## 5. 语义与限制（必须知悉）

1. **除零 UB**：Java 的 `int/long` 除零抛 `ArithmeticException`，C++ 有符号除零是未定义行为；
   生成的代码在对应位置写注释，但不做异常转换。`Integer.MIN_VALUE / -1` 的溢出同理。
2. **窄化转换**：`D2I/D2L` 使用 `chimera_d2i/chimera_d2l` 辅助函数，**精确匹配 Java 的饱和 + NaN→0 语义**；
   `L2I` 使用 C++ `(jint)` 强转，gcc/clang 下是二进制补码截断，与 Java 一致（标准层面属于实现定义）。
3. **DREM**：用 `std::fmod`，结果符号/NaN 行为与 Java `%` 基本一致；不处理 Java 的 `-0.0` 特例差异。
4. **double 常量**：只支持有限值；NaN/Infinity 常量会让方法变成 TODO stub（避免生成非法 C++ 字面量）。
5. **控制流支持范围**：if/else、for/while/do-while 用 `if (...) goto` + 标签生成；switch、
   异常、对象/数组/字段/调用仍回退 TODO，不会生成“看起来能编译但语义错误”的代码。
6. **@ChimeraNative 返回类型约束的适用范围（A4 明确）**：禁止 boolean/int/short/byte/char/void
   **仅适用于验签/授权/判定类 native 方法**（防止 `mov eax,1; ret` 解锁逻辑）。**VM（@ChimeraVM）
   计算类方法不受此约束**，可以返回 int/long/double/对象（在 M9 子集内），因为它们是业务数值，
   不是授权布尔值。M4 的检查在 `NativeStubTransformer.enforceBusinessReturnType`；M9 不调用它。
   因此实际带注解的 M4 方法只能落到 double/float/long/object；其中只有 double/long 会被转译，
   float/object 走 TODO。int 转译器主要供测试/后续数据流分析使用。
7. **重载方法文件名冲突**：当前文件名是 `<Class>_<method>`，同名重载会互相覆盖（后写者胜）。
   已知限制；需要时可在文件名中加入 descriptor hash，但会破坏现有命名约定。
8. **槽位命名**：局部变量按 `slot:type` 预声明为 `lv<slot>_<type>`，操作数栈按 `depth:type`
   预声明为 `s<depth>_<type>`，因此同一 slot 的不同类型视图互不干扰，分支合流语义正确。
9. **生成器不生成异常/栈回溯/对象引用语义**：这是 M4 的边界，不是通用 Java→C++ 编译器。

## 6. 测试

`NativeTranspilerTest` 覆盖：

- `static int add(int,int)` → `supported`，body 含 `lv0_i/lv1_i/s0_i` 声明与
  `(chimera_u32)s0_i + (chimera_u32)s1_i`；
- `static double mix(int,double)` → `supported`，body 含 `(jdouble)s0_i` 与 `s0_d = s0_d + s1_d;`；
- **if/else 与 for 循环** → `supported`，body 含 `if (...) goto L<n>;` / `goto L<n>;` / `IINC` 更新；
- 对象参数 / 非 static / 异常表 → `supported=false`，header 仍生成；
- `.h/.cpp` 成对内容、TODO fallback；
- **gcc 存在时**把 add/mix/分支/循环 4 个生成产物真实跑
  `gcc -x c++ -std=c++17 -fsyntax-only`；gcc 缺失则 `Assumptions` 跳过（不伪造结果）。

运行：

```bash
./gradlew test --tests dev.chimera.nativecode.NativeTranspilerTest
```

## 7. 验证记录（2026-10-19，本机 Windows + JDK 21 + MinGW gcc 15.2）

```text
$ gradle --no-daemon -q compileJava                      -> exit 0
$ gradle --no-daemon cleanTest test                       -> BUILD SUCCESSFUL, 52 tests / 0 failures / 0 skipped
$ gradle --no-daemon test --tests dev.chimera.nativecode.NativeTranspilerTest
                                                          -> 9 tests, 0 failures（gcc 语法冒烟真实执行 6.9s）
```

真实 JNI 端到端冒烟（非 mock）：

1. fixture：`@ChimeraNative public static long add(long,long)`；
2. `java -jar chimera-0.1.0-all.jar --input fixture.jar --output fixture-obf.jar --native-out native`
   → 生成 `fixtures_NativeAdd_add.h/.cpp`，符号 `Java_fixtures_NativeAdd_add`；
3. `gcc -shared -O2 -std=c++17 -I%JAVA_HOME%/include -I.../win32 ...` → DLL；
4. `System.load` 后反射调用 `add(40L,2L)` → `RESULT=42`（符号绑定成功）。

Gradle `chimeraNativeCompile` 真实执行（composite build 消费本插件）：

```text
> Task :chimeraNativeCompile
[chimera-native] gcc -shared -O2 -std=c++17 -I.../include -I.../include/win32     -o .../lib/fixtures_NativeAdd_add.dll .../native/fixtures_NativeAdd_add.cpp
[chimera-native] built .../lib/fixtures_NativeAdd_add.dll
BUILD SUCCESSFUL
$ nm -g --defined-only lib/fixtures_NativeAdd_add.dll | grep Java_fixtures
000000038e761450 T Java_fixtures_NativeAdd_add
```

> 修复记录：旧 mangling 把包分隔符二次转义成 `_5f_`（`Java_demo_5f_Hwid_hash`），JVM 永不查找该符号。
> 本版按 JNI 规范修正（`/`→`_`、原名 `_`→`_1`、`$`→`_00024`），真实 `System.load` + 反射调用验证通过。

## 8. 与既有模块的关系

- M1/M2/M3/M5 的字符串加密、片段化、完整性、VM 逻辑不变；
- `--no-native` 或 `chimera.nativeStubs=false` 时不生成 native stub，也不写模板、不参与编译；
- 生成的原生库仍需由业务方决定 `System.loadLibrary` 的时机与失败策略；
- 本 M4 不做“自动加载/自动回退到 Java 实现”，避免改变现有 `UnsatisfiedLinkError` 行为。

## 9. 生产 remap 检查（Fabric/Forge P0）

`strictFabric=true`（默认）时，`NativeStubTransformer` 与 `VMTransformer` 在改写方法之前调用
`dev.chimera.transform.FabricSafetyGuard.check(node, method, "@ChimeraNative"|"@ChimeraVM")`：

- **方法级**：descriptor、泛型 signature、声明异常、try/catch 类型、`TypeInsn/FieldInsn/MethodInsn`、
  `InvokeDynamicInsn`（descriptor + bsmArgs）、`MultiANewArray`、`Ldc`（Type/String/`Handle`/
  `ConstantDynamic`）、方法注解值（含数组/嵌套）、方法上的 Mixin 回调注解；
- **类级**：类名/父类/接口是否落在重映射命名空间、`@Mixin` 类注解、Mixin 回调注解；
- 命中 `net/minecraft/`、`net/fabricmc/`、`com.mojang/`（含 slash 形式字符串）直接 **BUILD FAILED**，
  错误信息要求把算法剥离成**独立纯逻辑类**（不引用游戏类型、不是 Mixin 类），再由游戏类做取值适配；
- 非生产实验可用 `--no-fabric-check`（Gradle：`chimera.strictFabric = false`），**不可随产品发布**。

必须知道的真实边界（独立审计结论，证据见 `docs/research/fabric-remap-guard.md`）：

1. Fabric **运行时**只在开发环境 remap mod；生产环境 Loader 不 remap mod jar。真正的类名改写发生在
   构建期 Loom `remapJar`（Fabric）与 Forge `reobfJar`（SRG）。因此“运行时把 body 里的 MC 引用改掉”
   这个假设不成立，guard 的价值是**把静默 TODO stub 提前为构建错误**，不是保证生产可加载。
2. mod 自身类名不会被 Loom/Loader 改名；但**覆盖 MC 方法的成员名**会被 tiny-remapper 沿继承链改名，
   Mixin 方法会被合并进目标类。JNI 先查短符号（类+方法，不含描述符），所以真正的断点是
   类/方法身份（Mixin、override、重载、下游改名），不是 descriptor 里的 MC 类型。
3. 本轮已补：Mixin 类/回调、类名/父类/接口重映射、`Handle`/`ConstantDynamic`/try-catch/注解值/
   slash 字符串检查。仍然**不覆盖**：JNI 符号身份（Mixin 合并后的 native 方法、override/重载）、Forge SRG、
   post-remap 终产物可解析性。发布前建议增加：终产物 verifier（final jar 常量池 + `.so` 导出符号与
   `symbols.txt`/nm 比对）、禁止 `@ChimeraNative` 重载、Gradle 强制输入为 `remapJar/reobfJar` 输出。
4. 误报提示：`net/fabricmc/*` 在 1.20.1 intermediary 产物中基本不存在，`com/mojang/*` 只有
   `blaze3d` 少量类；若项目大量使用 Fabric API 稳定类，可按审计建议收敛前缀（在
   `FabricSafetyGuard` 中调整 `REMAPPED_PREFIXES`）。

### 9.1 Gradle 插件与 excludes 语义（本轮修复）

- 插件扩展新增 `vm`/`honeypot`/`entangle`（默认 true），`ChimeraObfuscateTask` 会复制到引擎配置；
  之前插件路径无法关闭这三项，只能用 CLI。
- `ChimeraObfuscateTask` 增加 `@InputFile/@OutputFile/@InputDirectory/@Input` 注解，避免 Gradle
  误判 UP-TO-DATE 而跳过重新混淆；仍有疑问时用 `--rerun-tasks`。
- `nativeCompile` 优先使用 `JAVA_HOME`（回退 daemon `java.home`），并加 `-ffp-contract=off`，
  保证 M4 浮点对拍 bit 级一致。
- **`excludes` 的真实语义**：命中类会被从输出 jar 中**删除**（`ChimeraEngine.isExcluded`），不是
  "跳过变换但保留类"。因此不能用 excludes 保护 Mixin/API 类；要保留的类请不要加入 excludes。

### 9.2 Windows 专版与重载符号（本轮）

- `chimeraNativeCompile` **仅支持 Windows**，只生成 `.dll`；Linux/macOS 交叉编译逻辑已移除，
  非 Windows 直接抛 `GradleException`。输出名不再加 `lib` 前缀。
- 同名重载：`NativeTranspiler` 检测 owner 中同名方法数 >1，生成 JVMS JNI 长符号：
  `Java_<Class>_<method>__<mangled descriptor>`，例如 `add(II)I` → `Java_demo_Overload_add__(II)I`、
  `add(ID)D` → `Java_demo_Overload_add__(ID)D`；`.h/.cpp` 文件名追加 descriptor hash，避免互相覆盖。
- 为什么不用 `_int/_double` 后缀：JVM 自动查找 native 符号时只认 JNI 规范短名/长名；
  自定义 `_int` 会让 `System.loadLibrary` 后调用直接 `UnsatisfiedLinkError`。若坚持自定义符号，
  必须改用 `RegisterNatives` 显式注册；本工程仍走自动绑定，所以使用规范长名。

## 10. v2 代码生成要点

- **声明模型**：局部变量 `jint/jlong/jdouble lv<slot>_<type>`，操作数栈槽
  `s<depth>_<type>`，函数入口统一预声明；分支/循环用标签 + `goto`，合流点类型由 ASM
  `Analyzer<BasicValue> + BasicVerifier` 校验，保证读取的槽位身份一致。
- **Java 语义辅助函数**（生成在 `.h`）：`chimera_idiv/irem/ldiv/lrem`（b==0 与 MIN/-1 保护）、
  `chimera_isar/lsar`（算术右移避免实现定义行为）、`chimera_d2i/d2l`（饱和 + NaN→0）、
  `chimera_dcmpg/dcmpl`（NaN 排序）。
- **int/long 加减乘**用 `(jint)((chimera_u32)a + (chimera_u32)b)` 形式做二进制补码回绕，避免 C++
  有符号溢出 UB；移位量按 Java 掩码（`& 31` / `& 63`）。
- **double 常量**仍只支持有限值（NaN/Infinity → TODO stub，避免非法 C++ 字面量）。
- 生成器不生成异常/栈回溯/对象引用语义；这是 M4 的边界，不是通用 Java→C++ 编译器。
- 真实验证：`NativeTranspilerTest` 对 add/mix/分支/循环 4 个产物跑 gcc `-fsyntax-only`；
  `M4-VERIFY` 记录过真实 JNI 加载调用（`.dll` + `System.load` + 反射调用）。

## 11. M4/M9 分工（A5，2026-10-19）

- **M4 AOT（C++/OpenSSL）**：JNI 入口、错误码处理、OpenSSL 调用、反调试函数、Native 代码段
  自校验（保留调试可见性）。
- **M9 VM**：验签判定逻辑（签名比较、Nonce 绑定校验、SessionHandle 有效性判定）、密钥派生后的
  混合运算。
- **数据交接**：AOT 与 VM 通过受保护的共享状态结构体/寄存器交接，不通过 JNI 暴露中间密钥。
- **当前事实**：`nativeVerifyAuth` 的 Ed25519/X25519/HKDF/AES-GCM 与成败判定仍在 C++ AOT 中，
  **没有 @ChimeraVM 参与**。把判定逻辑移入 VM 是阶段 B7（task-24）；B7 完成前，本文档不得声称
  “判定逻辑在 VM 中”。
