# Chimera Obfuscator

Java 字节码混淆/保护引擎，**Gradle 插件 + CLI 双模运行**。面向 Minecraft Fabric 1.20.1+ 客户端 mod 的收费授权保护，也可用于普通 Java jar。

> 这不是"字符串替换"的半成品：M3 会真正抽离方法体、加密成 chunk，运行期用 `MethodHandles.Lookup.defineHiddenClass` + `invokedynamic` 还原执行；M1 的字符串也走 AES-GCM 资源表，不留在常量池。

## 0. 已验证（本机真实执行，非声明）

| 检查 | 结果 |
|---|---|
| `gradlew build` | BUILD SUCCESSFUL，**82 个测试全绿 / 0 skipped**（M9 控制流+对象字段/调用+流式、M4 分支+gcc、Fabric/Mixin 守卫、客户端握手+重放防护+SPKI pin、授权 E2E、nonce/CPU 时序） |
| 授权中心 `chimera-license-server` | `gradle build` BUILD SUCCESSFUL，10 个集成/单元测试全绿（v3 sequence 签名/原子推进/重放防护/验签/ECDH 解包/心跳轮换/换 HWID/过期/篡改/限流） |
| CLI 混淆 samples/demo（本轮） | `classes=6->6, strings=10, fragments=3, native=1, entangled=2, honeypot=3, vm=1, chunks=3` |
| 混淆后运行（带 key） | `label=chimera-demo-secret / check=false / score=81 / bonus=52 / damage=47 / ratio=1.75 / vm=11`，退出码 0 |
| 混淆后运行（无 key） | 不抛异常：静默 poison → 字符串诱饵、int 负数（如 `damage=-2147483601`）、double NaN（付费逻辑拒绝） |
| javap 检查 | `@ChimeraProtected` 方法只剩 `invokedynamic`；字符串只剩 `ldc int id + decryptStr` |
| 篡改 class 后运行 | 不抛异常：selfCheck 毒化 → 诱饵字符串 + 数值污染 |
| Nonce 轮换 | 旧 `sessionStamp` 校验失败 → poison；新 nonce 恢复会话 |
| 时序信道 | 注入 100ms 慢 CPU 时钟 → 静默 poison（无异常） |
| 明文擦除 | bootstrap 后 decrypted byte[] 被 Unsafe 对象相对写入清零，`wipeCount≥1` |
| M2 有 key | `damage=47 / ratio=1.75`，与未混淆完全一致 |
| M2 无 key | `damage≠47 / ratio=NaN / score=-1`，无异常抛出 |
| M4 JNI 冒烟 | 转译 calc(long,long)/mix(int,double) -> gcc DLL -> System.load -> 8 / 8.5 |
| M9 VM（v5） | 27+ fixture 方法虚拟化：控制流、对象字段 GET/PUT、INVOKEVIRTUAL/INVOKESTATIC 桥；**随机 opcode 表 + PC 链式 per-edge 解密 + 寄存器掩码 + 异常化跳转 + 10ms/1024 指令时序探针**；链式状态被篡改 → 直接 poison |
| M8 Native Auth | OpenSSL 3 C++：Ed25519 验签 + X25519 + HKDF + AES-GCM unwrap 全在 native；nativeVerifyAuth 失败/调试器/Frida → 返回 32B 毒密钥，Java 层已无 verifyEd25519/x25519 |
| 全链路反调试 | native：IsDebuggerPresent/CheckRemoteDebuggerPresent/NtQueryInformationProcess/module scan；Java：-javaagent/-Xrunjdwp/Frida 参数 + Frida/JDWP 线程名；runtime 类自哈希 /chimera/runtime.hash；VM 高频时序探针 |
| 业务集成 | @ChimeraPreGameCheck + ChimeraRuntime.preGameCheck()（失败不弹窗/不崩溃，只毒化）；[DTO 示例](../docs/MINECRAFT-DTO-EXAMPLE.md) |
| M5 时序防误杀 | 3 次预热 + 20 次空跑取中位数基线；阈值 5×；单次超时只累加 suspicion，默认 5 次才 poison；检测到 `-javaagent/-Xrunjdwp/Frida` 时阈值降为 1；测试断言单次慢启动不毒化 |
| M2 数值坏死 | 毒化后 int 通过返回点符号翻转保证为负、double/float 为 NaN；新增回归测试断言无异常 |
| M4 Windows 专版 | `chimeraNativeCompile` 仅 Windows/.dll；重载方法生成 JNI 长名 `Java_Class_method__(descriptor)` 与独立 .h/.cpp |
| M4 分支/循环 | `if/else`、`for` 转译为标签+goto，真实 gcc `-fsyntax-only` 通过（add/mix/branch/loop 4 个产物） |
| Fabric 生产守卫 | `@ChimeraNative`/`@ChimeraVM` 方法引用 `net.minecraft.*`/`net.fabricmc.*` → 构建期 BUILD FAILED（含引擎级测试） |
| 授权中心 + 客户端（v3） | Spring Boot 授权中心（X25519+HKDF+AES-GCM+Ed25519）；响应签名含 `sequence/issued_at/token`；心跳原子推进 sequence、旧响应重放 → 客户端 `markPoison`；支持 **SPKI pin**（自签名 TLS）与生产 HTTPS 强制；服务端 key → 混淆内容解密 E2E 通过 |
| Fabric 生产适配 | [docs/FABRIC-PRODUCTION.md](../docs/FABRIC-PRODUCTION.md)：fabric.mod.json + mixins.json + Loom `remapJar` 配置；`@ChimeraVM/@ChimeraNative` 仅限纯逻辑类，Mixin 类/继承 MC 类/重映射包名 → 构建期 BUILD FAILED |
| 实战测试计划 | [docs/RealWorld-Test-Plan.md](../docs/RealWorld-Test-Plan.md)：纯逻辑类挑选、MC 重依赖类拦截验证、M9/M4 纳秒/JMH 基线模板、上线检查清单 |
| Gradle 插件（includeBuild 消费） | `chimeraObfuscate` 成功产出混淆 jar 并可运行 |
| 生成 JNI 模板 | `out/native/demo_Hwid_hash.cpp` |

## 1. 模块映射

| 设计文档模块 | 本工程实现 | 说明 |
|---|---|---|
| M1 字符串/常量加密 | `StringEncryptTransformer` + `ChimeraRuntime.decryptStr` | LDC String → AES-GCM 表 `chimera/strings.dat` |
| M3 方法级碎片化 | `FragmentTransformer` + `ChimeraRuntime.bootstrapChunk` | 方法体 → 单方法 fragment class → 加密 chunk → hidden class |
| M4 全自动 JNIC | `NativeTranspiler` + `NativeTemplateWriter` + `ChimeraNativeCompileTask` + `FabricSafetyGuard` | 直线/分支/循环字节码 -> C++ body；生成 .h/.cpp；Gradle 自动 gcc 编译；Fabric 生产 remap 构建期拦截 |
| M9 不落地 VM | `VmCompiler` + `VMTransformer` + `ChimeraVmRuntime` | @ChimeraVM 方法 -> 多态 VM 指令 -> 逐边链式密文 + HMAC -> 异常化解释器（掩码 locals/时序探针）；原 Java 字节码不进类文件 |
| M8 Native Auth | `src/main/native/chimera_auth.cpp` + `ChimeraRuntime.nativeVerifyAuth` | OpenSSL Ed25519/X25519/AES-GCM 验签解包；反调试；失败返回毒密钥；预编译 DLL 在 `native/windows-x64/` |
| 授权中心（模块三） | `chimera-license-server/` | Spring Boot 3.2 + H2：activate/heartbeat/pubkey，X25519+HKDF+AES-GCM 包裹产品级 content_key，Ed25519 签名，设备绑定/限流 |
| 客户端握手（模块四） | `ChimeraRuntime.authenticate/heartbeatNow` | 读 `/chimera/auth.dat`，验签 → ECDH 解包 → `setContentKey(byte[])` + `updateServerNonce(byte[16])`，失败静默 poison |
| M5 完整性 | `ManifestBuilder` + `ChimeraRuntime.selfCheck` | 类 SHA-256 清单 + HMAC |
| M6 密钥集成 | `Crypto.hkdf` + `TransformContext.deriveItemKey` | content_key → kek → 每项子密钥 |
| M2 逻辑纠缠 | `EntangleTransformer` + `ChimeraRuntime` 掩码 / nonce / CPU 时序 | 零掩码：有 key 语义等价；无 key 数值污染。含 Task1 nonce 会话戳与 Task2 CPU 时序信道 + 明文擦除 |

## 2. 目录结构

```
chimera-obfuscator/
├── build.gradle                      # shadow / java-gradle-plugin / application
├── settings.gradle
├── gradle.properties
├── gradlew / gradlew.bat / gradle/wrapper/
├── README.md
├── scripts/run-demo.ps1
├── scripts/run-demo.sh
├── src/main/java/dev/chimera/
│   ├── annotations/{ChimeraProtected,ChimeraEntangle,ChimeraNative}.java
│   ├── cli/Main.java
│   ├── gradle/{ChimeraPlugin,ChimeraExtension,ChimeraObfuscateTask}.java
│   ├── core/{ChimeraConfig,ChimeraEngine,ChimeraClassWriter,ClassPool,TransformContext,Transformer,ResourceSink,NativeTemplate,NativeTemplateWriter,Stats}.java
│   ├── crypto/Crypto.java
│   ├── transform/{StringEncryptTransformer,EntangleTransformer,FragmentTransformer,NativeStubTransformer}.java
│   ├── integrity/ManifestBuilder.java
│   ├── nativecode/NativeTranspiler.java
│   ├── vm/{VmOpcode,VmCompiler}.java
│   └── runtime/{ChimeraRuntime,ChimeraVmRuntime}.java
├── src/test/java/
│   ├── dev/chimera/EndToEndTest.java
│   ├── dev/chimera/crypto/CryptoTest.java
│   ├── dev/chimera/core/ClassPoolTest.java
│   ├── dev/chimera/transform/StringEncryptTransformerTest.java
│   ├── dev/chimera/integrity/ManifestBuilderTest.java
│   └── fixtures/{Lic,Bonus,Hwid,Entangled}.java
└── samples/demo/
    ├── build.gradle
    └── src/main/java/demo/{Main,License,Bonus,Hwid}.java
```

## 3. 构建与运行

### 3.1 环境

- JDK 17+（本工程用 JDK 21 编译，`--release 17`；hidden class 目标 classfile ≥55）
- Gradle 8.10（wrapper 已带）
- 可选：MinGW/GCC（编译 JNI 模板）

### 3.2 一键演示

```powershell
.\scripts\run-demo.ps1
```

手动：

```powershell
.\gradlew.bat clean build :samples:demo:jar
java -jar build\libs\chimera-0.1.0-all.jar --input samples\demo\build\libs\demo.jar --output out\demo-obf.jar --key-pass demo-key-123 --native-out out\native
$env:CHIMERA_CONTENT_KEY='demo-key-123'
java -jar out\demo-obf.jar
```

### 3.3 验证保护效果

```powershell
javap -p -c -cp out\demo-obf.jar demo.License
jar tf out\demo-obf.jar | findstr chimera
java -jar out\demo-obf.jar
```

## 4. CLI 参数

```
--input, -i <jar>          输入 jar
--output, -o <jar>         输出 jar
--native-out <dir>         生成 JNI C++ 模板目录
--key-hex <hex>            content key（hex，来自授权下发）
--key-pass <pass>          content key（口令，SHA-256 派生）
--exclude <prefix>         跳过类/包前缀（可重复）
--no-strings               关闭 M1
--no-fragments             关闭 M3
--no-native                关闭 M4
--no-entangle              关闭 M2 逻辑纠缠
--no-honeypot             关闭 Task4 语义污染分支
--no-vm                  关闭 M9 @ChimeraVM 虚拟化
--no-integrity             关闭 M5（运行期跳过自检）
--verbose, -v / --help, -h
```

## 5. Gradle 插件

开发期用 includeBuild：

```groovy
// settings.gradle
pluginManagement { includeBuild("../chimera-obfuscator") }

// build.gradle
plugins {
    id 'java'
    id 'dev.chimera'
}

chimera {
    inputJar = tasks.named('jar').get().archiveFile.get().asFile
    outputJar = layout.buildDirectory.file('libs/app-obf.jar').get().asFile
    contentKey = 'demo-key-123'          // 生产环境应来自授权服务端
    nativeOutDir = layout.buildDirectory.dir('native').get().asFile
    encryptStrings = true
    fragmentMethods = true
    nativeStubs = true
    integrityManifest = true
    excludes = ['com/example/api']
}

tasks.named('chimeraObfuscate') { dependsOn tasks.named('jar') }
```

运行：`gradlew.bat chimeraObfuscate`

## 6. 注解

### 6.1 `@ChimeraProtected`

构建期把方法体抽成 `<Owner>$chimera$<id>` 单方法类，加密为 `chimera/chunks/chunk_<id>.bin`；原方法替换为 `invokedynamic`。运行期首次调用：

```
decrypt(chunk) -> caller.defineHiddenClass(bytes, true, NESTMATE)
               -> findStatic("run", callSiteType) -> ConstantCallSite
```

跳过（保留原样）：构造器/`<clinit>`、`synchronized`、`native/abstract`、含外部 `super.xxx()` 调用的方法。

限制：同包、hidden class 不能被其他类按名引用、不能被 Mixin 注入。

### 6.2 `@ChimeraNative`

构建期替换为 native 方法，并生成 C++ 模板（签名 + TODO 函数体）：

```powershell
java -jar build\libs\chimera-0.1.0-all.jar --input demo.jar --output demo-obf.jar --key-pass demo --native-out native
gcc -shared -I "%JAVA_HOME%\include" -I "%JAVA_HOME%\include\win32" -o chimera_native.dll native\demo_Hwid_hash.cpp
```

业务代码里 `System.loadLibrary("chimera_native")`（samples/demo 已演示，缺库时优雅降级）。

### 6.3 `@ChimeraEntangle`（M2 逻辑纠缠）

标记"数值域"方法（伤害、金币、坐标、比例）。构建期在方法入口取 4 个掩码，并在整数/长整数/浮点运算与返回处混入：

- 有合法 key：掩码 = 0（XOR 中性）、1.0（乘法中性）→ **语义逐位等价**；
- key 缺失/解密失败/完整性失败：掩码 = 非零毒值、NaN → 结果变成负数/溢出/NaN，**不抛任何授权异常**。

示例：

```java
public final class Damage {
    @ChimeraEntangle
    public static int hit(int attack, int defense) {
        return attack * 7 - defense * 3 + 42;   // 无 key 时被毒化成负数/异常值
    }

    @ChimeraEntangle
    public static double ratio(int a, int b) {
        return (double) (a + b) / (b + 1) + 0.5d; // 无 key 时 NaN
    }
}
```

运行期对应 API（`ChimeraRuntime`）：

```java
public static long entanglementMask(); // 0 或毒值
public static int  intMask();          // (int) mask
public static long longMask();
public static double doubleMask();     // 1.0 或 NaN
public static float  floatMask();
public static long dynamicKey();       // 有效 key 或毒 key（给自定义公式绑定用）
public static boolean isKeyHealthy();  // 仅诊断，不要用它做功能开关
```

注意：毒化后的值若被用作数组下标/除数，仍可能引发下游 JDK 异常；请只标注纯数值域方法，不要标注控制流/索引/资源路径逻辑。

#### 6.3.1 动态挑战码（Task 1）

运行期在登录/心跳时调用：

```java
ChimeraRuntime.updateServerNonce(serverNonceFromLicense);
```

- 会话密钥 = HKDF(content_key, salt=nonce, info="chimera/session/v1")
- `sessionStamp()` = SHA-256(sessionKey, nonce, "session-stamp/v1") 的前 64 位，按 nonce 缓存
- `@ChimeraEntangle` 方法入口保存 stamp，返回前调用 `verifySessionStamp(stamp)`
- 攻击者把旧 stamp 写死后，服务端下一次下发新 nonce → 校验失败 → 静默 poison；新 nonce 到达时 `updateServerNonce` 恢复会话
- 毒化掩码本身也参与 `sessionKey ^ nonce ^ (nanoTime & 0xFF)`，因此每次轮换后毒值都不同，不能观察一次就复用

> 设计说明：合法状态下 XOR 掩码必须是 0（乘法必须是 1.0）才能保证语义完全等价；nonce/时间因子作用在**毒化值与会话戳**上，而不是合法中性值上。否则正常玩家的伤害也会被改动。

#### 6.3.2 时序信道 + 用完即焚（Task 2）

```java
long started = now();                 // 可注入测试时钟
byte[] classBytes = ... decrypt ...;
Lookup hidden = caller.defineHiddenClass(classBytes, true, NESTMATE);
// finally:
wipe(classBytes); wipeCount++;
long elapsed = now() - started;
// now() 默认取 ManagementFactory.getThreadMXBean().getCurrentThreadCpuTime()
// 阈值 = max(1ms, 基准 CPU 时间 * 50)；GC/IO 等待不计入 CPU 时间
if (elapsed > thresholdNanos()) markPoison();
```

- `wipe` 优先用 `sun.misc.Unsafe.putByte(Object, long, byte)`（对象相对地址，GC 安全；不是绝对地址版本），并 `storeFence()`；失败回退 `VarHandle` + `Arrays.fill`。
- 注意：`defineHiddenClass` 已把 classfile 复制进 JVM 内部结构，擦除只消除**应用层明文窗口**，不能抹掉 JVM 内部副本。
- 时序信道用**线程 CPU 时间**（ThreadMXBean）而不是 nanoTime：GC/safepoint/IO 等待不计入，避免误杀；阈值默认 baseline*50，baseline 由正常 bootstrap 的 EMA 维护，可用 -Dchimera.timing.cpuRatio 调整。


### 6.4 `@ChimeraNative` 返回类型约束（Task 3）

构建期强制：返回 `boolean/int/short/byte/char/void` 的 native 方法**直接构建失败**，必须是 `double/float/long/业务对象`。

```text
@ChimeraNative double calculatedDamage(...);   // OK
@ChimeraNative String hwidHash(...);           // OK
@ChimeraNative boolean checkLicense(...);      // BUILD FAILED
@ChimeraNative int isValid(...);               // BUILD FAILED
```

原因：`mov eax, 1; ret` 这类 patch 只能骗过布尔/判断型返回值；返回 double 的业务值被改成 1 后，伤害/坐标直接失真。配合 M2 的毒值 CallSite，破解者无法用一个常量绕过。

### 6.5 语义污染（Task 4）

- `FragmentTransformer` 只对**小方法/低频 chunk** 注入蜜罐分支：`if (ChimeraRuntime.honeypot()) { ... }`，honeypot 永远 false；
- 蜜罐分支内放 `frida_bypass` / `bypass_auth` / `license_valid` / `isAdmin` 等假字符串，诱导 AI/人工误判；
- 注入前检查估算方法字节数（默认上限 8192）与指令数（默认 200），并在写出 fragment 时捕获 `MethodTooLargeException` 给出 64KB 明确错误；
- `ChimeraRuntime` 内保留一组 decoy token，供静态分析/AI 读取。

> 该模块是"上下文污染"成本项，不是安全边界；不要用它替代 M2/M3 的真实保护。

### 6.6 全自动 JNIC（M4）

```powershell
java -jar chimera-all.jar --input mod.jar --output mod-obf.jar --key-pass demo --native-out build/native
# 生成 build/native/<Class>_<method>.h 与 .cpp
# 基础运算（int/long/double 直线代码）会转译为真实 C++ body；否则保留 TODO stub
gcc -shared -O2 -I"%JAVA_HOME%\include" -I"%JAVA_HOME%\include\win32" -o build/native-lib/demo_Hwid_hash.dll build/native/demo_Hwid_hash.cpp
```

Gradle 插件新增任务：`gradlew chimeraNativeCompile`（读取 `chimera.nativeOutDir`/`nativeLibDir`，自动找 JDK 头文件并编译）。详见 [docs/M4-JNIC.md](docs/M4-JNIC.md)。

### 6.7 不落地 VM（M9）

```java
public final class VmMath {
    @ChimeraVM
    public static int addMul(int a, int b) {
        return a + b * 3;
    }
}
```

构建期把方法体编译成 VM 指令流（PUSH/LOAD/STORE/I·L·D 运算/RET），AES-GCM 加密为 `chimera/vm/vm_<id>.bin`；原方法只剩：

`ChimeraVmRuntime.execute(id, new Object[]{...})`

运行期解释器解密并执行；无 key/篡改/除零时返回毒值（-1/-1L/NaN）而不是抛异常。**原 Java 字节码不再出现在 class 文件里**。详见 [docs/M9-VM.md](../docs/M9-VM.md)。

## 7. 密钥链（M6）

```
content_key（授权服务端下发 / 测试口令）
  | SHA-256（口令）或直接 bytes（hex）
  v keyMaterial
  | HKDF-SHA256(salt="chimera-kek-v1", info="kek")
  v kek（构建期与运行期各自计算，永不落盘）
  | HKDF-SHA256(salt=envSalt, info="chimera/v1/<kind>/<id>")
  v 每字符串/每 chunk 独立 AES-256-GCM key
```

运行期注入：

```java
// 登录/授权成功后（AUTH-PROTOCOL 的 license response）
ChimeraRuntime.setContentKey(licenseContentKey);
// 或 -Dchimera.contentKey=<hex|pass>，或环境变量 CHIMERA_CONTENT_KEY
```

`envSalt` 写在 `chimera/env.dat`，攻击者可读但没有 content_key 无法派生。生产环境请接 [docs/AUTH-PROTOCOL.md](../docs/AUTH-PROTOCOL.md) 的服务端签名/包裹流程，不要硬编码。

## 8. 资源格式（jar 内）

| 路径 | 格式 |
|---|---|
| `chimera/env.dat` | `CHV1` + version + saltLen + salt + buildIdLen + buildId |
| `chimera/strings.dat` | `CHS1` + version + count + 重复[id, nonceLen, nonce(12), ctLen, ct] |
| `chimera/chunks/chunk_<id>.bin` | `CHK1` + id + nonceLen + nonce(12) + ctLen + ct |
| `chimera/manifest.dat` | `CHM1` + 每行 `<sha256hex>  <path>` |
| `chimera/manifest.mac` | HMAC-SHA256(kek, manifest) |

AES-GCM AAD 绑定 `"str/<id>"` / `"chunk/<id>"`，防止密文互换/重放。

## 9. 运行期行为

- `decryptStr(id)`：先 `selfCheck()`，再懒加载字符串表并缓存。
- `bootstrapChunk`：`selfCheck()` → 解密 → `defineHiddenClass` → `ConstantCallSite`；异常包 `BootstrapMethodError`。
- `selfCheck()`：HMAC 校验 manifest + 逐类 SHA-256；成功缓存，失败每次抛。无 manifest（`--no-integrity`）时自动跳过。
- 密钥三级来源：`setContentKey` → 系统属性 → 环境变量；缺失时抛 `content key missing`。

## 10. 完整性（M5）边界

- 清单用 key 派生 HMAC，攻击者无 content_key 无法伪造；
- 但客户端可 patch 掉 `selfCheck`，因此是"提高成本 + 让盗版可识别"，不是不可绕过；
- 真正的边界仍是服务端授权（见 AUTH-PROTOCOL）。

## 11. 测试

```powershell
.\gradlew.bat test
```

52 个测试：
- CryptoTest：RFC 5869 HKDF 官方向量、RFC 4231 HMAC、AES-GCM 篡改异常；
- ClassPoolTest：继承/接口/数组/未知类回退，自定义 ClassLoader 真实触发 verifier；
- StringEncryptTransformerTest：替换/去重/switch 跳过/开关；
- ManifestBuilderTest：排序与 HMAC；
- EndToEndTest：字符串/hidden class/native；篡改后降级；M2 有 key 精确 / 无 key 污染；**nonce 轮换使旧 stamp 失效**；**100ms 慢 CPU 时钟触发 poison 且擦除明文**。
- NativeTranspilerTest（9）：转译 + 真实 gcc 语法冒烟；NativeConstraintTest（4）：Task3 返回类型拒绝；VmTest（5）：M9 虚拟化/解释器/无 key 降级。

## 12. 已知限制

- 不重命名类/方法/字段（M3 是方法体碎片化，不是 rename）。
- `@ChimeraProtected` 跳过 super 调用方法与 `synchronized` 方法（保留原方法体）。
- 字符串 switch 所在方法整体跳过加密（语义安全优先）。
- hidden class 目标 classfile ≥55（Java 11+）；Fabric 1.20.1（Java 17）可用；Java 8 输入会在运行期失败。
- fragment 需同包；跨包/自定义 ClassLoader/被其他类按名引用不支持。
- Fabric 生产 remap：引用 Minecraft 类型的 fragment 需 M0.5 实测/策略 B；MVP 建议只保护不引用 MC 类型的纯逻辑。
- 入口类改名需同步重写 `fabric.mod.json`（本工程未内置，见 T26）。
- 不处理多版本 jar（`META-INF/versions/**` 跳过）与 jar 签名（签名文件会被移除）。
- native 模板需人工实现；未实现时调用抛 `UnsatisfiedLinkError`。

## 13. 故障排查

| 现象 | 原因 / 处理 |
|---|---|
| `VerifyError` | 目标类版本/帧；fragment 含不可迁移结构；用 `--no-fragments` 二分 |
| `content key missing` | 未注入 key；检查 `-Dchimera.contentKey` / `setContentKey` |
| `integrity check failed` | jar 被修改；重新混淆或 `--no-integrity` |
| `NoClassDefFoundError`（Fabric 生产） | fragment 引用 MC 类型未被 remap；改用不引用 MC 的逻辑 |
| `UnsatisfiedLinkError` | native 模板未实现/未 loadLibrary |
| 字符串乱码/解密失败 | 构建期与运行期 key 不一致 |

## 14. 与整体路线图

本工程 = M1 + M2 + M3 + M4 + M5 + M6 + M9 的可运行实现（M9 为基础子集）；Fabric 生产 remap（M0.5）、入口 JSON 重写（T26）、服务端授权联调（T29—T32）见 [docs/DEVELOPMENT-PATH.md](../docs/DEVELOPMENT-PATH.md) 与 [docs/AUTH-PROTOCOL.md](../docs/AUTH-PROTOCOL.md)。

## 15. 使用声明

仅用于你有权保护的软件/模组。客户端混淆不改变"客户端可被修改"的事实；授权与反盗版应结合服务端校验与法律条款。
