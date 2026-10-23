# Chimera

给 Minecraft Fabric mod 做**混淆 + 授权 + 反篡改**的工具链。输入一个未保护的 mod jar，输出一个
类体全密文、带授权门禁和完整性校验的产品包，配套一个自托管的授权服务端。

## 它由三部分组成

| 部分 | 作用 |
|---|---|
| `chimera-obfuscator/` | 引擎 + 客户端运行时。类体 AES-GCM 加密、改名、结构加固、indy、native sink、水印 |
| `chimera-license-server/` | 授权服务端（Spring Boot + H2）。激活、心跳、设备绑定、封禁、水印取证 |
| `tools/` | 构建链、交付打包、运维脚本、红队工具 |

## 保护链

```
未保护的 mod jar
   → 类体加密（CHENC1，密钥由 ResourceKey 派生，只在 native 里）
   → native sink（部分方法体下沉成 C++，随 DLL 一起 VMP）
   → 资源清单 + HMAC（改一个字节即拒绝启动）
   → 授权门禁（per-class，烘进类体，判定与处死都在 DLL 内）
   → 水印（每个类体带该账号的加密指纹，可离线追溯）
```

## 构建

```powershell
# 一条龙：引擎 → sink → DLL → VMProtect → 产品包（约 2.5 分钟）
powershell -NoProfile -File tools\rebuild-chain.ps1 -Tag r4i

# 服务端
cd chimera-license-server; gradle --offline --no-daemon bootJar

# 交付包（只有服务端，给客户）
powershell -NoProfile -File tools\refresh-dist.ps1 -ProductJar work\product\PrismHack-sink-r4i.jar

# 完整发布包（服务端 + 产品包）
powershell -NoProfile -File tools\pack-release.ps1 -Tag r4i
```

构建依赖：JDK 21、Gradle 8.10.2（离线）、MSYS2 mingw64、VMProtect。**不要用 `gradlew`**，会联网。

## 测试

```powershell
cd chimera-obfuscator;     gradle --offline --no-daemon test   # 484 tests
cd chimera-license-server; gradle --offline --no-daemon test   # 55 tests
```

真机验证要用授权服务端在线（心跳连续两次失败即终止）：

```powershell
python work\bench\run_mc.py work\product\PrismHack-sink-r4i.jar 200 work\bench\e2e.log "New World"
```

## 仓库约定

- `work/`、`dist*/`、`release-*/`、`*.jar`、`*.zip` 不进库——产物太大；
- **`chimera-license-server/data/`、`**/data*/keys/` 绝不进库**（Ed25519 私钥、ResourceKey）；
- `.ps1` 一律 ASCII：Windows PowerShell 5.1 按 ANSI 读无 BOM 脚本，中文路径会乱码；
- 构建产物必须带唯一 tag（`-Tag r4i`），禁止复用旧名字——历史上 `vmp3` 被复用 6 次，文档里的哈希对不上任何文件。

## 文档

| 文档 | 内容 |
|---|---|
| `docs/GOAL-R4.md` | 本轮目标与最终验收结果 |
| `docs/REDTEAM-ROUNDS-R4-2026-10-23.md` | 两轮红队核查 + 攻击链实测 + 加固方案取舍 |
| `docs/AUDIT-R4-2026-10-22.md` | 源码审计：发现、修复、验证矩阵 |
| `docs/HANDOVER-2026-10-22-SECURITY-B.md` | 技术记录与证据（§0–§19） |
| `docs/MEMORY-INDEX.md` | 全部文档索引 + 运行手册 |

## 已知边界

- **不防 dump**。类最终要以明文进入 JVM，有调试器的人总能抓到。能保证的是：没有 ResourceKey 的
  玩家破解成本很高（实测 8–20 小时未破），以及泄漏可通过水印追溯到账号。
- 自托管模式下**运营方持有 ResourceKey**，因此运营方能解开自己的构建。这是部署模式的必然，
  不是缺陷。
