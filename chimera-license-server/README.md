# chimera-license-server

Spring Boot 3.2 / Java 17 授权中心，实现 [docs/AUTH-V2-PROTOCOL.md](../docs/AUTH-V2-PROTOCOL.md) 的 v3 协议 +
KI-28 信封：X25519 临时密钥协商 + HKDF-SHA256 + AES-256-GCM + Ed25519 响应签名（canonical 含
`expires_at/issued_at/resource_ck/sequence/token`，心跳用 `sequence` 原子推进防重放）。

> **本轮变更（KI-28 信封加密，最高优先级）**
> 1. 旧“全局 content_key 下发”废弃：`wrapped_ck` 下发按 `(account_id, hwid)` 派生的
>    **UserContentKey**；MasterKey 永不出网。
> 2. 新增长期 **ResourceKey**（32B，构建期用它加密付费资源），以 `resource_ck` 信封下发：
>    AES-256-GCM(HKDF(UserContentKey, "chimera/resource-wrap/v1"), ResourceKey, aad)；
>    `resource_ck` **参与 activate canonical 签名**。
> 3. 风控：同账号 **5s 内**两个不同 HWID（激活/心跳）→ 异常 HWID 收到签名合法但
>    **UserContentKey 与 ResourceKey 均字节旋转 1 位**的毒化 payload；信封长度/签名正常。
> 4. 阈值/误杀/内存态风险见 [docs/known-issues.md](../docs/known-issues.md) **KI-28**。

## 快速开始

```powershell
# 首次启动生成 data/keys/ed25519.*、content.key(MasterKey)、resource.key(加密的 ResourceKey)
set CHIMERA_SEED_ACCOUNT=demo
set CHIMERA_SEED_PASSWORD=demo1234
$env:GRADLE_USER_HOME='G:\vibecoding\chimare\tools\gradle-home'
G:\vibecoding\chimare\tools\gradle-8.10.2\bin\gradle.bat --no-daemon bootRun
# 或：gradle --no-daemon build && java -jar build/libs/chimera-license-server-0.1.0.jar
```

启动日志（只打印公钥与指纹，绝不打印明文密钥）：

```
license signing public key (base64, bake into client): <base64 32B Ed25519>
master key sha256 fingerprint (never log the key itself): <16 hex>
resource key sha256 fingerprint (build resources must use this key): <16 hex>
```

## 密钥层级与来源

| 密钥 | 用途 | 存放/下发 |
|---|---|---|
| Ed25519 K_sign | 响应签名 | `data/keys/ed25519.pk8` + `ed25519.pub`；公钥烘焙客户端 |
| MasterKey 32B | 派生 UserContentKey；ResourceKey 的 KEK | `CHIMERA_CONTENT_KEY_HEX` → `license.content-key-hex` → `data/keys/content.key`；**永不下发** |
| UserContentKey 32B | 每 (account_id,hwid) 派生，包裹 ResourceKey | 仅以 `wrapped_ck` 下发 |
| ResourceKey 32B | 构建期加密付费资源 | `CHIMERA_RESOURCE_KEY_HEX` → `license.resource-key-hex` → `data/keys/resource.key`（AES-GCM 加密存储）；仅以 `resource_ck` 下发 |

`data/keys/resource.key` 格式：`"CHRK1" || 12B nonce || 48B ciphertext`，KEK =
`HKDF-SHA256(MasterKey, salt=UTF8("chimera/resource-kek/v1"), info=UTF8("resource-key"), 32)`，
权限尽量 600。MasterKey 更换会导致旧文件无法解密（需恢复 MasterKey 或显式配置 ResourceKey）。

### 构建流水线如何拿到同一个 ResourceKey（二选一）

1. **配置下发（推荐）**：构建机与服务端设置同一个 `CHIMERA_RESOURCE_KEY_HEX`（64 hex），
   无需联网、无需暴露端点。
2. **服务端端点（仅构建机）**：设置 `license.build-token` / `CHIMERA_BUILD_TOKEN` 后：
   ```powershell
   curl.exe -s http://127.0.0.1:8080/api/v1/license/resource-key ^
     -H "X-Chimera-Build-Token: <build-token>"
   # 200 {"resource_key":"base64(32B)","fingerprint":"<sha256 hex>"}
   ```
   未配置 token 时端点返回 404；token 错误返回 401。该端点必须只在 HTTPS/内网暴露。

## 接口契约（客户端必须逐字节一致）

### 1) wrapped_ck → UserContentKey

```
info           = BE64(account_id) || UTF8(hwid)      # 8B big-endian + hwid，无分隔符（仅服务端派生）
UserContentKey = HKDF-SHA256(ikm=MasterKey, salt=UTF8("chimera/uck/v1"), info=info, L=32)

shared   = X25519(client_eph_priv, server_ephemeral_pub)
wrapKey  = HKDF-SHA256(ikm=shared, salt=server_nonce_raw, info=UTF8("chimera/wrap/v1"), L=32)
raw      = 12B GCM nonce || AES-256-GCM(wrapKey, nonce, UserContentKey,
             aad=UTF8("chimera-wrap/v1|" + account + "|" + hwid))        # 60B
```

### 2) resource_ck → ResourceKey（KI-28）

```
raw           = Base64.decode(resource_ck)           # 60 bytes
nonce         = raw[0..11]
ciphertext    = raw[12..59]                          # 32B ResourceKey + 16B tag
resource_wrap = HKDF-SHA256(ikm=UserContentKey, salt=32B zeros,
                            info=UTF8("chimera/resource-wrap/v1"), L=32)
ResourceKey   = AES-256-GCM-decrypt(resource_wrap, nonce, ciphertext,
                  aad=UTF8("chimera-resource/v1|" + account + "|" + hwid))
```

客户端用 native handle 内的 UserContentKey 解开 envelope，把 ResourceKey 交给内容/资源解密层；
UserContentKey 不进入业务层。

### 3) 毒化语义

异常 HWID（5s 内同账号不同 HWID）的 activate 响应：

```
delivered UserContentKey = rotate_left(legit UserContentKey, 1)
delivered ResourceKey    = rotate_left(legit ResourceKey, 1)
```

两个信封都用 delivered key 正常加密并签名；客户端能“成功解包”但拿到错误 ResourceKey，内容
解密失败。响应长度（wrapped_ck/resource_ck 各 80 base64 字符）与错误码均不变。

### 4) canonical（activate）

```
{"expires_at":<n>,"issued_at":<n>,"resource_ck":"<b64>","sequence":<n>,
 "server_ephemeral_pub":"<b64>","server_nonce":"<b64>","token":"<b64>","wrapped_ck":"<b64>"}
```

心跳 canonical 不变（2 个数字 + nonce/token）。详见协议文档 §4/§4.1.1。

## HTTP 接口

### POST /api/v1/license/activate

请求：`account` / `password` / `hwid` / `client_ephemeral_pub`。

```powershell
curl.exe -s -X POST http://127.0.0.1:8080/api/v1/license/activate ^
  -H "Content-Type: application/json" ^
  -d "{\"account\":\"demo\",\"password\":\"demo1234\",\"hwid\":\"demo-hwid\",\"client_ephemeral_pub\":\"<base64 32B X25519 pub>\"}"
```

成功 200 字段：`server_nonce` / `server_ephemeral_pub` / `wrapped_ck` / `resource_ck` /
`expires_at` / `sequence` / `issued_at` / `token` / `account` / `server_time` / `signature`。

### POST /api/v1/license/heartbeat

返回新的 `server_nonce`、递增 `sequence`、`issued_at`/`expires_at` 与新签名；旧 sequence 并发/重放
返回 409 `E_REPLAY`。心跳响应不携带 key 载荷（v3 契约）；异常心跳只武装下一次 activate 毒化。

### POST /api/v1/license/v4/activate

v4 端点与 v3 并存，v3 路径/字段/签名规则完全不变。请求：
`v`(必须=4) / `account` / `password` / `hwid` / `client_ephemeral_pub` / `client_nonce`。
成功 200 字段（顺序即 canonical 顺序）：`v` / `account` / `hwid` / `client_ephemeral_pub` /
`client_nonce` / `server_ephemeral_pub` / `server_nonce` / `token` / `sequence`(恒为 1) /
`issued_at` / `expires_at` / `server_time` / `resource_ck`(可为空串) / `signature`。
`resource_ck` 仍按 KI-28 信封生成；v4 响应不包含 `wrapped_ck`（v4 客户端记录/契约中没有该字段）。

### POST /api/v1/license/v4/heartbeat

请求：`v`(4) / `hwid` / `token`(presented) / `client_nonce` / `sequence`(必须等于服务端当前值)。
成功 200 字段：`v` / `hwid` / `client_nonce` / `token`(新 token) / `sequence`(请求+1) /
`server_nonce` / `issued_at` / `expires_at` / `server_time` / `signature`。
旧 token 立即失效且进入 token 历史（永不复用）；过期优先于回拨（410 `E_EXPIRED` 先于
409 `E_CLOCK_ROLLBACK`）；重复 `client_nonce` 返回 409 `E_REPLAY`，sequence 回退返回
409 `E_SEQUENCE`。

#### v4 canonical（二进制，服务端/客户端逐字节一致）

```
field = u32be(UTF8 byte length) || UTF8 bytes
activate-response  = domain "chimera-auth-v4/activate-response", "4", account, hwid,
                     client_ephemeral_pub, client_nonce, server_ephemeral_pub, server_nonce,
                     token, sequence, issued_at, expires_at, server_time, resource_ck
heartbeat-response = domain "chimera-auth-v4/heartbeat-response", "4", hwid, client_nonce,
                     SHA256hex(presented token), token(new), sequence, server_nonce,
                     issued_at, expires_at, server_time
```

实现：`src/main/java/dev/chimera/license/crypto/AuthTranscriptV4.java`（服务端）与客户端
`dev.chimera.auth.AuthTranscriptV4` 使用相同的字段顺序/长度前缀；数字用最小十进制 ASCII。
服务端 v4 状态使用独立表（`auth_v4_sessions` / `auth_v4_nonces` / `auth_v4_sequences` /
`auth_v4_tokens`），不改动 v3 的 `sessions` 表。

### GET /api/v1/license/pubkey

`{"pubkey":"<base64 32B Ed25519>"}`，用于构建期烘焙。

### GET /api/v1/license/resource-key（构建机专用）

需要 `X-Chimera-Build-Token`；返回 `{"resource_key":"<base64 32B>","fingerprint":"<sha256 hex>"}`。
未配置 `license.build-token` 时 404；token 错误 401。**MasterKey 不会出现在任何响应中。**

## 配置（application.yml）

| 配置 | 默认 | 说明 |
|---|---|---|
| `license.session-ttl-seconds` | 86400 | 会话 TTL，心跳续期 |
| `license.max-devices-per-account` | 1 | 1:1 绑定；**>1 才允许多设备**（毒化路径需要 >=2） |
| `license.auto-bind-first-device` | true | 首设备自动绑定 |
| `license.resource-key-hex` | 空 | ResourceKey（64 hex）；空则生成并加密存储 |
| `license.build-token` | 空 | 启用 `GET /resource-key`；空=禁用 |
| `license.risk-control.window-seconds` | 5 | 同账号不同 HWID 判定窗口 |
| `license.risk-control.poison-ttl-seconds` | 300 | 异常 HWID 毒化标记存活时间 |
| `license.rate-limit.max-failures` / `window-seconds` | 5 / 900 | 按账号+IP 的失败锁定 |
| `license.key-dir` | data/keys | 私钥/MasterKey/ResourceKey 文件目录 |

默认 `max-devices-per-account=1` 时第二个 HWID 在绑定阶段就返回 `E_HWID_MISMATCH`，不会产生毒化
payload；多设备部署需显式调大（KI-28）。

## 数据模型与审计

`accounts` / `devices` / `sessions` / `audit_logs`（v3），以及 v4 独立的
`auth_v4_sessions` / `auth_v4_nonces` / `auth_v4_sequences` / `auth_v4_tokens`，见
`src/main/resources/schema.sql`。
风险审计事件：`ACTIVATE_POISONED`、`HEARTBEAT_POISON_ARMED`（只记录 hwid/ip 的 SHA-256）。

## 测试

```powershell
$env:GRADLE_USER_HOME='G:\vibecoding\chimare\tools\gradle-home'
G:\vibecoding\chimare\tools\gradle-8.10.2\bin\gradle.bat --no-daemon clean build
```

覆盖（客户端侧 `TestClientCrypto` 只用 JDK 原语独立实现，不复用服务端工具类）：

- 激活验签 + wrapped_ck 解出 UserContentKey；resource_ck 解出 ResourceKey（== 配置值，≠ MasterKey）。
- 重复激活：UserContentKey/ResourceKey 稳定，envelope nonce 每次不同。
- 5s 窗口内第二 HWID：签名合法、两个信封形态不变；解出的 UserContentKey 与 ResourceKey 均为毒化值。
- 跨机：B 的毒化 ResourceKey 解不开 A 的内容；A 的 wrapped_ck/resource_ck 分别用 B 的 client 私钥/
  UserContentKey 解包失败；跨客户端重放失败。
- ResourceKey 持久化：首次生成、加密落盘（64B 明文不出现）、重启复用、hex 覆盖、损坏文件 fail-fast。
- 心跳异常武装下一次激活毒化；nonce/sequence 轮换与签名校验。
- 错误密码 401 / 换 HWID 403 / 非法 pubkey 400 / 篡改字段验签失败 / 过期 410 / 旧 sequence 409 / 限流 429 /
  build-token 端点鉴权。

## 与混淆器/构建联动

1. 构建机取得 ResourceKey（见上文两种方式），用其加密付费资源。
2. 混淆器需要新增 `--resource-key-hex`（CLI）/ `resourceKeyHex`（Gradle）传入 ResourceKey；
   该改动属于构建模块，本次服务端只提供来源与契约。当前混淆器仍使用 `--key-hex`，请勿把它
   与 MasterKey/ResourceKey 混用。
3. 客户端（native-pipeline）按“接口契约”解 `wrapped_ck` → `resource_ck`，把 ResourceKey 安装到
   内容解密层；不要把 MasterKey 或 UserContentKey 暴露给业务代码。

## 已知限制 / 安全边界

- 风险状态是**单实例内存**：重启丢失、多节点不一致；生产需 Redis/DB。
- 5s/TTL 是启发式：合法快速换机/双开可能被误杀（授权 200 但内容解密失败）。
- ResourceKey 是产品级密钥：一次合法 session 的 dump 仍可能暴露该设备解出的 ResourceKey；
  毒化/短生命周期/VM 化只是提高成本，不能根除。
- MasterKey、Ed25519 私钥与 ResourceKey 文件需 KMS/HSM/严格 ACL；生产必须 HTTPS。
- vectors.json 尚未包含 resource_ck（待 task-16 重新生成）；当前以协议 §4.1.1 与本仓库测试为契约。
- 详见 [docs/known-issues.md](../docs/known-issues.md) KI-28/KI-24/KI-25。
