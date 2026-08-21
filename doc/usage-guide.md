# tlcp-pqc 开发与复现使用指南

> **项目根目录**（下文 `$TLCP`）：`D:\20240429certificate-verification\tlcp-pqc`  
> **OpenSSL**：Tongsuo 8.5（`bin\openssl.exe`），非系统 PATH 上的 openssl  
> **最后验证**：2026-08-21（含 Aigis 三套样证 openssl x509 / verify 实测通过）

---

## 1. 目录结构速览

```
tlcp-pqc/
├── bin/                          # 运行时 + 工具脚本
│   ├── openssl.exe               # Tongsuo CLI（layout 后）
│   ├── libcrypto-3-x64.dll
│   ├── libssl-3-x64.dll
│   ├── Set-TlcpEnv.bat/.ps1      # 导入环境（必用）
│   ├── demo-provider-gen-csr.bat           # 纯 PQC CSR 演示（含重编）
│   ├── demo-provider-gen-composite-csr.bat # 复合 CSR 演示（仅 CLI）
│   ├── verify-chain.ps1          # 样例证验链（-Algo mlkemdsa|aigis）
│   ├── verify-csr-certs2.py      # Python 双重验签（对照用）
│   └── rebuild-*.bat             # 增量重编
├── config/
│   └── openssl-all-providers.cnf # Provider 加载配置
├── providers/
│   ├── pqmagic.dll               # ML-DSA / ML-KEM GEN·签·编解码
│   ├── libml_dsa_sm2_provider.dll# 复合 SPKI 解析
│   ├── cert_verify.dll           # 复合/混合证·CSR 双重验签
│   ├── aigis.dll                 # Aigis-SIG1/Enc-1 证书解析与验签
├── certs/
│   ├── Pure PQC Certificate/
│   │   ├── mlkemdsa/             # 纯 ML-DSA/ML-KEM
│   │   └── aigis/                # 纯 Aigis-SIG1/Enc-1
│   ├── Hybrid Concatenated Certificate/
│   │   ├── mlkemdsa/             # ML-DSA-SM2 串联
│   │   └── aigissm2/             # Aigis‖SM2 串联
│   ├── Hybrid Using Extensions Certificate/
│   │   ├── mlkemdsa/             # SM2 + ML-DSA 扩展
│   │   └── sm2extaigis/          # SM2 + Aigis 扩展
│   ├── _provider_gen/             # 纯 PQC 演示产物
│   └── _provider_gen_composite/   # 复合 CSR 演示产物
├── Tongsuo/                      # Tongsuo 源码（含 -sm2key / Aigis 验链补丁）
├── pqmagic-algorithms-provider/
├── aigis-provider/               # Aigis X.509 provider（SIG1/ENC1）
├── x509-hybrid-spki-provider/
├── x509-hybrid-verify-provider/
├── build-*.bat                   # 全量/增量构建
├── rebuild-aigis-x509-provider.bat # 重建 PQMagic(SIG1/ENC1)+aigis.dll
├── layout-tlcp-pqc.bat           # 拷贝到 bin/providers
└── doc/
    ├── usage-guide.md            # 本文
    ├── csr-provider-flow.md      # 纯 PQC Provider 链路详解
    └── ../certs/Windows查看与验链命令.md
```

---

## 2. 前置依赖

| 组件 | 用途 |
|------|------|
| **Visual Studio 2022 Build Tools**（x64） | nmake / cl |
| **CMake 3.10+** | Provider、PQMagic 构建 |
| **Strawberry Perl** | Tongsuo `Configure` |
| **Python 3**（可选） | `verify-csr-certs2.py`、`gen-csr-certs*.py` |

脚本内默认路径（若本机不同需改 bat 内 `VCVARS` / `CMAKE`）：

- `D:\DevTools\VS2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat`
- `D:\DevTools\Strawberry\c\bin\cmake.exe`

---

## 3. 环境导入（每次新开终端先做）

### 3.1 CMD

```cmd
call D:\20240429certificate-verification\tlcp-pqc\bin\Set-TlcpEnv.bat
```

### 3.2 PowerShell

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
. D:\20240429certificate-verification\tlcp-pqc\bin\Set-TlcpEnv.ps1
```

### 3.3 验证

```cmd
openssl version
openssl list -providers
openssl req -help | findstr sm2key
```

**期望**：

- 版本含 `Tongsuo 8.5.0-dev`
- 4 个 active provider：`default`、`pqmagic`、`ml_dsa_sm2`、`cert_verify`；证书 Aigis 另加载 `aigis`
- `req -help` 中有 `-sm2key`（复合 CSR 必需）

也可在项目根使用包装器（自动设 `OPENSSL_CONF`）：

```cmd
cd /d D:\20240429certificate-verification\tlcp-pqc
openssl.cmd version
```

---

## 4. 编译与布局

### 4.1 首次全量构建（推荐顺序）

```cmd
cd /d D:\20240429certificate-verification\tlcp-pqc

REM 1) PQMagic + 全部 Provider DLL
build-providers.bat

REM 2) Tongsuo（含 libcrypto 补丁与 req -sm2key）
build-tongsuo.bat

REM 3) 拷贝 openssl.exe / DLL / providers 到 bin\
layout-tlcp-pqc.bat
```

`build-providers.bat` 依次构建：PQMagic → pqmagic.dll → ml_dsa_sm2 → cert_verify，最后调用 layout。Aigis 证书 provider 用 `rebuild-aigis-x509-provider.bat`。

`build-tongsuo.bat` 执行 `perl Configure` → `nmake build_libs build_apps` → `nmake install_sw`，安装到 `tongsuo-install\`。

### 4.2 增量重编（改代码后）

| 改了什么 | 脚本 |
|----------|------|
| 仅 `pqmagic-algorithms-provider` | 在 `pqmagic-algorithms-provider\build` 执行 `cmake --build . --config Release`，再 `copy Release\pqmagic.dll ..\..\providers\` |
| 仅 `cert_verify` | `rebuild-cert-verify.bat` |
| 仅 `Tongsuo/crypto/x509` 或 `apps/req.c` | `bin\rebuild-req-sm2key.bat` 或 `build-tongsuo-libs-apps.bat` |
| PQMagic 需可移植重编 | `rebuild-pqmagic-portable.bat` |

**改 `crypto/x509/build.info` 后**须先 `perl Configure ...` 再 nmake（见 `bin\rebuild-libcrypto-incremental.bat`）。

### 4.3 同步到 Electron GUI

```cmd
D:\20240429certificate-verification\certificate-verification-win32-x64\scrpts\layout-app-resources.bat
```

将 `tlcp-pqc\bin\openssl.exe`、DLL、providers、样例证拷贝到 `resources\app\`。GUI 启动时会自动生成 `config\openssl-all-providers.cnf`。

---

## 5. CSR 生成

### 5.1 纯 PQC（ML-DSA-44-SPKI）

**命令行（三步）**：

```cmd
call bin\Set-TlcpEnv.bat

openssl genpkey -algorithm id-ML-DSA-44-SPKI -out certs\_provider_gen\mldsa.key
openssl req -new -key certs\_provider_gen\mldsa.key ^
  -subj "/C=CN/ST=Beijing/O=Demo/CN=provider-gen.demo" ^
  -out certs\_provider_gen\demo.csr
openssl req -in certs\_provider_gen\demo.csr -verify -noout
```

**一键演示**（会先重编 pqmagic + Tongsuo，耗时较长）：

```cmd
bin\demo-provider-gen-csr.bat
```

**GUI**：算法选「ML-DSA-44-SPKI」，填 subj，指定 `.csr` 保存路径 →「生成 CSR」。同目录自动生成同名 `.key`。

### 5.2 复合 CSR（ML-DSA-44-SM2）

双钥各自为标准 PKCS#8，**不**合成单一密钥文件；`req` 通过 **`-sm2key`** 绑定。

**命令行（四步）**：

```cmd
call bin\Set-TlcpEnv.bat
set OUT=certs\_provider_gen_composite

openssl genpkey -algorithm id-ML-DSA-44-SPKI -out %OUT%\demo.mldsa.key
openssl genpkey -algorithm SM2              -out %OUT%\demo.sm2.key
openssl req -new -key %OUT%\demo.mldsa.key -sm2key %OUT%\demo.sm2.key ^
  -subj "/C=CN/ST=Beijing/O=TLCP-PQC/OU=Demo/CN=ProviderGenComposite" ^
  -out %OUT%\demo.csr
openssl req -in %OUT%\demo.csr -verify -noout
```

**一键演示**（仅 CLI，不重编）：

```cmd
bin\demo-provider-gen-composite-csr.bat
```

**期望输出**（验签段）：

```
[openssl-req-verify ML-DSA-44-SM2 复合 CSR 双重验签]
  [1/2] ML-DSA-44-with-SM3: OK
  [2/2] SM2-with-SM3(完整 CRI): OK
Certificate request self-signature verify OK
```

**GUI**：算法选「ML-DSA-44-SM2」，指定 `request.csr` 保存路径 → 自动生成 `<stem>.mldsa.key`、`<stem>.sm2.key`、`<stem>.csr` 并自签验签。

### 5.3 CSR 查看

```cmd
openssl req -in <path>.csr -text -noout
```

### 5.4 规格对照

| 项目 | 纯 PQC | 复合 ML-DSA-44-SM2 |
|------|--------|---------------------|
| SPKI OID | 1.2.156.10197.1.304.1 | 1.2.156.10197.1.508.1 |
| 签名 OID | 1.2.156.10197.1.505.1 | 1.2.156.10197.1.506.1 |
| 密钥 | 1× ML-DSA PKCS#8 | ML-DSA + SM2 各一文件 |
| 验签 | 标准 req -verify | cert_verify 双重验签 |

参考 CSR：`certs\Hybrid Concatenated Certificate\mlkemdsa\csr\用户证书请求.csr`

### 5.5 Python 对照验签（可选）

```cmd
python bin\verify-csr-certs2.py ^
  --openssl bin\openssl.exe ^
  --verifier bin\mldsa_sign_sm3.exe ^
  certs\Hybrid Concatenated Certificate\mlkemdsa\csr\用户证书请求.csr
```

> **注意**：`openssl req -verify` 为权威结果。Python 脚本对**较长 subject** 的 CRI 提取可能与 libcrypto 略有差异；若 Python FAIL 但 `req -verify` OK，以 OpenSSL 为准。

---

## 6. 证书查看与验链

三套样例链结构均为：**root → yunying（中间 CA）→ user_sig / user_enc**。

| 目录 | 类型 | 签名算法 |
|------|------|----------|
| `certs/Pure PQC Certificate/mlkemdsa` | 纯 PQC SPKI | ML-DSA-44-with-SM3 |
| `certs/Hybrid Concatenated Certificate/mlkemdsa` | 复合 SPKI（PQC+SM2 拼接） | ML-DSA-44-SM2-with-SM3 |
| `certs/Hybrid Using Extensions Certificate/mlkemdsa` | SM2 主体 + PQC 扩展 | 外层 SM2 + 内层 ML-DSA（扩展 4.1.8） |
| `certs/Pure PQC Certificate/aigis` | 纯 Aigis SPKI | Aigis-SIG1-with-SM3 |
| `certs/Hybrid Concatenated Certificate/aigissm2` | Aigis‖SM2 串联 | Aigis-SIG1-SM2-with-SM3 |
| `certs/Hybrid Using Extensions Certificate/sm2extaigis` | SM2 主体 + Aigis 扩展 | 外层 SM2 + 内层 Aigis-SIG1 |

加载 `aigis` provider 后可用 `openssl x509 -text` / `openssl verify` 查看与验链（与 mlkemdsa 相同流程）。重建：`rebuild-aigis-x509-provider.bat`。

### 6.1 一键验链

```powershell
# ML-DSA / ML-KEM（默认 -Algo mlkemdsa）
powershell -NoProfile -ExecutionPolicy Bypass -File bin\verify-chain.ps1 -CertSet pure
powershell -NoProfile -ExecutionPolicy Bypass -File bin\verify-chain.ps1 -CertSet concat
powershell -NoProfile -ExecutionPolicy Bypass -File bin\verify-chain.ps1 -CertSet ext

# Aigis SIG1 / Enc-1
powershell -NoProfile -ExecutionPolicy Bypass -File bin\verify-chain.ps1 -Algo aigis -CertSet pure
powershell -NoProfile -ExecutionPolicy Bypass -File bin\verify-chain.ps1 -Algo aigis -CertSet concat
powershell -NoProfile -ExecutionPolicy Bypass -File bin\verify-chain.ps1 -Algo aigis -CertSet ext
```

或一次跑完两类算法各三套：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File bin\verify-chain-all.ps1
# 仅 Aigis：
powershell -NoProfile -ExecutionPolicy Bypass -File bin\verify-chain-all.ps1 -Algo aigis
```

**期望**：每张证最后一行 `xxx.crt: OK`；混合串联/扩展会打印双重验签进度。

### 6.2 手动 openssl verify（以 certs/Hybrid Concatenated Certificate/mlkemdsa 为例）

```cmd
call bin\Set-TlcpEnv.bat

openssl verify -CAfile certs\Hybrid Concatenated Certificate\mlkemdsa\root.crt -untrusted certs\Hybrid Concatenated Certificate\mlkemdsa\yunying.crt certs\Hybrid Concatenated Certificate\mlkemdsa\user_sig.crt
openssl verify -CAfile certs\Hybrid Concatenated Certificate\mlkemdsa\root.crt -untrusted certs\Hybrid Concatenated Certificate\mlkemdsa\yunying.crt certs\Hybrid Concatenated Certificate\mlkemdsa\user_enc.crt
```

### 6.3 查看单张证

```cmd
openssl x509 -in certs\Hybrid Concatenated Certificate\mlkemdsa\user_sig.crt -text -noout
openssl x509 -in certs\Hybrid Concatenated Certificate\mlkemdsa\user_sig.crt -noout -subject -issuer -dates -signature_algorithm
```

PowerShell 脚本：

```powershell
bin\inspect-cert.ps1 -CertPath certs\Hybrid Concatenated Certificate\mlkemdsa\user_sig.crt -Summary
bin\check-cert-view-all.ps1  # 12 张证总验收（解析/ASN.1/链元数据）
bin\verify-chain-all.ps1     # 三套链密码学验签
```

更完整命令集见：`certs\Windows查看与验链命令.md`。

### 6.4 GUI 证书验证

「证书验证」页：填信任锚点（root）、中间证（可选）、待验证证 →「验证证书」。底层即 `openssl verify`，复合/混合证同样走 cert_verify 钩子。

---

## 7. 复现检查清单（2026-07-06 实测）

在 CMD 下执行，**全部应 exit 0 或显示 OK**：

```cmd
cd /d D:\20240429certificate-verification\tlcp-pqc
call bin\Set-TlcpEnv.bat
openssl version
openssl list -providers

bin\demo-provider-gen-composite-csr.bat

openssl req -in certs\Hybrid Concatenated Certificate\mlkemdsa\csr\用户证书请求.csr -verify -noout
openssl req -in certs\_provider_gen\demo.csr -verify -noout
```

PowerShell 验链：

```powershell
powershell -EP Bypass -File bin\verify-chain.ps1 -CertSet pure
powershell -EP Bypass -File bin\verify-chain.ps1 -CertSet concat
powershell -EP Bypass -File bin\verify-chain.ps1 -CertSet ext
```

| 步骤 | 结果 |
|------|------|
| `Set-TlcpEnv` + 5 providers | ✅ |
| `demo-provider-gen-composite-csr.bat` | ✅ |
| `demo-provider-gen-csr.bat`（含重编） | ✅ |
| `verify-chain.ps1` certs/Pure PQC Certificate/mlkemdsa/2/3 | ✅ 全部 OK |
| `req -verify` certs/Hybrid Concatenated Certificate/mlkemdsa 用户 CSR | ✅ |
| `req -verify` _provider_gen demo.csr | ✅ |

---

## 8. 脚本索引

### 8.1 构建 / 布局

| 脚本 | 作用 |
|------|------|
| `build-providers.bat` | 全量构建 PQMagic + 4 个 Provider |
| `build-providers-resume.bat` | Provider 构建断点续编 |
| `build-tongsuo.bat` | 全量 Configure + 编译 + install_sw |
| `build-tongsuo-libs-apps.bat` | 仅 nmake build_libs + build_apps + install |
| `build-tongsuo-resume.bat` | Tongsuo 断点续编 |
| `layout-tlcp-pqc.bat` | 拷贝运行时到 bin/providers |
| `rebuild-cert-verify.bat` | 仅 cert_verify.dll |
| `rebuild-pqmagic-portable.bat` | 可移植 PQMagic 重编 |
| `rebuild-aigis-x509-provider.bat` | aigis.dll（SIG1/ENC1 证书） |
| `bin\rebuild-req-sm2key.bat` | req -sm2key 改动后增量重编 openssl |
| `bin\rebuild-libcrypto-incremental.bat` | x509 补丁后重编 libcrypto |
| `bin\build-mldsa-sign.bat` | 编译 mldsa_sign_sm3.exe |

### 8.2 演示 / 验签

| 脚本 | 作用 |
|------|------|
| `bin\demo-provider-gen-csr.bat` | 纯 PQC：重编 + genpkey + req + verify |
| `bin\demo-provider-gen-composite-csr.bat` | 复合：双 genpkey + req -sm2key + verify |
| `bin\verify-chain.ps1` | 参数 `-CertSet pure|2|3` |
| `bin\verify-chain-all.ps1` | 三套链一次跑完 |
| `bin\verify-csr-certs2.py` | Python 双重验签（对照） |
| `bin\gen-csr-certs1.py` / `gen-csr-certs2.py` | 从 certs/Pure PQC Certificate/mlkemdsa、2 既有材料生成 CSR（历史脚本） |

### 8.3 查看 / 诊断

| 脚本 | 作用 |
|------|------|
| `bin\inspect-cert.ps1` | 单证摘要或全文 |
| `bin\check-cert-view-all.ps1` | 12 张证总验收：解析、ASN.1、issuer/subject、有效期 |
| `bin\verify-chain.ps1` / `verify-chain-all.ps1` | 密码学验链（含双重验签） |

---

## 9. 常见问题

### 9.1 `gen_init: operation not supported`

- 未加载 `pqmagic.dll`：检查 `OPENSSL_CONF`、`OPENSSL_MODULES`
- GUI 与 CLI 不一致：运行 `layout-app-resources.bat` 同步 `openssl.exe`

### 9.2 退出码 `0xC0000135`（找不到 DLL）

- `openssl.exe` 与 `libcrypto-3-x64.dll` 须在同一目录（`bin\` 或 GUI 的 `tongsuo\bin\`）
- Provider DLL 在 `providers\`，通过 `OPENSSL_MODULES` 加载

### 9.3 `req -new` 无 `-sm2key`

- Tongsuo 未重编到含补丁版本：运行 `bin\rebuild-req-sm2key.bat` 并 layout

### 9.4 复合 CSR 验签 FAIL

- 确认 `cert_verify.dll` 已加载（`openssl list -providers`）
- 必须用 **Tongsuo** `bin\openssl.exe`，不能用系统 openssl
- 环境变量 `CERT_VERIFY_VERIFY_INFO=1` 可看到逐步验签日志

### 9.5 修改 Tongsuo 后 makefile 循环提示 “run make again”

- 属正常：连续执行 2～3 次 `nmake build_libs` 直至生成 `libcrypto-3-x64.dll`

---

## 10. 延伸阅读

| 文档 | 内容 |
|------|------|
| [csr-provider-flow.md](./csr-provider-flow.md) | 纯 PQC Provider GEN/Encoder/Signature 链路 |
| [../certs/Windows查看与验链命令.md](../certs/Windows查看与验链命令.md) | 证书查看命令大全 |
| [../Windows证书查看与验链移植方案B.md](../Windows证书查看与验链移植方案B.md) | GUI/Electron 移植设计 |

---

## 11. 最小复现路径（新机器）

```cmd
REM 1. 安装 VS Build Tools + CMake + Strawberry Perl
REM 2. 克隆仓库到 D:\20240429certificate-verification

cd /d D:\20240429certificate-verification\tlcp-pqc
build-providers.bat
build-tongsuo.bat
layout-tlcp-pqc.bat

call bin\Set-TlcpEnv.bat
bin\demo-provider-gen-composite-csr.bat
powershell -EP Bypass -File bin\verify-chain.ps1 -CertSet concat

REM 3. 同步 GUI（可选）
..\certificate-verification-win32-x64\scrpts\layout-app-resources.bat
```

以上步骤通过即表示 **Provider + Tongsuo + 复合 CSR + 样例证验链** 全链路可用。
