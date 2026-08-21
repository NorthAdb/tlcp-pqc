# certs/Pure PQC Certificate/mlkemdsa、2、3 证书查看与验链命令（Windows）

> 适用环境：Windows 10/11 + Tongsuo（`tlcp-pqc` 已构建完成）  
> 项目根目录：`D:\20240429certificate-verification\tlcp-pqc`  
> OpenSSL 可执行文件：`bin\openssl.exe`（Tongsuo 8.5）

---

## 1. 三套证书说明

每套目录均包含 4 张证书，链结构为：**root → yunying（中间 CA）→ user_sig / user_enc（叶子证）**。

| 目录 | 类型 | 公钥（签名类） | 公钥（加密类 user_enc） | 签名算法 |
|------|------|----------------|-------------------------|----------|
| **certs/Pure PQC Certificate/mlkemdsa** | 纯 PQC 标准证 | ML-DSA-44-SPKI | ML-KEM-512-SPKI | ML-DSA-44-with-SM3 |
| **certs/Hybrid Concatenated Certificate/mlkemdsa** | 复合 SPKI 证 | ML-DSA-44-SM2 | ML-KEM-512-SM2 | ML-DSA-44-SM2-with-SM3 |
| **certs/Hybrid Using Extensions Certificate/mlkemdsa** | 国密混合证 | sm2 + 扩展 4.1.6（ML-DSA-44-SPKI） | sm2 + 扩展 4.1.6（ML-KEM-512-SPKI） | 外层 SM2-with-SM3 + 内层 ML-DSA（4.1.8） |

文件列表（每套相同）：

```
certs/{1,2,3}/
  root.crt
  yunying.crt
  user_sig.crt
  user_enc.crt
```

---

## 2. 导入环境（每次新开终端先执行）

验签与查看 PQC 公钥需要加载 provider 及 DLL 路径。

### 2.1 PowerShell（推荐）

若提示「禁止运行脚本」，先临时放开当前窗口的执行策略：

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

导入环境：

```powershell
. D:\20240429certificate-verification\tlcp-pqc\bin\Set-TlcpEnv.ps1
```

成功时显示：`TLCP environment loaded: D:\20240429certificate-verification\tlcp-pqc`

### 2.2 cmd

```cmd
call D:\20240429certificate-verification\tlcp-pqc\bin\Set-TlcpEnv.bat
```

### 2.3 验证环境

```powershell
openssl version
openssl list -providers
```

应看到 4 个 active provider：`default`、`pqmagic`、`ml_dsa_sm2`、`cert_verify`。

---

## 3. 查看证书

### 3.1 一键总验收（12 张）

解析、ASN.1、issuer/subject 链关系、有效期（不做密码学验签）：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File D:\20240429certificate-verification\tlcp-pqc\bin\check-cert-view-all.ps1
```

密码学验链请用 `bin\verify-chain-all.ps1`。

### 3.2 查看单张证书（完整文本）

将 `{N}` 换为 `1`、`2` 或 `3`，`{name}` 换为 `root`、`yunying`、`user_sig`、`user_enc`：

```powershell
openssl x509 -in D:\20240429certificate-verification\tlcp-pqc\certs\{N}\{name}.crt -text -noout
```

**示例 — 查看 certs/Hybrid Concatenated Certificate/mlkemdsa 的 user_enc：**

```powershell
openssl x509 -in D:\20240429certificate-verification\tlcp-pqc\certs\Hybrid Concatenated Certificate\mlkemdsa\user_enc.crt -text -noout
```

### 3.3 查看摘要（主题、颁发者、有效期、算法）

```powershell
openssl x509 -in D:\20240429certificate-verification\tlcp-pqc\certs\{N}\{name}.crt -noout -subject -issuer -dates -serial
openssl x509 -in D:\20240429certificate-verification\tlcp-pqc\certs\{N}\{name}.crt -noout -signature_algorithm
```

或使用项目脚本：

```powershell
D:\20240429certificate-verification\tlcp-pqc\bin\inspect-cert.ps1 `
  -CertPath D:\20240429certificate-verification\tlcp-pqc\certs\Hybrid Concatenated Certificate\mlkemdsa\user_enc.crt -Summary
```

### 3.4 按套别批量查看（复制即用）

**certs/Pure PQC Certificate/mlkemdsa：**

```powershell
foreach ($n in @("root","yunying","user_sig","user_enc")) {
  Write-Host "`n=== certs/Pure PQC Certificate/mlkemdsa/$n.crt ===" -ForegroundColor Cyan
  openssl x509 -in "D:\20240429certificate-verification\tlcp-pqc\certs\Pure PQC Certificate\mlkemdsa\$n.crt" -noout -subject -issuer -dates
  openssl x509 -in "D:\20240429certificate-verification\tlcp-pqc\certs\Pure PQC Certificate\mlkemdsa\$n.crt" -noout -text | Select-String "Signature Algorithm|Public Key Algorithm"
}
```

**certs/Hybrid Concatenated Certificate/mlkemdsa：**

```powershell
foreach ($n in @("root","yunying","user_sig","user_enc")) {
  Write-Host "`n=== certs/Hybrid Concatenated Certificate/mlkemdsa/$n.crt ===" -ForegroundColor Cyan
  openssl x509 -in "D:\20240429certificate-verification\tlcp-pqc\certs\Hybrid Concatenated Certificate\mlkemdsa\$n.crt" -noout -subject -issuer -dates
  openssl x509 -in "D:\20240429certificate-verification\tlcp-pqc\certs\Hybrid Concatenated Certificate\mlkemdsa\$n.crt" -noout -text | Select-String "Signature Algorithm|Public Key Algorithm"
}
```

**certs/Hybrid Using Extensions Certificate/mlkemdsa：**

```powershell
foreach ($n in @("root","yunying","user_sig","user_enc")) {
  Write-Host "`n=== certs/Hybrid Using Extensions Certificate/mlkemdsa/$n.crt ===" -ForegroundColor Cyan
  openssl x509 -in "D:\20240429certificate-verification\tlcp-pqc\certs\Hybrid Using Extensions Certificate\mlkemdsa\$n.crt" -noout -subject -issuer -dates
  openssl x509 -in "D:\20240429certificate-verification\tlcp-pqc\certs\Hybrid Using Extensions Certificate\mlkemdsa\$n.crt" -noout -text | Select-String "Signature Algorithm|Public Key Algorithm|PQC-"
}
```

---

## 4. 验证证书链

### 4.1 一键验证三套（推荐）

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File D:\20240429certificate-verification\tlcp-pqc\bin\verify-chain-all.ps1
```

### 4.2 按套别验证（脚本）

```powershell
# certs/Pure PQC Certificate/mlkemdsa — 纯 PQC
D:\20240429certificate-verification\tlcp-pqc\bin\verify-chain.ps1 -CertSet pure

# certs/Hybrid Concatenated Certificate/mlkemdsa — 复合 SPKI（双重验签 ML-DSA + SM2）
D:\20240429certificate-verification\tlcp-pqc\bin\verify-chain.ps1 -CertSet concat

# certs/Hybrid Using Extensions Certificate/mlkemdsa — 国密混合证（外层 SM2 + 内层 ML-DSA）
D:\20240429certificate-verification\tlcp-pqc\bin\verify-chain.ps1 -CertSet ext
```

只验证某一张叶子证：

```powershell
D:\20240429certificate-verification\tlcp-pqc\bin\verify-chain.ps1 -CertSet concat -Leaf user_enc
```

### 4.3 原生 openssl verify 命令

通用格式：

```powershell
openssl verify -CAfile D:\20240429certificate-verification\tlcp-pqc\certs\{N}\root.crt `
  -untrusted D:\20240429certificate-verification\tlcp-pqc\certs\{N}\yunying.crt `
  D:\20240429certificate-verification\tlcp-pqc\certs\{N}\{leaf}.crt
```

**certs/Pure PQC Certificate/mlkemdsa — 验证全部叶子证：**

```powershell
$R = "D:\20240429certificate-verification\tlcp-pqc\certs\Pure PQC Certificate\mlkemdsa"
openssl verify -CAfile "$R\root.crt" -untrusted "$R\yunying.crt" "$R\yunying.crt"
openssl verify -CAfile "$R\root.crt" -untrusted "$R\yunying.crt" "$R\user_sig.crt"
openssl verify -CAfile "$R\root.crt" -untrusted "$R\yunying.crt" "$R\user_enc.crt"
```

**certs/Hybrid Concatenated Certificate/mlkemdsa：**

```powershell
$R = "D:\20240429certificate-verification\tlcp-pqc\certs\Hybrid Concatenated Certificate\mlkemdsa"
openssl verify -CAfile "$R\root.crt" -untrusted "$R\yunying.crt" "$R\yunying.crt"
openssl verify -CAfile "$R\root.crt" -untrusted "$R\yunying.crt" "$R\user_sig.crt"
openssl verify -CAfile "$R\root.crt" -untrusted "$R\yunying.crt" "$R\user_enc.crt"
```

**certs/Hybrid Using Extensions Certificate/mlkemdsa：**

```powershell
$R = "D:\20240429certificate-verification\tlcp-pqc\certs\Hybrid Using Extensions Certificate\mlkemdsa"
openssl verify -CAfile "$R\root.crt" -untrusted "$R\yunying.crt" "$R\yunying.crt"
openssl verify -CAfile "$R\root.crt" -untrusted "$R\yunying.crt" "$R\user_sig.crt"
openssl verify -CAfile "$R\root.crt" -untrusted "$R\yunying.crt" "$R\user_enc.crt"
```

**根证自签（可选）：**

```powershell
openssl verify -CAfile D:\20240429certificate-verification\tlcp-pqc\certs\Pure PQC Certificate\mlkemdsa\root.crt D:\20240429certificate-verification\tlcp-pqc\certs\Pure PQC Certificate\mlkemdsa\root.crt
```

### 4.4 预期成功输出

每张证通过时应出现：

```
...\<name>.crt: OK
```

- **certs/Hybrid Concatenated Certificate/mlkemdsa**：额外打印 `[openssl-verify ML-DSA-44-SM2 复合证 双重验签]`，`[1/2] ML-DSA-44-with-SM3: OK` 与 `[2/2] SM2-with-SM3: OK`
- **certs/Hybrid Using Extensions Certificate/mlkemdsa**：额外打印 `[openssl-verify 国密混合证 双重验签]`，外层 SM2 OK、内层 ML-DSA 扩展 4.1.8 OK

---

## 5. 完整操作示例（从零开始）

在 PowerShell 中依次执行：

```powershell
# 1. 进入项目（可选）
cd D:\20240429certificate-verification\tlcp-pqc

# 2. 导入环境
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
. .\bin\Set-TlcpEnv.ps1

# 3. 确认 Tongsuo 与 provider
openssl version
openssl list -providers

# 4. 查看 certs/Hybrid Concatenated Certificate/mlkemdsa 的 user_enc
openssl x509 -in .\certs\Hybrid Concatenated Certificate\mlkemdsa\user_enc.crt -text -noout

# 5. 验证 certs/Hybrid Concatenated Certificate/mlkemdsa 全部证书链
.\bin\verify-chain.ps1 -CertSet concat

# 6. 一次性验证 certs/Pure PQC Certificate/mlkemdsa、2、3
powershell -NoProfile -ExecutionPolicy Bypass -File .\bin\verify-chain-all.ps1
```

---

## 6. cmd 完整示例

```cmd
call D:\20240429certificate-verification\tlcp-pqc\bin\Set-TlcpEnv.bat

D:\20240429certificate-verification\tlcp-pqc\bin\openssl.exe version
D:\20240429certificate-verification\tlcp-pqc\bin\openssl.exe list -providers

D:\20240429certificate-verification\tlcp-pqc\bin\openssl.exe x509 -in D:\20240429certificate-verification\tlcp-pqc\certs\Hybrid Concatenated Certificate\mlkemdsa\user_enc.crt -text -noout

D:\20240429certificate-verification\tlcp-pqc\bin\openssl.exe verify -CAfile D:\20240429certificate-verification\tlcp-pqc\certs\Hybrid Concatenated Certificate\mlkemdsa\root.crt -untrusted D:\20240429certificate-verification\tlcp-pqc\certs\Hybrid Concatenated Certificate\mlkemdsa\yunying.crt D:\20240429certificate-verification\tlcp-pqc\certs\Hybrid Concatenated Certificate\mlkemdsa\user_enc.crt
```

---

## 7. 常见问题

| 现象 | 原因 | 处理 |
|------|------|------|
| `禁止运行脚本` | PowerShell 执行策略限制 | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` |
| `openssl` 找不到或 DLL 错误 | 未导入环境，`PATH` 缺少 `bin`、`lib` | 执行 `Set-TlcpEnv.ps1` 或 `Set-TlcpEnv.bat` |
| 公钥显示不完整 | 未加载 pqmagic / ml_dsa_sm2 provider | 确认 `OPENSSL_CONF` 指向 `config\openssl-all-providers.cnf` |
| 验签进程崩溃 `0xC000001D` | PQMagic 使用了 CPU 不支持的 AVX-512 指令 | 用 `-DPQMAGIC_MSVC_PORTABLE=ON` 重编 PQMagic，运行 `rebuild-pqmagic-portable.bat` |

---

## 8. 相关脚本与配置

| 文件 | 用途 |
|------|------|
| `bin\Set-TlcpEnv.ps1` / `Set-TlcpEnv.bat` | 导入运行时环境变量 |
| `bin\inspect-cert.ps1` | 查看单张证书 |
| `bin\verify-chain.ps1` | 验证指定套别证书链 |
| `bin\verify-chain-all.ps1` | 验证 certs/Pure PQC Certificate/mlkemdsa、2、3 全部 |
| `bin\check-cert-view-all.ps1` | 12 张证总验收：解析、ASN.1、链元数据、有效期 |
| `config\openssl-all-providers.cnf` | 自动加载 5 个 provider |

---

## 9. 快速命令索引

```powershell
# 环境
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
. D:\20240429certificate-verification\tlcp-pqc\bin\Set-TlcpEnv.ps1

# 查看
openssl x509 -in D:\20240429certificate-verification\tlcp-pqc\certs\{1|2|3}\{root|yunying|user_sig|user_enc}.crt -text -noout

# 验链（单套）
D:\20240429certificate-verification\tlcp-pqc\bin\verify-chain.ps1 -CertSet {pure|concat|ext}

# 验链（全部）
powershell -NoProfile -ExecutionPolicy Bypass -File D:\20240429certificate-verification\tlcp-pqc\bin\verify-chain-all.ps1
```
