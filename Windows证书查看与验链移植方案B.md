# Windows 原生平台：混合证书查看与证书链验证移植方案（方案 B）

> 文档版本：1.0  
> 适用源环境：Linux（`/home/wang/Desktop` 当前工程）  
> 目标环境：Windows 10/11 原生（MSVC 或 MinGW-w64）  
> 最后更新：2026-06-16

---

## 1. 概述

### 1.1 目标

将当前 Linux 环境下已验证可用的以下能力，完整移植到 **原生 Windows** 平台：

| 能力 | 说明 |
|------|------|
| **查看证书** | 使用 Tongsuo `openssl x509 -text` 解析 certs/1、2、3 的混合/PQC 证书 |
| **验证证书链** | 使用 `openssl verify` + 混合验签逻辑，验证 root → yunying → user_sig/user_enc |
| **双重验签** | certs/2（ML-DSA + SM2 复合 SPKI）、certs/3（SM2 外层 + ML-DSA 扩展 4.1.8） |

### 1.2 与方案 A（WSL）的区别

| 对比项 | 方案 A（WSL2） | 方案 B（本方案） |
|--------|----------------|------------------|
| 运行方式 | Linux 子系统内直接复用现有脚本 | Windows 原生 `.exe` / `.dll` |
| 改动量 | 几乎为零 | 需改构建系统、动态加载、脚本 |
| 交付形态 | 依赖 WSL | 可独立分发、集成到 Windows 工具 |
| 预估工期 | 1–2 天 | 1–2 周 |

### 1.3 三套证书类型回顾

| 目录 | 公钥算法 | 签名算法 | 验签特点 |
|------|---------|---------|---------|
| `certs/1` | ML-DSA-44-SPKI | ML-DSA-44-with-SM3 | 纯 PQC，标准 verify 即可 |
| `certs/2` | ML-DSA-44-SM2 | ML-DSA-44-SM2-with-SM3 | ML-DSA(2420B) + SM2 双重验签 |
| `certs/3` | sm2 + 扩展 4.1.6 | SM2-with-SM3 + 扩展 4.1.8 ML-DSA | 外层 SM2 + 内层 ML-DSA |

---

## 2. 架构与依赖关系

### 2.1 组件清单

```
┌─────────────────────────────────────────────────────────────┐
│                    用户层（PowerShell / CMD）                 │
│   inspect-cert.ps1    verify-chain.ps1    verify-certs.exe   │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│              Tongsuo openssl.exe + libcrypto-3.dll           │
│   （含 x509_pqc_hybrid_vfy.c 混合验签钩子，需 Windows 适配）    │
└──────┬──────────────┬──────────────┬────────────────────────┘
       │              │              │
┌──────▼──────┐ ┌─────▼─────┐ ┌─────▼──────────────────────────┐
│ pqmagic.dll │ │libml_dsa_ │ │ cert_verify.dll                 │
│ (provider)  │ │sm2_       │ │ (x509-hybrid-verify-provider)   │
│             │ │provider   │ │                                 │
│             │ │.dll       │ │                                 │
└──────┬──────┘ └─────┬─────┘ └─────────────────────────────────┘
       │              │
       └──────┬───────┘
              │
┌─────────────▼─────────────┐
│   libpqmagic_std.dll      │
│   (PQMagic 算法库)         │
└───────────────────────────┘
```

### 2.2 Linux → Windows 映射表

| Linux | Windows |
|-------|---------|
| `libcrypto.so.3` | `libcrypto-3-x64.dll` 或 `libcrypto-3.dll` |
| `pqmagic.so` | `pqmagic.dll` |
| `libml_dsa_sm2_provider.so` | `libml_dsa_sm2_provider.dll` |
| `cert_verify.so` | `cert_verify.dll` |
| `libpqmagic_std.so` | `libpqmagic_std.dll` |
| `LD_LIBRARY_PATH` | `PATH`（DLL 搜索路径） |
| `OPENSSL_MODULES` | 同样有效，指向 provider 目录 |
| `CERT_VERIFY_SO` | 指向 `cert_verify.dll` 完整路径 |
| `bash *.sh` | `PowerShell *.ps1` |

### 2.3 建议 Windows 目录布局

```
C:\tlcp-pqc\
├── bin\
│   ├── openssl.exe
│   ├── verify_certs.exe          # 可选：独立验链工具
│   ├── inspect-cert.ps1
│   └── verify-chain.ps1
├── lib\
│   ├── libcrypto-3-x64.dll
│   ├── libssl-3-x64.dll
│   └── libpqmagic_std.dll
├── providers\
│   ├── pqmagic.dll
│   ├── libml_dsa_sm2_provider.dll
│   └── cert_verify.dll
├── config\
│   └── openssl-all-providers.cnf
├── certs\
│   ├── 1\
│   ├── 2\
│   └── 3\
└── src\                            # 源码（开发阶段）
    ├── Tongsuo\
    ├── pqmagic\
    ├── pqmagic-algorithms-provider\
    ├── x509-hybrid-spki-provider\
    └── x509-hybrid-verify-provider\
```

---

## 3. 开发环境准备

### 3.1 必需工具

| 工具 | 版本建议 | 用途 |
|------|---------|------|
| **Visual Studio 2022** | Community 或以上 | MSVC 编译器、`nmake`、Windows SDK |
| **CMake** | ≥ 3.20 | 构建 pqmagic、providers |
| **Perl** | Strawberry Perl 5.x + Text::Template | Tongsuo `Configure` 脚本 |
| **Git** | 任意 | 克隆/同步源码 |
| **NASM**（可选） | 最新稳定版 | Tongsuo 部分汇编优化 |

> 也可选用 **MSYS2 + MinGW-w64** 替代 MSVC，但 Tongsuo 官方 Windows 文档以 `nmake` 为主，本文以 **MSVC** 为主线，MinGW 差异在附录说明。

### 3.2 环境变量（开发机全局，可选）

```powershell
# 添加到系统或用户环境变量
$env:TLCP_ROOT = "C:\tlcp-pqc"
$env:PATH = "$env:TLCP_ROOT\bin;$env:TLCP_ROOT\lib;$env:PATH"
```

### 3.3 从 Linux 同步源码

将以下目录复制到 Windows（或通过 Git 同步）：

```
Tongsuo/                          # 含 x509_pqc_hybrid_vfy.c 补丁
pqmagic/
pqmagic-algorithms-provider/
x509-hybrid-spki-provider/
x509-hybrid-verify-provider/
certs/                            # 测试证书（1、2、3）
```

---

## 4. 分步构建指南

> **构建顺序不可颠倒**：pqmagic → Tongsuo → 三个 provider → 验链工具

### 4.1 第一步：构建 PQMagic

PQMagic 的 CMake 已内置 Windows 支持（MSVC / MinGW）。

```powershell
cd C:\tlcp-pqc\src\pqmagic
mkdir build
cd build

cmake .. -DCMAKE_BUILD_TYPE=Release `
         -DCMAKE_INSTALL_PREFIX=C:\tlcp-pqc\pqmagic-install

cmake --build . --config Release
cmake --install . --config Release
```

**预期产物：**

```
C:\tlcp-pqc\pqmagic-install\
├── include\
│   └── pqmagic_api.h 等
└── lib\
    ├── libpqmagic_std.dll
    └── libpqmagic_std.lib   # import library（MSVC）
```

**验收：**

```powershell
dir C:\tlcp-pqc\pqmagic-install\lib\libpqmagic_std.dll
```

---

### 4.2 第二步：构建 Tongsuo（含混合验签补丁）

#### 4.2.1 Windows 适配（必须先做）

当前 `Tongsuo/crypto/x509/x509_pqc_hybrid_vfy.c` 存在 Linux 专用代码，移植前需修改：

**问题 1：硬编码 Linux 默认路径**

```c
// 当前（需改）
#define DEFAULT_PQMAGIC_PROVIDER \
    "/home/wang/Desktop/pqmagic-algorithms-provider/build/pqmagic.so"
#define DEFAULT_ML_DSA_SM2_PROVIDER \
    "/home/wang/Desktop/x509-hybrid-spki-provider/libml_dsa_sm2_provider.so"
#define DEFAULT_PQMAGIC_STD_LIB \
    "/home/wang/Desktop/pqmagic/install/lib/libpqmagic_std.so"
#define DEFAULT_CERT_VERIFY_SO \
    "/home/wang/Desktop/x509-hybrid-verify-provider/cert_verify.so"
```

**建议改法：** 去掉硬编码，仅通过环境变量加载；或在 `#ifdef _WIN32` 分支中使用 Windows 默认路径：

```c
#ifdef _WIN32
# define DEFAULT_PQMAGIC_PROVIDER \
    "C:\\tlcp-pqc\\providers\\pqmagic.dll"
# define DEFAULT_ML_DSA_SM2_PROVIDER \
    "C:\\tlcp-pqc\\providers\\libml_dsa_sm2_provider.dll"
# define DEFAULT_PQMAGIC_STD_LIB \
    "C:\\tlcp-pqc\\lib\\libpqmagic_std.dll"
# define DEFAULT_CERT_VERIFY_SO \
    "C:\\tlcp-pqc\\providers\\cert_verify.dll"
#else
/* 保留原有 Linux 路径或 getenv 优先 */
#endif
```

**问题 2：直接使用 `dlopen/dlsym`**

```c
#include <dlfcn.h>   // Windows 上不存在
pqmagic_std_dso = dlopen(libpath, RTLD_LAZY | RTLD_LOCAL);
```

**建议改法：** 新增 `crypto/x509/x509_pqc_dso.c` 抽象层：

```c
/* x509_pqc_dso.h */
void *x509_pqc_dso_load(const char *path);
void *x509_pqc_dso_sym(void *handle, const char *name);
void  x509_pqc_dso_unload(void *handle);
void *x509_pqc_dso_default_sym(const char *name);

#ifdef _WIN32
#include <windows.h>
void *x509_pqc_dso_load(const char *path) {
    return (void *)LoadLibraryA(path);
}
void *x509_pqc_dso_sym(void *handle, const char *name) {
    return (void *)GetProcAddress((HMODULE)handle, name);
}
void x509_pqc_dso_unload(void *handle) {
    if (handle) FreeLibrary((HMODULE)handle);
}
void *x509_pqc_dso_default_sym(const char *name) {
    return x509_pqc_dso_sym(GetModuleHandle(NULL), name);
}
#else
#include <dlfcn.h>
/* Linux 实现：dlopen / dlsym / dlclose / dlsym(RTLD_DEFAULT, ...) */
#endif
```

然后将 `x509_pqc_hybrid_vfy.c` 中所有 `dlopen/dlsym` 替换为上述封装。

**问题 3：`_GNU_SOURCE`**

文件头部 `#define _GNU_SOURCE` 仅 Linux 需要，Windows 下应去掉或置于 `#ifndef _WIN32` 内。

#### 4.2.2 编译 Tongsuo

在 **「x64 Native Tools Command Prompt for VS 2022」** 中执行：

```cmd
cd C:\tlcp-pqc\src\Tongsuo

perl Configure VC-WIN64A --prefix=C:\tlcp-pqc\tongsuo-install enable-ntls

nmake
nmake install_sw
```

> `enable-ntls` 为 TLCP/国密相关功能所必需。若仅需证书查看与 verify，可保留；若体积敏感可评估是否裁剪。

**预期产物：**

```
C:\tlcp-pqc\tongsuo-install\
├── bin\
│   └── openssl.exe
└── lib\
    ├── libcrypto-3-x64.lib
    └── libcrypto-3-x64.dll   # 运行时需放入 PATH
```

**验收：**

```powershell
$env:PATH = "C:\tlcp-pqc\tongsuo-install\bin;C:\tlcp-pqc\tongsuo-install\lib;$env:PATH"
openssl version -a
# 应显示 Tongsuo / OpenSSL 3.x
```

---

### 4.3 第三步：构建 pqmagic-algorithms-provider

Linux 版 CMakeLists.txt 使用了 `-fPIC`（GCC 专用），Windows 需调整。

**建议 `CMakeLists.txt` 修改要点：**

```cmake
cmake_minimum_required(VERSION 3.10)
project(pqmagic_openssl_provider C)

# 指向 Tongsuo 安装目录（而非系统 OpenSSL）
set(TONGSUO_ROOT "C:/tlcp-pqc/tongsuo-install" CACHE PATH "Tongsuo install prefix")
set(TONGSUO_INCLUDE "${TONGSUO_ROOT}/include")
set(TONGSUO_LIB     "${TONGSUO_ROOT}/lib")

set(_PQMAGIC_PREFIX "C:/tlcp-pqc/pqmagic-install")
find_library(PQMAGIC_LIB pqmagic_std PATHS "${_PQMAGIC_PREFIX}/lib" REQUIRED)

add_library(pqmagic MODULE pqmagic_prov.c)
set_target_properties(pqmagic PROPERTIES
    PREFIX ""
    OUTPUT_NAME "pqmagic"
)

target_include_directories(pqmagic PRIVATE
    "${_PQMAGIC_PREFIX}/include"
    "${TONGSUO_INCLUDE}")

target_link_directories(pqmagic PRIVATE "${TONGSUO_LIB}")
target_link_libraries(pqmagic PRIVATE libcrypto pqmagic_std)

if(MSVC)
    target_compile_options(pqmagic PRIVATE /W3)
else()
    target_compile_options(pqmagic PRIVATE -Wall)
endif()
```

**构建：**

```powershell
cd C:\tlcp-pqc\src\pqmagic-algorithms-provider
mkdir build
cd build

cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release

copy Release\pqmagic.dll C:\tlcp-pqc\providers\
```

---

### 4.4 第四步：构建 x509-hybrid-spki-provider

Linux Makefile 需迁移为 CMake。新建 `CMakeLists.txt`：

```cmake
cmake_minimum_required(VERSION 3.10)
project(ml_dsa_sm2_provider C)

set(TONGSUO_ROOT "C:/tlcp-pqc/tongsuo-install" CACHE PATH "")

add_library(ml_dsa_sm2_provider MODULE
    src/ml_dsa_sm2_ameth.c
    src/ml_kem512_sm2_ameth.c
    src/ml_dsa_sm2_provider.c)

set_target_properties(ml_dsa_sm2_provider PROPERTIES
    PREFIX "lib"
    OUTPUT_NAME "ml_dsa_sm2_provider"
)

target_include_directories(ml_dsa_sm2_provider PRIVATE
    include
    "${TONGSUO_ROOT}/include")

target_link_directories(ml_dsa_sm2_provider PRIVATE "${TONGSUO_ROOT}/lib")
target_link_libraries(ml_dsa_sm2_provider PRIVATE libcrypto libssl)
```

**构建：**

```powershell
cd C:\tlcp-pqc\src\x509-hybrid-spki-provider
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release

copy Release\libml_dsa_sm2_provider.dll C:\tlcp-pqc\providers\
```

---

### 4.5 第五步：构建 x509-hybrid-verify-provider

#### 4.5.1 CMakeLists.txt 示例

```cmake
cmake_minimum_required(VERSION 3.10)
project(cert_verify C)

set(TONGSUO_ROOT "C:/tlcp-pqc/tongsuo-install" CACHE PATH "")
set(PQMAGIC_PREFIX "C:/tlcp-pqc/pqmagic-install" CACHE PATH "")

# cert_verify.dll（供 Tongsuo dlopen 及 provider 加载）
add_library(cert_verify SHARED
    src/cert_verify.c
    src/cert_verify_prov.c
    src/cert_verify_openssl.c)

set_target_properties(cert_verify PROPERTIES
    OUTPUT_NAME "cert_verify"
)

target_include_directories(cert_verify PRIVATE
    include
    "${TONGSUO_ROOT}/include"
    "${TONGSUO_ROOT}"           # crypto/x509.h 等内部头
    "${PQMAGIC_PREFIX}/include")

target_link_directories(cert_verify PRIVATE "${TONGSUO_ROOT}/lib")
target_link_libraries(cert_verify PRIVATE libcrypto)

# verify_certs.exe（独立验链 CLI，可选）
add_executable(verify_certs
    tools/verify_certs_1.c
    src/cert_verify.c)

target_include_directories(verify_certs PRIVATE
    include "${TONGSUO_ROOT}/include" "${TONGSUO_ROOT}" "${PQMAGIC_PREFIX}/include")
target_link_libraries(verify_certs PRIVATE libcrypto)
```

#### 4.5.2 cert_verify_openssl.c 的 Windows 说明

该文件使用 `dlsym(RTLD_NEXT, ...)` 实现 LD_PRELOAD 挂钩，**仅 Linux 有效**。

在 Windows 上：

- **主路径**：Tongsuo 内置 `x509_pqc_hybrid_vfy.c` 通过 `CERT_VERIFY_SO` dlopen `cert_verify.dll`，**不依赖** LD_PRELOAD
- **建议**：在 `#ifdef _WIN32` 下将 `cert_verify_openssl.c` 编译为空实现或跳过该文件

#### 4.5.3 verify_certs_1.c 的 Windows 说明

该工具 `#include <unistd.h>`，Windows 需：

- 移除或替换为 `<io.h>` / `<direct.h>`
- 路径分隔符使用 `\` 或通过 CMake 定义 `PATH_MAX`

**构建：**

```powershell
cd C:\tlcp-pqc\src\x509-hybrid-verify-provider
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release

copy Release\cert_verify.dll C:\tlcp-pqc\providers\
copy Release\verify_certs.exe C:\tlcp-pqc\bin\
```

---

### 4.6 第六步：整理运行时文件

```powershell
# 复制 Tongsuo（Windows：运行时 DLL 在 tongsuo-install\bin，与 openssl.exe 同目录）
copy C:\tlcp-pqc\tongsuo-install\bin\openssl.exe C:\tlcp-pqc\bin\
copy C:\tlcp-pqc\tongsuo-install\bin\libcrypto-3-x64.dll C:\tlcp-pqc\bin\
copy C:\tlcp-pqc\tongsuo-install\bin\libssl-3-x64.dll C:\tlcp-pqc\bin\

# 复制 PQMagic 静态库（链接用）
copy C:\tlcp-pqc\pqmagic-install\lib\libpqmagic_std.lib C:\tlcp-pqc\lib\

# Provider 已在 4.3–4.5 复制到 providers\

# 复制测试证书
xcopy /E /I C:\tlcp-pqc\src\certs C:\tlcp-pqc\certs
```

---

## 5. 配置文件

### 5.1 openssl-all-providers.cnf（Windows 版）

在 `C:\tlcp-pqc\config\openssl-all-providers.cnf`：

```ini
config_diagnostics = 0
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
pqmagic = pqmagic_sect
ml_dsa_sm2 = ml_dsa_sm2_sect
cert_verify = cert_verify_sect

[default_sect]
activate = 1

[pqmagic_sect]
module = C:/tlcp-pqc/providers/pqmagic.dll
activate = 1

[ml_dsa_sm2_sect]
module = C:/tlcp-pqc/providers/libml_dsa_sm2_provider.dll
activate = 1

[cert_verify_sect]
module = C:/tlcp-pqc/providers/cert_verify.dll
activate = 1
```

> OpenSSL 配置文件中路径推荐使用 **正斜杠 `/`**，避免转义问题。

---

## 6. 环境变量与 PowerShell 脚本

### 6.1 运行时环境变量

```powershell
# Set-TlcpEnv.ps1 — 每次打开新终端时 source（dot-source）
$TLCP_ROOT = "C:\tlcp-pqc"

$env:PATH = "$TLCP_ROOT\bin;$TLCP_ROOT\lib;$env:PATH"
$env:OPENSSL_CONF = "$TLCP_ROOT\config\openssl-all-providers.cnf"
$env:OPENSSL_MODULES = "$TLCP_ROOT\providers"

$env:PQMAGIC_PROVIDER = "$TLCP_ROOT\providers\pqmagic.dll"
$env:ML_DSA_SM2_PROVIDER = "$TLCP_ROOT\providers\libml_dsa_sm2_provider.dll"
$env:PQMAGIC_STD_LIB = "$TLCP_ROOT\lib\libpqmagic_std.dll"
$env:CERT_VERIFY_SO = "$TLCP_ROOT\providers\cert_verify.dll"
$env:CERT_VERIFY_VERIFY_INFO = "1"   # 打印 [1/2][2/2] 验签进度

$env:OPENSSL = "$TLCP_ROOT\bin\openssl.exe"
```

使用方式：

```powershell
. C:\tlcp-pqc\bin\Set-TlcpEnv.ps1
```

### 6.2 inspect-cert.ps1 — 查看证书

```powershell
# C:\tlcp-pqc\bin\inspect-cert.ps1
param(
    [Parameter(Mandatory=$true)]
    [string]$CertPath,

    [switch]$Summary
)

. "$PSScriptRoot\Set-TlcpEnv.ps1"

$prov = @(
    "-provider-path", "$env:TLCP_ROOT\lib",
    "-provider", "default",
    "-provider", $env:PQMAGIC_PROVIDER,
    "-provider", $env:ML_DSA_SM2_PROVIDER
)

if ($Summary) {
    & $env:OPENSSL x509 -in $CertPath -noout -subject -issuer -dates -serial @prov
    & $env:OPENSSL x509 -in $CertPath -noout -signature_algorithm @prov
} else {
    & $env:OPENSSL x509 -in $CertPath -text -noout @prov
}
```

**示例：**

```powershell
. C:\tlcp-pqc\bin\Set-TlcpEnv.ps1

# 查看 certs/3 签名证
.\inspect-cert.ps1 -CertPath C:\tlcp-pqc\certs\3\user_sig.crt

# 仅摘要
.\inspect-cert.ps1 -CertPath C:\tlcp-pqc\certs\2\root.crt -Summary
```

### 6.3 verify-chain.ps1 — 验证证书链

```powershell
# C:\tlcp-pqc\bin\verify-chain.ps1
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("1","2","3")]
    [string]$CertSet,

    [ValidateSet("yunying","user_sig","user_enc","all")]
    [string]$Leaf = "all"
)

. "$PSScriptRoot\Set-TlcpEnv.ps1"

$base = "$env:TLCP_ROOT\certs\$CertSet"
$root = "$base\root.crt"
$untrusted = "$base\yunying.crt"

$leaves = if ($Leaf -eq "all") {
    @("yunying", "user_sig", "user_enc")
} else {
    @($Leaf)
}

Write-Host "======== certs/$CertSet 证书链验证 ========" -ForegroundColor Cyan

foreach ($name in $leaves) {
    $cert = "$base\$name.crt"
    Write-Host ""
    Write-Host ">>> 验证 ${name}.crt" -ForegroundColor Yellow
    & $env:OPENSSL verify -CAfile $root -untrusted $untrusted $cert
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAILED: $cert" -ForegroundColor Red
        exit $LASTEXITCODE
    }
}

Write-Host ""
Write-Host "全部验证通过。" -ForegroundColor Green
```

**示例：**

```powershell
# 验证 certs/3 全部证书
.\verify-chain.ps1 -CertSet 3

# 仅验证 certs/2 的 user_sig
.\verify-chain.ps1 -CertSet 2 -Leaf user_sig
```

### 6.4 verify-all.ps1 — 批量验收

```powershell
# C:\tlcp-pqc\bin\verify-all.ps1
. "$PSScriptRoot\Set-TlcpEnv.ps1"

Write-Host "=== Provider 列表 ===" -ForegroundColor Cyan
& $env:OPENSSL list -providers `
    -provider-path "$env:TLCP_ROOT\lib" `
    -provider default `
    -provider $env:PQMAGIC_PROVIDER `
    -provider $env:ML_DSA_SM2_PROVIDER

foreach ($set in @("1","2","3")) {
    & "$PSScriptRoot\verify-chain.ps1" -CertSet $set
    if ($LASTEXITCODE -ne 0) { exit 1 }
}

Write-Host "`n=== 全部 certs/1/2/3 验链通过 ===" -ForegroundColor Green
```

---

## 7. 验收标准

### 7.1 构建验收

- [ ] `openssl version -a` 显示 Tongsuo / OpenSSL 3.x
- [ ] `openssl list -providers` 包含 `default`、`pqmagic`、`ml_dsa_sm2`、`cert_verify`
- [ ] 四个 DLL 均可被 `dumpbin /DEPENDENTS` 正常解析依赖

### 7.2 查看证书验收

| 证书 | 预期 Public Key | 预期 Signature |
|------|----------------|----------------|
| certs/1/user_sig.crt | ML-DSA-44-SPKI | ML-DSA-44-with-SM3 |
| certs/2/user_sig.crt | ML-DSA-44-SM2 | ML-DSA-44-SM2-with-SM3 |
| certs/3/user_sig.crt | sm2 + PQC 扩展 4.1.6 | SM2-with-SM3 + 扩展 4.1.8 |

### 7.3 验链验收

| 目录 | yunying | user_sig | user_enc | 额外输出 |
|------|---------|----------|----------|---------|
| certs/1 | OK | OK | OK | 无双重验签日志 |
| certs/2 | OK | OK | OK | `[1/2] ML-DSA` + `[2/2] SM2` |
| certs/3 | OK | OK | OK | `[1/2] SM2 外层` + `[2/2] ML-DSA 扩展 4.1.8` |

### 7.4 与 Linux 对照

在 Linux 源环境执行：

```bash
/home/wang/Desktop/x509-hybrid-verify-provider/scripts/openssl-hybrid-verify.sh \
  -CAfile /home/wang/Desktop/certs/3/root.crt \
  -untrusted /home/wang/Desktop/certs/3/yunying.crt \
  /home/wang/Desktop/certs/3/user_sig.crt
```

Windows 对应命令输出应一致（路径不同，结果均为 `OK`）。

---

## 8. 需修改的源文件清单

| 文件 | 修改内容 | 优先级 |
|------|---------|--------|
| `Tongsuo/crypto/x509/x509_pqc_hybrid_vfy.c` | dlopen → DSO 抽象层；去掉硬编码 Linux 路径 | **P0** |
| `Tongsuo/crypto/x509/x509_pqc_dso.c`（新建） | Windows LoadLibrary / Linux dlopen 封装 | **P0** |
| `pqmagic-algorithms-provider/CMakeLists.txt` | 去掉 `-fPIC`；指向 Tongsuo 而非系统 OpenSSL | **P0** |
| `x509-hybrid-spki-provider/CMakeLists.txt`（新建） | 替代 Linux Makefile | **P0** |
| `x509-hybrid-verify-provider/CMakeLists.txt`（新建） | 替代 Linux Makefile | **P0** |
| `x509-hybrid-verify-provider/src/cert_verify_openssl.c` | Windows 下禁用 LD_PRELOAD 逻辑 | **P1** |
| `x509-hybrid-verify-provider/tools/verify_certs_1.c` | 去掉 `unistd.h`，路径兼容 | **P1** |
| `x509-hybrid-verify-provider/openssl-all-providers.cnf` | `.so` → `.dll`，Windows 路径 | **P1** |
| `bin/*.ps1`（新建） | PowerShell 脚本 | **P1** |

---

## 9. 常见问题排查

### 9.1 `Unable to load Public Key`

**原因：** provider 未加载。

**排查：**

```powershell
$env:OPENSSL_MODULES
Test-Path $env:PQMAGIC_PROVIDER
& $env:OPENSSL list -providers -provider-path "$env:TLCP_ROOT\lib" -provider default -provider $env:PQMAGIC_PROVIDER
```

### 9.2 `The code execution cannot proceed because libcrypto-3-x64.dll was not found`

**原因：** DLL 不在 `PATH`。

**解决：** 确认 `Set-TlcpEnv.ps1` 已将 `C:\tlcp-pqc\lib` 加入 `PATH`。

### 9.3 verify 通过但无双重验签日志（certs/2/3）

**原因：** 加载的不是带 `x509_pqc_hybrid_vfy.c` 补丁的 Tongsuo，或 `CERT_VERIFY_SO` 未设置。

**排查：**

```powershell
echo $env:CERT_VERIFY_SO
Test-Path $env:CERT_VERIFY_SO
# 确认 openssl 来自 Tongsuo 构建产物，而非系统或其他 OpenSSL
Get-Command openssl | Format-List
```

### 9.4 `cert_verify.dll` 加载失败

**原因：** 依赖链断裂（缺 libcrypto / libpqmagic_std）。

**排查：**

```cmd
dumpbin /DEPENDENTS C:\tlcp-pqc\providers\cert_verify.dll
```

确保列出的所有 DLL 均在 `PATH` 中。

### 9.5 Provider 模块找不到

**原因：** `OPENSSL_MODULES` 目录不正确，或 `.dll` 文件名与 cnf 中 `module =` 不一致。

**解决：** 检查 `openssl-all-providers.cnf` 中路径与实际文件名完全匹配。

---

## 10. 实施计划（建议 1–2 周）

| 阶段 | 任务 | 工期 | 交付物 |
|------|------|------|--------|
| **第 1 阶段** | 搭建 VS + CMake + Perl 环境；构建 pqmagic | 1–2 天 | `libpqmagic_std.dll` |
| **第 2 阶段** | Tongsuo Windows 适配（DSO 抽象层 + 去硬编码路径）；编译 Tongsuo | 2–3 天 | `openssl.exe` + `libcrypto-3-x64.dll` |
| **第 3 阶段** | 三个 provider 迁移 CMake 并编译 | 2–3 天 | `pqmagic.dll` 等 |
| **第 4 阶段** | PowerShell 脚本 + cnf 配置 | 1 天 | `Set-TlcpEnv.ps1` 等 |
| **第 5 阶段** | certs/1/2/3 全量验收；与 Linux 对照 | 1 天 | 验收报告 |
| **第 6 阶段（可选）** | 打包 zip / MSI；GUI 封装 | 2–3 天 | 可分发安装包 |

---

## 11. 附录

### 11.1 MinGW-w64 构建差异

若使用 MSYS2 MinGW 而非 MSVC：

```bash
# 在 MSYS2 UCRT64 终端
cd /c/tlcp-pqc/src/Tongsuo
./Configure mingw64 --prefix=/c/tlcp-pqc/tongsuo-install enable-ntls
make
make install_sw
```

- Tongsuo 产物为 `libcrypto-3.dll`（无 `-x64` 后缀）
- Provider 链接时使用 `-lcrypto` 而非 `libcrypto.lib`
- PowerShell 脚本中 DLL 名称需对应调整

### 11.2 功能覆盖矩阵

| 功能 | certs/1 | certs/2 | certs/3 | 依赖 |
|------|---------|---------|---------|------|
| `x509 -text` 查看 | ✅ | ✅ | ✅ | pqmagic + ml_dsa_sm2 provider |
| `openssl verify` 标准链 | ✅ | ⚠️ 需 cert_verify | ⚠️ 需 cert_verify | Tongsuo 补丁 |
| ML-DSA + SM2 双重验签 | — | ✅ | — | cert_verify.dll |
| SM2 外层 + ML-DSA 扩展验签 | — | — | ✅ | cert_verify.dll |
| TLCP 握手（s_client） | 另需 NTLS 配置 | 另需 NTLS 配置 | 另需 NTLS 配置 | 超出本文范围 |

### 11.3 Linux 源环境参考命令

```bash
export LD_LIBRARY_PATH=/home/wang/Desktop/Tongsuo:/home/wang/Desktop/pqmagic/install/lib
export OPENSSL_MODULES=/home/wang/Desktop/pqmagic-algorithms-provider/build
export PQMAGIC_PROVIDER=/home/wang/Desktop/pqmagic-algorithms-provider/build/pqmagic.so
export ML_DSA_SM2_PROVIDER=/home/wang/Desktop/x509-hybrid-spki-provider/libml_dsa_sm2_provider.so
export CERT_VERIFY_SO=/home/wang/Desktop/x509-hybrid-verify-provider/cert_verify.so
export CERT_VERIFY_VERIFY_INFO=1

/home/wang/Desktop/Tongsuo/apps/openssl x509 \
  -in /home/wang/Desktop/certs/3/user_sig.crt -text -noout \
  -provider-path /home/wang/Desktop/Tongsuo \
  -provider default -provider $PQMAGIC_PROVIDER -provider $ML_DSA_SM2_PROVIDER

/home/wang/Desktop/x509-hybrid-verify-provider/scripts/openssl-hybrid-verify.sh \
  -CAfile /home/wang/Desktop/certs/3/root.crt \
  -untrusted /home/wang/Desktop/certs/3/yunying.crt \
  /home/wang/Desktop/certs/3/user_sig.crt
```

### 11.4 相关仓库/目录

| 目录 | 说明 |
|------|------|
| `Tongsuo/` | 铜锁 OpenSSL 分支，含混合验签钩子 |
| `pqmagic/` | PQMagic 后量子算法库 |
| `pqmagic-algorithms-provider/` | OpenSSL pqmagic provider |
| `x509-hybrid-spki-provider/` | ML-DSA-44-SM2 混合 SPKI provider |
| `x509-hybrid-verify-provider/` | 混合证书验签库 cert_verify |
| `certs/1`、`2`、`3` | 测试证书集 |

---

## 12. 总结

方案 B 在技术上 **完全可行**：核心验签逻辑（`cert_verify.c`）与 OpenSSL Provider API 均为跨平台 C 代码；主要工作量集中在：

1. **Tongsuo 补丁的 Windows 动态加载适配**（`dlopen` → `LoadLibrary`）
2. **三个 provider 从 Makefile 迁移到 CMake**
3. **环境变量与 Shell 脚本改写为 PowerShell**
4. **DLL 依赖路径整理**

按本文第 4–6 节顺序构建并配置后，即可在 Windows 上实现与 Linux 等价的证书查看与 certs/1/2/3 全链验证能力。
