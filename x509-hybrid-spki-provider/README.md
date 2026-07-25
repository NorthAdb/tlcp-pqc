# ML-DSA / ML-KEM 复合 SM2 Provider

用于 Tongsuo 的 provider，注册混合 SPKI 的 ASN1 解码与打印方法。

## 功能

| OID | 算法 | 公钥布局 |
|-----|------|----------|
| `1.2.156.10197.1.508.1` | ML-DSA-44-SM2 | 1312 字节 ML-DSA-44 + 65 字节 SM2 |
| `1.2.156.10197.1.507.1` | ML-KEM-512-SM2 | 800 字节 ML-KEM-512 + 65 字节 SM2 |

- 解析并显示上述复合公钥（`x509 -text` 不再出现 `Unable to load Public Key`）
- 供证书链构建时 `X509_get0_pubkey` 成功解码主体公钥

## 编译

```bash
cd /home/wang/Desktop/x509-hybrid-spki-provider
make
```

## 快速开始

### 基本用法

**必须同时加载两个 provider：**

```bash
# 方式 1: 使用 -provider-path（推荐）
tongsuo x509 -provider-path /home/wang/Desktop/x509-hybrid-spki-provider \
            -provider default \
            -provider libml_dsa_sm2_provider \
            -in /path/to/certificate.crt \
            -text -noout

# 方式 2: 使用环境变量
export OPENSSL_MODULES=/home/wang/Desktop/x509-hybrid-spki-provider
tongsuo x509 -provider default \
            -provider libml_dsa_sm2_provider \
            -in /path/to/certificate.crt \
            -text -noout
```

### 为什么需要两个 provider？

1. **default provider**：提供基础功能（如 OID 解析、基本算法等）
2. **libml_dsa_sm2_provider**：提供 ML-DSA-44-SM2 的 ASN1 解码和打印功能

两个 provider 缺一不可！

## 命令行参数说明

### 参数区别

1. **`-provider-path <目录路径>`**
   - 作用：指定包含 provider 库文件（.so）的目录
   - 示例：`-provider-path /home/wang/Desktop/x509-hybrid-spki-provider`
   - 注意：这是目录路径，不是文件名

2. **`-provider <provider名称>`**
   - 作用：指定要加载的 provider 名称
   - 常见名称：`default`, `legacy`, `fips` 等
   - 示例：`-provider default` 或 `-provider libml_dsa_sm2_provider`
   - 注意：这是名称，不是路径（不需要 .so 扩展名）

### 常见错误

#### 错误 1: 只加载 default
```bash
tongsuo x509 -provider default -in root.crt -text -noout
```
**结果：** `Unable to load Public Key` - 因为 ASN1 方法没有注册

#### 错误 2: 只加载我们的 provider
```bash
tongsuo x509 -provider libml_dsa_sm2_provider -in root.crt -text -noout
```
**结果：** 可能缺少基础功能

#### 错误 3: 使用错误的 provider 名称
```bash
tongsuo x509 -provider libml_dsa_sm2_provider.so -in root.crt -text -noout
```
**结果：** 找不到 provider（名称不需要 .so 扩展名）

#### 错误 4: 把目录路径当作 provider 名称
```bash
tongsuo x509 -provider /home/wang/Desktop/x509-hybrid-spki-provider -in root.crt -text -noout
```
**结果：** `cannot read file data: Is a directory`

## 使用配置文件（推荐用于生产环境）

1. 编辑 `/usr/local/lib/ssl/openssl.cnf` 或创建自定义配置文件
2. 添加以下配置：

```ini
# 在文件顶部确保有：
openssl_conf = openssl_init

# 在 [openssl_init] 部分添加：
[openssl_init]
providers = provider_sect

# 在 [provider_sect] 部分添加：
[provider_sect]
default = default_sect
ml_dsa_sm2 = ml_dsa_sm2_sect

# 添加 ML-DSA-44-SM2 Provider 配置：
[ml_dsa_sm2_sect]
module = /home/wang/Desktop/x509-hybrid-spki-provider/libml_dsa_sm2_provider.so
activate = 1
```

3. 使用配置文件：

```bash
tongsuo x509 -config /path/to/openssl.cnf \
            -in /path/to/certificate.crt \
            -text -noout
```

示例配置文件已创建在 `openssl.cnf.example`，可以参考使用。

## 验证 provider 是否加载成功

```bash
# 查看已加载的 providers
tongsuo list -provider-path /home/wang/Desktop/x509-hybrid-spki-provider \
            -provider default \
            -provider libml_dsa_sm2_provider \
            -providers
```

如果看到两个 provider 都显示为 "active"，说明加载成功。

## 文件结构

- `src/ml_dsa_sm2_ameth.c` - ASN1 方法实现（pub_decode 和 pub_print）
- `src/ml_dsa_sm2_provider.c` - Provider 入口点
- `include/ml_dsa_sm2_ameth.h` - 头文件
- `Makefile` - 编译配置
- `openssl.cnf.example` - 配置文件示例

## 公钥格式

ML-DSA-44-SM2 混合公钥格式：
- ML-DSA-44 公钥：1312 字节
- SM2 公钥：65 字节（未压缩格式：0x04 + 32字节X + 32字节Y）
- 总计：1377 字节（11016 位）

公钥显示为标准格式：
```
Public-Key: (11016 bit)
pub:
    a5:2f:24:3f:07:f4:82:aa:19:0f:03:2c:19:88:5f:63:
    ...
```

## 故障排除

### 问题：公钥无法解析

如果看到 "Unable to load Public Key" 错误，请检查：

1. **确认 Provider 已加载**
   - 必须同时加载 `default` 和 `libml_dsa_sm2_provider` 两个 provider
   - 使用 `tongsuo list -providers` 验证

2. **检查公钥数据格式**
   - 确认证书中的公钥数据格式正确
   - ML-DSA-44 公钥：1312 字节
   - SM2 公钥：65 字节
   - 总计：1377 字节

3. **检查错误信息**
   ```bash
   tongsuo x509 -in root.crt -text -noout 2>&1 | grep -A 5 "error:"
   ```

### Provider 加载失败

如果 provider 加载失败，检查：
- 库文件路径是否正确
- 库文件是否可执行
- 依赖库是否可用

## 技术细节

### 已完成的修改

1. **修改了 Tongsuo 的 `x509_pubkey_decode` 函数** (`crypto/x509/x_pubkey.c`)
   - 在没有 ENGINE 的情况下，也会检查是否有可用的 ASN1 方法
   - 这允许我们的 provider 的 ASN1 方法被正确调用

2. **实现了完整的公钥解析和显示功能**
   - `ml_dsa_sm2_pub_decode`: 解析 ML-DSA-44 (1312 字节) + SM2 (65 字节) 混合公钥
   - `ml_dsa_sm2_pub_print`: 显示合并后的公钥信息（标准格式）

### 注意事项

- 需要重新编译并安装修改后的 Tongsuo 以应用对 `x509_pubkey.c` 的修改
- Provider 库需要与 Tongsuo 的版本匹配
- Provider 在初始化时会自动注册 ASN1 方法
