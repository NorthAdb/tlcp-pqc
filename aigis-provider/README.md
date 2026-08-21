# Aigis Provider（证书解析 / 公钥提取 / 验签）

面向 `certs/aigis` 三类样证（均为 Aigis **SIG1 / ENC1**）：

| 目录 | 模式 | SPKI / 签名 OID |
|------|------|-----------------|
| `aigis/` | 纯抗量子 | 306.1 / 305.1，签名 509.1 |
| `aigissm2/` | 混合串联 | 512.1 / 511.1，签名 510.1 = Aigis‖SM2 |
| `sm2extaigis/` | 混合扩展 | 主体 SM2 + 扩展 4.1.6/7/8 |

## 构建

```bash
cd /home/wang/Desktop/aigis-provider
cmake -S . -B build \
  -DTONGSUO_ROOT=/home/wang/Desktop/tongsuo-clean \
  -DPQMAGIC_PREFIX=/home/wang/Desktop/pqmagic/install
cmake --build build -j
```

产物：

- `build/aigis.so` — OpenSSL 3 Provider
- `build/aigis_cert_tool` — 解析/提取/验签工具

## Provider 能力

- KEYMGMT + DECODER + TEXT：裸 / 串联 SPKI
- SIGNATURE：`Aigis-SIG1-with-SM3`（SM3(TBS) → PQMagic）
- KEM：`Aigis-Enc-1`

```bash
export LD_LIBRARY_PATH=/home/wang/Desktop/tongsuo-clean:/home/wang/Desktop/pqmagic/install/lib
export OPENSSL_MODULES=/home/wang/Desktop/aigis-provider/build
/home/wang/Desktop/tongsuo-clean/apps/openssl list -providers -provider-path $OPENSSL_MODULES -provider aigis -provider default
```

## 工具用法

```bash
export LD_LIBRARY_PATH=/home/wang/Desktop/tongsuo-clean:/home/wang/Desktop/pqmagic/install/lib
TOOL=/home/wang/Desktop/aigis-provider/build/aigis_cert_tool

# 提取公钥
$TOOL extract /home/wang/Desktop/certs/aigis/aigis/user_sig.crt
$TOOL extract /home/wang/Desktop/certs/aigis/aigissm2/user_sig.crt
$TOOL extract /home/wang/Desktop/certs/aigis/sm2extaigis/user_sig.crt

# 单步验签
$TOOL verify .../yunying.crt .../root.crt

# 整目录链：root → yunying → user_sig[/user_enc]
$TOOL verify-dir /home/wang/Desktop/certs/aigis/aigis
$TOOL verify-dir /home/wang/Desktop/certs/aigis/aigissm2
$TOOL verify-dir /home/wang/Desktop/certs/aigis/sm2extaigis
```

调试：`AIGIS_CERT_TRACE=1`

## 用 openssl 查看证书公钥（与 Kyber/Dilithium 一样）

必须加载 `aigis` provider（类似查看 `certs/1` 时加载 `pqmagic`）：

```bash
export LD_LIBRARY_PATH=/home/wang/Desktop/tongsuo-clean:/home/wang/Desktop/pqmagic/install/lib
export OPENSSL=/home/wang/Desktop/tongsuo-clean/apps/openssl
export OPENSSL_MODULES=/home/wang/Desktop/aigis-provider/build

# 纯抗量子
$OPENSSL x509 -provider-path $OPENSSL_MODULES -provider default -provider aigis \
  -in /home/wang/Desktop/certs/aigis/aigis/user_sig.crt -text -noout

# 混合串联
$OPENSSL x509 -provider-path $OPENSSL_MODULES -provider default -provider aigis \
  -in /home/wang/Desktop/certs/aigis/aigissm2/user_sig.crt -text -noout

# 混合扩展（主体 SM2，扩展里是 Aigis；default 即可看主体，aigis 用于工具验签）
$OPENSSL x509 -provider-path $OPENSSL_MODULES -provider default -provider aigis \
  -in /home/wang/Desktop/certs/aigis/sm2extaigis/user_sig.crt -text -noout
```

不加 `-provider aigis` 时会出现 `Unable to load Public Key`（与未加载 pqmagic 时看 ML-DSA 证书相同）。

## 说明

- 证书 X.509 与 **Enc-1/SIG1** 由本模块提供；旧的 `ntls-aigis-provider`（Enc-2 握手 KEM）已移除，当前产品路径不需要。
- 验签消息：`SM3(TBS)`，调用 PQMagic **`pqmagic_aigis_sig1_std_verify_internal`**（与当前样证签发方式一致）。
- 变色龙证书目录 `aigischam` 当前样证未提供，本 Provider 暂不覆盖。
- Provider 初始化使用 `OSSL_LIB_CTX_new_from_dispatch`（与 pqmagic 一致），否则 `x509 -text` 无法解码公钥。
