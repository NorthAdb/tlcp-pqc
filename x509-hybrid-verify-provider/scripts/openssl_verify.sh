#!/usr/bin/env bash
# 使用 Tongsuo openssl verify 验证混合证书链（含 ML-DSA 扩展 4.1.8）
#
# 用法与 openssl verify 相同，例如：
#   ./scripts/openssl_verify.sh -CAfile /path/root.crt /path/yunying.crt
#   ./scripts/openssl_verify.sh -CAfile root.crt -untrusted yunying.crt user_sig.crt
#
# 依赖：
#   - cert_verify.so（本目录 provider + LD_PRELOAD 挂钩）
#   - pqmagic provider（ML-DSA-44-with-SM3）
#   - Tongsuo libcrypto
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TONGSUO="${TONGSUO:-/home/wang/Desktop/Tongsuo}"
PQMAGIC_LIB="${PQMAGIC_LIB:-/home/wang/Desktop/pqmagic/install/lib}"
PQMAGIC_MOD="${PQMAGIC_MOD:-/home/wang/Desktop/pqmagic-algorithms-provider/build}"
OPENSSL="${OPENSSL:-${TONGSUO}/apps/openssl}"

if [[ ! -x "$OPENSSL" ]]; then
	echo "未找到 openssl: $OPENSSL" >&2
	exit 1
fi

if [[ ! -f "${DIR}/cert_verify.so" ]]; then
	echo "正在编译 x509-hybrid-verify-provider ..."
	make -C "$DIR" cert_verify.so
fi

# 优先 Tongsuo 源码树 libcrypto.so.3，否则 /usr/local 下可能是旧库且无进度输出
export LD_LIBRARY_PATH="${TONGSUO}:${PQMAGIC_LIB}:${LD_LIBRARY_PATH:-}"
export OPENSSL_MODULES="${PQMAGIC_MOD}"
# Tongsuo x509_vfy 对混合证会 dlopen 此 so，调用 cert_verify_mldsa_hybrid
export CERT_VERIFY_SO="${DIR}/cert_verify.so"
# 默认打印 [1/2] SM2 + [2/2] ML-DSA 双重验签进度；设为 0 可关闭
export CERT_VERIFY_VERIFY_INFO="${CERT_VERIFY_VERIFY_INFO:-1}"
# 可选：仍可用 LD_PRELOAD 挂钩（与内置 dlopen 二选一即可）
# export LD_PRELOAD="${DIR}/cert_verify.so${LD_PRELOAD:+:${LD_PRELOAD}}"
# export CERT_VERIFY_OPENSSL_INTERPOSE=1

exec "$OPENSSL" verify "$@"
