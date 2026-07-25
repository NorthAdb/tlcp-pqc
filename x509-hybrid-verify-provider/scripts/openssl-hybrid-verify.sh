#!/usr/bin/env bash
# 混合证 openssl verify（含 [1/2] SM2 + [2/2] ML-DSA 进度输出）
# 用法与 openssl verify 完全相同，例如：
#   ./scripts/openssl-hybrid-verify.sh -CAfile certs/3/root.crt \
#     -untrusted certs/3/yunying.crt certs/3/user_sig.crt
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TONGSUO="${TONGSUO:-/home/wang/Desktop/Tongsuo}"
PQMAGIC_LIB="${PQMAGIC_LIB:-/home/wang/Desktop/pqmagic/install/lib}"
PQMAGIC_MOD="${PQMAGIC_MOD:-/home/wang/Desktop/pqmagic-algorithms-provider/build}"
OPENSSL_CONF="${OPENSSL_CONF:-${DIR}/openssl-all-providers.cnf}"
OPENSSL="${OPENSSL:-/usr/local/bin/openssl}"

if [[ ! -x "$OPENSSL" ]]; then
	OPENSSL="${TONGSUO}/apps/openssl"
fi

if [[ ! -f "${DIR}/cert_verify.so" ]]; then
	make -C "$DIR" cert_verify.so
fi

# 必须优先加载含双重验签逻辑的 Tongsuo libcrypto（不用 cp，用库路径覆盖）
export LD_LIBRARY_PATH="${TONGSUO}:${PQMAGIC_LIB}:${LD_LIBRARY_PATH:-}"
export OPENSSL_CONF
export OPENSSL_MODULES="${PQMAGIC_MOD}"
export CERT_VERIFY_SO="${DIR}/cert_verify.so"
export CERT_VERIFY_VERIFY_INFO="${CERT_VERIFY_VERIFY_INFO:-1}"

exec "$OPENSSL" verify "$@"
