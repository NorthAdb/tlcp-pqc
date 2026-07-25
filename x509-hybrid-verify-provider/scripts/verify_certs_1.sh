#!/usr/bin/env bash
# x509-hybrid-verify-provider 验签工具
#   ./scripts/verify_certs_1.sh [目录]              # 整条链
#   ./scripts/verify_certs_1.sh 签发者.crt 证书.crt  # 单张，如 root.crt yunying.crt
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TONGSUO="${TONGSUO:-/home/wang/Desktop/Tongsuo}"
PQMAGIC_LIB="${PQMAGIC_LIB:-/home/wang/Desktop/pqmagic/install/lib}"
PQMAGIC_MOD="${PQMAGIC_MOD:-/home/wang/Desktop/pqmagic-algorithms-provider/build}"

export LD_LIBRARY_PATH="${TONGSUO}:${PQMAGIC_LIB}:${LD_LIBRARY_PATH:-}"
export OPENSSL_MODULES="${PQMAGIC_MOD}"
export CERT_VERIFY_PROVIDER_PATH="${PQMAGIC_MOD}"

TOOL="${DIR}/verify_certs_1"
if [[ ! -x "$TOOL" ]]; then
	echo "正在编译 x509-hybrid-verify-provider ..."
	make -C "$DIR"
fi

if [[ $# -eq 0 ]]; then
	set -- /home/wang/Desktop/certs/3
fi
exec "$TOOL" "$@"
