#!/usr/bin/env bash
# 使用 Tongsuo 的 openssl，并加载 build/pqmagic.so，以解析/显示国密 PQ 证书公钥
#（OID 1.2.156.10197.1.304.1 ML-DSA-44、1.2.156.10197.1.303.1 ML-KEM-512）
#
# 用法：第一个参数必须是 openssl 子命令（与直接运行 openssl 相同），例如：
#   ./tongsuo-openssl-pqmagic.sh x509 -in /path/to/cert.crt -noout -text
#   ./tongsuo-openssl-pqmagic.sh list -providers
#
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TONGSUO="${TONGSUO:-/home/wang/Desktop/Tongsuo}"
PQ_INSTALL="${PQ_INSTALL:-/home/wang/Desktop/pqmagic/install/lib}"
PROV_DIR="$DIR/build"

export LD_LIBRARY_PATH="${TONGSUO}:${PQ_INSTALL}:/usr/local/lib:${LD_LIBRARY_PATH:-}"

if [ "$#" -eq 0 ]; then
  echo "用法: $0 <openssl 子命令> [参数...]" >&2
  echo "示例: $0 x509 -in cert.crt -noout -text" >&2
  exit 1
fi

SUB="$1"
shift
exec "${TONGSUO}/apps/openssl" "$SUB" \
  -provider-path "$PROV_DIR" \
  -provider default \
  -provider pqmagic \
  "$@"
