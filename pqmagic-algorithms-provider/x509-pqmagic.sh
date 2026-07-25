#!/usr/bin/env bash
# 使用本仓库的 pqmagic provider 调用 openssl（需已构建 build/pqmagic.so）
# 与 Tongsuo 同源的 libcrypto 对象表一致时，请用 Tongsuo 的 apps/openssl 并设置：
#   export LD_LIBRARY_PATH=/path/to/Tongsuo
#   export OPENSSL_MODULES="$(cd "$(dirname "$0")" && pwd)/build"
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
PROV="$DIR/build/pqmagic.so"
export OPENSSL_MODULES="${OPENSSL_MODULES:-$DIR/build}"
OSSL="${OPENSSL:-openssl}"
exec "$OSSL" "$@" -provider default -provider "$PROV"
