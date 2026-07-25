#!/usr/bin/env bash
# certs/2 证书链 openssl verify（ML-DSA-44-SM2 + ML-KEM-512-SM2）
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TONGSUO="${TONGSUO:-/home/wang/Desktop/Tongsuo}"
CERTS="${CERTS:-/home/wang/Desktop/certs/2}"
OPENSSL="${OPENSSL:-${TONGSUO}/apps/openssl}"

export LD_LIBRARY_PATH="${TONGSUO}:${LD_LIBRARY_PATH:-}"
# 可选；未设置时 libcrypto 会自动加载 provider 与 cert_verify.so
export OPENSSL_CONF="${OPENSSL_CONF:-${DIR}/openssl-all-providers.cnf}"
export CERT_VERIFY_SO="${CERT_VERIFY_SO:-${DIR}/cert_verify.so}"

exec "$OPENSSL" verify \
  -CAfile "${CERTS}/root.crt" \
  -untrusted "${CERTS}/yunying.crt" \
  "${CERTS}/user_sig.crt" \
  "${CERTS}/user_enc.crt" \
  "$@"
