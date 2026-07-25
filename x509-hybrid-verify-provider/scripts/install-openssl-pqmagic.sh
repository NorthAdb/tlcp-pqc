#!/usr/bin/env bash
# 配置 pqmagic + Tongsuo 混合验签，不使用 cp 大文件（避免 SSH 断开）。
#
# 做法：
#   1) openssl.cnf 用 module= 指向 pqmagic.so 绝对路径（无需复制到 ossl-modules）
#   2) 若 openssl 仍链到旧 libcrypto，用 ln -sf 指到新库（秒级，不复制）
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PQMAGIC_SO="${PQMAGIC_SO:-/home/wang/Desktop/pqmagic-algorithms-provider/build/pqmagic.so}"
OPENSSL_CNF="${OPENSSL_CNF:-/usr/local/ssl/openssl.cnf}"
NEW_CRYPTO="${NEW_CRYPTO:-/usr/local/lib64/libcrypto.so.3}"
OLD_CRYPTO="${OLD_CRYPTO:-/usr/local/lib/lib64/libcrypto.so.3}"

if [[ ! -f "$PQMAGIC_SO" ]]; then
	echo "未找到 pqmagic.so: $PQMAGIC_SO" >&2
	exit 1
fi

# --- 1) openssl.cnf：pqmagic 用绝对路径 ---
if ! grep -q 'pqmagic = pqmagic_sect' "$OPENSSL_CNF" 2>/dev/null; then
	echo "请手动在 $OPENSSL_CNF 的 [provider_sect] 加入: pqmagic = pqmagic_sect"
else
	if ! grep -q '^\[pqmagic_sect\]' "$OPENSSL_CNF" 2>/dev/null; then
		cat >>"$OPENSSL_CNF" <<EOF

# hybrid PQC (ML-DSA) — added by x509-hybrid-verify-provider
[pqmagic_sect]
module = $PQMAGIC_SO
activate = 1
EOF
		echo "已在 openssl.cnf 追加 [pqmagic_sect]（module 绝对路径，无需 cp）"
	else
		# 若已有段但无 module=，提示用户改为绝对路径
		if ! grep -q "^module = " "$OPENSSL_CNF" 2>/dev/null; then
			echo "建议在 [pqmagic_sect] 中加入: module = $PQMAGIC_SO"
		fi
	fi
fi

# --- 2) libcrypto：仅当两路径不同且新库更新时用符号链接 ---
if [[ -f "$NEW_CRYPTO" && -f "$OLD_CRYPTO" ]]; then
	if [[ "$NEW_CRYPTO" -ef "$OLD_CRYPTO" ]]; then
		echo "libcrypto 已是同一文件，无需处理"
	elif [[ "$NEW_CRYPTO" -nt "$OLD_CRYPTO" ]]; then
		echo "建议执行（ln 不复制数据，比 cp 快）:"
		echo "  sudo ln -sf $NEW_CRYPTO $OLD_CRYPTO"
	fi
fi

echo ""
echo "完成后可直接运行:"
echo "  openssl verify -CAfile certs/3/root.crt -untrusted certs/3/yunying.crt \\"
echo "    certs/3/user_sig.crt certs/3/user_enc.crt"
echo ""
echo "Tongsuo 需在 x509_vfy 中已集成 ossl_x509_verify_pqc_hybrid（见 Tongsuo/crypto/x509/）。"
