#!/usr/bin/env bash
# 恢复 /usr/local/lib/lib64/libcrypto.so.3 并指向当前 Tongsuo 构建（需 root）
# 若 sudo 因缺少 libcrypto 失效，请先在 root 终端执行本脚本，或：
#   LD_LIBRARY_PATH=/home/wang/Desktop/Tongsuo pkexec bash /home/wang/Desktop/x509-hybrid-verify-provider/scripts/fix-openssl-libcrypto.sh
set -euo pipefail

TONGSUO="${TONGSUO:-/home/wang/Desktop/Tongsuo}"
SRC="${TONGSUO}/libcrypto.so.3"

if [[ ! -f "$SRC" ]]; then
	echo "未找到: $SRC，请先在 Tongsuo 目录执行 make" >&2
	exit 1
fi

for dest in /usr/local/lib/lib64/libcrypto.so.3 /usr/local/lib64/libcrypto.so.3; do
	ln -sf "$SRC" "$dest"
	echo "OK: $dest -> $SRC"
done

echo "完成。可执行: openssl verify ...（无需 LD_LIBRARY_PATH）"
