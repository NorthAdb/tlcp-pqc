#!/usr/bin/env python3
"""
Generate PKCS#10 CSR for Hybrid Concatenated Certificate/mlkemdsa (ML-DSA-44-SM2 / ML-KEM-512-SM2).

思路与 Pure PQC (mlkemdsa) 一致：
1. 从现有证书提取 subject；
2. 从 .key 的 PUBLIC KEY 块读取 PQC 裸公钥；
3. 从 *_sm2.key 导出 SM2 公钥点；
4. 手工拼装复合 SPKI：
   - ML-DSA-44-SM2  -> 1.2.156.10197.1.508.1
   - ML-KEM-512-SM2 -> 1.2.156.10197.1.507.1
5. 对 CertificationRequestInfo 做双签名：
   - ML-DSA-44-with-SM3：签名对象为 SM3(CRI)
   - SM2-with-SM3：签名对象为 CRI（由 openssl dgst -sm3 -sign 完成）

说明：
- root / yunying / user_sig 可生成标准“复合签名” CSR
- user_enc 不生成：其 PQC 部分为 ML-KEM，不具备签名能力，无法构造标准自签 PKCS#10
"""

from __future__ import annotations

import argparse
import base64
import re
import subprocess
import sys
import tempfile
from pathlib import Path

OID_MLKEM512_SM2 = "1.2.156.10197.1.507.1"
OID_MLDSA44_SM2 = "1.2.156.10197.1.508.1"
OID_MLDSA44_SM2_WITH_SM3 = "1.2.156.10197.1.506.1"

ML_DSA_44_PUBLICKEYBYTES = 1312
ML_DSA_44_SECRETKEYBYTES = 2560
ML_KEM_512_PUBLICKEYBYTES = 800
SM2_PUBLICKEYBYTES = 65

KEY_PROFILES = {
    "root": ("mldsa_sm2", ML_DSA_44_PUBLICKEYBYTES, ML_DSA_44_SECRETKEYBYTES),
    "yunying": ("mldsa_sm2", ML_DSA_44_PUBLICKEYBYTES, ML_DSA_44_SECRETKEYBYTES),
    "user_sig": ("mldsa_sm2", ML_DSA_44_PUBLICKEYBYTES, ML_DSA_44_SECRETKEYBYTES),
    "user_enc": ("mlkem_sm2", ML_KEM_512_PUBLICKEYBYTES, 1632),
}


def der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = []
    while n:
        out.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(out)]) + bytes(out)


def der_tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + der_len(len(content)) + content


def der_seq(*parts: bytes) -> bytes:
    return der_tlv(0x30, b"".join(parts))


def der_oid(dotted: str) -> bytes:
    parts = [int(x) for x in dotted.split(".")]
    first = 40 * parts[0] + parts[1]
    enc = [first]
    for p in parts[2:]:
        stack = []
        while p:
            stack.insert(0, p & 0x7F)
            p >>= 7
        for i, b in enumerate(stack):
            enc.append((0x80 | b) if i < len(stack) - 1 else b)
    return der_tlv(0x06, bytes(enc))


def der_null() -> bytes:
    return der_tlv(0x05, b"")


def der_int0() -> bytes:
    return der_tlv(0x02, b"\x00")


def der_bit_string(raw: bytes) -> bytes:
    return der_tlv(0x03, b"\x00" + raw)


def read_tlv(data: bytes, off: int = 0) -> tuple[int, int, int, bytes]:
    start = off
    tag = data[off]
    off += 1
    lb = data[off]
    off += 1
    if lb & 0x80:
        n = lb & 0x7F
        length = int.from_bytes(data[off : off + n], "big")
        off += n
    else:
        length = lb
    value = data[off : off + length]
    return tag, start, off + length, value


def extract_subject_der(cert_pem: Path) -> bytes:
    der = subprocess.check_output(
        ["openssl", "x509", "-in", str(cert_pem), "-outform", "DER"],
        stderr=subprocess.DEVNULL,
        timeout=30,
    )
    _, _, _, cert_body = read_tlv(der, 0)
    _, _, _, tbs = read_tlv(cert_body, 0)
    off = 0
    if tbs[off] == 0xA0:
        _, _, off, _ = read_tlv(tbs, off)
    for _ in range(4):  # serial, sigAlg, issuer, validity
        _, _, off, _ = read_tlv(tbs, off)
    tag, subj_start, subj_end, _ = read_tlv(tbs, off)
    if tag != 0x30:
        raise ValueError(f"expected subject SEQUENCE, got tag 0x{tag:02x}")
    return tbs[subj_start:subj_end]


def split_key_pem(key_path: Path) -> tuple[bytes, bytes]:
    text = key_path.read_text(encoding="ascii")
    priv_m = re.search(
        r"-----BEGIN PRIVATE KEY-----\s*(.*?)\s*-----END PRIVATE KEY-----",
        text,
        re.S,
    )
    pub_m = re.search(
        r"-----BEGIN PUBLIC KEY-----\s*(.*?)\s*-----END PUBLIC KEY-----",
        text,
        re.S,
    )
    if not priv_m or not pub_m:
        raise ValueError(f"{key_path}: missing PRIVATE KEY or PUBLIC KEY block")
    priv = base64.b64decode("".join(priv_m.group(1).split()))
    pub = base64.b64decode("".join(pub_m.group(1).split()))
    return priv, pub


def extract_sm2_pub_raw(sm2_key_path: Path) -> bytes:
    with tempfile.TemporaryDirectory() as td:
        pub_der = Path(td) / "sm2pub.der"
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(sm2_key_path),
                "-pubout",
                "-outform",
                "DER",
                "-out",
                str(pub_der),
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )
        der = pub_der.read_bytes()
        if len(der) < SM2_PUBLICKEYBYTES:
            raise ValueError(f"{sm2_key_path}: SM2 public DER too short")
        raw = der[-SM2_PUBLICKEYBYTES:]
        if len(raw) != SM2_PUBLICKEYBYTES or raw[0] != 0x04:
            raise ValueError(f"{sm2_key_path}: invalid SM2 public point")
        return raw


def build_spki(profile: str, pqc_pk: bytes, sm2_pk: bytes) -> bytes:
    if len(sm2_pk) != SM2_PUBLICKEYBYTES:
        raise ValueError("SM2 public key must be 65 bytes (04 || X || Y)")
    if profile == "mldsa_sm2":
        if len(pqc_pk) != ML_DSA_44_PUBLICKEYBYTES:
            raise ValueError("ML-DSA-44 public key length mismatch")
        oid = OID_MLDSA44_SM2
    elif profile == "mlkem_sm2":
        if len(pqc_pk) != ML_KEM_512_PUBLICKEYBYTES:
            raise ValueError("ML-KEM-512 public key length mismatch")
        oid = OID_MLKEM512_SM2
    else:
        raise ValueError(f"unknown profile: {profile}")
    alg = der_seq(der_oid(oid), der_null())
    return der_seq(alg, der_bit_string(pqc_pk + sm2_pk))


def build_cert_req_info(subject: bytes, spki: bytes) -> bytes:
    return der_seq(der_int0(), subject, spki)


def sm3(data: bytes, openssl: str = "openssl", env: dict | None = None) -> bytes:
    p = subprocess.run(
        [openssl, "dgst", "-sm3", "-binary"],
        input=data,
        capture_output=True,
        check=True,
        timeout=30,
        env=env,
    )
    return p.stdout


def mldsa_sign(signer: Path, sk: bytes, digest: bytes) -> bytes:
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        sk_path = td_path / "sk.bin"
        dg_path = td_path / "digest.bin"
        sig_path = td_path / "sig.bin"
        sk_path.write_bytes(sk)
        dg_path.write_bytes(digest)
        p = subprocess.run(
            [str(signer), "sign", str(sk_path), str(dg_path), str(sig_path)],
            capture_output=True,
            timeout=60,
        )
        if p.returncode != 0:
            err = p.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"mldsa_sign_sm3 sign failed: {err}")
        return sig_path.read_bytes()


def sm2_sign(
    sm2_key_path: Path,
    message: bytes,
    openssl: str = "openssl",
    env: dict | None = None,
) -> bytes:
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        msg_path = td_path / "cri.der"
        sig_path = td_path / "sm2sig.der"
        msg_path.write_bytes(message)
        p = subprocess.run(
            [
                openssl,
                "dgst",
                "-sm3",
                "-sign",
                str(sm2_key_path),
                "-out",
                str(sig_path),
                str(msg_path),
            ],
            capture_output=True,
            timeout=60,
            env=env,
        )
        if p.returncode != 0:
            err = p.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"SM2 sign failed: {err}")
        return sig_path.read_bytes()


def build_csr(
    profile: str,
    subject: bytes,
    pqc_pk: bytes,
    pqc_sk: bytes,
    sm2_pk: bytes,
    sm2_key_path: Path,
    signer: Path,
    openssl: str = "openssl",
    env: dict | None = None,
) -> bytes:
    spki = build_spki(profile, pqc_pk, sm2_pk)
    cri = build_cert_req_info(subject, spki)
    if profile != "mldsa_sm2":
        raise ValueError(
            "ML-KEM-512-SM2 属于加密/KEM 复合公钥，PQC 部分不具备签名能力；"
            "当前不生成 user_enc 的标准自签 PKCS#10 CSR。"
        )
    mldsa_sig = mldsa_sign(signer, pqc_sk, sm3(cri, openssl=openssl, env=env))
    sm2_sig = sm2_sign(sm2_key_path, cri, openssl=openssl, env=env)
    sig_alg = der_seq(der_oid(OID_MLDSA44_SM2_WITH_SM3), der_null())
    return der_seq(cri, sig_alg, der_bit_string(mldsa_sig + sm2_sig))


def pem_csr(der: bytes) -> str:
    b64 = base64.encodebytes(der).decode("ascii").replace("\n", "")
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    return (
        "-----BEGIN CERTIFICATE REQUEST-----\n"
        + "\n".join(lines)
        + "\n-----END CERTIFICATE REQUEST-----\n"
    )


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description="Generate CSR for Hybrid Concatenated Certificate/mlkemdsa")
    parser.add_argument("--certs-dir", type=Path, default=root / "certs" / "Hybrid Concatenated Certificate" / "mlkemdsa")
    parser.add_argument("--out-dir", type=Path, default=None)
    parser.add_argument(
        "--signer",
        type=Path,
        default=Path(__file__).resolve().parent / "mldsa_sign_sm3.exe",
    )
    parser.add_argument(
        "--names",
        nargs="*",
        default=["root", "yunying", "user_sig"],
        help="默认不含 user_enc：其 PQC 部分是 ML-KEM，无法生成标准自签 CSR",
    )
    args = parser.parse_args()
    out_dir = args.out_dir or (args.certs_dir / "csr")
    out_dir.mkdir(parents=True, exist_ok=True)

    if not args.signer.is_file():
        print(f"ERROR: 未找到 {args.signer}", file=sys.stderr)
        return 1

    ok = 0
    skipped = 0
    for name in args.names:
        profile, _, _ = KEY_PROFILES[name]
        key_path = args.certs_dir / f"{name}.key"
        sm2_key_path = args.certs_dir / f"{name}_sm2.key"
        crt_path = args.certs_dir / f"{name}.crt"
        out_path = out_dir / f"{name}.csr"

        if not key_path.is_file() or not crt_path.is_file() or not sm2_key_path.is_file():
            print(f"SKIP {name}: 缺少 {key_path.name} / {sm2_key_path.name} / {crt_path.name}")
            skipped += 1
            continue

        try:
            pqc_sk, pqc_pk = split_key_pem(key_path)
            sm2_pk = extract_sm2_pub_raw(sm2_key_path)
            subject = extract_subject_der(crt_path)
            csr_der = build_csr(
                profile,
                subject,
                pqc_pk,
                pqc_sk,
                sm2_pk,
                sm2_key_path,
                args.signer,
            )
            out_path.write_text(pem_csr(csr_der), encoding="ascii")
            print(f"OK   {name} -> {out_path}")
            ok += 1
        except Exception as exc:
            print(f"FAIL {name}: {exc}", file=sys.stderr)
            skipped += 1

    print(f"\n完成: 成功 {ok}，失败/跳过 {skipped} -> {out_dir}")
    return 0 if ok and not skipped else (1 if not ok else 0)


if __name__ == "__main__":
    sys.exit(main())
