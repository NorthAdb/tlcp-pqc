#!/usr/bin/env python3
"""
Generate PKCS#10 CSR for tlcp-pqc/certs/1 (pure PQC).

Inputs (recommended):
  --key  PKCS#8 private key PEM (e.g. user_sig_pkcs8.pem)
  --cert matching certificate PEM (subject + SPKI taken from TBSCertificate)

Legacy batch mode still accepts raw PQMagic *.key (PRIVATE KEY + PUBLIC KEY blocks).

Signing uses ML-DSA-44-with-SM3 over SM3(CertificationRequestInfo) via mldsa_sign_sm3.exe.

openssl req -new is not used: Tongsuo still fails at X509_PUBKEY_set for ML-DSA-44-SPKI.
"""

from __future__ import annotations

import argparse
import base64
import re
import subprocess
import sys
import tempfile
from pathlib import Path

OID_MLDSA44_SPKI = "1.2.156.10197.1.304.1"
OID_MLKEM512_SPKI = "1.2.156.10197.1.303.1"
OID_MLDSA44_SM3 = "1.2.156.10197.1.505.1"

ML_DSA_44_PUBLICKEYBYTES = 1312
ML_DSA_44_SECRETKEYBYTES = 2560
ML_DSA_44_SIGBYTES = 2420
ML_KEM_512_PUBLICKEYBYTES = 800
ML_KEM_512_SECRETKEYBYTES = 1632

KEY_PROFILES = {
    "root": ("mldsa", ML_DSA_44_PUBLICKEYBYTES, ML_DSA_44_SECRETKEYBYTES),
    "yunying": ("mldsa", ML_DSA_44_PUBLICKEYBYTES, ML_DSA_44_SECRETKEYBYTES),
    "user_sig": ("mldsa", ML_DSA_44_PUBLICKEYBYTES, ML_DSA_44_SECRETKEYBYTES),
    "user_enc": ("mlkem", ML_KEM_512_PUBLICKEYBYTES, ML_KEM_512_SECRETKEYBYTES),
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


def openssl_bin(explicit: str | None) -> str:
    return explicit or "openssl"


def cert_to_der(cert_pem: Path, openssl: str) -> bytes:
    return subprocess.check_output(
        [openssl, "x509", "-in", str(cert_pem), "-outform", "DER"],
        stderr=subprocess.STDOUT,
        timeout=30,
    )


def extract_subject_der(cert_pem: Path, openssl: str = "openssl") -> bytes:
    der = cert_to_der(cert_pem, openssl)
    _, _, _, cert_body = read_tlv(der, 0)
    _, _, _, tbs = read_tlv(cert_body, 0)
    tbs_off = 0
    if tbs[tbs_off] == 0xA0:
        _, _, tbs_off, _ = read_tlv(tbs, tbs_off)
    for _ in range(4):
        _, _, tbs_off, _ = read_tlv(tbs, tbs_off)
    tag, subj_start, subj_end, _ = read_tlv(tbs, tbs_off)
    if tag != 0x30:
        raise ValueError(f"expected subject SEQUENCE, got tag 0x{tag:02x}")
    return tbs[subj_start:subj_end]


def extract_spki_der(cert_pem: Path, openssl: str = "openssl") -> bytes:
    """SubjectPublicKeyInfo from TBSCertificate (not openssl x509 -pubkey)."""
    der = cert_to_der(cert_pem, openssl)
    _, _, _, cert_body = read_tlv(der, 0)
    _, _, _, tbs = read_tlv(cert_body, 0)
    tbs_off = 0
    if tbs[tbs_off] == 0xA0:
        _, _, tbs_off, _ = read_tlv(tbs, tbs_off)
    for _ in range(5):
        _, _, tbs_off, _ = read_tlv(tbs, tbs_off)
    tag, spki_start, spki_end, _ = read_tlv(tbs, tbs_off)
    if tag != 0x30:
        raise ValueError(f"expected SPKI SEQUENCE, got tag 0x{tag:02x}")
    return tbs[spki_start:spki_end]


def raw_pk_from_spki(spki: bytes) -> bytes:
    _, _, _, spki_body = read_tlv(spki, 0)
    _, _, off, _ = read_tlv(spki_body, 0)
    tag, _, _, bitstr = read_tlv(spki_body, off)
    if tag != 0x03 or len(bitstr) < 2:
        raise ValueError("invalid SPKI BIT STRING")
    return bitstr[1:]


def load_private_key_der(key_path: Path) -> bytes:
    text = key_path.read_text(encoding="ascii")
    m = re.search(
        r"-----BEGIN PRIVATE KEY-----\s*(.*?)\s*-----END PRIVATE KEY-----",
        text,
        re.S,
    )
    if not m:
        raise ValueError(f"{key_path}: missing PRIVATE KEY PEM block")
    return base64.b64decode("".join(m.group(1).split()))


def load_raw_sk_from_pkcs8(key_path: Path) -> bytes:
    der = load_private_key_der(key_path)
    _, _, _, p8_body = read_tlv(der, 0)
    off = 0
    _, _, off, _ = read_tlv(p8_body, off)
    _, _, off, _ = read_tlv(p8_body, off)
    tag, _, _, octets = read_tlv(p8_body, off)
    if tag != 0x04:
        raise ValueError(f"{key_path}: PKCS#8 privateKey is not OCTET STRING")
    if len(octets) == ML_DSA_44_SECRETKEYBYTES:
        return octets
    if octets and octets[0] == 0x04:
        _, _, _, octets = read_tlv(octets, 0)
    if len(octets) != ML_DSA_44_SECRETKEYBYTES:
        raise ValueError(
            f"{key_path}: expected {ML_DSA_44_SECRETKEYBYTES}-byte ML-DSA secret key, "
            f"got {len(octets)}"
        )
    return octets


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


def is_raw_pq_key_pem(key_path: Path) -> bool:
    text = key_path.read_text(encoding="ascii")
    return "BEGIN PUBLIC KEY" in text


def load_signing_material(
    key_path: Path, cert_path: Path, openssl: str
) -> tuple[bytes, bytes, bytes]:
    subject = extract_subject_der(cert_path, openssl)
    spki = extract_spki_der(cert_path, openssl)
    raw_pk = raw_pk_from_spki(spki)

    if is_raw_pq_key_pem(key_path):
        raw_sk, raw_pk_key = split_key_pem(key_path)
        if raw_pk_key != raw_pk:
            raise ValueError(
                f"{key_path} public key does not match SPKI in {cert_path.name}"
            )
    else:
        raw_sk = load_raw_sk_from_pkcs8(key_path)

    if len(raw_pk) == ML_DSA_44_PUBLICKEYBYTES:
        profile = "mldsa"
    elif len(raw_pk) == ML_KEM_512_PUBLICKEYBYTES:
        profile = "mlkem"
    else:
        raise ValueError(f"unsupported public key length {len(raw_pk)} in certificate")

    return subject, spki, raw_sk if profile == "mldsa" else b""


def build_spki(profile: str, raw_pk: bytes) -> bytes:
    if profile == "mldsa":
        if len(raw_pk) != ML_DSA_44_PUBLICKEYBYTES:
            raise ValueError(
                f"ML-DSA public key expected {ML_DSA_44_PUBLICKEYBYTES} bytes, got {len(raw_pk)}"
            )
        alg = der_seq(der_oid(OID_MLDSA44_SPKI), der_null())
    else:
        if len(raw_pk) != ML_KEM_512_PUBLICKEYBYTES:
            raise ValueError(
                f"ML-KEM public key expected {ML_KEM_512_PUBLICKEYBYTES} bytes, got {len(raw_pk)}"
            )
        alg = der_seq(der_oid(OID_MLKEM512_SPKI), der_null())
    return der_seq(alg, der_bit_string(raw_pk))


def build_cert_req_info(subject: bytes, spki: bytes) -> bytes:
    return der_seq(der_int0(), subject, spki)


def sm3(data: bytes, openssl: str = "openssl") -> bytes:
    p = subprocess.run(
        [openssl, "dgst", "-sm3", "-binary"],
        input=data,
        capture_output=True,
        check=True,
        timeout=30,
    )
    return p.stdout


def mldsa_sign(signer: Path, sk: bytes, digest: bytes) -> bytes:
    if len(sk) != ML_DSA_44_SECRETKEYBYTES:
        raise ValueError(f"ML-DSA secret key expected {ML_DSA_44_SECRETKEYBYTES} bytes")
    if len(digest) != 32:
        raise ValueError("digest must be 32-byte SM3 hash")
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        sk_path = td_path / "sk.bin"
        dg_path = td_path / "digest.bin"
        sig_path = td_path / "signature.bin"
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
        sig = sig_path.read_bytes()
        if not sig:
            raise RuntimeError("mldsa_sign_sm3 returned empty signature")
        return sig


def mldsa_verify(signer: Path, pk: bytes, digest: bytes, signature: bytes) -> bool:
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        pk_path = td_path / "pk.bin"
        dg_path = td_path / "digest.bin"
        sig_path = td_path / "sig.bin"
        pk_path.write_bytes(pk)
        dg_path.write_bytes(digest)
        sig_path.write_bytes(signature)
        p = subprocess.run(
            [str(signer), "verify", str(pk_path), str(dg_path), str(sig_path)],
            capture_output=True,
            timeout=60,
        )
        return p.returncode == 0


def build_csr_from_parts(
    subject: bytes, spki: bytes, raw_sk: bytes, signer: Path, openssl: str
) -> bytes:
    cri = build_cert_req_info(subject, spki)
    if not raw_sk:
        raise ValueError(
            "ML-KEM-512 是 KEM 密钥，无法自签 PKCS#10 CSR；"
            "请使用 ML-DSA 签名密钥（如 user_sig）。"
        )
    digest = sm3(cri, openssl)
    signature = mldsa_sign(signer, raw_sk, digest)
    sig_alg = der_seq(der_oid(OID_MLDSA44_SM3), der_null())
    return der_seq(cri, sig_alg, der_bit_string(signature))


def pem_csr(der: bytes) -> str:
    b64 = base64.encodebytes(der).decode("ascii").replace("\n", "")
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    return (
        "-----BEGIN CERTIFICATE REQUEST-----\n"
        + "\n".join(lines)
        + "\n-----END CERTIFICATE REQUEST-----\n"
    )


def verify_csr_der(
    csr_der: bytes, raw_pk: bytes, signer: Path, openssl: str
) -> None:
    _, _, _, csr_body = read_tlv(csr_der, 0)
    _, cri_start, cri_end, _ = read_tlv(csr_body, 0)
    cri = csr_body[cri_start:cri_end]
    digest = sm3(cri, openssl)
    _, _, off, _ = read_tlv(csr_body, 0)
    _, _, off, _ = read_tlv(csr_body, off)
    _, _, _, sig_val = read_tlv(csr_body, off)
    if not mldsa_verify(signer, raw_pk, digest, sig_val[1:]):
        raise RuntimeError("CSR 自签验签失败（mldsa_sign_sm3）")


def generate_one(
    key_path: Path,
    cert_path: Path,
    out_path: Path,
    signer: Path,
    openssl: str,
) -> None:
    subject, spki, raw_sk = load_signing_material(key_path, cert_path, openssl)
    raw_pk = raw_pk_from_spki(spki)
    csr_der = build_csr_from_parts(subject, spki, raw_sk, signer, openssl)
    verify_csr_der(csr_der, raw_pk, signer, openssl)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(pem_csr(csr_der), encoding="ascii")


def resolve_batch_key(certs_dir: Path, name: str) -> Path:
    pkcs8 = certs_dir / f"{name}_pkcs8.pem"
    if pkcs8.is_file():
        return pkcs8
    return certs_dir / f"{name}.key"


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    bin_dir = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        description="Generate pure PQC PKCS#10 CSR for tlcp-pqc/certs/1"
    )
    parser.add_argument(
        "--key",
        type=Path,
        help="PKCS#8 或裸 PQ 私钥 PEM（推荐 *_pkcs8.pem）",
    )
    parser.add_argument(
        "--cert",
        type=Path,
        help="对应证书 PEM（从中提取 Subject 与 SPKI）",
    )
    parser.add_argument(
        "--out",
        type=Path,
        help="输出 CSR 路径（单文件模式）",
    )
    parser.add_argument("--certs-dir", type=Path, default=root / "certs" / "1")
    parser.add_argument("--out-dir", type=Path, default=None)
    parser.add_argument(
        "--signer",
        type=Path,
        default=bin_dir / "mldsa_sign_sm3.exe",
        help="mldsa_sign_sm3.exe（build via bin/build-mldsa-sign.bat）",
    )
    parser.add_argument(
        "--openssl",
        default=openssl_bin(None),
        help="openssl 可执行文件路径",
    )
    parser.add_argument(
        "--names",
        nargs="*",
        default=["root", "yunying", "user_sig"],
        help="批量模式：要生成的名称（默认不含 user_enc）",
    )
    args = parser.parse_args()

    if not args.signer.is_file():
        print(
            f"ERROR: 未找到 {args.signer}\n"
            f"请先运行: {bin_dir / 'build-mldsa-sign.bat'}",
            file=sys.stderr,
        )
        return 1

    if args.key and args.cert:
        out_path = args.out
        if out_path is None:
            out_path = args.key.parent / f"{args.cert.stem}.csr"
        try:
            generate_one(args.key, args.cert, out_path, args.signer, args.openssl)
            print(f"OK   {args.key.name} + {args.cert.name} -> {out_path}")
            print(f"验证: {args.openssl} req -in {out_path} -verify -noout")
            return 0
        except Exception as exc:
            print(f"FAIL: {exc}", file=sys.stderr)
            return 1

    out_dir = args.out_dir or (args.certs_dir / "csr")
    ok = skipped = 0
    for name in args.names:
        key_path = resolve_batch_key(args.certs_dir, name)
        crt_path = args.certs_dir / f"{name}.crt"
        out_path = out_dir / f"{name}.csr"
        if not key_path.is_file() or not crt_path.is_file():
            print(f"SKIP {name}: 缺少 {key_path.name} 或 {crt_path.name}")
            skipped += 1
            continue
        try:
            generate_one(key_path, crt_path, out_path, args.signer, args.openssl)
            print(f"OK   {name} ({key_path.name}) -> {out_path}")
            ok += 1
        except Exception as exc:
            print(f"FAIL {name}: {exc}", file=sys.stderr)
            skipped += 1

    print(f"\n完成: 成功 {ok}，失败/跳过 {skipped} -> {out_dir}")
    return 0 if ok and not skipped else (1 if not ok else 0)


if __name__ == "__main__":
    sys.exit(main())
