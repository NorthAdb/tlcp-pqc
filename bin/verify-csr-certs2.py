#!/usr/bin/env python3
"""
Verify PKCS#10 CSR for Hybrid Concatenated Certificate/mlkemdsa (ML-DSA-44-SM2 composite self-signature).

Dual verification (aligned with cert_verify_mldsa44_sm2_composite / gen-csr-certs2.py):
  [1/2] ML-DSA-44-with-SM3: SM3(CertificationRequestInfo) vs ML-DSA segment (2420 B)
  [2/2] SM2-with-SM3:        full CRI vs SM2 segment (openssl dgst -sm3 -verify)

openssl req -verify does not handle OID 1.2.156.10197.1.506.1 composite signatures.
"""

from __future__ import annotations

import argparse
import base64
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

OID_EC = "1.2.840.10045.2.1"
OID_SM2 = "1.2.156.10197.1.301"
OID_MLDSA44_SM2 = "1.2.156.10197.1.508.1"
OID_MLDSA44_SM2_WITH_SM3 = "1.2.156.10197.1.506.1"

ML_DSA_44_PUBLICKEYBYTES = 1312
ML_DSA_44_SIGBYTES = 2420
SM2_PUBLICKEYBYTES = 65

DEFAULT_NAMES = ("root", "yunying", "user_sig")


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


def oid_from_tlv(oid_tlv: bytes) -> str:
    if not oid_tlv or oid_tlv[0] != 0x06:
        raise ValueError("expected OID TLV")
    off = 1
    lb = oid_tlv[off]
    off += 1
    if lb & 0x80:
        n = lb & 0x7F
        length = int.from_bytes(oid_tlv[off : off + n], "big")
        off += n
    else:
        length = lb
    body = oid_tlv[off : off + length]
    if not body:
        raise ValueError("empty OID")
    first = body[0]
    parts = [first // 40, first % 40]
    val = 0
    for b in body[1:]:
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            parts.append(val)
            val = 0
    return ".".join(str(p) for p in parts)


def load_csr_der(path: Path) -> bytes:
    raw = path.read_bytes()
    if b"-----BEGIN CERTIFICATE REQUEST-----" in raw:
        text = raw.decode("ascii", errors="replace")
        b64 = "".join(
            line.strip()
            for line in text.splitlines()
            if line and not line.startswith("-----")
        )
        return base64.b64decode(b64)
    return raw


def parse_csr(der: bytes) -> tuple[bytes, str, bytes, bytes, bytes]:
    """Return (cri_der, sig_alg_oid, mldsa_sig, sm2_sig, spki_der)."""
    _, _, _, body = read_tlv(der, 0)
    off = 0
    _, cri_start, cri_end, _ = read_tlv(body, off)
    cri_der = body[cri_start:cri_end]
    off = cri_end
    _, sig_alg_start, sig_alg_end, _ = read_tlv(body, off)
    sig_alg_der = body[sig_alg_start:sig_alg_end]
    off = sig_alg_end
    _, _, _, sig_bits = read_tlv(body, off)
    if sig_bits and sig_bits[0] == 0:
        sig_raw = sig_bits[1:]
    else:
        sig_raw = sig_bits
    if len(sig_raw) <= ML_DSA_44_SIGBYTES:
        raise ValueError(
            f"composite signature too short: {len(sig_raw)} bytes "
            f"(expect > {ML_DSA_44_SIGBYTES})"
        )
    mldsa_sig = sig_raw[:ML_DSA_44_SIGBYTES]
    sm2_sig = sig_raw[ML_DSA_44_SIGBYTES:]

    _, _, _, sig_alg_body = read_tlv(sig_alg_der, 0)
    oid_tag, oid_start, oid_end, _ = read_tlv(sig_alg_body, 0)
    if oid_tag != 0x06:
        raise ValueError("expected signature algorithm OID")
    sig_alg_oid = oid_from_tlv(sig_alg_body[oid_start:oid_end])

    _, _, _, cri_body = read_tlv(cri_der, 0)
    off = 0
    _, _, off, _ = read_tlv(cri_body, off)  # version
    _, _, off, _ = read_tlv(cri_body, off)  # subject
    _, spki_start, spki_end, _ = read_tlv(cri_body, off)
    spki_der = cri_body[spki_start:spki_end]

    return cri_der, sig_alg_oid, mldsa_sig, sm2_sig, spki_der


def parse_mldsa44_sm2_spki(spki_der: bytes) -> tuple[bytes, bytes]:
    _, _, _, spki_body = read_tlv(spki_der, 0)
    off = 0
    _, alg_start, alg_end, _ = read_tlv(spki_body, off)
    alg_der = spki_body[alg_start:alg_end]
    off = alg_end
    _, _, _, alg_inner = read_tlv(alg_der, 0)
    oid_tag, oid_start, oid_end, _ = read_tlv(alg_inner, 0)
    if oid_tag != 0x06:
        raise ValueError("expected SPKI algorithm OID")
    oid = oid_from_tlv(alg_inner[oid_start:oid_end])
    if oid != OID_MLDSA44_SM2:
        raise ValueError(f"expected SPKI OID {OID_MLDSA44_SM2}, got {oid}")
    _, _, _, pk_bits = read_tlv(spki_body, off)
    if pk_bits and pk_bits[0] == 0:
        pk_raw = pk_bits[1:]
    else:
        pk_raw = pk_bits
    need = ML_DSA_44_PUBLICKEYBYTES + SM2_PUBLICKEYBYTES
    if len(pk_raw) < need:
        raise ValueError(f"composite SPKI bit string too short: {len(pk_raw)} < {need}")
    mldsa_pk = pk_raw[:ML_DSA_44_PUBLICKEYBYTES]
    sm2_pk = pk_raw[ML_DSA_44_PUBLICKEYBYTES : ML_DSA_44_PUBLICKEYBYTES + SM2_PUBLICKEYBYTES]
    if sm2_pk[0] != 0x04:
        raise ValueError("SM2 public point must start with 0x04")
    return mldsa_pk, sm2_pk


def build_sm2_spki(sm2_raw: bytes) -> bytes:
    alg = der_seq(der_oid(OID_EC), der_oid(OID_SM2))
    return der_seq(alg, der_bit_string(sm2_raw))


def sm3(data: bytes, openssl: str = "openssl") -> bytes:
    p = subprocess.run(
        [openssl, "dgst", "-sm3", "-binary"],
        input=data,
        capture_output=True,
        check=True,
        timeout=30,
    )
    return p.stdout


def mldsa_verify(
    verifier: Path, pk: bytes, digest: bytes, signature: bytes
) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        pk_path = td_path / "pk.bin"
        dg_path = td_path / "digest.bin"
        sig_path = td_path / "sig.bin"
        pk_path.write_bytes(pk)
        dg_path.write_bytes(digest)
        sig_path.write_bytes(signature)
        p = subprocess.run(
            [str(verifier), "verify", str(pk_path), str(dg_path), str(sig_path)],
            capture_output=True,
            timeout=60,
        )
        if p.returncode == 0:
            return True, "OK"
        err = p.stderr.decode("utf-8", errors="replace").strip()
        return False, err or "verify failed"


def sm2_verify(
    sm2_pk_raw: bytes,
    cri_der: bytes,
    sm2_sig: bytes,
    openssl: str = "openssl",
) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        spki_path = td_path / "sm2pub.der"
        pub_pem = td_path / "sm2pub.pem"
        cri_path = td_path / "cri.der"
        sig_path = td_path / "sm2sig.der"
        spki_path.write_bytes(build_sm2_spki(sm2_pk_raw))
        cri_path.write_bytes(cri_der)
        sig_path.write_bytes(sm2_sig)
        subprocess.run(
            [
                openssl,
                "pkey",
                "-pubin",
                "-inform",
                "DER",
                "-in",
                str(spki_path),
                "-out",
                str(pub_pem),
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )
        p = subprocess.run(
            [
                openssl,
                "dgst",
                "-sm3",
                "-verify",
                str(pub_pem),
                "-signature",
                str(sig_path),
                str(cri_path),
            ],
            capture_output=True,
            timeout=60,
        )
        if p.returncode == 0:
            return True, "OK"
        err = (p.stderr or p.stdout).decode("utf-8", errors="replace").strip()
        return False, err or "SM2 verify failed"


@dataclass
class VerifyResult:
    name: str
    path: Path
    sig_alg_oid: str
    cri_len: int
    mldsa_ok: bool
    sm2_ok: bool
    mldsa_detail: str = ""
    sm2_detail: str = ""

    @property
    def ok(self) -> bool:
        return self.mldsa_ok and self.sm2_ok


def verify_csr_file(
    csr_path: Path,
    verifier: Path,
    openssl: str = "openssl",
    label: str | None = None,
) -> VerifyResult:
    name = label or csr_path.stem
    der = load_csr_der(csr_path)
    cri_der, sig_alg_oid, mldsa_sig, sm2_sig, spki_der = parse_csr(der)
    if sig_alg_oid != OID_MLDSA44_SM2_WITH_SM3:
        raise ValueError(
            f"unsupported signature algorithm OID {sig_alg_oid} "
            f"(expect {OID_MLDSA44_SM2_WITH_SM3})"
        )
    mldsa_pk, sm2_pk = parse_mldsa44_sm2_spki(spki_der)
    digest = sm3(cri_der, openssl=openssl)
    mldsa_ok, mldsa_detail = mldsa_verify(verifier, mldsa_pk, digest, mldsa_sig)
    sm2_ok, sm2_detail = sm2_verify(sm2_pk, cri_der, sm2_sig, openssl=openssl)
    return VerifyResult(
        name=name,
        path=csr_path,
        sig_alg_oid=sig_alg_oid,
        cri_len=len(cri_der),
        mldsa_ok=mldsa_ok,
        sm2_ok=sm2_ok,
        mldsa_detail=mldsa_detail,
        sm2_detail=sm2_detail,
    )


def print_rules() -> None:
    print("=== CSR 验签规则 (Hybrid Concatenated / mlkemdsa) ===")
    print(f"  签名算法 OID: {OID_MLDSA44_SM2_WITH_SM3} (ML-DSA-44-SM2-with-SM3)")
    print(f"  SPKI OID:     {OID_MLDSA44_SM2} (ML-DSA-44-SM2)")
    print("  [1/2] ML-DSA-44-with-SM3: SM3(完整 CRI)，签名段前 2420 字节")
    print("  [2/2] SM2-with-SM3:       完整 CRI，签名段 SM2 部分 (openssl dgst -sm3)")
    print()


def print_result(res: VerifyResult) -> None:
    yn = lambda v: "OK" if v else "FAIL"
    print(f"--- {res.name} ({res.path.name}) ---")
    print(f"  CRI 长度:               {res.cri_len} 字节")
    print(f"  ML-DSA(SM3(CRI)):       {yn(res.mldsa_ok)}")
    if not res.mldsa_ok and res.mldsa_detail:
        print(f"    说明: {res.mldsa_detail}")
    print(f"  SM2(完整 CRI):          {yn(res.sm2_ok)}")
    if not res.sm2_ok and res.sm2_detail:
        print(f"    说明: {res.sm2_detail}")
    print(f"  结果:                   {yn(res.ok)}")
    print()


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(
        description="Verify ML-DSA-44-SM2 composite CSR (Hybrid Concatenated Certificate/mlkemdsa)"
    )
    parser.add_argument(
        "csr",
        nargs="*",
        type=Path,
        help="CSR 文件路径；省略时验 Hybrid Concatenated Certificate/mlkemdsa/csr 下默认三项",
    )
    parser.add_argument(
        "--certs-dir",
        type=Path,
        default=root / "certs" / "Hybrid Concatenated Certificate" / "mlkemdsa",
    )
    parser.add_argument("--csr-dir", type=Path, default=None)
    parser.add_argument(
        "--names",
        nargs="*",
        default=list(DEFAULT_NAMES),
        help="默认 CSR 名（不含扩展名）",
    )
    parser.add_argument(
        "--verifier",
        type=Path,
        default=Path(__file__).resolve().parent / "mldsa_sign_sm3.exe",
    )
    parser.add_argument(
        "--openssl",
        default="openssl",
        help="openssl 可执行文件（默认 PATH 中的 openssl）",
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="仅输出失败项")
    args = parser.parse_args()

    if not args.verifier.is_file():
        print(
            f"ERROR: 未找到 {args.verifier}\n"
            f"请先运行: {root / 'bin' / 'build-mldsa-sign.bat'}",
            file=sys.stderr,
        )
        return 1

    if args.csr:
        targets = [(p.stem, p) for p in args.csr]
    else:
        csr_dir = args.csr_dir or (args.certs_dir / "csr")
        targets = [(n, csr_dir / f"{n}.csr") for n in args.names]

    if not args.quiet:
        print("======== Hybrid Concatenated / mlkemdsa CSR 复合验签 ========")
        print_rules()

    failed = 0
    for name, path in targets:
        if not path.is_file():
            print(f"SKIP {name}: 未找到 {path}", file=sys.stderr)
            failed += 1
            continue
        try:
            res = verify_csr_file(
                path, args.verifier, openssl=args.openssl, label=name
            )
        except Exception as exc:
            print(f"FAIL {name}: {exc}", file=sys.stderr)
            failed += 1
            continue
        if not args.quiet or not res.ok:
            print_result(res)
        if not res.ok:
            failed += 1

    if not args.quiet:
        print(f"完成: {len(targets) - failed}/{len(targets)} 通过")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
