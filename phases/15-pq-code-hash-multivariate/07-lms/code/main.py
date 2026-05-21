"""
Educational LMS (RFC 8554) implementation in pure Python (stdlib only).

This script:
- Implements the LM-OTS (one-time) signature used inside LMS.
- Builds a small LMS Merkle tree (H=5) and signs/verifies messages.
- Demonstrates verification against an RFC 8554 test vector (Appendix F).

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from pathlib import Path


LMOTS_SHA256_N32_W8 = 0x00000004
LMS_SHA256_M32_H5 = 0x00000005

D_PBLC = 0x8080
D_MESG = 0x8181
D_LEAF = 0x8282
D_INTR = 0x8383


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def u8str(x: int) -> bytes:
    if not (0 <= x <= 0xFF):
        raise ValueError("u8 out of range")
    return x.to_bytes(1, "big")


def u16str(x: int) -> bytes:
    if not (0 <= x <= 0xFFFF):
        raise ValueError("u16 out of range")
    return x.to_bytes(2, "big")


def u32str(x: int) -> bytes:
    if not (0 <= x <= 0xFFFFFFFF):
        raise ValueError("u32 out of range")
    return x.to_bytes(4, "big")


def bytes_to_u32(b: bytes) -> int:
    if len(b) != 4:
        raise ValueError("need 4 bytes for u32")
    return int.from_bytes(b, "big")


def coef(s: bytes, i: int, w: int) -> int:
    if w not in (1, 2, 4, 8):
        raise ValueError("w must be 1,2,4,8")
    if i < 0:
        raise ValueError("i must be non-negative")
    elems_per_byte = 8 // w
    num_elems = len(s) * elems_per_byte
    if i >= num_elems:
        raise ValueError("coef index out of range")
    byte_index = (i * w) // 8
    shift = 8 - (w * (i % elems_per_byte) + w)
    return (s[byte_index] >> shift) & ((1 << w) - 1)


def cksm(q: bytes, w: int, ls: int) -> int:
    if w not in (1, 2, 4, 8):
        raise ValueError("w must be 1,2,4,8")
    if ls < 0:
        raise ValueError("ls must be non-negative")
    num_elems = (len(q) * 8) // w
    max_coef = (1 << w) - 1
    total = 0
    for i in range(num_elems):
        total += max_coef - coef(q, i, w)
    return total << ls


def lmots_params(lmots_type: int) -> tuple[int, int, int, int]:
    if lmots_type == LMOTS_SHA256_N32_W8:
        n = 32
        w = 8
        p = 34
        ls = 0
        return n, w, p, ls
    raise ValueError(f"unsupported LM-OTS type: {lmots_type:#x}")


def lms_params(lms_type: int) -> tuple[int, int]:
    if lms_type == LMS_SHA256_M32_H5:
        m = 32
        h = 5
        return m, h
    raise ValueError(f"unsupported LMS type: {lms_type:#x}")


def lmots_x(I: bytes, q: int, i: int, seed: bytes, n: int) -> bytes:
    if len(I) != 16:
        raise ValueError("I must be 16 bytes")
    if len(seed) != n:
        raise ValueError("seed must be n bytes")
    if not (0 <= q <= 0xFFFFFFFF):
        raise ValueError("q out of range")
    if not (0 <= i <= 0xFFFF):
        raise ValueError("i out of range")
    return sha256(I + u32str(q) + u16str(i) + u8str(0xFF) + seed)[:n]


def hash_chain(I: bytes, q: int, i: int, start_j: int, stop_j: int, x: bytes) -> bytes:
    if not (0 <= start_j <= stop_j <= 0xFF):
        raise ValueError("invalid chain range")
    tmp = x
    for j in range(start_j, stop_j):
        tmp = sha256(I + u32str(q) + u16str(i) + u8str(j) + tmp)
    return tmp


def lmots_public_key_hash(I: bytes, q: int, seed: bytes, lmots_type: int) -> bytes:
    n, w, p, ls = lmots_params(lmots_type)
    if w != 8 or n != 32 or p != 34 or ls != 0:
        raise ValueError("this lesson implements only LMOTS_SHA256_N32_W8")
    z_parts: list[bytes] = []
    for i in range(p):
        x_i = lmots_x(I, q, i, seed, n)
        z_i = hash_chain(I, q, i, 0, (1 << w) - 1, x_i)
        z_parts.append(z_i[:n])
    return sha256(I + u32str(q) + u16str(D_PBLC) + b"".join(z_parts))[:n]


def lmots_sign(I: bytes, q: int, seed: bytes, message: bytes, lmots_type: int, C: bytes | None = None) -> bytes:
    n, w, p, ls = lmots_params(lmots_type)
    if C is None:
        C = secrets.token_bytes(n)
    if len(C) != n:
        raise ValueError("C must be n bytes")
    Q = sha256(I + u32str(q) + u16str(D_MESG) + C + message)[:n]
    Q_with_cksm = Q + u16str(cksm(Q, w, ls))
    y_parts: list[bytes] = []
    for i in range(p):
        a = coef(Q_with_cksm, i, w)
        x_i = lmots_x(I, q, i, seed, n)
        y_i = hash_chain(I, q, i, 0, a, x_i)
        y_parts.append(y_i[:n])
    return u32str(lmots_type) + C + b"".join(y_parts)


def lmots_public_key_candidate(I: bytes, q: int, message: bytes, lmots_sig: bytes, lmots_type: int) -> bytes:
    n, w, p, ls = lmots_params(lmots_type)
    min_len = 4 + n + p * n
    if len(lmots_sig) != min_len:
        raise ValueError("invalid LM-OTS signature length")
    sig_type = bytes_to_u32(lmots_sig[0:4])
    if sig_type != lmots_type:
        raise ValueError("LM-OTS type mismatch")
    C = lmots_sig[4 : 4 + n]
    y = [lmots_sig[4 + n + i * n : 4 + n + (i + 1) * n] for i in range(p)]
    Q = sha256(I + u32str(q) + u16str(D_MESG) + C + message)[:n]
    Q_with_cksm = Q + u16str(cksm(Q, w, ls))
    z_parts: list[bytes] = []
    for i in range(p):
        a = coef(Q_with_cksm, i, w)
        z_i = hash_chain(I, q, i, a, (1 << w) - 1, y[i])
        z_parts.append(z_i[:n])
    return sha256(I + u32str(q) + u16str(D_PBLC) + b"".join(z_parts))[:n]


def lms_leaf_hash(I: bytes, node_num: int, ots_pub_hash: bytes, m: int) -> bytes:
    return sha256(I + u32str(node_num) + u16str(D_LEAF) + ots_pub_hash)[:m]


def lms_internal_hash(I: bytes, node_num: int, left: bytes, right: bytes, m: int) -> bytes:
    return sha256(I + u32str(node_num) + u16str(D_INTR) + left + right)[:m]


def lms_public_key_bytes(lms_type: int, lmots_type: int, I: bytes, root: bytes) -> bytes:
    m, _ = lms_params(lms_type)
    if len(I) != 16:
        raise ValueError("I must be 16 bytes")
    if len(root) != m:
        raise ValueError("root length mismatch")
    return u32str(lms_type) + u32str(lmots_type) + I + root


@dataclass
class LMSPrivateKey:
    lms_type: int
    lmots_type: int
    I: bytes
    seed: bytes
    q: int
    T: list[bytes]


def lms_keygen(I: bytes, seed: bytes, lms_type: int, lmots_type: int) -> tuple[LMSPrivateKey, bytes]:
    m, h = lms_params(lms_type)
    n, _, _, _ = lmots_params(lmots_type)
    if len(seed) != n:
        raise ValueError("seed must be n bytes")
    leaf_count = 1 << h
    node_count = 1 << (h + 1)
    T: list[bytes] = [b""] * node_count
    leaf_start = 1 << h
    for q in range(leaf_count):
        node_num = leaf_start + q
        ots_pub_hash = lmots_public_key_hash(I, q, seed, lmots_type)
        T[node_num] = lms_leaf_hash(I, node_num, ots_pub_hash, m)
    for node_num in range(leaf_start - 1, 0, -1):
        T[node_num] = lms_internal_hash(I, node_num, T[2 * node_num], T[2 * node_num + 1], m)
    prv = LMSPrivateKey(lms_type=lms_type, lmots_type=lmots_type, I=I, seed=seed, q=0, T=T)
    pub = lms_public_key_bytes(lms_type, lmots_type, I, T[1])
    return prv, pub


def lms_sig_len(lms_type: int, lmots_type: int) -> int:
    m, h = lms_params(lms_type)
    n, _, p, _ = lmots_params(lmots_type)
    return 4 + (4 + n + p * n) + 4 + h * m


def lms_sign(prv: LMSPrivateKey, message: bytes, C: bytes | None = None) -> bytes:
    m, h = lms_params(prv.lms_type)
    leaf_count = 1 << h
    if prv.q >= leaf_count:
        raise ValueError("LMS private key exhausted (no unused one-time keys left)")
    q = prv.q
    lmots_sig = lmots_sign(prv.I, q, prv.seed, message, prv.lmots_type, C=C)
    r = (1 << h) + q
    path = [prv.T[(r >> i) ^ 1] for i in range(h)]
    prv.q += 1
    return u32str(q) + lmots_sig + u32str(prv.lms_type) + b"".join(path)


def parse_lms_public_key(pub: bytes) -> tuple[int, int, bytes, bytes]:
    if len(pub) < 8 + 16:
        raise ValueError("public key too short")
    lms_type = bytes_to_u32(pub[0:4])
    lmots_type = bytes_to_u32(pub[4:8])
    m, _ = lms_params(lms_type)
    I = pub[8:24]
    root = pub[24 : 24 + m]
    if len(root) != m or len(pub) != 24 + m:
        raise ValueError("invalid public key length")
    return lms_type, lmots_type, I, root


def parse_lms_signature(sig: bytes, lms_type: int, lmots_type: int) -> tuple[int, bytes, int, list[bytes]]:
    m, h = lms_params(lms_type)
    n, _, p, _ = lmots_params(lmots_type)
    lmots_sig_len = 4 + n + p * n
    expected_len = 4 + lmots_sig_len + 4 + h * m
    if len(sig) != expected_len:
        raise ValueError("invalid LMS signature length")
    q = bytes_to_u32(sig[0:4])
    lmots_sig = sig[4 : 4 + lmots_sig_len]
    sig_lms_type = bytes_to_u32(sig[4 + lmots_sig_len : 4 + lmots_sig_len + 4])
    if sig_lms_type != lms_type:
        raise ValueError("LMS type mismatch")
    path_bytes = sig[4 + lmots_sig_len + 4 :]
    path = [path_bytes[i * m : (i + 1) * m] for i in range(h)]
    return q, lmots_sig, sig_lms_type, path


def lms_verify(pub: bytes, message: bytes, sig: bytes) -> bool:
    try:
        lms_type, lmots_type, I, root = parse_lms_public_key(pub)
        m, h = lms_params(lms_type)
        q, lmots_sig, _, path = parse_lms_signature(sig, lms_type, lmots_type)
        if q >= (1 << h):
            return False
        Kc = lmots_public_key_candidate(I, q, message, lmots_sig, lmots_type)
        r = (1 << h) + q
        tmp = lms_leaf_hash(I, r, Kc, m)
        for i in range(h):
            parent = r >> (i + 1)
            if ((r >> i) & 1) == 1:
                tmp = lms_internal_hash(I, parent, path[i], tmp, m)
            else:
                tmp = lms_internal_hash(I, parent, tmp, path[i], m)
        return tmp == root
    except Exception:
        return False


def derive_C_deterministic(I: bytes, q: int, seed: bytes, message: bytes, n: int) -> bytes:
    return sha256(b"LMS-DEMO-C" + I + u32str(q) + seed + message)[:n]


def hex_to_bytes(s: str) -> bytes:
    s2 = s.strip().lower().replace("0x", "").replace(" ", "").replace("\n", "")
    if len(s2) % 2 != 0:
        raise ValueError("hex must have even length")
    return bytes.fromhex(s2)


def bytes_to_hex(b: bytes) -> str:
    return b.hex()


def load_lms_verify_vector(name: str) -> tuple[bytes, bytes, bytes]:
    vectors_path = Path(__file__).resolve().parent.parent / "tests" / "vectors.json"
    raw = json.loads(vectors_path.read_text())
    for v in raw.get("vectors", []):
        if v.get("op") == "lms_verify" and v.get("name") == name:
            return bytes.fromhex(v["pub_hex"]), bytes.fromhex(v["message_hex"]), bytes.fromhex(v["sig_hex"])
    raise ValueError(f"vector not found: {name}")


def main() -> None:
    print("=== Step 1: Byte encodings and coefficient extraction ===")
    sample = b"\x01\xab\xff"
    print("coef(sample, 0, 8) =", coef(sample, 0, 8))
    print("coef(sample, 1, 8) =", coef(sample, 1, 8))
    print("coef(sample, 2, 8) =", coef(sample, 2, 8))

    print("\n=== Step 2: LM-OTS (one-time signature) ===")
    I = sha256(b"lms-demo-I")[:16]
    seed = sha256(b"lms-demo-seed")[:32]
    msg = b"hello LM-OTS"
    n, _, _, _ = lmots_params(LMOTS_SHA256_N32_W8)
    C = derive_C_deterministic(I, 0, seed, msg, n)
    sig_ots = lmots_sign(I, 0, seed, msg, LMOTS_SHA256_N32_W8, C=C)
    K = lmots_public_key_hash(I, 0, seed, LMOTS_SHA256_N32_W8)
    Kc = lmots_public_key_candidate(I, 0, msg, sig_ots, LMOTS_SHA256_N32_W8)
    print("LM-OTS public key hash (K)  =", bytes_to_hex(K)[:32] + "…")
    print("LM-OTS candidate hash (Kc)  =", bytes_to_hex(Kc)[:32] + "…")
    print("LM-OTS signature verifies   =", Kc == K)

    print("\n=== Step 3: LMS keygen (Merkle tree over OTS keys) ===")
    prv, pub = lms_keygen(I, seed, LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8)
    _, _, _, root = parse_lms_public_key(pub)
    print("LMS root (public key)       =", bytes_to_hex(root)[:32] + "…")
    print("LMS signature length (bytes)=", lms_sig_len(LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8))

    print("\n=== Step 4: LMS sign/verify (stateful) + RFC test vector ===")
    m1 = b"message #1"
    C1 = derive_C_deterministic(I, 0, seed, m1, n)
    s1 = lms_sign(prv, m1, C=C1)
    ok1 = lms_verify(pub, m1, s1)
    print("sign/verify message #1      =", ok1)
    m2 = b"message #2"
    C2 = derive_C_deterministic(I, 1, seed, m2, n)
    s2 = lms_sign(prv, m2, C=C2)
    ok2 = lms_verify(pub, m2, s2)
    print("sign/verify message #2      =", ok2)
    print("next unused leaf index (q)  =", prv.q)

    try:
        rfc_pub, rfc_msg, rfc_sig = load_lms_verify_vector("rfc8554-testcase2-final_signature")
        ok_rfc = lms_verify(rfc_pub, rfc_msg, rfc_sig)
        print("RFC 8554 Test Case 2 final_signature verifies =", ok_rfc)
    except Exception as e:
        print("RFC test vector not available:", str(e))


if __name__ == "__main__":
    main()
