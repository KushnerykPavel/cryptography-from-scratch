# LMS (Leighton–Micali Signatures)
> One-time signatures + a Merkle tree = many post-quantum signatures.

**Type:** Build
**Languages:** Python
**Prerequisites:** `03-lamport`, `04-winternitz`, `05-merkle-signatures`, `06-xmss`
**Time:** ~70 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** why LMS is stateful and what `q` means
- **Compute** an authentication path and rebuild the Merkle root
- **Implement** LM-OTS signing + public-key-candidate verification
- **Distinguish** LMS vs XMSS at a systems-integration level (state, formats, parameters)
- **Apply** an integration checklist to avoid one-time-key reuse bugs

## The Problem
You need a post-quantum signature scheme that is simple to implement, avoids “big integer” math, and can be deployed in constrained environments (bootloaders, firmware updaters, embedded verification, etc.). Hash-based signatures fit that bill: the “hardness” comes from a hash function, not factoring or discrete logs.

But you also need to sign *many* messages (hundreds, thousands, or more). A one-time signature (OTS) can safely sign one message — and then it must never be used again. The practical problem is turning an OTS into a multi-message signature system without accidentally reusing an OTS key after a crash, rollback, or concurrency bug.

LMS solves this by putting OTS public keys under a Merkle tree root. You publish one small root. Each signature proves (a) an OTS signature for the message and (b) that the OTS public key is one of the tree’s leaves.

## The Concept
LMS (RFC 8554) combines two layers:

1) **LM-OTS**: a one-time signature (Winternitz-style hash chains) for a *single* message.

2) **Merkle tree**: leaf `r = 2^h + q` contains a hash of the LM-OTS public key for leaf index `q`.

The LMS public key is a single root hash `T[1]`. An LMS signature contains:

- `q`: which one-time key was used (stateful counter)
- `lmots_signature`: proves “this leaf’s OTS key signed the message”
- `path[0..h-1]`: sibling hashes to recompute the Merkle root

Two key hashes (domain-separated by constants in RFC 8554):

- Leaf hash: `H(I || u32(r) || u16(D_LEAF) || ots_pub_hash)`
- Internal node: `H(I || u32(r) || u16(D_INTR) || left || right)`

This lesson implements a single parameter set to keep things focused:

- `LMOTS_SHA256_N32_W8` (`n=32, w=8, p=34, ls=0`)
- `LMS_SHA256_M32_H5` (`m=32, h=5`, so `2^5 = 32` signatures per key)

## Build It

### Step 1: Byte encodings and coefficient extraction
We need (a) fixed-width encodings (`u16`, `u32`) because the RFC defines exact byte layouts, and (b) `coef()` because LM-OTS turns a hash into `w`-bit “digits” that decide how far to advance each hash chain.

```python
import hashlib


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
```

### Step 2: LM-OTS (one-time signature)
LM-OTS signs a message by revealing *partially advanced* hash chains. Verification completes each chain to the end and hashes all endpoints into a public-key candidate.

```python
import secrets


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
```

### Step 3: LMS keygen (Merkle tree over OTS keys)
Key generation builds `2^h` leaves (each leaf commits to an LM-OTS public key) and hashes upward to compute the root. The root is the LMS public key.

```python
from dataclasses import dataclass


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
```

### Step 4: LMS sign/verify (stateful) + RFC test vector
Signing consumes the next unused leaf index `q` and returns a signature with the OTS signature + authentication path. Verification rebuilds the Merkle root and checks it equals the public root.

```python
import json
from pathlib import Path


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
    sample = b\"\\x01\\xab\\xff\"
    print(\"coef(sample, 0, 8) =\", coef(sample, 0, 8))
    print(\"coef(sample, 1, 8) =\", coef(sample, 1, 8))
    print(\"coef(sample, 2, 8) =\", coef(sample, 2, 8))

    print(\"\\n=== Step 2: LM-OTS (one-time signature) ===\")
    I = sha256(b\"lms-demo-I\")[:16]
    seed = sha256(b\"lms-demo-seed\")[:32]
    msg = b\"hello LM-OTS\"
    n, _, _, _ = lmots_params(LMOTS_SHA256_N32_W8)
    C = derive_C_deterministic(I, 0, seed, msg, n)
    sig_ots = lmots_sign(I, 0, seed, msg, LMOTS_SHA256_N32_W8, C=C)
    K = lmots_public_key_hash(I, 0, seed, LMOTS_SHA256_N32_W8)
    Kc = lmots_public_key_candidate(I, 0, msg, sig_ots, LMOTS_SHA256_N32_W8)
    print(\"LM-OTS public key hash (K)  =\", bytes_to_hex(K)[:32] + \"…\")
    print(\"LM-OTS candidate hash (Kc)  =\", bytes_to_hex(Kc)[:32] + \"…\")
    print(\"LM-OTS signature verifies   =\", Kc == K)

    print(\"\\n=== Step 3: LMS keygen (Merkle tree over OTS keys) ===\")
    prv, pub = lms_keygen(I, seed, LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8)
    _, _, _, root = parse_lms_public_key(pub)
    print(\"LMS root (public key)       =\", bytes_to_hex(root)[:32] + \"…\")
    print(\"LMS signature length (bytes)=\", lms_sig_len(LMS_SHA256_M32_H5, LMOTS_SHA256_N32_W8))

    print(\"\\n=== Step 4: LMS sign/verify (stateful) + RFC test vector ===\")
    m1 = b\"message #1\"
    C1 = derive_C_deterministic(I, 0, seed, m1, n)
    s1 = lms_sign(prv, m1, C=C1)
    ok1 = lms_verify(pub, m1, s1)
    print(\"sign/verify message #1      =\", ok1)
    m2 = b\"message #2\"
    C2 = derive_C_deterministic(I, 1, seed, m2, n)
    s2 = lms_sign(prv, m2, C=C2)
    ok2 = lms_verify(pub, m2, s2)
    print(\"sign/verify message #2      =\", ok2)
    print(\"next unused leaf index (q)  =\", prv.q)

    try:
        rfc_pub, rfc_msg, rfc_sig = load_lms_verify_vector(\"rfc8554-testcase2-final_signature\")
        ok_rfc = lms_verify(rfc_pub, rfc_msg, rfc_sig)
        print(\"RFC 8554 Test Case 2 final_signature verifies =\", ok_rfc)
    except Exception as e:
        print(\"RFC test vector not available:\", str(e))


if __name__ == \"__main__\":
    main()
```

Run it:

`python3 code/main.py`

## Use It
- **Standards**: RFC 8554 (LMS/LM-OTS) and NIST SP 800-208 (stateful hash-based signatures guidance).
- **Implementations**: Use a vetted implementation rather than rolling your own. LMS/HSS appears in multiple libraries and reference implementations; see RFC 8554’s pointers to example code and your platform’s crypto provider documentation.
- **Where it fits**: verification in boot chains and long-lived artifacts, or environments where side-channel resistance and simplicity matter more than signature size.

## Pitfalls
- **Reusing `q` (one-time key reuse)**: crashes, rollback, or parallel signing can reuse a leaf and destroy security.
- **Treating LMS like a stateless signature**: LMS keys have a maximum number of signatures (`2^h`). Exceed it and you’re either broken or you must rotate keys.
- **Non-atomic counter updates**: a “sign then increment” bug under concurrency can reuse a leaf.
- **Wrong byte encodings**: the scheme is byte-layout-sensitive (`u16`, `u32`, and domain constants). One endianness mismatch breaks verification.
- **Deterministic `C` in production**: in this lesson we allow deterministic `C` for reproducible vectors; real signing must use fresh randomness for `C`.

## Ship It
Save and reuse the LMS integration checklist at:

- `outputs/lms-integration-checklist.md`

Use it as a PR review checklist when you see “we’re adding LMS/HSS signatures” in firmware, package signing, or artifact verification code.

## Exercises
1. Easy: Run `python3 code/main.py`. Observe that `q` increases and signatures have a fixed length for a given parameter set.
2. Medium: Add a loop that signs 10 messages and prints `(q, signature_len)` for each. Confirm `q` increments and verify all signatures.
3. Hard: Pick a real LMS/HSS implementation in your target stack (language/runtime) and verify an RFC test vector end-to-end. Compare formats and parameter sets to this lesson’s parser.

## Key Terms
| Term | What people say | What it actually means |
|------|------------------|------------------------|
| LM-OTS | “one-time signature” | A hash-chain-based OTS; safe only once per keypair |
| LMS | “Merkle signature” | A Merkle tree over OTS public keys; root is the public key |
| `q` | “signature index” | The leaf index selecting which OTS key is consumed (state) |
| Authentication path | “Merkle proof” | Sibling hashes that let you recompute the root from a leaf |
| Domain separation | “different hash prefixes” | Fixed constants (`D_*`) that prevent cross-protocol collisions |

## Further Reading
- McGrew, Curcio, Fluhrer, *Leighton-Micali Hash-Based Signatures* (RFC 8554) — the LMS/LM-OTS specification and test vectors.
- NIST, *SP 800-208: Recommendation for Stateful Hash-Based Signature Schemes* (2020) — guidance for safe parameter choices and operational pitfalls.
- Cisco, *hash-sigs* (reference implementation) — practical code to compare against while debugging.
