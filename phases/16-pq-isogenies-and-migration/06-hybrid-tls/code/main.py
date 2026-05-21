"""Hybrid TLS — combine classical + PQ secrets safely (toy model).

This lesson script models the core *idea* behind hybrid TLS key exchange:

- run a classical key agreement (e.g., ECDHE) to get `ss_classical`
- run a PQ KEM (e.g., ML-KEM/Kyber) to get `ss_pq`
- combine them with a KDF to get one `hybrid_secret`
- derive traffic secrets from `hybrid_secret` *and* the handshake transcript

Everything here is educational. The "PQ KEM" below is a deterministic toy
construction and is not secure. The point is to understand wiring, KDF use,
and transcript binding.

Run: python3 code/main.py
"""

from __future__ import annotations

import hashlib
import hmac


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def hkdf_extract_sha256(salt: bytes, ikm: bytes) -> bytes:
    if not salt:
        salt = b"\x00" * 32
    return hmac_sha256(salt, ikm)


def hkdf_expand_sha256(prk: bytes, info: bytes, length: int) -> bytes:
    if length < 0:
        raise ValueError("length must be non-negative")
    if length > 255 * 32:
        raise ValueError("length too large for HKDF-Expand")

    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac_sha256(prk, t + info + bytes([counter]))
        okm += t
        counter += 1
    return okm[:length]


def hkdf_sha256(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    return hkdf_expand_sha256(hkdf_extract_sha256(salt, ikm), info, length)


def int_to_fixed_length_bytes(x: int, length: int) -> bytes:
    if x < 0:
        raise ValueError("x must be non-negative")
    if length <= 0:
        raise ValueError("length must be positive")
    return x.to_bytes(length, "big")


def dh_public_key(p: int, g: int, sk: int) -> int:
    if sk <= 0:
        raise ValueError("secret key must be positive")
    if p <= 2:
        raise ValueError("p must be > 2")
    if not (1 < g < p):
        raise ValueError("g must be in (1, p)")
    return pow(g, sk, p)


def dh_shared_secret_int(p: int, pk_other: int, sk: int) -> int:
    if sk <= 0:
        raise ValueError("secret key must be positive")
    if not (1 <= pk_other < p):
        raise ValueError("peer public key out of range")
    return pow(pk_other, sk, p)


def toy_dh_shared_secret_bytes(p: int, g: int, sk_a: int, sk_b: int, length: int) -> bytes:
    pk_a = dh_public_key(p, g, sk_a)
    pk_b = dh_public_key(p, g, sk_b)
    ss_a = dh_shared_secret_int(p, pk_b, sk_a)
    ss_b = dh_shared_secret_int(p, pk_a, sk_b)
    if ss_a != ss_b:
        raise AssertionError("DH mismatch (should never happen)")
    return int_to_fixed_length_bytes(ss_a, length)


def toy_kem_keypair_from_seed(seed: bytes) -> tuple[bytes, bytes]:
    sk = sha256(b"sk:" + seed)
    pk = sha256(b"pk:" + sk)
    return sk, pk


def toy_kem_encapsulate(pk: bytes, seed: bytes) -> tuple[bytes, bytes]:
    tag = hmac_sha256(pk, b"ct:" + seed)[:16]
    ct = tag + seed
    ss = sha256(b"ss:" + pk + seed)
    return ct, ss


def toy_kem_decapsulate(sk: bytes, ct: bytes) -> bytes:
    if len(ct) < 16:
        raise ValueError("ciphertext too short")
    pk = sha256(b"pk:" + sk)
    tag = ct[:16]
    seed = ct[16:]
    expected_tag = hmac_sha256(pk, b"ct:" + seed)[:16]
    if tag != expected_tag:
        raise ValueError("invalid ciphertext")
    return sha256(b"ss:" + pk + seed)


def transcript_hash_sha256(messages: list[bytes]) -> bytes:
    return sha256(b"|".join(messages))


def combine_hybrid_secret_concat_hkdf(ss_classical: bytes, ss_pq: bytes) -> bytes:
    zero_salt = b"\x00" * 32
    return hkdf_sha256(zero_salt, ss_classical + ss_pq, b"hybrid secret", 32)


def derive_tls13_like_secrets(hybrid_secret: bytes, transcript_hash: bytes) -> dict[str, bytes]:
    zero_salt = b"\x00" * 32
    handshake_secret = hkdf_sha256(zero_salt, hybrid_secret, b"handshake" + transcript_hash, 32)
    master_secret = hkdf_sha256(zero_salt, handshake_secret, b"master" + transcript_hash, 32)
    client_app_traffic = hkdf_sha256(
        zero_salt, master_secret, b"c ap traffic" + transcript_hash, 32
    )
    server_app_traffic = hkdf_sha256(
        zero_salt, master_secret, b"s ap traffic" + transcript_hash, 32
    )
    return {
        "handshake_secret": handshake_secret,
        "master_secret": master_secret,
        "client_app_traffic": client_app_traffic,
        "server_app_traffic": server_app_traffic,
    }


def main():
    print("=== Step 1: HKDF (HMAC-SHA256) ===")
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    prk = hkdf_extract_sha256(salt, ikm)
    okm = hkdf_expand_sha256(prk, info, 42)
    print(f"  RFC 5869 test case 1 PRK: {prk.hex()}")
    print(f"  RFC 5869 test case 1 OKM: {okm.hex()}")

    print()
    print("=== Step 2: Toy classical shared secret (Diffie–Hellman) ===")
    p = 2**127 - 1
    g = 3
    sk_a = 123456789
    sk_b = 987654321
    ss_classical = toy_dh_shared_secret_bytes(p, g, sk_a, sk_b, length=16)
    print(f"  p = 2^127-1, g = {g}")
    print(f"  sk_a = {sk_a}, sk_b = {sk_b}")
    print(f"  ss_classical (16 bytes) = {ss_classical.hex()}")

    print()
    print("=== Step 3: Toy PQ shared secret (KEM encap/decap) ===")
    sk_kem, pk_kem = toy_kem_keypair_from_seed(b"alice")
    ct, ss_pq = toy_kem_encapsulate(pk_kem, b"encap-seed-01")
    ss_pq_2 = toy_kem_decapsulate(sk_kem, ct)
    print(f"  pk = {pk_kem.hex()}")
    print(f"  ct = {ct.hex()}  (tag||seed, seed is in clear in this toy KEM)")
    print(f"  ss_pq(encap) = {ss_pq.hex()}")
    print(f"  ss_pq(decap) = {ss_pq_2.hex()}")
    print(f"  match = {ss_pq == ss_pq_2}")

    print()
    print("=== Step 4: Hybrid combiner + TLS-like key schedule ===")
    hybrid_secret = combine_hybrid_secret_concat_hkdf(ss_classical, ss_pq)
    transcript = transcript_hash_sha256([b"client_hello", b"server_hello"])
    secrets = derive_tls13_like_secrets(hybrid_secret, transcript)
    print(f"  transcript_hash = {transcript.hex()}")
    print(f"  hybrid_secret   = {hybrid_secret.hex()}")
    print(f"  handshake_secret = {secrets['handshake_secret'].hex()}")
    print(f"  master_secret    = {secrets['master_secret'].hex()}")
    print(f"  client_app_traffic = {secrets['client_app_traffic'].hex()}")
    print(f"  server_app_traffic = {secrets['server_app_traffic'].hex()}")


if __name__ == "__main__":
    main()
