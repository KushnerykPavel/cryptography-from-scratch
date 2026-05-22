"""
Verifiable Random Functions (VRF) — educational DH-VRF over a MODP group.

This implements a discrete-log VRF (DH-VRF / ECVRF-style but over a MODP
group instead of an elliptic curve).  The construction is:

  pk  = g^sk mod p
  H   = hash_to_group(m)           — element in q-order subgroup
  Γ   = H^sk mod p                 — VRF proof intermediate
  β   = SHA-256(Γ)                 — pseudorandom output
  π   = (c, s) Schnorr-style proof that sk(Γ) = sk(pk):
          k  ← nonce (static k for determinism in tests)
          U  = g^k mod p
          V  = H^k mod p
          c  = SHA-256(pk‖Γ‖U‖V)  mod q
          s  = (k − sk·c) mod q

Verification: recompute U' = g^s·pk^c, V' = H^s·Γ^c, check c.

Group: RFC 2409 Oakley Group 2 — 1024-bit safe prime, generator g=2, q=(p-1)/2.
Using a safe prime (p=2q+1) means every quadratic residue has order q.
hash_to_group maps via candidate^2 mod p to land in the q-order subgroup.

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib
import struct

# ---------------------------------------------------------------------------
# RFC 2409 Oakley Group 2 — 1024-bit safe prime, g=2
# p is a well-known safe prime; q = (p-1)/2 is the subgroup order.
# ---------------------------------------------------------------------------

_P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF"
)

P: int = int(_P_HEX, 16)
G: int = 2
SUBGROUP_ORDER: int = (P - 1) // 2  # q = (p-1)/2 for safe prime

_P_BYTE_LEN: int = (P.bit_length() + 7) // 8  # 128 bytes


def _sha256_int(data: bytes) -> int:
    return int.from_bytes(hashlib.sha256(data).digest(), "big")


def _encode_fixed(x: int) -> bytes:
    """Encode integer as fixed-width (128-byte) big-endian for stable hashing."""
    return x.to_bytes(_P_BYTE_LEN, "big")


# ---------------------------------------------------------------------------
# VRF primitives
# ---------------------------------------------------------------------------


def vrf_keygen(sk: int) -> int:
    """Compute public key pk = g^sk mod p."""
    return pow(G, sk, P)


def vrf_hash_to_group(m: bytes) -> int:
    """
    Hash a message to an element of the q-order subgroup.

    For a safe prime (p = 2q+1), squaring maps any non-trivial element into
    the unique q-order subgroup.  We try candidate = SHA-256(m ‖ counter) % p
    and return candidate^2 mod p once it avoids {0, 1, p-1}.
    """
    counter = 0
    while True:
        candidate = _sha256_int(m + struct.pack(">I", counter)) % P
        h = pow(candidate, 2, P)
        if h not in (0, 1, P - 1):
            return h
        counter += 1


def vrf_evaluate(sk: int, m: bytes, k: int) -> tuple[int, int, int]:
    """
    Evaluate the VRF on message m with secret key sk using nonce k.

    Returns (gamma, c, s) where:
      gamma = H^sk mod p  (VRF output seed)
      (c, s) = Schnorr-style proof of discrete-log equality between pk and gamma
    """
    pk = vrf_keygen(sk)
    h = vrf_hash_to_group(m)
    gamma = pow(h, sk, P)

    u = pow(G, k, P)  # g^k
    v = pow(h, k, P)  # H^k

    # challenge: fixed-width encoding avoids length-extension edge cases
    c_data = (
        _encode_fixed(pk)
        + _encode_fixed(gamma)
        + _encode_fixed(u)
        + _encode_fixed(v)
    )
    c = _sha256_int(c_data) % SUBGROUP_ORDER
    s = (k - sk * c) % SUBGROUP_ORDER

    return gamma, c, s


def vrf_verify(pk: int, m: bytes, gamma: int, c: int, s: int) -> bool:
    """
    Verify a VRF proof (gamma, c, s) against public key pk and message m.

    Recompute U' = g^s * pk^c  and  V' = H^s * gamma^c,
    then check that SHA-256(pk‖gamma‖U'‖V') mod q == c.
    """
    h = vrf_hash_to_group(m)

    u_prime = pow(G, s, P) * pow(pk, c, P) % P
    v_prime = pow(h, s, P) * pow(gamma, c, P) % P

    c_data = (
        _encode_fixed(pk)
        + _encode_fixed(gamma)
        + _encode_fixed(u_prime)
        + _encode_fixed(v_prime)
    )
    c_check = _sha256_int(c_data) % SUBGROUP_ORDER
    return c_check == c


def vrf_proof_to_hash(gamma: int) -> bytes:
    """Convert VRF gamma output to a 32-byte pseudorandom value."""
    return hashlib.sha256(_encode_fixed(gamma)).digest()


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------


def main() -> None:
    SK = 12345
    K_NONCE = 67890  # static for determinism

    print("=== Step 1: Key Generation ===")
    pk = vrf_keygen(SK)
    print(f"  sk  = {SK}")
    print(f"  pk  = {pk}")
    print()

    print("=== Step 2: Hash to Group ===")
    msg = b"hello vrf"
    h = vrf_hash_to_group(msg)
    print(f"  m   = {msg!r}")
    print(f"  H(m)= {h}")
    print()

    print("=== Step 3: VRF Evaluate ===")
    gamma, c, s = vrf_evaluate(SK, msg, K_NONCE)
    beta = vrf_proof_to_hash(gamma)
    print(f"  gamma   = {gamma}")
    print(f"  c       = {c}")
    print(f"  s       = {s}")
    print(f"  beta    = {beta.hex()}  (pseudorandom output)")
    print()

    print("=== Step 4: VRF Verify ===")
    ok = vrf_verify(pk, msg, gamma, c, s)
    print(f"  verify(pk, msg, gamma, c, s) = {ok}")
    bad_gamma = (gamma + 1) % P
    ok_bad = vrf_verify(pk, msg, bad_gamma, c, s)
    print(f"  verify with tampered gamma   = {ok_bad}")
    print()

    print("=== Step 5: Pseudorandomness Demo ===")
    messages = [b"block-1", b"block-2", b"block-3"]
    for m2 in messages:
        g2, c2, s2 = vrf_evaluate(SK, m2, K_NONCE + hash(m2) % 10000)
        beta2 = vrf_proof_to_hash(g2)
        ok2 = vrf_verify(pk, m2, g2, c2, s2)
        print(f"  msg={m2!r:<12}  beta={beta2.hex()[:16]}...  verify={ok2}")


if __name__ == "__main__":
    main()
