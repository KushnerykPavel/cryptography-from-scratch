"""
PQ-Secure Messenger capstone (educational).

Run:
  python3 code/main.py

Demonstrates:
  1. Toy LWE KEM  (n=8, q=257, chi = {-1,0,+1})
  2. Hybrid KEM   (LWE + tiny DH, combined via HKDF)
  3. Toy lattice signature (simplified Fiat-Shamir over small vectors)
  4. HMAC-based AEAD  (CTR-mode PRF + HMAC-SHA256 auth tag)
  5. Alice-Bob message exchange with a single ratchet step
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from dataclasses import dataclass
from typing import Sequence, Tuple

# ---------------------------------------------------------------------------
# Global parameters
# ---------------------------------------------------------------------------

LWE_N = 8        # dimension
LWE_Q = 257      # modulus (prime, fits in uint16)
LWE_HALF = LWE_Q // 2  # 128 — used for bit encoding

# Small DH group (pedagogical) — prime p, generator g
DH_P = 2**127 - 1   # Mersenne prime M_127 (not NIST curve; strictly demo)
DH_G = 3

# ---------------------------------------------------------------------------
# Deterministic RNG wrapper — swap in random.Random(seed) for tests
# ---------------------------------------------------------------------------

class _SeededRNG:
    """Simple seeded PRNG for deterministic test vectors (NOT cryptographic)."""

    def __init__(self, seed: int) -> None:
        self._state = seed & ((1 << 64) - 1)

    def _next(self) -> int:
        # xorshift64
        x = self._state
        x ^= (x << 13) & ((1 << 64) - 1)
        x ^= (x >> 7)
        x ^= (x << 17) & ((1 << 64) - 1)
        self._state = x & ((1 << 64) - 1)
        return self._state

    def randbelow(self, n: int) -> int:
        return self._next() % n

    def randbytes(self, k: int) -> bytes:
        out = bytearray()
        while len(out) < k:
            val = self._next()
            out += val.to_bytes(8, "little")
        return bytes(out[:k])


def _secure_rng() -> "_SecureRNG":
    return _SecureRNG()


class _SecureRNG:
    """Thin wrapper around os.urandom that mirrors _SeededRNG's API."""

    def randbelow(self, n: int) -> int:
        # rejection-sample to avoid bias
        bits = n.bit_length()
        nbytes = (bits + 7) // 8
        mask = (1 << bits) - 1
        while True:
            val = int.from_bytes(os.urandom(nbytes), "little") & mask
            if val < n:
                return val

    def randbytes(self, k: int) -> bytes:
        return os.urandom(k)


# ---------------------------------------------------------------------------
# Helper: modular arithmetic on lists
# ---------------------------------------------------------------------------

def _mod_q(v: int) -> int:
    return v % LWE_Q


def _inner(a: Sequence[int], b: Sequence[int]) -> int:
    return _mod_q(sum(x * y for x, y in zip(a, b)))


def _matvec(M: Sequence[Sequence[int]], v: Sequence[int]) -> list:
    """Matrix-vector product mod q."""
    return [_mod_q(sum(M[i][j] * v[j] for j in range(LWE_N))) for i in range(LWE_N)]


def _vec_add(a: Sequence[int], b: Sequence[int]) -> list:
    return [_mod_q(x + y) for x, y in zip(a, b)]


def _vec_sub(a: Sequence[int], b: Sequence[int]) -> list:
    return [_mod_q(x - y) for x, y in zip(a, b)]


def _vec_scale(v: Sequence[int], s: int) -> list:
    return [_mod_q(x * s) for x in v]


# ---------------------------------------------------------------------------
# Small error distribution chi: {-1, 0, +1} with equal probability
# ---------------------------------------------------------------------------

def _sample_chi(rng) -> int:
    return (rng.randbelow(3) - 1) % LWE_Q  # maps -1 -> q-1


def _sample_chi_vec(rng, n: int = LWE_N) -> list:
    return [_sample_chi(rng) for _ in range(n)]


def _sample_uniform_vec(rng, n: int = LWE_N) -> list:
    return [rng.randbelow(LWE_Q) for _ in range(n)]


def _sample_uniform_matrix(rng, rows: int = LWE_N, cols: int = LWE_N) -> list:
    return [[rng.randbelow(LWE_Q) for _ in range(cols)] for _ in range(rows)]


# ---------------------------------------------------------------------------
# Toy LWE KEM
# ---------------------------------------------------------------------------
#
#  KeyGen:   A  <- Uniform_{n×n}(Z_q)
#            s  <- chi^n   (secret)
#            e  <- chi^n   (error)
#            b  = A·s + e  mod q   (public key component)
#
#  Encaps(A, b):
#            r  <- chi^n
#            e' <- chi^n
#            e''<- chi      (scalar)
#            u  = A^T · r + e'   mod q
#            v  = <b, r> + e'' + round(q/2)·m   mod q
#                 where m ∈ {0,1} (one bit per call; loop 256 times for 32 bytes)
#            Returns: (u, v), shared_secret_bits
#
#  Decaps(s, u, v):
#            w  = v - <s, u>   mod q
#            recover m: if |w| < q/4 then 0 else 1
#
#  For a 32-byte shared secret we run 256 independent single-bit encapsulations
#  sharing the same A matrix (the same public key).
# ---------------------------------------------------------------------------

@dataclass
class LWEPublicKey:
    A: list   # n×n matrix
    b: list   # n-vector


@dataclass
class LWEPrivateKey:
    s: list   # n-vector (secret)


@dataclass
class LWECiphertext:
    # Each element: (u_i, v_i) for bit i
    pairs: list


def lwe_keygen(rng=None):
    """Generate LWE keypair."""
    if rng is None:
        rng = _secure_rng()
    A = _sample_uniform_matrix(rng)
    s = _sample_chi_vec(rng)
    e = _sample_chi_vec(rng)
    b = _vec_add(_matvec(A, s), e)
    return LWEPublicKey(A=A, b=b), LWEPrivateKey(s=s)


def lwe_encaps(pk: LWEPublicKey, shared_secret_bits: bytes, rng=None) -> LWECiphertext:
    """
    Encrypt each bit of *shared_secret_bits* (32 bytes = 256 bits).
    Returns ciphertext carrying those bits.
    """
    if rng is None:
        rng = _secure_rng()
    if len(shared_secret_bits) != 32:
        raise ValueError("shared_secret_bits must be 32 bytes")

    A = pk.A
    # Precompute A^T
    AT = [[A[j][i] for j in range(LWE_N)] for i in range(LWE_N)]

    pairs = []
    for byte_val in shared_secret_bits:
        for bit_pos in range(8):
            m = (byte_val >> bit_pos) & 1
            r = _sample_chi_vec(rng)
            e_prime = _sample_chi_vec(rng)
            e_double_prime = _sample_chi(rng)
            u = _vec_add(_matvec(AT, r), e_prime)
            v = _mod_q(_inner(pk.b, r) + e_double_prime + LWE_HALF * m)
            pairs.append((u, v))
    return LWECiphertext(pairs=pairs)


def lwe_decaps(sk: LWEPrivateKey, ct: LWECiphertext) -> bytes:
    """
    Decrypt 256 bits from ciphertext, return 32 bytes.
    Decision: if (v - <s,u>) mod q is closer to 0 than to q/2, bit=0 else bit=1.
    """
    bits = []
    for u, v in ct.pairs:
        w = _mod_q(v - _inner(sk.s, u))
        # Distance to 0 or to LWE_HALF
        d0 = min(w, LWE_Q - w)
        d1 = min(abs(w - LWE_HALF), LWE_Q - abs(w - LWE_HALF))
        bits.append(0 if d0 < d1 else 1)
    # Pack bits into bytes (LSB first per byte)
    result = bytearray()
    for i in range(0, 256, 8):
        byte_val = sum(bits[i + j] << j for j in range(8))
        result.append(byte_val)
    return bytes(result)


# ---------------------------------------------------------------------------
# HKDF (RFC 5869) — stdlib only (hashlib + hmac)
# ---------------------------------------------------------------------------

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)."""
    if not salt:
        salt = b"\x00" * 32
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand: produce *length* bytes of keying material."""
    if length > 255 * 32:
        raise ValueError("HKDF-Expand output too long")
    out = bytearray()
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return bytes(out[:length])


def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    """Single-call HKDF."""
    prk = hkdf_extract(salt, ikm)
    return hkdf_expand(prk, info, length)


# ---------------------------------------------------------------------------
# Tiny DH (pedagogical) — discrete log over Z_{DH_P}
# ---------------------------------------------------------------------------

def dh_generate_keypair(rng=None):
    """Return (private_key, public_key = g^private mod p)."""
    if rng is None:
        rng = _secure_rng()
    # private key: 16-byte random value
    priv_bytes = rng.randbytes(16)
    priv = int.from_bytes(priv_bytes, "big") % (DH_P - 2) + 2
    pub = pow(DH_G, priv, DH_P)
    return priv, pub


def dh_shared_secret(private_key: int, other_public: int) -> bytes:
    """Compute g^(ab) mod p, encode as 16 bytes."""
    shared = pow(other_public, private_key, DH_P)
    return shared.to_bytes(16, "big")  # M_127 fits in 16 bytes


# ---------------------------------------------------------------------------
# Hybrid KEM: LWE + DH combined via HKDF
# ---------------------------------------------------------------------------

def hybrid_combine(lwe_secret: bytes, dh_secret: bytes, salt: bytes, info: bytes) -> bytes:
    """Combine two raw secrets into a 32-byte session key using HKDF."""
    ikm = lwe_secret + dh_secret
    return hkdf(salt, ikm, info, 32)


# ---------------------------------------------------------------------------
# Toy lattice signature (simplified Fiat-Shamir / Lyubashevsky sketch)
#
#  Setup: same n, q as LWE
#
#  SigKeyGen:
#    A_sig <- uniform n×n   (public parameter, could be global)
#    s_sig <- chi^n          (signing key)
#    t_sig = A_sig · s_sig mod q  (verification key)
#
#  Sign(msg, s_sig, A_sig):
#    y   <- uniform^n    (commitment randomness)
#    w   = A_sig · y mod q
#    c   = H(w || msg) reduced to a scalar in Z_q  (Fiat-Shamir challenge)
#    z   = y + c * s_sig  mod q   (response vector; c is a scalar)
#    reject if any z_i falls in the "danger zone" near 0 or q-1
#    sig = (z, c_scalar)
#
#  Verify(msg, sig, t_sig, A_sig):
#    w' = A_sig · z - c * t_sig   mod q   (c is the same scalar)
#    check H(w' || msg) reduced == c_scalar
#
#  Correctness:
#    A·z - c·t = A·(y + c·s) - c·(A·s) = A·y = w  ✓
# ---------------------------------------------------------------------------

@dataclass
class SigPublicKey:
    A_sig: list
    t_sig: list   # A·s


@dataclass
class SigPrivateKey:
    s_sig: list
    A_sig: list


@dataclass
class Signature:
    z: list
    c_scalar: int   # challenge as scalar in Z_q


def _hash_to_challenge(w: list, message: bytes) -> int:
    """Hash (w, message) into a scalar challenge c ∈ Z_q."""
    w_bytes = b"".join(v.to_bytes(2, "little") for v in w)
    digest = hashlib.sha256(w_bytes + message).digest()
    return int.from_bytes(digest[:2], "little") % LWE_Q


def sig_keygen(rng=None):
    """Generate signature keypair."""
    if rng is None:
        rng = _secure_rng()
    A_sig = _sample_uniform_matrix(rng)
    s_sig = _sample_chi_vec(rng)
    t_sig = _matvec(A_sig, s_sig)
    return SigPublicKey(A_sig=A_sig, t_sig=t_sig), SigPrivateKey(s_sig=s_sig, A_sig=A_sig)


def sig_sign(sk: SigPrivateKey, message: bytes, rng=None) -> Signature:
    """Sign *message* with *sk*. Retries until rejection sampling passes."""
    if rng is None:
        rng = _secure_rng()
    A_sig = sk.A_sig
    for _attempt in range(1000):
        y = _sample_uniform_vec(rng)
        w = _matvec(A_sig, y)
        # scalar Fiat-Shamir challenge
        c = _hash_to_challenge(w, message)
        # z = y + c * s mod q  (c is a scalar; z is a vector)
        z = [_mod_q(y[i] + c * sk.s_sig[i]) for i in range(LWE_N)]
        # Rejection: keep z away from the "wrap" region (near 0 or q-1)
        B = LWE_Q // 4
        if all(z[i] < B or z[i] > LWE_Q - B for i in range(LWE_N)):
            continue  # reject
        return Signature(z=z, c_scalar=c)
    raise RuntimeError("sig_sign: too many rejections (should not happen with n=8)")


def sig_verify(pk: SigPublicKey, message: bytes, sig: Signature) -> bool:
    """Verify *sig* over *message* with *pk*."""
    A_sig = pk.A_sig
    c = sig.c_scalar
    # w' = A·z - c·t mod q  (c is scalar: multiply every component of t by c)
    Az = _matvec(A_sig, sig.z)
    ct_vec = [_mod_q(c * pk.t_sig[i]) for i in range(LWE_N)]
    w_prime = _vec_sub(Az, ct_vec)
    expected_c = _hash_to_challenge(w_prime, message)
    return expected_c == c


# ---------------------------------------------------------------------------
# HMAC-AEAD
#
#  Encrypt:
#    enc_key, mac_key = HKDF(key, nonce, info="pq-messenger-enc" / "pq-messenger-mac", 32)
#    keystream[i]     = HMAC-SHA256(enc_key, nonce || struct.pack(">Q", i))[:32]
#    ciphertext       = plaintext XOR keystream
#    tag              = HMAC-SHA256(mac_key, nonce || len(aad) || aad || len(ct) || ct)
#
#  Decrypt: recompute tag, compare in constant time, then XOR keystream.
# ---------------------------------------------------------------------------

def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def _keystream(enc_key: bytes, nonce: bytes, length: int) -> bytes:
    """Generate *length* bytes of keystream using HMAC-SHA256 as a PRF."""
    out = bytearray()
    block = 0
    while len(out) < length:
        blk = _hmac_sha256(enc_key, nonce + struct.pack(">Q", block))
        out += blk
        block += 1
    return bytes(out[:length])


def _aead_mac_input(nonce: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    """Canonical MAC input: nonce || len(aad) [4B] || aad || len(ct) [4B] || ct."""
    return (
        nonce
        + struct.pack(">I", len(aad))
        + aad
        + struct.pack(">I", len(ciphertext))
        + ciphertext
    )


def hmac_aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes):
    """
    Encrypt *plaintext* with HMAC-based AEAD.
    Returns (ciphertext, tag).
    """
    enc_key = hkdf(nonce, key, b"pq-messenger-enc", 32)
    mac_key = hkdf(nonce, key, b"pq-messenger-mac", 32)
    ks = _keystream(enc_key, nonce, len(plaintext))
    ciphertext = bytes(p ^ k for p, k in zip(plaintext, ks))
    tag = _hmac_sha256(mac_key, _aead_mac_input(nonce, aad, ciphertext))
    return ciphertext, tag


def hmac_aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes) -> bytes:
    """
    Decrypt, verifying the tag first.
    Raises ValueError on authentication failure.
    """
    enc_key = hkdf(nonce, key, b"pq-messenger-enc", 32)
    mac_key = hkdf(nonce, key, b"pq-messenger-mac", 32)
    expected_tag = _hmac_sha256(mac_key, _aead_mac_input(nonce, aad, ciphertext))
    if not hmac.compare_digest(expected_tag, tag):
        raise ValueError("AEAD authentication failed")
    ks = _keystream(enc_key, nonce, len(ciphertext))
    return bytes(c ^ k for c, k in zip(ciphertext, ks))


# ---------------------------------------------------------------------------
# Key ratchet: forward-secrecy step
# ---------------------------------------------------------------------------

def ratchet_key(current_key: bytes) -> bytes:
    """Derive next session key: KDF(current_key, 'ratchet')."""
    return hkdf(b"", current_key, b"pq-messenger-ratchet", 32)


# ---------------------------------------------------------------------------
# Main: step-by-step messenger demo
# ---------------------------------------------------------------------------

def main() -> None:
    print("=== Step 1: LWE key exchange (Alice generates KEM keys) ===")
    rng_alice = _SeededRNG(0xA11CE)
    lwe_pk, lwe_sk = lwe_keygen(rng_alice)
    print("  LWE public key b[:4]:", lwe_pk.b[:4], "(first 4 components mod", LWE_Q, ")")
    print("  LWE secret s[:4]    :", lwe_sk.s[:4])

    print()
    print("=== Step 2: DH keypairs (classic component of hybrid KEM) ===")
    alice_dh_priv, alice_dh_pub = dh_generate_keypair(_SeededRNG(0xA11CE2))
    bob_dh_priv, bob_dh_pub = dh_generate_keypair(_SeededRNG(0xB0B))
    alice_dh_shared = dh_shared_secret(alice_dh_priv, bob_dh_pub)
    bob_dh_shared = dh_shared_secret(bob_dh_priv, alice_dh_pub)
    assert alice_dh_shared == bob_dh_shared
    print("  Alice DH shared:", alice_dh_shared.hex())

    print()
    print("=== Step 3: Hybrid encapsulation (Bob -> Alice) ===")
    # Bob picks a random 32-byte LWE message, encapsulates it under Alice's LWE pk
    lwe_plaintext = _SeededRNG(0xB0B2).randbytes(32)
    rng_enc = _SeededRNG(0xB0BEA)
    ct = lwe_encaps(lwe_pk, lwe_plaintext, rng_enc)
    # Alice decapsulates
    lwe_recovered = lwe_decaps(lwe_sk, ct)
    assert lwe_recovered == lwe_plaintext, "LWE KEM decapsulation failed!"
    print("  LWE encaps/decaps: OK (256 bits)")
    # Combine LWE secret + DH shared -> session key
    salt = bytes.fromhex("deadbeef" * 8)
    session_key = hybrid_combine(lwe_plaintext, bob_dh_shared, salt, b"pq-messenger-session-v1")
    print("  Session key:", session_key.hex())

    print()
    print("=== Step 4: Lattice signature (authentication) ===")
    rng_sig = _SeededRNG(0x516A7)
    sig_pk, sig_sk = sig_keygen(rng_sig)
    # Alice signs her DH public key to prevent MITM
    alice_dh_pub_bytes = alice_dh_pub.to_bytes(16, "big")
    sig = sig_sign(sig_sk, alice_dh_pub_bytes, _SeededRNG(0x516A72))
    valid = sig_verify(sig_pk, alice_dh_pub_bytes, sig)
    tampered = sig_verify(sig_pk, b"impersonator", sig)
    print("  Signature over Alice's DH pubkey : valid =", valid)
    print("  Signature over tampered message  : valid =", tampered)
    assert valid and not tampered

    print()
    print("=== Step 5: Encrypted message exchange + key ratchet ===")
    # Alice sends first message
    nonce1 = bytes.fromhex("00" * 12)
    msg1 = b"Hello Bob! This channel is PQ-secure."
    aad1 = b"pq-messenger|msg_seq=1"
    ct1, tag1 = hmac_aead_encrypt(session_key, nonce1, msg1, aad1)
    print("  Alice->Bob ciphertext:", ct1.hex())
    plain1 = hmac_aead_decrypt(session_key, nonce1, ct1, tag1, aad1)
    assert plain1 == msg1
    print("  Bob decrypts         :", plain1.decode())

    # Key ratchet before Bob's reply
    ratcheted_key = ratchet_key(session_key)
    print("  Ratcheted key        :", ratcheted_key.hex())

    # Bob replies with the ratcheted key
    nonce2 = bytes.fromhex("00" * 11 + "01")
    msg2 = b"Hi Alice! Confirmed - quantum adversaries locked out."
    aad2 = b"pq-messenger|msg_seq=2"
    ct2, tag2 = hmac_aead_encrypt(ratcheted_key, nonce2, msg2, aad2)
    plain2 = hmac_aead_decrypt(ratcheted_key, nonce2, ct2, tag2, aad2)
    assert plain2 == msg2
    print("  Bob->Alice ciphertext:", ct2.hex())
    print("  Alice decrypts       :", plain2.decode())

    print()
    print("=== Done: PQ-secure messenger session complete ===")


if __name__ == "__main__":
    main()
