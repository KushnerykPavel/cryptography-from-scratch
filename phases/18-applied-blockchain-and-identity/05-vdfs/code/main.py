"""
VDFs — Verifiable Delay Functions (educational toy).

Implements a Wesolowski-style VDF over an RSA group:
  - Setup:  N = p * q  (product of two Mersenne primes)
  - Eval:   y = x^(2^T) mod N  (T sequential squarings)
  - Proof:  pi = x^(floor(2^T / l)) mod N  where l = vdf_challenge(x, y, T)
  - Verify: (pi^l * x^(2^T mod l)) mod N == y

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib
import os
import struct


# ---------------------------------------------------------------------------
# RSA modulus — product of two Mersenne primes (fixed for deterministic tests)
# p = 2^31 - 1 = 2 147 483 647
# q = 2^61 - 1 = 2 305 843 009 213 693 951
# ---------------------------------------------------------------------------
_P = (1 << 31) - 1   # Mersenne prime 2^31-1
_Q = (1 << 61) - 1   # Mersenne prime 2^61-1
_N = _P * _Q         # 92-bit RSA modulus (demo only)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def vdf_setup() -> int:
    """Return the RSA modulus N = p * q (two fixed Mersenne primes)."""
    return _N


def vdf_eval(x: int, T: int, N: int) -> int:
    """
    Evaluate the VDF: return y = x^(2^T) mod N.

    Uses fast repeated squaring — T multiplications total (not exponentiating
    the huge exponent 2^T directly).
    """
    y = x % N
    for _ in range(T):
        y = (y * y) % N
    return y


def vdf_challenge(x: int, y: int, T: int) -> int:
    """
    Derive the Wesolowski challenge l = H(x || y || T) as a positive integer.

    The hash is taken over a canonical byte encoding so that x, y each
    occupy 16 bytes (big-endian) and T occupies 8 bytes.

    The challenge is reduced modulo 2^(T//2 + 1) so it is guaranteed to be
    strictly less than 2^T (ensuring q = floor(2^T / l) >= 1 and pi != 1
    for non-trivial proofs).  A minimum of 2 is enforced.
    """
    data = (
        x.to_bytes(16, "big")
        + y.to_bytes(16, "big")
        + struct.pack(">Q", T)
    )
    h = hashlib.sha256(data).digest()
    raw = int.from_bytes(h, "big")
    # Keep enough bits so l is in [2, 2^(T-1)-1], guaranteeing q >= 1.
    # For T >= 4 we use T-2 bits; for small T we clamp to T-1 bits minimum.
    bits = max(T - 2, 3)
    l = (raw % ((1 << bits) - 1)) + 2
    return l


def vdf_eval_with_proof(x: int, T: int, N: int) -> tuple[int, int]:
    """
    Evaluate the VDF and produce a Wesolowski proof.

    Returns (y, pi) where:
      y  = x^(2^T) mod N
      pi = x^(floor(2^T / l)) mod N,  l = vdf_challenge(x, y, T)

    The verifier can check the proof in O(log T) work instead of T.
    """
    y = vdf_eval(x, T, N)
    l = vdf_challenge(x, y, T)

    # Compute q = floor(2^T / l) incrementally without materialising 2^T.
    # Invariant: after i steps, q = floor(2^i / l), r = 2^i mod l.
    q = 0
    r = 1  # 2^0 mod l = 1
    for _ in range(T):
        two_r = 2 * r
        q = 2 * q + two_r // l
        r = two_r % l

    pi = pow(x, q, N)
    return y, pi


def vdf_verify(x: int, T: int, y: int, pi: int, N: int) -> bool:
    """
    Verify a Wesolowski VDF proof.

    Check: (pi^l * x^(2^T mod l)) mod N == y
    where l = vdf_challenge(x, y, T) and r = 2^T mod l.
    """
    l = vdf_challenge(x, y, T)
    r = pow(2, T, l)
    lhs = (pow(pi, l, N) * pow(x, r, N)) % N
    return lhs == y


def vdf_time_lock_encrypt(
    message: bytes, T: int, N: int
) -> tuple[int, int, bytes]:
    """
    Time-lock encrypt a message using a VDF puzzle.

    Picks a random x, computes y = VDF(x, T, N), then encrypts:
      ciphertext = message XOR keystream  (keystream from SHA-256 of y)

    Messages of any length are supported (keystream is extended with a
    block counter).

    Returns (x, T, ciphertext).  The receiver must solve the VDF to get y,
    then call vdf_time_lock_decrypt(y, ciphertext).
    """
    x = int.from_bytes(os.urandom(16), "big") % (N - 2) + 1
    y = vdf_eval(x, T, N)
    ciphertext = _xor_with_keystream(message, y)
    return x, T, ciphertext


def vdf_time_lock_decrypt(y: int, ciphertext: bytes) -> bytes:
    """
    Decrypt a time-lock ciphertext given the VDF output y.

    Reverses the XOR keystream derived from SHA-256(y).
    """
    return _xor_with_keystream(ciphertext, y)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _keystream(y: int, length: int) -> bytes:
    """Generate `length` bytes of keystream from y using SHA-256 + counter."""
    key_seed = y.to_bytes(16, "big")
    stream = bytearray()
    counter = 0
    while len(stream) < length:
        block = hashlib.sha256(key_seed + counter.to_bytes(4, "big")).digest()
        stream.extend(block)
        counter += 1
    return bytes(stream[:length])


def _xor_with_keystream(data: bytes, y: int) -> bytes:
    ks = _keystream(y, len(data))
    return bytes(a ^ b for a, b in zip(data, ks))


def _hx(n: int) -> str:
    return hex(n)


# ---------------------------------------------------------------------------
# main — demo walkthrough
# ---------------------------------------------------------------------------

def main() -> None:
    print("=== Step 1: VDF Setup — RSA Modulus ===")
    N = vdf_setup()
    print(f"p  = {_P}")
    print(f"q  = {_Q}")
    print(f"N  = p * q = {N}")
    print(f"N (hex) = {_hx(N)}")
    print()

    print("=== Step 2: Evaluate VDF ===")
    x = 2
    T = 20
    y = vdf_eval(x, T, N)
    print(f"x = {x},  T = {T}")
    print(f"y = x^(2^T) mod N = {y}")
    print(f"y (hex) = {_hx(y)}")
    print()

    print("=== Step 3: Generate Wesolowski Proof ===")
    y2, pi = vdf_eval_with_proof(x, T, N)
    assert y2 == y, "eval_with_proof output mismatch"
    l = vdf_challenge(x, y, T)
    print(f"challenge l = {l}")
    print(f"proof pi    = {pi}")
    print(f"pi (hex)    = {_hx(pi)}")
    print()

    print("=== Step 4: Verify Proof ===")
    valid = vdf_verify(x, T, y, pi, N)
    print(f"vdf_verify(x={x}, T={T}, y, pi, N) = {valid}")
    tampered = vdf_verify(x, T, y + 1, pi, N)
    print(f"tampered y+1 => verify = {tampered}")
    print()

    print("=== Step 5: Time-Lock Encryption ===")
    secret = b"hello VDF world!"
    T_lock = 15
    enc_x, enc_T, ciphertext = vdf_time_lock_encrypt(secret, T_lock, N)
    print(f"plaintext   = {secret!r}")
    print(f"T_lock      = {enc_T}")
    print(f"puzzle x    = {enc_x}")
    print(f"ciphertext  = {ciphertext.hex()}")
    solved_y = vdf_eval(enc_x, enc_T, N)
    recovered = vdf_time_lock_decrypt(solved_y, ciphertext)
    print(f"recovered   = {recovered!r}")
    assert recovered == secret, "decryption failed"
    print("Time-lock encryption round-trip: OK")


if __name__ == "__main__":
    main()
