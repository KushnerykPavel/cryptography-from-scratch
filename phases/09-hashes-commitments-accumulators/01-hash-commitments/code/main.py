"""
Hash-based commitments (educational).

Run:
  python3 code/main.py

This script:
- Implements a simple hash-based commitment scheme: c = SHA256(encode(m, r)).
- Shows why you must include fresh randomness (a nonce) for hiding.
- Shows why you must use an unambiguous encoding (length-prefixing + domain separation).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import struct


COMMITMENT_DOMAIN = b"CFSC-HASH-COMMIT-v1"


def sha256_hex(data: bytes) -> str:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("data must be bytes-like")
    return hashlib.sha256(bytes(data)).hexdigest()


def _u32be(n: int) -> bytes:
    if n < 0 or n > 0xFFFFFFFF:
        raise ValueError("length out of range for u32")
    return struct.pack(">I", n)


def encode_commit_input(*, message: bytes, nonce: bytes) -> bytes:
    if not isinstance(message, (bytes, bytearray, memoryview)):
        raise TypeError("message must be bytes-like")
    if not isinstance(nonce, (bytes, bytearray, memoryview)):
        raise TypeError("nonce must be bytes-like")

    m = bytes(message)
    r = bytes(nonce)
    return COMMITMENT_DOMAIN + _u32be(len(m)) + m + _u32be(len(r)) + r


def commit(*, message: bytes, nonce: bytes) -> str:
    return sha256_hex(encode_commit_input(message=message, nonce=nonce))


def _validate_commitment_hex(commitment_hex: str) -> str:
    if not isinstance(commitment_hex, str):
        raise TypeError("commitment_hex must be a string")
    cleaned = commitment_hex.strip().lower()
    if len(cleaned) != 64:
        raise ValueError("commitment_hex must be a 64-character SHA-256 hex digest")
    try:
        bytes.fromhex(cleaned)
    except ValueError as e:
        raise ValueError("commitment_hex must be hex") from e
    return cleaned


def verify(*, commitment_hex: str, message: bytes, nonce: bytes) -> bool:
    expected = _validate_commitment_hex(commitment_hex)
    got = commit(message=message, nonce=nonce)
    return hmac.compare_digest(got, expected)


def commit_with_random_nonce(*, message: bytes, nonce_len: int = 32) -> tuple[str, bytes]:
    if nonce_len <= 0:
        raise ValueError("nonce_len must be positive")
    r = secrets.token_bytes(nonce_len)
    return commit(message=message, nonce=r), r


def naive_commit(*, message: bytes, nonce: bytes) -> str:
    if not isinstance(message, (bytes, bytearray, memoryview)):
        raise TypeError("message must be bytes-like")
    if not isinstance(nonce, (bytes, bytearray, memoryview)):
        raise TypeError("nonce must be bytes-like")
    return sha256_hex(bytes(message) + bytes(nonce))


def _print_step(n: int, name: str) -> None:
    print(f"=== Step {n}: {name} ===")


def step1_sha256_and_encoding() -> None:
    _print_step(1, "SHA-256 and unambiguous encoding")
    print(f"SHA256('abc') = {sha256_hex(b'abc')}")

    message = b"hello"
    nonce = b"\x00" * 4
    encoded = encode_commit_input(message=message, nonce=nonce)
    print(f"encode_commit_input(message='hello', nonce=00..00) (hex) = {encoded.hex()}")


def step2_commit_and_verify() -> None:
    _print_step(2, "Commit and verify (commit-reveal)")
    message = b"launch at 06:00"
    commitment, nonce = commit_with_random_nonce(message=message, nonce_len=16)

    print(f"commitment c = {commitment}")
    print(f"(kept secret for now) nonce r = {nonce.hex()}")

    ok = verify(commitment_hex=commitment, message=message, nonce=nonce)
    print(f"verify(c, m, r) = {ok}")

    tampered = verify(commitment_hex=commitment, message=b"launch at 07:00", nonce=nonce)
    print(f"verify(c, m', r) with tampered message = {tampered}")


def step3_hiding_needs_nonce() -> None:
    _print_step(3, "Why hiding needs a nonce (dictionary attack)")
    candidates = [b"red", b"green", b"blue", b"yellow"]
    secret_message = b"green"

    c_no_nonce = sha256_hex(secret_message)
    guessed = next((m for m in candidates if sha256_hex(m) == c_no_nonce), None)
    print(f"commit without nonce: c = SHA256(m) = {c_no_nonce}")
    print(f"attacker guesses m from 4 candidates -> {guessed!r}")

    nonce = b"\x00" * 32
    c_with_nonce = commit(message=secret_message, nonce=nonce)
    guessed2 = next((m for m in candidates if commit(message=m, nonce=nonce) == c_with_nonce), None)
    print(f"commit with nonce (but leaked nonce): c = {c_with_nonce}")
    print(f"attacker guesses if nonce is known -> {guessed2!r}")

    c_secret_nonce, secret_nonce = commit_with_random_nonce(message=secret_message, nonce_len=32)
    guessed3 = next((m for m in candidates if commit(message=m, nonce=secret_nonce) == c_secret_nonce), None)
    print(f"commit with secret nonce: c = {c_secret_nonce}")
    print("attacker cannot test candidates without r (even if m-space is small)")
    print(f"(after reveal) attacker can check: guessed -> {guessed3!r}")


def step4_ambiguity_attack_on_naive_concat() -> None:
    _print_step(4, "Pitfall: naive concatenation allows ambiguous openings")
    m1, r1 = b"a", b"bc"
    m2, r2 = b"ab", b"c"
    c1 = naive_commit(message=m1, nonce=r1)
    c2 = naive_commit(message=m2, nonce=r2)
    print(f"naive_commit(a, bc) = {c1}")
    print(f"naive_commit(ab, c) = {c2}")
    print(f"same commitment from different (m, r) pairs: {c1 == c2}")

    safe1 = commit(message=m1, nonce=r1)
    safe2 = commit(message=m2, nonce=r2)
    print(f"commit(a, bc)  = {safe1}")
    print(f"commit(ab, c)  = {safe2}")
    print(f"length-prefix encoding prevents ambiguity: {safe1 != safe2}")


def main() -> None:
    step1_sha256_and_encoding()
    print()
    step2_commit_and_verify()
    print()
    step3_hiding_needs_nonce()
    print()
    step4_ambiguity_attack_on_naive_concat()


if __name__ == "__main__":
    main()
