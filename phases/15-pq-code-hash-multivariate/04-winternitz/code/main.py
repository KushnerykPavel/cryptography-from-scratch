"""
Winternitz one-time signatures (WOTS+) — educational, stdlib-only demo.

This file implements a simplified Winternitz one-time signature scheme in the
spirit of WOTS+ from RFC 8391, using SHA-256 as the hash and HMAC-SHA256 as a
deterministic PRF to derive private key elements from a seed.

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib
import hmac
import math
from dataclasses import dataclass
from typing import Iterable, List, Sequence, Tuple


DEFAULT_N = 32
DEFAULT_W = 16  # RFC 8391 uses w in {4, 16}


@dataclass(frozen=True)
class WOTSParams:
    n: int
    w: int
    lg_w: int
    len_1: int
    len_2: int
    length: int


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def wots_params(n: int = DEFAULT_N, w: int = DEFAULT_W) -> WOTSParams:
    if n <= 0:
        raise ValueError("n must be positive")
    if w not in (4, 16):
        raise ValueError("w must be 4 or 16 (RFC 8391 parameter sets)")
    lg_w = int(math.log2(w))
    if (1 << lg_w) != w:
        raise ValueError("w must be a power of two")

    len_1 = math.ceil((8 * n) / lg_w)
    len_2 = math.floor(math.log2(len_1 * (w - 1)) / math.log2(w)) + 1
    return WOTSParams(n=n, w=w, lg_w=lg_w, len_1=len_1, len_2=len_2, length=len_1 + len_2)


def base_w(x: bytes, w: int, out_len: int) -> List[int]:
    """
    Convert bytes to base-w digits as in RFC 8391, Algorithm 1 (base_w).

    For w in {4,16}, lg(w) is 2 or 4, so digits are extracted in big-endian
    order by consuming lg(w) bits at a time.
    """
    params = wots_params(n=1, w=w)
    lg_w = params.lg_w
    max_out = (8 * len(x)) // lg_w
    if out_len < 0 or out_len > max_out:
        raise ValueError("out_len too large for input length and w")

    in_idx = 0
    total = 0
    bits = 0
    out: List[int] = []

    for _ in range(out_len):
        if bits == 0:
            total = x[in_idx]
            in_idx += 1
            bits = 8
        bits -= lg_w
        out.append((total >> bits) & (w - 1))
    return out


def _to_byte(x: int, length: int) -> bytes:
    if x < 0:
        raise ValueError("x must be non-negative")
    return x.to_bytes(length, "big")


def _wots_checksum(msg_base_w: Sequence[int], w: int, len_2: int) -> List[int]:
    lg_w = int(math.log2(w))
    csum = sum((w - 1 - d) for d in msg_base_w)
    shift = (8 - ((len_2 * lg_w) % 8)) % 8
    csum <<= shift
    len_2_bytes = math.ceil((len_2 * lg_w) / 8)
    return base_w(_to_byte(csum, len_2_bytes), w, len_2)


def wots_message_digits(message: bytes, n: int = DEFAULT_N, w: int = DEFAULT_W) -> List[int]:
    """
    Hash an arbitrary message to n bytes and convert it to len base-w digits,
    including the checksum digits (RFC 8391, Algorithms 5/6).
    """
    p = wots_params(n=n, w=w)
    digest = sha256(message)[:n]
    msg_digits = base_w(digest, w, p.len_1)
    csum_digits = _wots_checksum(msg_digits, w=w, len_2=p.len_2)
    return msg_digits + csum_digits


def chain(x: bytes, steps: int) -> bytes:
    if steps < 0:
        raise ValueError("steps must be non-negative")
    y = x
    for _ in range(steps):
        y = sha256(y)
    return y


def wots_private_key_from_seed(sk_seed: bytes, n: int = DEFAULT_N, w: int = DEFAULT_W) -> List[bytes]:
    """
    Deterministically derive the WOTS private key elements from a seed.

    Real WOTS+ derives elements via a PRF keyed by a secret seed plus addresses.
    Here we use HMAC-SHA256(SK.seed, b\"WOTS-SK\" || i32) and truncate to n bytes.
    """
    if len(sk_seed) < 16:
        raise ValueError("sk_seed too short; use at least 16 bytes")
    p = wots_params(n=n, w=w)
    out: List[bytes] = []
    for i in range(p.length):
        i32 = i.to_bytes(4, "big")
        out.append(hmac_sha256(sk_seed, b"WOTS-SK" + i32)[:n])
    return out


def wots_public_key_from_private(sk: Sequence[bytes], n: int = DEFAULT_N, w: int = DEFAULT_W) -> List[bytes]:
    p = wots_params(n=n, w=w)
    if len(sk) != p.length:
        raise ValueError("wrong private key length for parameters")
    for x in sk:
        if len(x) != n:
            raise ValueError("wrong private key element length")
    return [chain(sk[i], w - 1) for i in range(p.length)]


def wots_keypair_from_seed(sk_seed: bytes, n: int = DEFAULT_N, w: int = DEFAULT_W) -> Tuple[List[bytes], List[bytes]]:
    sk = wots_private_key_from_seed(sk_seed, n=n, w=w)
    pk = wots_public_key_from_private(sk, n=n, w=w)
    return sk, pk


def wots_sign(message: bytes, sk_seed: bytes, n: int = DEFAULT_N, w: int = DEFAULT_W) -> List[bytes]:
    p = wots_params(n=n, w=w)
    digits = wots_message_digits(message, n=n, w=w)
    if len(digits) != p.length:
        raise AssertionError("internal error: digits length mismatch")
    sk = wots_private_key_from_seed(sk_seed, n=n, w=w)
    return [chain(sk[i], digits[i]) for i in range(p.length)]


def wots_public_key_from_signature(signature: Sequence[bytes], message: bytes, n: int = DEFAULT_N, w: int = DEFAULT_W) -> List[bytes]:
    p = wots_params(n=n, w=w)
    if len(signature) != p.length:
        raise ValueError("wrong signature length for parameters")
    for x in signature:
        if len(x) != n:
            raise ValueError("wrong signature element length")
    digits = wots_message_digits(message, n=n, w=w)
    return [chain(signature[i], (w - 1) - digits[i]) for i in range(p.length)]


def wots_verify(signature: Sequence[bytes], message: bytes, public_key: Sequence[bytes], n: int = DEFAULT_N, w: int = DEFAULT_W) -> bool:
    p = wots_params(n=n, w=w)
    if len(public_key) != p.length:
        raise ValueError("wrong public key length for parameters")
    derived = wots_public_key_from_signature(signature, message, n=n, w=w)
    return list(public_key) == derived


def _fingerprint(parts: Iterable[bytes]) -> str:
    return sha256(b"".join(parts)).hex()


def _print_step_header(n: int, name: str) -> None:
    print(f"=== Step {n}: {name} ===")


def main() -> None:
    n = DEFAULT_N
    w = DEFAULT_W
    p = wots_params(n=n, w=w)

    message = b"winternitz: one-time signatures are hash chains"
    sk_seed = bytes.fromhex("11" * 32)

    _print_step_header(1, "Parameters, base-w digits, checksum")
    print(f"params: n={p.n} w={p.w} len_1={p.len_1} len_2={p.len_2} len={p.length}")
    digits = wots_message_digits(message, n=n, w=w)
    print(f"message sha256: {sha256(message).hex()}")
    print(f"first 20 digits (base {w}): {digits[:20]}")
    print(f"checksum digits: {digits[p.len_1:]}")
    print()

    _print_step_header(2, "Hash chains and deterministic private key")
    sk = wots_private_key_from_seed(sk_seed, n=n, w=w)
    print(f"sk[0]: {sk[0].hex()}")
    print(f"chain(sk[0], 0):  {chain(sk[0], 0).hex()}")
    print(f"chain(sk[0], 5):  {chain(sk[0], 5).hex()}")
    print(f"chain(sk[0], 15): {chain(sk[0], 15).hex()}")
    print()

    _print_step_header(3, "Public key from private key (commitments)")
    pk = wots_public_key_from_private(sk, n=n, w=w)
    print(f"public key length: {len(pk)} elements of {n} bytes")
    print(f"pk fingerprint (sha256 of concat): {_fingerprint(pk)[:32]}...")
    print()

    _print_step_header(4, "Sign and verify")
    sig = wots_sign(message, sk_seed, n=n, w=w)
    print(f"sig fingerprint (sha256 of concat): {_fingerprint(sig)[:32]}...")
    ok = wots_verify(sig, message, pk, n=n, w=w)
    print(f"verify(sig, message, pk) = {ok}")

    tampered = message + b"!"
    ok2 = wots_verify(sig, tampered, pk, n=n, w=w)
    print(f"verify(sig, tampered_message, pk) = {ok2}")

    derived_pk = wots_public_key_from_signature(sig, message, n=n, w=w)
    print(f"pk derived from signature matches: {derived_pk == pk}")


if __name__ == "__main__":
    main()
