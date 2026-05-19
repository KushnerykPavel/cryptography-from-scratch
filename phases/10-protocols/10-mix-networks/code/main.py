"""Mix networks from scratch: toy onion packets + mix rounds to illustrate metadata resistance.

This lesson builds a small, dependency-free demo of a Chaum-style mix network:
messages are wrapped in multiple encryption layers, then each mix node removes
one layer and *shuffles the batch* to break the input↔output link.

Stdlib only: hashlib, hmac, random, struct.
Run: python3 code/main.py
"""

from __future__ import annotations

import hashlib
import hmac
import random
import struct
from typing import Iterable, List, Sequence

NONCE_LEN = 16
TAG_LEN = 32  # HMAC-SHA256
CELL_LEN = 64  # fixed-size payload to avoid trivial length leakage in the demo


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor_bytes: length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))


def kdf_stream(key: bytes, nonce: bytes, nbytes: int) -> bytes:
    if nbytes < 0:
        raise ValueError("kdf_stream: nbytes must be non-negative")
    out = b""
    counter = 0
    while len(out) < nbytes:
        out += hashlib.sha256(key + nonce + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:nbytes]


def encrypt_then_mac(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    if len(nonce) != NONCE_LEN:
        raise ValueError("encrypt_then_mac: bad nonce length")
    stream = kdf_stream(key, nonce, len(plaintext))
    ciphertext = xor_bytes(plaintext, stream)
    tag = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
    return nonce + ciphertext + tag


def decrypt_then_verify(key: bytes, packet: bytes) -> bytes:
    if len(packet) < NONCE_LEN + TAG_LEN:
        raise ValueError("decrypt_then_verify: packet too short")
    nonce = packet[:NONCE_LEN]
    tag = packet[-TAG_LEN:]
    ciphertext = packet[NONCE_LEN:-TAG_LEN]
    expected = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("decrypt_then_verify: authentication failed")
    stream = kdf_stream(key, nonce, len(ciphertext))
    return xor_bytes(ciphertext, stream)


def pack_cell(text: str, *, cell_len: int = CELL_LEN) -> bytes:
    raw = text.encode("utf-8")
    if cell_len < 2:
        raise ValueError("pack_cell: cell_len must be >= 2")
    if len(raw) > cell_len - 2:
        raise ValueError("pack_cell: message too long for cell")
    return struct.pack(">H", len(raw)) + raw + b"\x00" * (cell_len - 2 - len(raw))


def unpack_cell(cell: bytes) -> str:
    if len(cell) < 2:
        raise ValueError("unpack_cell: cell too short")
    (n,) = struct.unpack(">H", cell[:2])
    if n > len(cell) - 2:
        raise ValueError("unpack_cell: invalid length prefix")
    return cell[2 : 2 + n].decode("utf-8")


def onion_encrypt(plaintext: bytes, keys: Sequence[bytes], nonces: Sequence[bytes]) -> bytes:
    if len(keys) != len(nonces):
        raise ValueError("onion_encrypt: keys/nonces length mismatch")
    packet = plaintext
    for key, nonce in reversed(list(zip(keys, nonces))):
        packet = encrypt_then_mac(key, nonce, packet)
    return packet


def peel_one_layer(packet: bytes, key: bytes) -> bytes:
    return decrypt_then_verify(key, packet)


def apply_permutation(items: Sequence[bytes], permutation: Sequence[int]) -> List[bytes]:
    n = len(items)
    if len(permutation) != n:
        raise ValueError("apply_permutation: wrong permutation length")
    if sorted(permutation) != list(range(n)):
        raise ValueError("apply_permutation: not a permutation")
    return [items[i] for i in permutation]


def mix_round(packets: Sequence[bytes], hop_key: bytes, permutation: Sequence[int]) -> List[bytes]:
    peeled = [peel_one_layer(p, hop_key) for p in packets]
    return apply_permutation(peeled, permutation)


def _key(label: str) -> bytes:
    return hashlib.sha256(("mixkey:" + label).encode("utf-8")).digest()


def _nonce(label: str) -> bytes:
    return hashlib.sha256(("nonce:" + label).encode("utf-8")).digest()[:NONCE_LEN]


def _fp(data: bytes, n: int = 10) -> str:
    return hashlib.sha256(data).hexdigest()[:n]


def _print_batch(prefix: str, packets: Sequence[bytes]) -> None:
    fps = ", ".join(_fp(p) for p in packets)
    print(f"  {prefix}: [{fps}]")


def main() -> None:
    rng = random.Random(0)

    print("=== Step 1: toy authenticated encryption (stream XOR + HMAC) ===")
    key = _key("demo")
    n1 = _nonce("n1")
    n2 = _nonce("n2")
    msg = b"hello"
    p1 = encrypt_then_mac(key, n1, msg)
    p2 = encrypt_then_mac(key, n2, msg)
    print(f"  same plaintext, different nonces -> different packets: {_fp(p1)} vs {_fp(p2)}")
    recovered = decrypt_then_verify(key, p1)
    print(f"  decrypt_then_verify(encrypt_then_mac(...)) -> {recovered!r}")

    print()
    print("=== Step 2: fixed-size cells (pad to constant length) ===")
    cell = pack_cell("Alice -> Bob: meet at 5")
    print(f"  cell length: {len(cell)} bytes (constant)")
    print(f"  unpack_cell(cell) -> {unpack_cell(cell)!r}")

    print()
    print("=== Step 3: onion-wrap a cell for 3 mix hops ===")
    hop_keys = [_key("mix-1"), _key("mix-2"), _key("mix-3")]
    hop_nonces = [_nonce("hop-1"), _nonce("hop-2"), _nonce("hop-3")]
    onion = onion_encrypt(cell, hop_keys, hop_nonces)
    print(f"  payload: {len(cell)} bytes, onion packet: {len(onion)} bytes")
    print(f"  overhead per hop: {NONCE_LEN + TAG_LEN} bytes (nonce + tag)")

    print()
    print("=== Step 4: mix rounds (peel + shuffle batches) ===")
    texts = [
        "Alice -> Bob: #1",
        "Carol -> Dave: #2",
        "Eve -> Frank: #3",
        "Grace -> Heidi: #4",
        "Ivan -> Judy: #5",
    ]

    packets: List[bytes] = []
    for i, text in enumerate(texts):
        cell_i = pack_cell(text)
        nonces_i = [_nonce(f"m{i}-hop{j}") for j in range(len(hop_keys))]
        packets.append(onion_encrypt(cell_i, hop_keys, nonces_i))

    _print_batch("input order", packets)
    for hop_idx, hop_key in enumerate(hop_keys, start=1):
        perm = list(range(len(packets)))
        rng.shuffle(perm)
        packets = mix_round(packets, hop_key, perm)
        _print_batch(f"after hop {hop_idx} (perm={perm})", packets)

    decoded = [unpack_cell(p) for p in packets]
    print("  final decoded messages:")
    for t in decoded:
        print(f"    - {t}")


if __name__ == "__main__":
    main()
