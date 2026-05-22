"""
Private Set Intersection (PSI) from scratch (educational).

We implement a toy PSI protocol based on commutative "encryption" via modular
exponentiation:

  Enc_k(m) = m^k mod p

If k is invertible modulo (p-1), we can "remove" a layer by exponentiating by
inv(k) mod (p-1). This gives a clean way to build a PSI-style flow:

  - client blinds items with a
  - server re-blinds with b
  - client unblinds to obtain server-keyed tags
  - membership tests reveal intersection (or just cardinality)

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib
import math
import random
import secrets
from dataclasses import dataclass
from typing import Iterable, Sequence


DEFAULT_P = (1 << 127) - 1  # 2^127-1, a Mersenne prime (educational-sized)


def sha256(data: bytes) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("data must be bytes-like")
    return hashlib.sha256(bytes(data)).digest()


def _int_to_bytes(n: int) -> bytes:
    if not isinstance(n, int):
        raise TypeError("n must be int")
    if n < 0:
        raise ValueError("n must be non-negative")
    if n == 0:
        return b"\x00"
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def hash_to_group_elem(*, item: str, p: int) -> int:
    """
    Deterministically map a string to an element of Z_p^* (excluding {0,1}).
    """
    if not isinstance(item, str):
        raise TypeError("item must be str")
    if not isinstance(p, int):
        raise TypeError("p must be int")
    if p <= 5:
        raise ValueError("p must be > 5")

    h = sha256(item.encode("utf-8"))
    x = int.from_bytes(h, "big")
    return (x % (p - 3)) + 2  # in [2, p-2]


def _egcd(a: int, b: int) -> tuple[int, int, int]:
    if not isinstance(a, int) or not isinstance(b, int):
        raise TypeError("a and b must be int")
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def modinv(*, a: int, m: int) -> int:
    if not isinstance(a, int):
        raise TypeError("a must be int")
    if not isinstance(m, int):
        raise TypeError("m must be int")
    if m <= 1:
        raise ValueError("m must be > 1")
    g, x, _y = _egcd(a % m, m)
    if g != 1:
        raise ValueError("a is not invertible modulo m")
    return x % m


def choose_coprime_exponent(*, phi: int, seed: int | None = None) -> int:
    """
    Pick e uniformly-ish from [2, phi-1] such that gcd(e, phi) = 1.

    - With seed=None, uses secrets for randomness.
    - With seed=int, uses a deterministic RNG (useful for test vectors).
    """
    if not isinstance(phi, int):
        raise TypeError("phi must be int")
    if phi <= 4:
        raise ValueError("phi must be > 4")
    if seed is not None and not isinstance(seed, int):
        raise TypeError("seed must be int or None")

    if seed is None:
        def _randbelow(upper: int) -> int:
            return secrets.randbelow(upper)
    else:
        rng = random.Random(seed)

        def _randbelow(upper: int) -> int:
            return rng.randrange(0, upper)

    while True:
        e = _randbelow(phi - 2) + 2  # [2, phi-1]
        if math.gcd(e, phi) == 1:
            return e


def commutative_enc(*, m: int, e: int, p: int) -> int:
    if not isinstance(m, int):
        raise TypeError("m must be int")
    if not isinstance(e, int):
        raise TypeError("e must be int")
    if not isinstance(p, int):
        raise TypeError("p must be int")
    if p <= 5:
        raise ValueError("p must be > 5")
    if not (1 <= m <= p - 1):
        raise ValueError("m must be in [1, p-1]")
    if e <= 1 or e >= p - 1:
        raise ValueError("e must be in [2, p-2]")
    return pow(m, e, p)


def commutative_remove_layer(*, c: int, e: int, p: int) -> int:
    """
    Remove a commutative exponentiation layer by raising to inv(e) mod (p-1).
    Requires gcd(e, p-1)=1 and c in Z_p^*.
    """
    if not isinstance(c, int):
        raise TypeError("c must be int")
    if not isinstance(e, int):
        raise TypeError("e must be int")
    if not isinstance(p, int):
        raise TypeError("p must be int")
    if p <= 5:
        raise ValueError("p must be > 5")
    if not (1 <= c <= p - 1):
        raise ValueError("c must be in [1, p-1]")

    inv_e = modinv(a=e, m=p - 1)
    return pow(c, inv_e, p)


def _print_step(n: int, name: str) -> None:
    print(f"=== Step {n}: {name} ===")


def _dedupe_preserve_order(items: Iterable[str]) -> list[str]:
    if not isinstance(items, Iterable):
        raise TypeError("items must be iterable")
    out: list[str] = []
    seen: set[str] = set()
    for it in items:
        if not isinstance(it, str):
            raise TypeError("all items must be str")
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out


def server_tags(*, server_items: Sequence[str], p: int, b: int) -> set[int]:
    if not isinstance(server_items, Sequence):
        raise TypeError("server_items must be a sequence")
    tags: set[int] = set()
    for it in _dedupe_preserve_order(server_items):
        m = hash_to_group_elem(item=it, p=p)
        tags.add(commutative_enc(m=m, e=b, p=p))
    return tags


def client_request(*, client_items: Sequence[str], p: int, a: int) -> list[int]:
    if not isinstance(client_items, Sequence):
        raise TypeError("client_items must be a sequence")
    req: list[int] = []
    for it in _dedupe_preserve_order(client_items):
        m = hash_to_group_elem(item=it, p=p)
        req.append(commutative_enc(m=m, e=a, p=p))
    return req


def server_response(*, blinded_items: Sequence[int], p: int, b: int, reveal_intersection: bool) -> list[int]:
    if not isinstance(blinded_items, Sequence):
        raise TypeError("blinded_items must be a sequence")
    if not isinstance(reveal_intersection, bool):
        raise TypeError("reveal_intersection must be bool")

    out = [commutative_enc(m=v, e=b, p=p) for v in blinded_items]
    if not reveal_intersection:
        out.sort()
    return out


def client_unblind_response(*, response: Sequence[int], p: int, a: int) -> list[int]:
    if not isinstance(response, Sequence):
        raise TypeError("response must be a sequence")
    return [commutative_remove_layer(c=c, e=a, p=p) for c in response]


def psi_intersection(
    *,
    client_items: Sequence[str],
    server_items: Sequence[str],
    p: int = DEFAULT_P,
    a: int | None = None,
    b: int | None = None,
    reveal_intersection: bool = True,
    seed: int | None = None,
) -> list[str] | int:
    """
    End-to-end PSI simulation.

    - If reveal_intersection=True, returns the list of client items that are in the intersection.
      (Order is the client's input order after de-duplication.)
    - If reveal_intersection=False, returns an integer "intersection size" computed without
      preserving per-item alignment.
    """
    if not isinstance(client_items, Sequence):
        raise TypeError("client_items must be a sequence")
    if not isinstance(server_items, Sequence):
        raise TypeError("server_items must be a sequence")
    if not isinstance(p, int):
        raise TypeError("p must be int")
    if p <= 5:
        raise ValueError("p must be > 5")
    if not isinstance(reveal_intersection, bool):
        raise TypeError("reveal_intersection must be bool")
    if seed is not None and not isinstance(seed, int):
        raise TypeError("seed must be int or None")

    phi = p - 1
    if a is None:
        a = choose_coprime_exponent(phi=phi, seed=seed)
    if b is None:
        b = choose_coprime_exponent(phi=phi, seed=None if seed is None else seed + 1)

    if math.gcd(a, phi) != 1:
        raise ValueError("a must be coprime with (p-1)")
    if math.gcd(b, phi) != 1:
        raise ValueError("b must be coprime with (p-1)")

    client_items_u = _dedupe_preserve_order(client_items)
    req = client_request(client_items=client_items_u, p=p, a=a)
    resp = server_response(blinded_items=req, p=p, b=b, reveal_intersection=reveal_intersection)
    client_tags = client_unblind_response(response=resp, p=p, a=a)

    srv_tags = server_tags(server_items=server_items, p=p, b=b)

    if reveal_intersection:
        if len(client_tags) != len(client_items_u):
            raise AssertionError("internal error: tag/item length mismatch")
        intersection: list[str] = []
        for it, tag in zip(client_items_u, client_tags, strict=True):
            if tag in srv_tags:
                intersection.append(it)
        return intersection

    # Order was destroyed (sorted), so we only return a size.
    # Note: if you used a probabilistic membership structure (Bloom filter),
    # this count could have false positives.
    return len(set(client_tags).intersection(srv_tags))


@dataclass(frozen=True)
class BloomFilter:
    m_bits: int
    k_hashes: int
    bits: bytes

    def maybe_contains(self, key: bytes) -> bool:
        if not isinstance(key, (bytes, bytearray, memoryview)):
            raise TypeError("key must be bytes-like")
        for idx in bloom_indices(key=bytes(key), m_bits=self.m_bits, k_hashes=self.k_hashes):
            if not _bit_get(self.bits, idx):
                return False
        return True


def _bit_get(buf: bytes, bit_index: int) -> bool:
    if not isinstance(buf, (bytes, bytearray, memoryview)):
        raise TypeError("buf must be bytes-like")
    if not isinstance(bit_index, int):
        raise TypeError("bit_index must be int")
    if bit_index < 0:
        raise ValueError("bit_index must be non-negative")
    byte_i = bit_index // 8
    bit_i = bit_index % 8
    if byte_i >= len(buf):
        raise ValueError("bit_index out of range")
    return (buf[byte_i] >> bit_i) & 1 == 1


def _bit_set(buf: bytearray, bit_index: int) -> None:
    if not isinstance(buf, bytearray):
        raise TypeError("buf must be bytearray")
    if not isinstance(bit_index, int):
        raise TypeError("bit_index must be int")
    if bit_index < 0:
        raise ValueError("bit_index must be non-negative")
    byte_i = bit_index // 8
    bit_i = bit_index % 8
    if byte_i >= len(buf):
        raise ValueError("bit_index out of range")
    buf[byte_i] |= 1 << bit_i


def bloom_indices(*, key: bytes, m_bits: int, k_hashes: int) -> list[int]:
    """
    Bloom indices via "double hashing" on SHA-256:

      idx_i = (h1 + i*h2) mod m
    """
    if not isinstance(key, (bytes, bytearray, memoryview)):
        raise TypeError("key must be bytes-like")
    if not isinstance(m_bits, int):
        raise TypeError("m_bits must be int")
    if not isinstance(k_hashes, int):
        raise TypeError("k_hashes must be int")
    if m_bits <= 0:
        raise ValueError("m_bits must be > 0")
    if k_hashes <= 0:
        raise ValueError("k_hashes must be > 0")

    d = sha256(bytes(key))
    h1 = int.from_bytes(d[:16], "big")
    h2 = int.from_bytes(d[16:], "big") or 1
    return [((h1 + i * h2) % m_bits) for i in range(k_hashes)]


def bloom_build(*, keys: Sequence[bytes], m_bits: int, k_hashes: int) -> BloomFilter:
    if not isinstance(keys, Sequence):
        raise TypeError("keys must be a sequence")
    nbytes = (m_bits + 7) // 8
    buf = bytearray(nbytes)
    for k in keys:
        if not isinstance(k, (bytes, bytearray, memoryview)):
            raise TypeError("all keys must be bytes-like")
        for idx in bloom_indices(key=bytes(k), m_bits=m_bits, k_hashes=k_hashes):
            _bit_set(buf, idx)
    return BloomFilter(m_bits=m_bits, k_hashes=k_hashes, bits=bytes(buf))


def step1_hash_items_to_group() -> None:
    _print_step(1, "Hash items into group elements")
    p = DEFAULT_P
    items = ["alice@example.com", "bob@example.com", "carol@example.com"]
    elems = [hash_to_group_elem(item=it, p=p) for it in items]
    for it, e in zip(items, elems, strict=True):
        print(f"{it:>18} -> {e}")


def step2_commutative_encryption_and_inverse() -> None:
    _print_step(2, "Commutative encryption and inverse exponents")
    p = DEFAULT_P
    phi = p - 1
    a = choose_coprime_exponent(phi=phi, seed=123)
    inv_a = modinv(a=a, m=phi)
    msg = hash_to_group_elem(item="alice@example.com", p=p)
    c = commutative_enc(m=msg, e=a, p=p)
    m2 = pow(c, inv_a, p)
    print(f"p = {p}")
    print(f"a = {a}")
    print(f"inv(a) mod (p-1) = {inv_a}")
    print(f"m  = {msg}")
    print(f"Enc_a(m) = {c}")
    print(f"Remove_a(Enc_a(m)) = {m2}")
    print(f"roundtrip ok: {m2 == msg}")


def step3_psi_reveal_intersection() -> None:
    _print_step(3, "PSI (reveal intersection via order-preserving response)")
    client = ["alice", "bob", "carol", "dave"]
    server = ["bob", "dave", "erin"]
    intersection = psi_intersection(
        client_items=client,
        server_items=server,
        p=DEFAULT_P,
        a=choose_coprime_exponent(phi=DEFAULT_P - 1, seed=1),
        b=choose_coprime_exponent(phi=DEFAULT_P - 1, seed=2),
        reveal_intersection=True,
    )
    print(f"client: {client}")
    print(f"server: {server}")
    print(f"intersection (client items): {intersection}")


def step4_psi_cardinality_and_bloom_filters() -> None:
    _print_step(4, "PSI (cardinality mode) + Bloom filter membership")
    client = [f"user{i}" for i in range(1, 9)]
    server = [f"user{i}" for i in range(6, 15)]
    p = DEFAULT_P
    phi = p - 1
    a = choose_coprime_exponent(phi=phi, seed=7)
    b = choose_coprime_exponent(phi=phi, seed=8)

    # Server setup: exact tag set, plus a Bloom filter "compressed" version.
    tags_set = server_tags(server_items=server, p=p, b=b)
    tag_keys = [_int_to_bytes(t) for t in tags_set]
    bf = bloom_build(keys=tag_keys, m_bits=2048, k_hashes=4)

    # Client query:
    req = client_request(client_items=client, p=p, a=a)
    resp_sorted = server_response(blinded_items=req, p=p, b=b, reveal_intersection=False)
    client_tags = client_unblind_response(response=resp_sorted, p=p, a=a)

    exact_size = len(set(client_tags).intersection(tags_set))
    bloom_size = sum(1 for t in client_tags if bf.maybe_contains(_int_to_bytes(t)))

    print(f"client size: {len(set(client))}, server size: {len(set(server))}")
    print(f"exact intersection size: {exact_size}")
    print(f"bloom-reported size:     {bloom_size} (can be higher due to false positives)")


def main() -> None:
    step1_hash_items_to_group()
    print()
    step2_commutative_encryption_and_inverse()
    print()
    step3_psi_reveal_intersection()
    print()
    step4_psi_cardinality_and_bloom_filters()


if __name__ == "__main__":
    main()
