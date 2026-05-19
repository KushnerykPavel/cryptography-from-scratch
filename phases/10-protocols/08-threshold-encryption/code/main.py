"""
Threshold encryption (educational): ElGamal KEM + Shamir-shared secret key.

This script builds a small, from-scratch threshold decryption demo:

- A dealer samples an ElGamal private key x (mod q) and Shamir-splits it across n parties.
- Anyone can encrypt bytes to the public key y = g^x using a KEM-DEM style construction:
  c1 = g^k, shared = y^k, ciphertext = plaintext XOR SHA256_STREAM(shared).
- To decrypt, any t parties produce partial decryptions d_i = c1^{share_i}.
  A combiner recombines them with Lagrange coefficients in the exponent to get shared = c1^x.

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import Dict, Iterable, List, Sequence, Tuple


def _egcd(a: int, b: int) -> Tuple[int, int, int]:
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def modinv(a: int, modulus: int) -> int:
    a %= modulus
    if a == 0:
        raise ValueError("not invertible modulo modulus")
    g, x, _ = _egcd(a, modulus)
    if g != 1:
        raise ValueError("not invertible modulo modulus")
    return x % modulus


def poly_eval(coeffs: Sequence[int], x: int, modulus: int) -> int:
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % modulus
    return acc


Share = Tuple[int, int]  # (id, value)


def shamir_make_shares(
    *,
    secret: int,
    threshold: int,
    num_shares: int,
    modulus: int,
    coeffs: Sequence[int] | None = None,
    x_coords: Sequence[int] | None = None,
) -> List[Share]:
    if threshold < 2:
        raise ValueError("threshold must be >= 2")
    if num_shares < threshold:
        raise ValueError("num_shares must be >= threshold")
    if modulus <= 2:
        raise ValueError("modulus too small")

    secret %= modulus
    if coeffs is None:
        coeffs = [secrets.randbelow(modulus) for _ in range(threshold - 1)]
    if len(coeffs) != threshold - 1:
        raise ValueError("coeffs must have length threshold-1")
    poly = [secret, *[c % modulus for c in coeffs]]

    if x_coords is None:
        x_coords = list(range(1, num_shares + 1))
    if len(x_coords) != num_shares:
        raise ValueError("x_coords must have length num_shares")
    if len(set(x_coords)) != len(x_coords):
        raise ValueError("x_coords must be distinct")
    if any(x % modulus == 0 for x in x_coords):
        raise ValueError("x_coords must be non-zero modulo modulus")

    return [(int(x), poly_eval(poly, int(x), modulus)) for x in x_coords]


def lagrange_coefficients_at_zero(x_coords: Sequence[int], modulus: int) -> Dict[int, int]:
    if modulus <= 2:
        raise ValueError("modulus too small")
    if len(x_coords) == 0:
        raise ValueError("need at least one x-coordinate")
    if len(set(x_coords)) != len(x_coords):
        raise ValueError("x_coords must be distinct")

    out: Dict[int, int] = {}
    xs = [int(x) % modulus for x in x_coords]
    for i, xi in zip(x_coords, xs):
        num = 1
        den = 1
        for xj in xs:
            if xj == xi:
                continue
            num = (num * (-xj)) % modulus
            den = (den * (xi - xj)) % modulus
        out[int(i)] = (num * modinv(den, modulus)) % modulus
    return out


def shamir_recover_secret(shares: Sequence[Share], *, modulus: int) -> int:
    if len(shares) == 0:
        raise ValueError("need at least one share")
    x_coords = [int(x) for x, _ in shares]
    lambdas = lagrange_coefficients_at_zero(x_coords, modulus)
    acc = 0
    for x, y in shares:
        acc = (acc + int(y) * lambdas[int(x)]) % modulus
    return acc


def int_to_bytes(n: int, length: int | None = None) -> bytes:
    if n < 0:
        raise ValueError("n must be non-negative")
    if length is None:
        length = max(1, (n.bit_length() + 7) // 8)
    return n.to_bytes(length, "big")


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor requires equal-length buffers")
    return bytes(x ^ y for x, y in zip(a, b))


def sha256_stream(key_material: bytes, out_len: int, *, label: bytes = b"") -> bytes:
    if out_len < 0:
        raise ValueError("out_len must be non-negative")
    out = bytearray()
    counter = 0
    while len(out) < out_len:
        h = hashlib.sha256()
        h.update(label)
        h.update(counter.to_bytes(4, "big"))
        h.update(key_material)
        out.extend(h.digest())
        counter += 1
    return bytes(out[:out_len])


@dataclass(frozen=True)
class PrimeOrderGroup:
    p: int
    q: int
    g: int

    @property
    def byte_len(self) -> int:
        return (self.p.bit_length() + 7) // 8

    def validate_elem(self, x: int) -> None:
        if not (2 <= x <= self.p - 2):
            raise ValueError("group element out of range")
        if pow(x, self.q, self.p) != 1:
            raise ValueError("group element not in subgroup")


def demo_group() -> PrimeOrderGroup:
    p = 467
    q = 233  # (p-1)/2
    g = 4  # generator of the order-q subgroup: (2^2 mod p), where 2 generates Z_p*
    group = PrimeOrderGroup(p=p, q=q, g=g)
    if (p - 1) % q != 0:
        raise ValueError("bad demo group parameters")
    if pow(g, q, p) != 1 or g in (0, 1):
        raise ValueError("bad demo generator")
    return group


@dataclass(frozen=True)
class ThresholdPublicKey:
    group: PrimeOrderGroup
    y: int
    threshold: int


@dataclass(frozen=True)
class KeyShare:
    id: int
    share: int


Ciphertext = Tuple[int, bytes]  # (c1, masked_bytes)


def threshold_keygen(
    *,
    group: PrimeOrderGroup,
    threshold: int,
    num_shares: int,
    secret_x: int | None = None,
    coeffs: Sequence[int] | None = None,
) -> Tuple[ThresholdPublicKey, List[KeyShare], int]:
    if secret_x is None:
        secret_x = secrets.randbelow(group.q - 1) + 1
    if not (1 <= secret_x <= group.q - 1):
        raise ValueError("secret_x out of range")

    y = pow(group.g, secret_x, group.p)
    group.validate_elem(y)
    shares = shamir_make_shares(
        secret=secret_x,
        threshold=threshold,
        num_shares=num_shares,
        modulus=group.q,
        coeffs=coeffs,
        x_coords=list(range(1, num_shares + 1)),
    )
    return (
        ThresholdPublicKey(group=group, y=y, threshold=threshold),
        [KeyShare(id=x, share=s) for x, s in shares],
        secret_x,
    )


def threshold_encrypt(
    pub: ThresholdPublicKey,
    plaintext: bytes,
    *,
    k: int | None = None,
    label: bytes = b"threshold-kem",
) -> Ciphertext:
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes-like")
    g = pub.group
    if k is None:
        k = secrets.randbelow(g.q - 1) + 1
    if not (1 <= k <= g.q - 1):
        raise ValueError("k out of range")
    c1 = pow(g.g, k, g.p)
    g.validate_elem(c1)
    shared = pow(pub.y, k, g.p)
    key_material = int_to_bytes(shared, g.byte_len)
    stream = sha256_stream(key_material, len(plaintext), label=label)
    return c1, xor_bytes(bytes(plaintext), stream)


def partial_decrypt(*, share: KeyShare, c1: int, group: PrimeOrderGroup) -> Tuple[int, int]:
    group.validate_elem(c1)
    if not (1 <= share.id):
        raise ValueError("share id must be positive")
    if not (0 <= share.share <= group.q - 1):
        raise ValueError("share value out of range")
    return share.id, pow(c1, share.share, group.p)


def combine_partial_decryptions(
    *,
    partials: Sequence[Tuple[int, int]],
    group: PrimeOrderGroup,
) -> int:
    if len(partials) == 0:
        raise ValueError("need at least one partial decryption")
    ids = [int(i) for i, _ in partials]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate ids in partials")
    lambdas = lagrange_coefficients_at_zero(ids, group.q)
    acc = 1
    for i, di in partials:
        group.validate_elem(di)
        acc = (acc * pow(di, lambdas[int(i)], group.p)) % group.p
    group.validate_elem(acc)
    return acc


def threshold_decrypt(
    pub: ThresholdPublicKey,
    shares: Sequence[KeyShare],
    ct: Ciphertext,
    *,
    label: bytes = b"threshold-kem",
) -> bytes:
    c1, masked = ct
    if len(shares) < pub.threshold:
        raise ValueError("not enough shares to decrypt")
    pub.group.validate_elem(c1)
    partials = [partial_decrypt(share=s, c1=c1, group=pub.group) for s in shares]
    shared = combine_partial_decryptions(partials=partials, group=pub.group)
    key_material = int_to_bytes(shared, pub.group.byte_len)
    stream = sha256_stream(key_material, len(masked), label=label)
    return xor_bytes(masked, stream)


def _step(title: str) -> None:
    print(f"=== {title} ===")


def main() -> None:
    group = demo_group()

    _step("Step 1: Shamir shares (secret is an x in Z_q)")
    secret_x = 123
    threshold = 3
    num_shares = 5
    coeffs = [77, 9]  # f(z) = x + 77*z + 9*z^2  (mod q)
    shares = shamir_make_shares(
        secret=secret_x,
        threshold=threshold,
        num_shares=num_shares,
        modulus=group.q,
        coeffs=coeffs,
    )
    subset = [shares[0], shares[2], shares[3]]  # ids 1,3,4
    recovered = shamir_recover_secret(subset, modulus=group.q)
    print(f"q={group.q}, secret_x={secret_x}")
    print(f"shares={shares}")
    print(f"recovered_from_ids={[x for x,_ in subset]} => {recovered}")

    _step("Step 2: ElGamal KEM-DEM encryption to y = g^x")
    y = pow(group.g, secret_x, group.p)
    pub = ThresholdPublicKey(group=group, y=y, threshold=threshold)
    plaintext = b"hello"
    k = 42
    ct = threshold_encrypt(pub, plaintext, k=k)
    print(f"public y=g^x mod p = {y}")
    print(f"plaintext={plaintext!r}, k={k} => c1={ct[0]}, masked={ct[1].hex()}")

    _step("Step 3: Dealer keygen (shares + public key)")
    pub2, keyshares, x2 = threshold_keygen(group=group, threshold=threshold, num_shares=num_shares, secret_x=secret_x, coeffs=coeffs)
    print(f"threshold={pub2.threshold}, n={len(keyshares)}, x(dealer secret)={x2}, y={pub2.y}")
    print(f"keyshares={[(s.id, s.share) for s in keyshares]}")

    _step("Step 4: Threshold decryption (t parties + Lagrange in the exponent)")
    chosen = [keyshares[0], keyshares[2], keyshares[3]]  # ids 1,3,4
    recovered_pt = threshold_decrypt(pub2, chosen, ct)
    print(f"decrypt_with_ids={[s.id for s in chosen]} => {recovered_pt!r}")
    try:
        _ = threshold_decrypt(pub2, chosen[:2], ct)
        raise AssertionError("expected not-enough-shares failure")
    except ValueError as e:
        print(f"decrypt_with_ids={[s.id for s in chosen[:2]]} => ValueError({e})")


if __name__ == "__main__":
    main()
