"""
Diffie-Hellman key exchange (educational).

Run:
  python3 code/main.py

This script:
- Implements modular exponentiation (square-and-multiply).
- Implements classic finite-field Diffie-Hellman over a prime modulus group.
- Demonstrates key agreement, key derivation (HKDF-SHA256), and a simple MITM attack
  when the exchange is not authenticated.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import secrets
from typing import Iterable


def parse_hex_int(text: str) -> int:
    cleaned = "".join(ch for ch in text if ch.strip()).replace("0x", "").replace("0X", "")
    if not cleaned:
        raise ValueError("empty hex string")
    return int(cleaned, 16)


def modexp(base: int, exponent: int, modulus: int) -> int:
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    if exponent < 0:
        raise ValueError("exponent must be non-negative")

    base %= modulus
    result = 1
    e = exponent
    while e:
        if e & 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        e >>= 1
    return result


def int_to_bytes(value: int, length: int | None = None) -> bytes:
    if value < 0:
        raise ValueError("value must be non-negative")
    if length is None:
        length = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(length, "big")


def hkdf_sha256(*, ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    if length <= 0:
        raise ValueError("length must be positive")

    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
        if counter > 255:
            raise ValueError("length too large for HKDF")
    return okm[:length]


@dataclass(frozen=True)
class DHGroup:
    name: str
    p: int
    g: int
    q: int | None = None

    def __post_init__(self) -> None:
        if self.p <= 2:
            raise ValueError("p must be > 2")
        if not (2 <= self.g <= self.p - 2):
            raise ValueError("g must be in [2, p-2]")
        if self.q is not None and self.q <= 1:
            raise ValueError("q must be > 1")


def generate_private_key(*, rng: secrets.SystemRandom, group: DHGroup, nbits: int) -> int:
    if nbits <= 1:
        raise ValueError("nbits must be > 1")
    upper = (1 << nbits) - 1
    while True:
        x = rng.randrange(2, upper)
        if x < group.p - 1:
            return x


def dh_public_key(*, group: DHGroup, private_key: int) -> int:
    if not (2 <= private_key <= group.p - 2):
        raise ValueError("private key out of range")
    return modexp(group.g, private_key, group.p)


def validate_dh_public_key(*, group: DHGroup, public_key: int) -> None:
    if not (2 <= public_key <= group.p - 2):
        raise ValueError("public key out of range")
    if group.q is not None and modexp(public_key, group.q, group.p) != 1:
        raise ValueError("public key not in expected subgroup")


def dh_shared_secret(
    *,
    group: DHGroup,
    private_key: int,
    peer_public_key: int,
    validate_public_key: bool = True,
) -> int:
    if validate_public_key:
        validate_dh_public_key(group=group, public_key=peer_public_key)
    if not (2 <= private_key <= group.p - 2):
        raise ValueError("private key out of range")
    return modexp(peer_public_key, private_key, group.p)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))


def chunk_hex(value: int, *, bytes_per_line: int = 16) -> str:
    raw = int_to_bytes(value)
    lines: list[str] = []
    for i in range(0, len(raw), bytes_per_line):
        lines.append(raw[i : i + bytes_per_line].hex())
    return "\n".join(lines)


RFC3526_GROUP14_P_HEX = """
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
"""


def rfc3526_group14() -> DHGroup:
    p = parse_hex_int(RFC3526_GROUP14_P_HEX)
    q = (p - 1) // 2
    return DHGroup(name="RFC3526 group14 (2048-bit MODP)", p=p, g=2, q=q)


def _print_step(n: int, name: str) -> None:
    print(f"=== Step {n}: {name} ===")


def step1_modexp() -> None:
    _print_step(1, "Square-and-multiply modular exponentiation")
    base, exponent, modulus = 5, 117, 19
    got = modexp(base, exponent, modulus)
    expected = pow(base, exponent, modulus)
    print(f"modexp({base}, {exponent}, {modulus}) = {got}")
    print(f"python pow({base}, {exponent}, {modulus}) = {expected}")


def step2_toy_dh() -> None:
    _print_step(2, "Public keys in a tiny toy group")
    toy = DHGroup(name="toy (p=23, g=5)", p=23, g=5, q=None)

    alice_private = 6
    bob_private = 15

    alice_public = dh_public_key(group=toy, private_key=alice_private)
    bob_public = dh_public_key(group=toy, private_key=bob_private)

    print(f"Alice private a={alice_private} -> public A={alice_public}")
    print(f"Bob   private b={bob_private} -> public B={bob_public}")


def step3_shared_secret_and_kdf() -> None:
    _print_step(3, "Shared secret + key derivation (HKDF-SHA256)")
    group = rfc3526_group14()
    rng = secrets.SystemRandom()

    alice_private = generate_private_key(rng=rng, group=group, nbits=256)
    bob_private = generate_private_key(rng=rng, group=group, nbits=256)
    alice_public = dh_public_key(group=group, private_key=alice_private)
    bob_public = dh_public_key(group=group, private_key=bob_private)

    z_ab = dh_shared_secret(group=group, private_key=alice_private, peer_public_key=bob_public)
    z_ba = dh_shared_secret(group=group, private_key=bob_private, peer_public_key=alice_public)
    print(f"Alice public A (hex, first 16 bytes): {int_to_bytes(alice_public)[:16].hex()}")
    print(f"Bob   public B (hex, first 16 bytes): {int_to_bytes(bob_public)[:16].hex()}")
    print(f"Shared secret matches: {z_ab == z_ba}")

    shared_bytes = int_to_bytes(z_ab)
    session_key = hkdf_sha256(
        ikm=shared_bytes,
        salt=b"cryptography-from-scratch:dhex",
        info=b"demo session key",
        length=32,
    )
    print(f"Derived 32-byte key: {session_key.hex()}")


def step4_mitm_demo() -> None:
    _print_step(4, "Attack demo: MITM when DH is unauthenticated")
    group = DHGroup(name="toy (p=23, g=5)", p=23, g=5, q=None)

    alice_private = 6
    bob_private = 15
    mallory_private_to_alice = 13
    mallory_private_to_bob = 7

    alice_public = dh_public_key(group=group, private_key=alice_private)
    bob_public = dh_public_key(group=group, private_key=bob_private)
    mallory_public_to_alice = dh_public_key(group=group, private_key=mallory_private_to_alice)
    mallory_public_to_bob = dh_public_key(group=group, private_key=mallory_private_to_bob)

    z_alice_mallory = dh_shared_secret(group=group, private_key=alice_private, peer_public_key=mallory_public_to_alice, validate_public_key=False)
    z_bob_mallory = dh_shared_secret(group=group, private_key=bob_private, peer_public_key=mallory_public_to_bob, validate_public_key=False)

    key_alice = hkdf_sha256(ikm=int_to_bytes(z_alice_mallory), salt=b"salt", info=b"toy", length=16)
    key_bob = hkdf_sha256(ikm=int_to_bytes(z_bob_mallory), salt=b"salt", info=b"toy", length=16)

    message = b"meet at dawn!!!"
    padded = message.ljust(16, b"\x00")
    ciphertext_from_alice = xor_bytes(padded, key_alice)
    recovered_by_mallory = xor_bytes(ciphertext_from_alice, key_alice)
    decrypted_by_bob_wrong = xor_bytes(ciphertext_from_alice, key_bob)

    print(f"Alice thinks shared key is with Bob; Bob thinks shared key is with Alice.")
    print(f"Alice derived key: {key_alice.hex()}")
    print(f"Bob   derived key: {key_bob.hex()}")
    print(f"Ciphertext (hex):  {ciphertext_from_alice.hex()}")
    print(f"Mallory recovers:  {recovered_by_mallory.rstrip(b'\\x00')!r}")
    print(f"Bob decrypts to:   {decrypted_by_bob_wrong.rstrip(b'\\x00')!r}")


def main() -> None:
    step1_modexp()
    print()
    step2_toy_dh()
    print()
    step3_shared_secret_and_kdf()
    print()
    step4_mitm_demo()


if __name__ == "__main__":
    main()
