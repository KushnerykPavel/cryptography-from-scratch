"""
KEM vs key agreement (educational).

Run:
  python3 code/main.py

This script:
- Implements HKDF-SHA256 and transcript hashing for context binding.
- Implements a 2-message Diffie-Hellman key agreement in a tiny toy group.
- Wraps DH into a KEM-style Encaps/Decaps API (like HPKE's DHKEM, but toy).
- Demonstrates how you can "mix" multiple shared secrets into one session key.

Educational implementation. Not constant-time. Not production-safe.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
from typing import Iterable


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


def i2osp(value: int, length: int) -> bytes:
    if value < 0:
        raise ValueError("value must be non-negative")
    if length <= 0:
        raise ValueError("length must be positive")
    return value.to_bytes(length, "big")


def os2ip(data: bytes) -> int:
    return int.from_bytes(data, "big")


def u32be(value: int) -> bytes:
    if not (0 <= value <= 0xFFFFFFFF):
        raise ValueError("value out of range for u32")
    return value.to_bytes(4, "big")


def encode_length_prefixed(parts: Iterable[bytes]) -> bytes:
    out = b""
    for p in parts:
        out += u32be(len(p)) + p
    return out


def transcript_hash(parts: Iterable[bytes]) -> bytes:
    return hashlib.sha256(encode_length_prefixed(parts)).digest()


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

    def __post_init__(self) -> None:
        if self.p <= 2:
            raise ValueError("p must be > 2")
        if not (2 <= self.g <= self.p - 2):
            raise ValueError("g must be in [2, p-2]")

    @property
    def element_bytes(self) -> int:
        return max(1, (self.p.bit_length() + 7) // 8)


TOY_GROUP = DHGroup(name="toy (p=23, g=5)", p=23, g=5)


def dh_public_key(*, group: DHGroup, private_key: int) -> int:
    if not (2 <= private_key <= group.p - 2):
        raise ValueError("private key out of range")
    return modexp(group.g, private_key, group.p)


def validate_dh_public_key(*, group: DHGroup, public_key: int) -> None:
    if not (2 <= public_key <= group.p - 2):
        raise ValueError("public key out of range")


def dh_shared_secret(*, group: DHGroup, private_key: int, peer_public_key: int) -> int:
    validate_dh_public_key(group=group, public_key=peer_public_key)
    if not (2 <= private_key <= group.p - 2):
        raise ValueError("private key out of range")
    return modexp(peer_public_key, private_key, group.p)


def serialize_group_element(*, group: DHGroup, element: int) -> bytes:
    if not (0 <= element < group.p):
        raise ValueError("element out of range")
    return i2osp(element, group.element_bytes)


def deserialize_group_element(*, group: DHGroup, data: bytes) -> int:
    if len(data) != group.element_bytes:
        raise ValueError("wrong element length")
    x = os2ip(data)
    if not (0 <= x < group.p):
        raise ValueError("element out of range")
    return x


def derive_session_key_from_dh(
    *,
    group: DHGroup,
    dh_shared: int,
    context: bytes,
    length: int = 32,
) -> bytes:
    dh_bytes = serialize_group_element(group=group, element=dh_shared)
    salt = hashlib.sha256(b"cryptography-from-scratch:dh").digest()
    return hkdf_sha256(ikm=dh_bytes, salt=salt, info=context, length=length)


def ka_2msg_session_key(
    *,
    group: DHGroup,
    alice_private: int,
    bob_private: int,
    info: bytes,
    length: int = 32,
) -> tuple[bytes, bytes, bytes]:
    alice_public = dh_public_key(group=group, private_key=alice_private)
    bob_public = dh_public_key(group=group, private_key=bob_private)

    transcript = transcript_hash(
        [
            b"KA-2msg",
            serialize_group_element(group=group, element=alice_public),
            serialize_group_element(group=group, element=bob_public),
            info,
        ]
    )

    z_ab = dh_shared_secret(group=group, private_key=alice_private, peer_public_key=bob_public)
    z_ba = dh_shared_secret(group=group, private_key=bob_private, peer_public_key=alice_public)
    if z_ab != z_ba:
        raise RuntimeError("key agreement did not match (should never happen)")

    context = encode_length_prefixed([b"KA", transcript])
    key_a = derive_session_key_from_dh(group=group, dh_shared=z_ab, context=context, length=length)
    key_b = derive_session_key_from_dh(group=group, dh_shared=z_ba, context=context, length=length)
    return key_a, key_b, transcript


def dhkem_encap(
    *,
    group: DHGroup,
    recipient_public_key: int,
    sender_ephemeral_private: int,
    info: bytes,
    length: int = 32,
    suite_id: bytes = b"DHKEM-TOY-HKDF-SHA256",
) -> tuple[bytes, bytes]:
    validate_dh_public_key(group=group, public_key=recipient_public_key)
    sender_ephemeral_public = dh_public_key(group=group, private_key=sender_ephemeral_private)
    enc = serialize_group_element(group=group, element=sender_ephemeral_public)
    dh = dh_shared_secret(
        group=group, private_key=sender_ephemeral_private, peer_public_key=recipient_public_key
    )

    pk_r = serialize_group_element(group=group, element=recipient_public_key)
    kem_context = encode_length_prefixed([b"KEM", suite_id, enc, pk_r, info])
    shared = derive_session_key_from_dh(group=group, dh_shared=dh, context=kem_context, length=length)
    return enc, shared


def dhkem_decap(
    *,
    group: DHGroup,
    recipient_private_key: int,
    enc: bytes,
    info: bytes,
    length: int = 32,
    suite_id: bytes = b"DHKEM-TOY-HKDF-SHA256",
) -> bytes:
    pk_e = deserialize_group_element(group=group, data=enc)
    validate_dh_public_key(group=group, public_key=pk_e)
    pk_r = dh_public_key(group=group, private_key=recipient_private_key)
    dh = dh_shared_secret(group=group, private_key=recipient_private_key, peer_public_key=pk_e)

    pk_r_bytes = serialize_group_element(group=group, element=pk_r)
    kem_context = encode_length_prefixed([b"KEM", suite_id, enc, pk_r_bytes, info])
    return derive_session_key_from_dh(group=group, dh_shared=dh, context=kem_context, length=length)


def mix_secrets(*, secrets_list: Iterable[bytes], context: bytes, length: int = 32) -> bytes:
    joined = encode_length_prefixed(secrets_list)
    salt = hashlib.sha256(b"cryptography-from-scratch:mix").digest()
    return hkdf_sha256(ikm=joined, salt=salt, info=context, length=length)


def _print_step(n: int, name: str) -> None:
    print(f"=== Step {n}: {name} ===")


def step1_kdf_and_transcripts() -> None:
    _print_step(1, "HKDF-SHA256 + transcript hashing")
    ikm = bytes([0x0B]) * 22
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    okm = hkdf_sha256(ikm=ikm, salt=salt, info=info, length=42)
    print("HKDF test-case (RFC 5869 #1) OKM:", okm.hex())

    t = transcript_hash([b"msg1", b"msg2", b"msg3"])
    print("transcript_hash([msg1,msg2,msg3]) =", t.hex())


def step2_key_agreement() -> bytes:
    _print_step(2, "2-message DH key agreement (derive a session key)")
    alice_private = 6
    bob_private = 15
    info = b"demo:toy-ka"

    alice_public = dh_public_key(group=TOY_GROUP, private_key=alice_private)
    bob_public = dh_public_key(group=TOY_GROUP, private_key=bob_private)
    print(f"Alice: a={alice_private} -> A={alice_public}")
    print(f"Bob:   b={bob_private} -> B={bob_public}")

    key_a, key_b, transcript = ka_2msg_session_key(
        group=TOY_GROUP, alice_private=alice_private, bob_private=bob_private, info=info
    )
    print("transcript (sha256) =", transcript.hex())
    print("session_key (alice) =", key_a.hex())
    print("session_key (bob)   =", key_b.hex())
    print("keys match:", key_a == key_b)
    return key_a


def step3_kem() -> bytes:
    _print_step(3, "A KEM view of DH (Encaps/Decaps API)")
    recipient_private = 15
    recipient_public = dh_public_key(group=TOY_GROUP, private_key=recipient_private)
    sender_ephemeral_private = 6
    info = b"demo:toy-kem"

    enc, shared_sender = dhkem_encap(
        group=TOY_GROUP,
        recipient_public_key=recipient_public,
        sender_ephemeral_private=sender_ephemeral_private,
        info=info,
    )
    shared_recipient = dhkem_decap(
        group=TOY_GROUP,
        recipient_private_key=recipient_private,
        enc=enc,
        info=info,
    )

    print(f"recipient pkR={recipient_public} (published ahead of time)")
    print(f"sender ephemeral skE={sender_ephemeral_private} -> enc={enc.hex()}")
    print("shared (sender)   =", shared_sender.hex())
    print("shared (recipient)=", shared_recipient.hex())
    print("shared matches:", shared_sender == shared_recipient)
    return shared_sender


def step4_hybrid_mix(key_ka: bytes, key_kem: bytes) -> None:
    _print_step(4, "Hybrid mixing (combine multiple secrets safely)")
    hybrid = mix_secrets(secrets_list=[key_ka, key_kem], context=b"demo:hybrid", length=32)
    print("key_agreement_key =", key_ka.hex())
    print("kem_shared_key    =", key_kem.hex())
    print("hybrid_key        =", hybrid.hex())


def main() -> None:
    step1_kdf_and_transcripts()
    key_ka = step2_key_agreement()
    key_kem = step3_kem()
    step4_hybrid_mix(key_ka, key_kem)


if __name__ == "__main__":
    main()
