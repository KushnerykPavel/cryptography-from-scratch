"""Toy Noise Protocol Framework handshake (NN) from scratch.

Implements the minimum moving pieces to understand Noise:
- transcript hash (mix_hash)
- chaining key + HKDF (mix_key)
- a toy Diffie-Hellman group (mod prime) to get a shared secret
- a toy AEAD (XOR stream + HMAC tag) to show encrypt-and-hash semantics

Stdlib only. Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib
import hmac
import random
import secrets
from dataclasses import dataclass


HASHLEN = 32
TAGLEN = 16

DH_P = (1 << 127) - 1
DH_G = 3
DH_PUB_LEN = 32


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def hkdf_sha256(chaining_key: bytes, input_key_material: bytes, num_outputs: int = 2) -> list[bytes]:
    if len(chaining_key) != HASHLEN:
        raise ValueError("chaining_key must be 32 bytes")
    if num_outputs < 1 or num_outputs > 3:
        raise ValueError("num_outputs must be 1..3 (Noise-style HKDF)")

    prk = hmac_sha256(chaining_key, input_key_material)
    out: list[bytes] = []
    t = b""
    for i in range(1, num_outputs + 1):
        t = hmac_sha256(prk, t + bytes([i]))
        out.append(t)
    return out


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))


def int_to_bytes(n: int, length: int) -> bytes:
    if n < 0:
        raise ValueError("n must be non-negative")
    out = n.to_bytes(length, "big", signed=False)
    if int.from_bytes(out, "big") != n:
        raise ValueError("integer does not fit")
    return out


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big", signed=False)


def encode_dh_public_key(public_key: int) -> bytes:
    if not (1 <= public_key <= DH_P - 1):
        raise ValueError("public_key out of range")
    return int_to_bytes(public_key, DH_PUB_LEN)


def decode_dh_public_key(public_key_bytes: bytes) -> int:
    if len(public_key_bytes) != DH_PUB_LEN:
        raise ValueError("wrong public key length")
    public_key = bytes_to_int(public_key_bytes)
    if not (1 <= public_key <= DH_P - 1):
        raise ValueError("public_key out of range")
    return public_key


def dh_public_key(private_key: int) -> int:
    if not (1 <= private_key <= DH_P - 2):
        raise ValueError("private_key out of range")
    return pow(DH_G, private_key, DH_P)


def dh_keypair(rng: random.Random | None = None) -> tuple[int, int]:
    if rng is None:
        private_key = secrets.randbelow(DH_P - 2) + 1
    else:
        private_key = (rng.getrandbits(256) % (DH_P - 2)) + 1
    return private_key, dh_public_key(private_key)


def dh_shared_secret(private_key: int, public_key: int) -> bytes:
    if not (1 <= public_key <= DH_P - 1):
        raise ValueError("public_key out of range")
    shared = pow(public_key, private_key, DH_P)
    return int_to_bytes(shared, DH_PUB_LEN)


def initialize_symmetric(protocol_name: str) -> tuple[bytes, bytes]:
    name_bytes = protocol_name.encode("utf-8")
    if len(name_bytes) <= HASHLEN:
        h = name_bytes + b"\x00" * (HASHLEN - len(name_bytes))
    else:
        h = sha256(name_bytes)
    ck = h
    return ck, h


def mix_hash(h: bytes, data: bytes) -> bytes:
    if len(h) != HASHLEN:
        raise ValueError("h must be 32 bytes")
    return sha256(h + data)


def mix_key(ck: bytes, input_key_material: bytes) -> tuple[bytes, bytes]:
    out = hkdf_sha256(ck, input_key_material, num_outputs=2)
    return out[0], out[1]


def _keystream(key: bytes, nonce: int, length: int) -> bytes:
    if len(key) != HASHLEN:
        raise ValueError("key must be 32 bytes")
    if nonce < 0 or nonce >= 1 << 64:
        raise ValueError("nonce must fit uint64")
    nonce_bytes = int_to_bytes(nonce, 8)
    out = bytearray()
    counter = 0
    while len(out) < length:
        counter_bytes = int_to_bytes(counter, 4)
        block = hmac_sha256(key, b"stream" + nonce_bytes + counter_bytes)
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def aead_encrypt(key: bytes, nonce: int, aad: bytes, plaintext: bytes) -> bytes:
    stream = _keystream(key, nonce, len(plaintext))
    ciphertext = xor_bytes(plaintext, stream)
    nonce_bytes = int_to_bytes(nonce, 8)
    tag = hmac_sha256(key, b"tag" + nonce_bytes + aad + ciphertext)[:TAGLEN]
    return ciphertext + tag


def aead_decrypt(key: bytes, nonce: int, aad: bytes, ciphertext_and_tag: bytes) -> bytes:
    if len(ciphertext_and_tag) < TAGLEN:
        raise ValueError("ciphertext too short")
    ciphertext = ciphertext_and_tag[:-TAGLEN]
    tag = ciphertext_and_tag[-TAGLEN:]
    nonce_bytes = int_to_bytes(nonce, 8)
    expected = hmac_sha256(key, b"tag" + nonce_bytes + aad + ciphertext)[:TAGLEN]
    if not hmac.compare_digest(tag, expected):
        raise ValueError("tag mismatch")
    stream = _keystream(key, nonce, len(ciphertext))
    return xor_bytes(ciphertext, stream)


def encrypt_and_hash(k: bytes | None, h: bytes, nonce: int, plaintext: bytes) -> tuple[bytes, bytes]:
    if k is None:
        ciphertext = plaintext
    else:
        ciphertext = aead_encrypt(k, nonce, aad=h, plaintext=plaintext)
    h2 = mix_hash(h, ciphertext)
    return h2, ciphertext


def decrypt_and_hash(k: bytes | None, h: bytes, nonce: int, ciphertext: bytes) -> tuple[bytes, bytes]:
    if k is None:
        plaintext = ciphertext
    else:
        plaintext = aead_decrypt(k, nonce, aad=h, ciphertext_and_tag=ciphertext)
    h2 = mix_hash(h, ciphertext)
    return h2, plaintext


@dataclass(frozen=True)
class HandshakeResult:
    initiator_tx: bytes
    initiator_rx: bytes
    responder_tx: bytes
    responder_rx: bytes
    handshake_hash: bytes


def noise_nn_handshake(
    initiator_e_priv: int,
    responder_e_priv: int,
    prologue: bytes = b"",
    protocol_name: str = "Noise_NN_25519_SHA256_ToyAEAD",
) -> HandshakeResult:
    ck_i, h_i = initialize_symmetric(protocol_name)
    ck_r, h_r = ck_i, h_i
    if prologue:
        h_i = mix_hash(h_i, prologue)
        h_r = mix_hash(h_r, prologue)

    e_i_pub = dh_public_key(initiator_e_priv)
    msg1 = encode_dh_public_key(e_i_pub)
    h_i = mix_hash(h_i, msg1)
    h_r = mix_hash(h_r, msg1)

    e_r_pub = dh_public_key(responder_e_priv)
    msg2 = encode_dh_public_key(e_r_pub)
    h_r = mix_hash(h_r, msg2)

    ss_r = dh_shared_secret(responder_e_priv, e_i_pub)
    ck_r, k_r = mix_key(ck_r, ss_r)
    h_r, payload2 = encrypt_and_hash(k_r, h_r, nonce=0, plaintext=b"responder:ok")

    h_i = mix_hash(h_i, msg2)
    ss_i = dh_shared_secret(initiator_e_priv, e_r_pub)
    ck_i, k_i = mix_key(ck_i, ss_i)
    h_i, payload_plain = decrypt_and_hash(k_i, h_i, nonce=0, ciphertext=payload2)
    if payload_plain != b"responder:ok":
        raise ValueError("bad responder payload")

    t1_i, t2_i = hkdf_sha256(ck_i, b"", num_outputs=2)
    t1_r, t2_r = hkdf_sha256(ck_r, b"", num_outputs=2)

    return HandshakeResult(
        initiator_tx=t1_i,
        initiator_rx=t2_i,
        responder_tx=t2_r,
        responder_rx=t1_r,
        handshake_hash=h_i,
    )


def _hex(b: bytes) -> str:
    return b.hex()


def main():
    print("=== Step 1: hash + HKDF (chaining key) ===")
    ck, h = initialize_symmetric("Noise_NN_25519_SHA256_ToyAEAD")
    print(f"  ck0 = {ck.hex()}")
    print(f"   h0 = {h.hex()}")
    out1, out2 = hkdf_sha256(ck, b"input-key-material", num_outputs=2)
    print(f"  hkdf[0] = {_hex(out1)}")
    print(f"  hkdf[1] = {_hex(out2)}")

    print()
    print("=== Step 2: toy Diffie-Hellman (mod prime) ===")
    rng = random.Random(0)
    a_priv, a_pub = dh_keypair(rng)
    b_priv, b_pub = dh_keypair(rng)
    ss_a = dh_shared_secret(a_priv, b_pub)
    ss_b = dh_shared_secret(b_priv, a_pub)
    print(f"  A pub = {a_pub}")
    print(f"  B pub = {b_pub}")
    print(f"  shared(A) = {ss_a.hex()}")
    print(f"  shared(B) = {ss_b.hex()}")
    print(f"  match? {ss_a == ss_b}")

    print()
    print("=== Step 3: symmetric state (mix_hash / mix_key / encrypt_and_hash) ===")
    ck0, h0 = initialize_symmetric("Noise_NN_25519_SHA256_ToyAEAD")
    h0 = mix_hash(h0, b"prologue")
    ck1, k = mix_key(ck0, b"some-shared-secret")
    h1, c = encrypt_and_hash(k, h0, nonce=0, plaintext=b"hello")
    h2, p = decrypt_and_hash(k, h0, nonce=0, ciphertext=c)
    print(f"  ciphertext = {c.hex()}")
    print(f"  plaintext  = {p!r}")
    print(f"  transcript match? {h1 == h2}")

    print()
    print("=== Step 4: Noise NN handshake (toy) ===")
    res = noise_nn_handshake(initiator_e_priv=12345, responder_e_priv=67890, prologue=b"demo")
    print(f"  handshake_hash = {res.handshake_hash.hex()}")
    print(f"  initiator tx key = {res.initiator_tx.hex()}")
    print(f"  initiator rx key = {res.initiator_rx.hex()}")
    print(f"  responder tx key = {res.responder_tx.hex()}")
    print(f"  responder rx key = {res.responder_rx.hex()}")
    print(f"  tx/rx match? {res.initiator_tx == res.responder_rx and res.initiator_rx == res.responder_tx}")

    print()
    print("demo transport:")
    msg = b"ping"
    ct = aead_encrypt(res.initiator_tx, nonce=0, aad=b"", plaintext=msg)
    pt = aead_decrypt(res.responder_rx, nonce=0, aad=b"", ciphertext_and_tag=ct)
    print(f"  initiator -> responder: {msg!r} -> {ct.hex()} -> {pt!r}")


if __name__ == "__main__":
    main()
