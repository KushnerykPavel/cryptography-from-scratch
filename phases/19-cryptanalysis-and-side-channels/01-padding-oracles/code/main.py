"""
Padding oracle demo (educational).

Run:
  python3 code/main.py

This lesson builds a toy CBC encryption scheme with PKCS#7 padding, exposes a
"padding oracle" (valid padding? yes/no), then uses it to recover the
plaintext without knowing the key.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Callable, Iterable


BLOCK_SIZE = 16


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor_bytes length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if block_size <= 0 or block_size > 255:
        raise ValueError("invalid block_size")
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(padded: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if block_size <= 0 or block_size > 255:
        raise ValueError("invalid block_size")
    if not padded or (len(padded) % block_size) != 0:
        raise ValueError("invalid padded length")
    pad_len = padded[-1]
    if pad_len == 0 or pad_len > block_size:
        raise ValueError("invalid padding")
    if padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("invalid padding")
    return padded[:-pad_len]


def _toy_round_f(key: bytes, round_idx: int, half_block: bytes) -> bytes:
    return hmac.new(key, bytes([round_idx]) + half_block, hashlib.sha256).digest()[:8]


def toy_cipher_encrypt_block(key: bytes, block: bytes, rounds: int = 6) -> bytes:
    if len(key) != 16:
        raise ValueError("toy cipher expects 16-byte key")
    if len(block) != 16:
        raise ValueError("toy cipher expects 16-byte block")
    left, right = block[:8], block[8:]
    for r in range(rounds):
        f = _toy_round_f(key, r, right)
        left, right = right, xor_bytes(left, f)
    return left + right


def toy_cipher_decrypt_block(key: bytes, block: bytes, rounds: int = 6) -> bytes:
    if len(key) != 16:
        raise ValueError("toy cipher expects 16-byte key")
    if len(block) != 16:
        raise ValueError("toy cipher expects 16-byte block")
    left, right = block[:8], block[8:]
    for r in reversed(range(rounds)):
        prev_right = left
        f = _toy_round_f(key, r, prev_right)
        prev_left = xor_bytes(right, f)
        left, right = prev_left, prev_right
    return left + right


def cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be 16 bytes")
    padded = pkcs7_pad(plaintext, BLOCK_SIZE)
    out = bytearray()
    prev = iv
    for off in range(0, len(padded), BLOCK_SIZE):
        block = padded[off : off + BLOCK_SIZE]
        x = xor_bytes(block, prev)
        c = toy_cipher_encrypt_block(key, x)
        out += c
        prev = c
    return bytes(out)


def cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be 16 bytes")
    if (len(ciphertext) % BLOCK_SIZE) != 0:
        raise ValueError("ciphertext must be block-aligned")
    out = bytearray()
    prev = iv
    for off in range(0, len(ciphertext), BLOCK_SIZE):
        c = ciphertext[off : off + BLOCK_SIZE]
        x = toy_cipher_decrypt_block(key, c)
        p = xor_bytes(x, prev)
        out += p
        prev = c
    return pkcs7_unpad(bytes(out), BLOCK_SIZE)


def padding_oracle_factory(key: bytes) -> Callable[[bytes, bytes], bool]:
    def oracle(iv: bytes, ciphertext: bytes) -> bool:
        try:
            _ = cbc_decrypt(key, iv, ciphertext)
            return True
        except ValueError:
            return False

    return oracle


def _chunks(data: bytes, size: int) -> Iterable[bytes]:
    for off in range(0, len(data), size):
        yield data[off : off + size]


def recover_plaintext_via_padding_oracle(
    iv: bytes, ciphertext: bytes, oracle: Callable[[bytes, bytes], bool], block_size: int = BLOCK_SIZE
) -> bytes:
    if len(iv) != block_size:
        raise ValueError("bad IV length")
    if (len(ciphertext) % block_size) != 0 or not ciphertext:
        raise ValueError("ciphertext must be non-empty and block-aligned")

    blocks = [iv] + list(_chunks(ciphertext, block_size))
    recovered = bytearray()

    for block_idx in range(1, len(blocks)):
        prev = bytearray(blocks[block_idx - 1])
        cur = blocks[block_idx]

        inter = bytearray(block_size)
        plain = bytearray(block_size)

        for pad_len in range(1, block_size + 1):
            byte_idx = block_size - pad_len

            base = bytearray(prev)
            for j in range(block_size - 1, byte_idx, -1):
                base[j] = inter[j] ^ pad_len

            found = None
            for guess in range(256):
                trial = bytearray(base)
                trial[byte_idx] = guess

                trial_iv = bytes(trial)
                trial_ct = cur
                if not oracle(trial_iv, trial_ct):
                    continue
                if pad_len == 1:
                    probe = bytearray(trial)
                    probe[byte_idx - 1] ^= 1
                    if not oracle(bytes(probe), trial_ct):
                        continue
                found = guess
                break

            if found is None:
                raise RuntimeError("oracle attack failed (no byte found)")

            inter_byte = found ^ pad_len
            inter[byte_idx] = inter_byte
            plain[byte_idx] = inter_byte ^ prev[byte_idx]

        recovered += plain

    return pkcs7_unpad(bytes(recovered), block_size)


def main():
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    iv = bytes.fromhex("0f0e0d0c0b0a09080706050403020100")
    msg = b"attack at dawn; bring coffee"

    print("=== Step 1: PKCS#7 padding ===")
    padded = pkcs7_pad(msg)
    print("padded_len:", len(padded), "last_byte:", padded[-1])

    print("=== Step 2: A reversible toy block cipher ===")
    block = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    enc = toy_cipher_encrypt_block(key, block)
    dec = toy_cipher_decrypt_block(key, enc)
    print("block:", block.hex())
    print("enc  :", enc.hex())
    print("dec  :", dec.hex())

    print("=== Step 3: CBC mode ===")
    ct = cbc_encrypt(key, iv, msg)
    pt = cbc_decrypt(key, iv, ct)
    print("ciphertext_len:", len(ct))
    print("roundtrip_ok  :", pt == msg)

    print("=== Step 4: A padding oracle ===")
    oracle = padding_oracle_factory(key)
    ok = oracle(iv, ct)
    bad = oracle(iv, ct[:-1] + bytes([ct[-1] ^ 1]))
    print("oracle(valid_ct) :", ok)
    print("oracle(tampered) :", bad)

    print("=== Step 5: Recover plaintext via the oracle ===")
    recovered = recover_plaintext_via_padding_oracle(iv, ct, oracle)
    print("recovered:", recovered)


if __name__ == "__main__":
    main()
