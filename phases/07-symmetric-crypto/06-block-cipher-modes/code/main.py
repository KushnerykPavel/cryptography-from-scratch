"""
Block cipher modes (ECB, CBC, CTR, CFB) built from a toy 128-bit block cipher.

Run:
  python3 code/main.py

This is an educational implementation to make mode mechanics visible.
It is not constant-time and is not production-safe.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor_bytes requires equal-length inputs")
    return bytes(x ^ y for x, y in zip(a, b))


def split_blocks(data: bytes, block_size: int) -> list[bytes]:
    if block_size <= 0:
        raise ValueError("block_size must be positive")
    if len(data) % block_size != 0:
        raise ValueError("data length must be a multiple of block_size")
    return [data[i : i + block_size] for i in range(0, len(data), block_size)]


def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    if not (2 <= block_size <= 255):
        raise ValueError("block_size must be in [2, 255]")
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(padded: bytes, block_size: int) -> bytes:
    if not (2 <= block_size <= 255):
        raise ValueError("block_size must be in [2, 255]")
    if len(padded) == 0 or (len(padded) % block_size) != 0:
        raise ValueError("invalid padded length")
    pad_len = padded[-1]
    if pad_len == 0 or pad_len > block_size:
        raise ValueError("invalid padding length")
    if padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("invalid padding bytes")
    return padded[:-pad_len]


@dataclass(frozen=True)
class ToyFeistelCipher128:
    key: bytes
    rounds: int = 10

    block_size: int = 16
    half_size: int = 8

    def _f(self, round_index: int, right: bytes) -> bytes:
        if len(right) != self.half_size:
            raise ValueError("right must be 8 bytes")
        h = hashlib.sha256()
        h.update(self.key)
        h.update(round_index.to_bytes(4, "big"))
        h.update(right)
        return h.digest()[: self.half_size]

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != self.block_size:
            raise ValueError("block must be 16 bytes")
        left = block[: self.half_size]
        right = block[self.half_size :]
        for r in range(self.rounds):
            new_left = right
            new_right = xor_bytes(left, self._f(r, right))
            left, right = new_left, new_right
        return left + right

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != self.block_size:
            raise ValueError("block must be 16 bytes")
        left = block[: self.half_size]
        right = block[self.half_size :]
        for r in reversed(range(self.rounds)):
            prev_right = left
            prev_left = xor_bytes(right, self._f(r, prev_right))
            left, right = prev_left, prev_right
        return left + right


def ecb_encrypt(cipher: ToyFeistelCipher128, plaintext: bytes) -> bytes:
    padded = pkcs7_pad(plaintext, cipher.block_size)
    out = bytearray()
    for block in split_blocks(padded, cipher.block_size):
        out.extend(cipher.encrypt_block(block))
    return bytes(out)


def ecb_decrypt(cipher: ToyFeistelCipher128, ciphertext: bytes) -> bytes:
    out = bytearray()
    for block in split_blocks(ciphertext, cipher.block_size):
        out.extend(cipher.decrypt_block(block))
    return pkcs7_unpad(bytes(out), cipher.block_size)


def cbc_encrypt(cipher: ToyFeistelCipher128, iv: bytes, plaintext: bytes) -> bytes:
    if len(iv) != cipher.block_size:
        raise ValueError("iv must be 16 bytes")
    padded = pkcs7_pad(plaintext, cipher.block_size)
    prev = iv
    out = bytearray()
    for block in split_blocks(padded, cipher.block_size):
        x = xor_bytes(block, prev)
        c = cipher.encrypt_block(x)
        out.extend(c)
        prev = c
    return bytes(out)


def cbc_decrypt(cipher: ToyFeistelCipher128, iv: bytes, ciphertext: bytes) -> bytes:
    if len(iv) != cipher.block_size:
        raise ValueError("iv must be 16 bytes")
    blocks = split_blocks(ciphertext, cipher.block_size)
    prev = iv
    out = bytearray()
    for c in blocks:
        x = cipher.decrypt_block(c)
        p = xor_bytes(x, prev)
        out.extend(p)
        prev = c
    return pkcs7_unpad(bytes(out), cipher.block_size)


def ctr_xcrypt(
    cipher: ToyFeistelCipher128, nonce: bytes, data: bytes, initial_counter: int = 0
) -> bytes:
    if len(nonce) != 8:
        raise ValueError("nonce must be 8 bytes")
    if not (0 <= initial_counter < (1 << 64)):
        raise ValueError("initial_counter must fit in uint64")
    out = bytearray()
    counter = initial_counter
    offset = 0
    while offset < len(data):
        counter_bytes = counter.to_bytes(8, "big")
        keystream = cipher.encrypt_block(nonce + counter_bytes)
        take = min(len(keystream), len(data) - offset)
        chunk = data[offset : offset + take]
        out.extend(xor_bytes(chunk, keystream[:take]))
        offset += take
        counter = (counter + 1) % (1 << 64)
    return bytes(out)


def cfb_encrypt(cipher: ToyFeistelCipher128, iv: bytes, plaintext: bytes) -> bytes:
    if len(iv) != cipher.block_size:
        raise ValueError("iv must be 16 bytes")
    out = bytearray()
    prev = iv
    offset = 0
    while offset < len(plaintext):
        keystream = cipher.encrypt_block(prev)
        take = min(cipher.block_size, len(plaintext) - offset)
        chunk = plaintext[offset : offset + take]
        c = xor_bytes(chunk, keystream[:take])
        out.extend(c)
        prev = prev[take:] + c
        offset += take
    return bytes(out)


def cfb_decrypt(cipher: ToyFeistelCipher128, iv: bytes, ciphertext: bytes) -> bytes:
    if len(iv) != cipher.block_size:
        raise ValueError("iv must be 16 bytes")
    out = bytearray()
    prev = iv
    offset = 0
    while offset < len(ciphertext):
        keystream = cipher.encrypt_block(prev)
        take = min(cipher.block_size, len(ciphertext) - offset)
        chunk = ciphertext[offset : offset + take]
        p = xor_bytes(chunk, keystream[:take])
        out.extend(p)
        prev = prev[take:] + chunk
        offset += take
    return bytes(out)


def _h(label: str) -> None:
    print(f"\n=== {label} ===")


def _hex(b: bytes) -> str:
    return b.hex()


def main() -> None:
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    iv = bytes.fromhex("0f0e0d0c0b0a09080706050403020100")
    nonce = bytes.fromhex("0001020304050607")
    cipher = ToyFeistelCipher128(key=key, rounds=10)

    _h("Step 1: A toy 128-bit block cipher")
    block = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    c = cipher.encrypt_block(block)
    p = cipher.decrypt_block(c)
    print("block      :", _hex(block))
    print("enc(block) :", _hex(c))
    print("dec(enc)   :", _hex(p))

    _h("Step 2: ECB (why patterns leak)")
    repeated = (b"YELLOW SUBMARINE" * 4) + b"!!!"
    ecb_ct = ecb_encrypt(cipher, repeated)
    print("plaintext (hex):", _hex(repeated))
    print("ECB ct   (hex):", _hex(ecb_ct))

    _h("Step 3: CBC (random-looking blocks, needs unique IV)")
    msg = b"Pay Bob $100. Pay Bob $100. Pay Bob $100."
    cbc_ct = cbc_encrypt(cipher, iv, msg)
    roundtrip = cbc_decrypt(cipher, iv, cbc_ct)
    print("msg       :", msg)
    print("CBC ct    :", _hex(cbc_ct))
    print("dec(CBC)  :", roundtrip)

    _h("Step 4: CTR and CFB (stream-like, bit flips are visible)")
    pt = b"attack at dawn"
    ctr_ct = ctr_xcrypt(cipher, nonce, pt)
    ctr_pt = ctr_xcrypt(cipher, nonce, ctr_ct)
    print("CTR pt    :", pt)
    print("CTR ct    :", _hex(ctr_ct))
    print("CTR dec   :", ctr_pt)
    tampered = bytearray(ctr_ct)
    tampered[0] ^= 0x01
    print("CTR tamper:", ctr_xcrypt(cipher, nonce, bytes(tampered)))

    cfb_ct = cfb_encrypt(cipher, iv, pt)
    cfb_pt = cfb_decrypt(cipher, iv, cfb_ct)
    print("CFB ct    :", _hex(cfb_ct))
    print("CFB dec   :", cfb_pt)


if __name__ == "__main__":
    main()
