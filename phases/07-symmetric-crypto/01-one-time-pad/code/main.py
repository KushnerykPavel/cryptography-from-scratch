"""
One-Time Pad (OTP) demo: XOR encryption, key generation, and key-reuse failure.

Run:
  python3 code/main.py
"""

from __future__ import annotations

import secrets


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if not isinstance(a, (bytes, bytearray)):
        raise TypeError("a must be bytes-like")
    if not isinstance(b, (bytes, bytearray)):
        raise TypeError("b must be bytes-like")
    if len(a) != len(b):
        raise ValueError("inputs must have the same length")
    return bytes(x ^ y for x, y in zip(a, b))


def otp_encrypt(plaintext: bytes, key: bytes) -> bytes:
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes-like")
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key must be bytes-like")
    if len(plaintext) != len(key):
        raise ValueError("OTP key must be the same length as the plaintext")
    return xor_bytes(plaintext, key)


def otp_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("ciphertext must be bytes-like")
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key must be bytes-like")
    if len(ciphertext) != len(key):
        raise ValueError("OTP key must be the same length as the ciphertext")
    return xor_bytes(ciphertext, key)


def generate_otp_key(length: int) -> bytes:
    if not isinstance(length, int):
        raise TypeError("length must be int")
    if length < 0:
        raise ValueError("length must be >= 0")
    return secrets.token_bytes(length)


def to_hex(data: bytes) -> str:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes-like")
    return bytes(data).hex()


def from_hex(hex_str: str) -> bytes:
    if not isinstance(hex_str, str):
        raise TypeError("hex_str must be str")
    try:
        return bytes.fromhex(hex_str)
    except ValueError as e:
        raise ValueError("invalid hex string") from e


def main() -> None:
    print("=== Step 1: XOR bytes ===")
    a = from_hex("1c0111001f010100061a024b53535009181c")
    b = from_hex("686974207468652062756c6c277320657965")
    x = xor_bytes(a, b)
    print(f"a      = {to_hex(a)}")
    print(f"b      = {to_hex(b)}")
    print(f"a XOR b= {to_hex(x)}")
    print()

    print("=== Step 2: OTP encrypt and decrypt ===")
    plaintext = b"attack at dawn!!"
    key = from_hex("00112233445566778899aabbccddeeff")
    ciphertext = otp_encrypt(plaintext, key)
    decrypted = otp_decrypt(ciphertext, key)
    print(f"plaintext = {plaintext!r}")
    print(f"key       = {to_hex(key)}")
    print(f"ciphertext= {to_hex(ciphertext)}")
    print(f"decrypted = {decrypted!r}")
    print()

    print("=== Step 3: Generate a truly random OTP key ===")
    msg = b"meet at the bridge"
    key2 = generate_otp_key(len(msg))
    c2 = otp_encrypt(msg, key2)
    m2 = otp_decrypt(c2, key2)
    print(f"msg       = {msg!r}")
    print(f"key (hex) = {to_hex(key2)}")
    print(f"ct  (hex) = {to_hex(c2)}")
    print(f"roundtrip = {m2!r}")
    print()

    print("=== Step 4: Key reuse breaks secrecy (two-time pad) ===")
    p1 = b"send more money!!"
    p2 = b"meet at the park!"
    reused_key = generate_otp_key(len(p1))
    c1 = otp_encrypt(p1, reused_key)
    c2 = otp_encrypt(p2, reused_key)

    leak = xor_bytes(c1, c2)
    recovered_p2 = xor_bytes(leak, p1)

    print(f"p1        = {p1!r}")
    print(f"p2        = {p2!r}")
    print(f"c1 (hex)  = {to_hex(c1)}")
    print(f"c2 (hex)  = {to_hex(c2)}")
    print(f"c1^c2(hex)= {to_hex(leak)}  (this equals p1^p2)")
    print(f"if attacker knows p1, p2 = (c1^c2)^p1 = {recovered_p2!r}")
    print()

    print("Bonus: OTP provides no integrity (bit flipping)")
    tampered = bytearray(c1)
    tampered[0] ^= 0x20
    tampered_plain = otp_decrypt(bytes(tampered), reused_key)
    print(f"tampered c1 (hex) = {to_hex(bytes(tampered))}")
    print(f"decrypt(tampered) = {tampered_plain!r}")


if __name__ == "__main__":
    main()
