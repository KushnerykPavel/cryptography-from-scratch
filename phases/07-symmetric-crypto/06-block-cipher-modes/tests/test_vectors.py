import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (  # noqa: E402
    ToyFeistelCipher128,
    cbc_decrypt,
    cbc_encrypt,
    cfb_decrypt,
    cfb_encrypt,
    ctr_xcrypt,
    ecb_decrypt,
    ecb_encrypt,
    pkcs7_pad,
    pkcs7_unpad,
    split_blocks,
)


def _b(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


def _cipher(key_hex: str, rounds: int) -> ToyFeistelCipher128:
    return ToyFeistelCipher128(key=_b(key_hex), rounds=rounds)


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]
        inputs = v["inputs"]
        expected = _b(v["expected_hex"])

        if op == "pkcs7_pad":
            got = pkcs7_pad(_b(inputs["data_hex"]), inputs["block_size"])
        elif op == "pkcs7_unpad":
            got = pkcs7_unpad(_b(inputs["padded_hex"]), inputs["block_size"])
        elif op == "toy_encrypt_block":
            cipher = _cipher(inputs["key_hex"], inputs["rounds"])
            got = cipher.encrypt_block(_b(inputs["block_hex"]))
        elif op == "toy_decrypt_block":
            cipher = _cipher(inputs["key_hex"], inputs["rounds"])
            got = cipher.decrypt_block(_b(inputs["block_hex"]))
        elif op == "ecb_encrypt":
            cipher = _cipher(inputs["key_hex"], inputs["rounds"])
            got = ecb_encrypt(cipher, _b(inputs["plaintext_hex"]))
        elif op == "ecb_decrypt":
            cipher = _cipher(inputs["key_hex"], inputs["rounds"])
            got = ecb_decrypt(cipher, _b(inputs["ciphertext_hex"]))
        elif op == "cbc_encrypt":
            cipher = _cipher(inputs["key_hex"], inputs["rounds"])
            got = cbc_encrypt(cipher, _b(inputs["iv_hex"]), _b(inputs["plaintext_hex"]))
        elif op == "cbc_decrypt":
            cipher = _cipher(inputs["key_hex"], inputs["rounds"])
            got = cbc_decrypt(cipher, _b(inputs["iv_hex"]), _b(inputs["ciphertext_hex"]))
        elif op == "ctr_xcrypt":
            cipher = _cipher(inputs["key_hex"], inputs["rounds"])
            got = ctr_xcrypt(
                cipher,
                _b(inputs["nonce_hex"]),
                _b(inputs["data_hex"]),
                initial_counter=inputs["initial_counter"],
            )
        elif op == "cfb_encrypt":
            cipher = _cipher(inputs["key_hex"], inputs["rounds"])
            got = cfb_encrypt(cipher, _b(inputs["iv_hex"]), _b(inputs["plaintext_hex"]))
        elif op == "cfb_decrypt":
            cipher = _cipher(inputs["key_hex"], inputs["rounds"])
            got = cfb_decrypt(cipher, _b(inputs["iv_hex"]), _b(inputs["ciphertext_hex"]))
        else:
            raise AssertionError(f"unknown op {op}")

        assert got == expected, f"{op} failed: got {got.hex()}, expected {expected.hex()}"


def test_pkcs7_rejects_bad_padding():
    good = pkcs7_pad(b"hi", 16)
    assert pkcs7_unpad(good, 16) == b"hi"

    bad_last = good[:-1] + b"\x00"
    try:
        pkcs7_unpad(bad_last, 16)
        raise AssertionError("expected ValueError for pad_len=0")
    except ValueError:
        pass

    bad_bytes = good[:-1] + b"\x02"
    try:
        pkcs7_unpad(bad_bytes, 16)
        raise AssertionError("expected ValueError for invalid padding bytes")
    except ValueError:
        pass


def test_roundtrips_and_lengths():
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    iv = bytes.fromhex("0f0e0d0c0b0a09080706050403020100")
    nonce = bytes.fromhex("0001020304050607")
    cipher = ToyFeistelCipher128(key=key, rounds=10)

    for pt in [b"", b"a", b"1234567890abcdef", b"hello world", b"x" * 100]:
        e = ecb_encrypt(cipher, pt)
        assert ecb_decrypt(cipher, e) == pt

        c = cbc_encrypt(cipher, iv, pt)
        assert cbc_decrypt(cipher, iv, c) == pt

        s = ctr_xcrypt(cipher, nonce, pt)
        assert len(s) == len(pt)
        assert ctr_xcrypt(cipher, nonce, s) == pt

        f = cfb_encrypt(cipher, iv, pt)
        assert len(f) == len(pt)
        assert cfb_decrypt(cipher, iv, f) == pt


def test_ecb_leaks_repeated_blocks():
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    cipher = ToyFeistelCipher128(key=key, rounds=10)
    block = b"A" * cipher.block_size
    pt = block + block
    ct = ecb_encrypt(cipher, pt)
    blocks = split_blocks(ct, cipher.block_size)
    assert blocks[0] == blocks[1], "ECB should produce identical ciphertext for identical blocks"


def test_rejects_bad_iv_nonce_lengths():
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    cipher = ToyFeistelCipher128(key=key, rounds=10)

    try:
        cbc_encrypt(cipher, b"\x00" * 15, b"hi")
        raise AssertionError("expected ValueError for bad iv length")
    except ValueError:
        pass

    try:
        ctr_xcrypt(cipher, b"\x00" * 7, b"hi")
        raise AssertionError("expected ValueError for bad nonce length")
    except ValueError:
        pass


if __name__ == "__main__":
    test_vectors()
    test_pkcs7_rejects_bad_padding()
    test_roundtrips_and_lengths()
    test_ecb_leaks_repeated_blocks()
    test_rejects_bad_iv_nonce_lengths()
    print("all tests pass")
