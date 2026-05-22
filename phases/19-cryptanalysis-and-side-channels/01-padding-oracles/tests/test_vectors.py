import json
import os
import random
import sys
from contextlib import contextmanager

HERE = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as po  # noqa: E402


@contextmanager
def _raises(exc_type):
    try:
        yield
    except exc_type:
        return
    raise AssertionError(f"expected {exc_type.__name__} to be raised")


def _b(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


def test_vectors():
    with open(os.path.join(HERE, "vectors.json"), "r", encoding="utf-8") as f:
        data = json.load(f)

    for vec in data["vectors"]:
        op = vec["op"]

        if op == "pkcs7_pad":
            got = po.pkcs7_pad(_b(vec["data_hex"]), int(vec["block_size"]))
            expected = _b(vec["expected_hex"])
        elif op == "pkcs7_unpad":
            got = po.pkcs7_unpad(_b(vec["padded_hex"]), int(vec["block_size"]))
            expected = _b(vec["expected_hex"])
        elif op == "toy_cipher_encrypt_block":
            got = po.toy_cipher_encrypt_block(_b(vec["key_hex"]), _b(vec["block_hex"]))
            expected = _b(vec["expected_hex"])
        elif op == "toy_cipher_decrypt_block":
            got = po.toy_cipher_decrypt_block(_b(vec["key_hex"]), _b(vec["block_hex"]))
            expected = _b(vec["expected_hex"])
        elif op == "cbc_encrypt":
            got = po.cbc_encrypt(_b(vec["key_hex"]), _b(vec["iv_hex"]), _b(vec["plaintext_hex"]))
            expected = _b(vec["expected_hex"])
        elif op == "cbc_decrypt":
            got = po.cbc_decrypt(_b(vec["key_hex"]), _b(vec["iv_hex"]), _b(vec["ciphertext_hex"]))
            expected = _b(vec["expected_hex"])
        else:
            raise ValueError(f"unknown op in vectors.json: {op}")

        assert got == expected, f"vector failed: op={op}"


def test_pkcs7_unpad_rejects_bad_padding():
    with _raises(ValueError):
        po.pkcs7_unpad(b"", 16)
    with _raises(ValueError):
        po.pkcs7_unpad(b"\x01", 16)
    with _raises(ValueError):
        po.pkcs7_unpad(b"A" * 16, 16)
    with _raises(ValueError):
        po.pkcs7_unpad(b"A" * 15 + b"\x00", 16)


def test_toy_cipher_roundtrip_random_blocks():
    rng = random.Random(0)
    key = bytes(range(16))
    for _ in range(50):
        block = bytes(rng.randrange(0, 256) for _ in range(16))
        enc = po.toy_cipher_encrypt_block(key, block)
        dec = po.toy_cipher_decrypt_block(key, enc)
        assert dec == block


def test_cbc_roundtrip_and_oracle_attack():
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    iv = bytes.fromhex("0f0e0d0c0b0a09080706050403020100")
    msg = b"attack at dawn; bring coffee"
    ct = po.cbc_encrypt(key, iv, msg)
    assert po.cbc_decrypt(key, iv, ct) == msg

    oracle = po.padding_oracle_factory(key)
    recovered = po.recover_plaintext_via_padding_oracle(iv, ct, oracle)
    assert recovered == msg

    tampered = ct[:-1] + b"\x00"
    assert oracle(iv, tampered) is False


if __name__ == "__main__":
    tests = [
        test_vectors,
        test_pkcs7_unpad_rejects_bad_padding,
        test_toy_cipher_roundtrip_random_blocks,
        test_cbc_roundtrip_and_oracle_attack,
    ]
    for t in tests:
        t()
    print("all tests pass")
