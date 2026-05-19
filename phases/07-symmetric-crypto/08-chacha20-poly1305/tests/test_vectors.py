import json
import os
import sys
from pathlib import Path


THIS_DIR = Path(__file__).resolve().parent
CODE_DIR = (THIS_DIR / ".." / "code").resolve()

sys.path.insert(0, str(CODE_DIR))

import main as impl  # noqa: E402


def _b(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


def _load_vectors() -> dict:
    path = THIS_DIR / "vectors.json"
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def test_vectors():
    data = _load_vectors()
    vectors = data["vectors"]

    for v in vectors:
        op = v["op"]
        inputs = v["inputs"]
        expected = v["expected"]

        if op == "chacha20_block":
            got = impl.chacha20_block(
                _b(inputs["key_hex"]), inputs["counter"], _b(inputs["nonce_hex"])
            )
            assert got == _b(expected["block_hex"])

        elif op == "chacha20_encrypt":
            pt = inputs["plaintext_utf8"].encode("utf-8")
            got = impl.chacha20_encrypt(
                _b(inputs["key_hex"]), inputs["counter"], _b(inputs["nonce_hex"]), pt
            )
            assert got == _b(expected["ciphertext_hex"])

        elif op == "poly1305_mac":
            msg = inputs["msg_utf8"].encode("utf-8")
            got = impl.poly1305_mac(msg, _b(inputs["key_hex"]))
            assert got == _b(expected["tag_hex"])

        elif op == "poly1305_key_gen":
            got = impl.poly1305_key_gen(_b(inputs["key_hex"]), _b(inputs["nonce_hex"]))
            assert got == _b(expected["otk_hex"])

        elif op == "aead_encrypt":
            pt = inputs["plaintext_utf8"].encode("utf-8")
            ct, tag = impl.aead_chacha20_poly1305_encrypt(
                _b(inputs["key_hex"]),
                _b(inputs["nonce_hex"]),
                _b(inputs["aad_hex"]),
                pt,
            )
            assert ct == _b(expected["ciphertext_hex"])
            assert tag == _b(expected["tag_hex"])

        elif op == "aead_decrypt":
            got = impl.aead_chacha20_poly1305_decrypt(
                _b(inputs["key_hex"]),
                _b(inputs["nonce_hex"]),
                _b(inputs["aad_hex"]),
                _b(inputs["ciphertext_hex"]),
                _b(inputs["tag_hex"]),
            )
            assert got == expected["plaintext_utf8"].encode("utf-8")

        else:
            raise AssertionError(f"unknown op: {op}")


def test_roundtrip_properties():
    rng = __import__("random").Random(0)

    key = bytes(rng.getrandbits(8) for _ in range(32))
    nonce = bytes(rng.getrandbits(8) for _ in range(12))
    aad = bytes(rng.getrandbits(8) for _ in range(23))

    for n in [0, 1, 2, 15, 16, 17, 31, 32, 33, 100, 256]:
        msg = bytes(rng.getrandbits(8) for _ in range(n))

        ct = impl.chacha20_encrypt(key, 1, nonce, msg)
        pt = impl.chacha20_decrypt(key, 1, nonce, ct)
        assert pt == msg

        ct2, tag2 = impl.aead_chacha20_poly1305_encrypt(key, nonce, aad, msg)
        pt2 = impl.aead_chacha20_poly1305_decrypt(key, nonce, aad, ct2, tag2)
        assert pt2 == msg


def test_aead_rejects_modified_ciphertext():
    key = bytes(range(32))
    nonce = bytes.fromhex("070000004041424344454647")
    aad = b"header"
    pt = b"hello"

    ct, tag = impl.aead_chacha20_poly1305_encrypt(key, nonce, aad, pt)
    modified = bytes([ct[0] ^ 1]) + ct[1:]

    try:
        impl.aead_chacha20_poly1305_decrypt(key, nonce, aad, modified, tag)
        raise AssertionError("expected invalid tag")
    except ValueError as e:
        assert "invalid tag" in str(e)


def test_argument_validation():
    key = b"\x00" * 31
    nonce = b"\x00" * 12
    try:
        impl.chacha20_block(key, 1, nonce)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass

    key32 = b"\x00" * 32
    try:
        impl.chacha20_block(key32, 1, b"\x00" * 11)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass

    try:
        impl.aead_chacha20_poly1305_decrypt(key32, nonce, b"", b"", b"\x00" * 15)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


if __name__ == "__main__":
    os.environ.setdefault("PYTHONHASHSEED", "0")
    test_vectors()
    test_roundtrip_properties()
    test_aead_rejects_modified_ciphertext()
    test_argument_validation()
    print("all tests pass")

