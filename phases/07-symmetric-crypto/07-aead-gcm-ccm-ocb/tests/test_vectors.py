import json
import random
import sys
from pathlib import Path


THIS_DIR = Path(__file__).resolve().parent
CODE_DIR = (THIS_DIR / ".." / "code").resolve()
sys.path.insert(0, str(CODE_DIR))

import main  # noqa: E402


def _hx(s: str) -> bytes:
    return bytes.fromhex(s)


def _load_vectors() -> dict:
    path = THIS_DIR / "vectors.json"
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def test_vectors() -> None:
    data = _load_vectors()
    vectors = data["vectors"]

    for vec in vectors:
        op = vec["op"]
        inputs = vec["inputs"]
        expected = vec["expected"]

        if op == "aes_encrypt_block":
            out = main.aes_encrypt_block(_hx(inputs["key_hex"]), _hx(inputs["block_hex"]))
            assert out.hex() == expected["cipher_hex"]
            continue

        if op == "gcm_encrypt":
            ct, tag = main.gcm_encrypt(
                _hx(inputs["key_hex"]),
                _hx(inputs["nonce_hex"]),
                _hx(inputs["plaintext_hex"]),
                aad=_hx(inputs["aad_hex"]),
                tag_len=16,
            )
            assert ct.hex() == expected["ciphertext_hex"]
            assert tag.hex() == expected["tag_hex"]
            continue

        if op == "gcm_decrypt":
            pt = main.gcm_decrypt(
                _hx(inputs["key_hex"]),
                _hx(inputs["nonce_hex"]),
                _hx(inputs["ciphertext_hex"]),
                aad=_hx(inputs["aad_hex"]),
                tag=_hx(inputs["tag_hex"]),
            )
            assert pt.hex() == expected["plaintext_hex"]
            continue

        raise AssertionError(f"unknown op: {op}")


def test_gcm_rejects_modified_ciphertext() -> None:
    key = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
    nonce = bytes.fromhex("cafebabefacedbaddecaf888")
    aad = bytes.fromhex("3ad77bb40d7a3660a89ecaf32466ef97f5d3d585")
    pt = b"message"
    ct, tag = main.gcm_encrypt(key, nonce, pt, aad=aad)

    tampered = bytearray(ct)
    tampered[0] ^= 0x01
    try:
        main.gcm_decrypt(key, nonce, bytes(tampered), aad=aad, tag=tag)
        raise AssertionError("expected authentication failure")
    except ValueError:
        pass


def test_gcm_rejects_modified_aad() -> None:
    rng = random.Random(2026)
    key = rng.randbytes(16)
    nonce = rng.randbytes(12)
    aad = b"header:v1"
    pt = b"payload"
    ct, tag = main.gcm_encrypt(key, nonce, pt, aad=aad)

    try:
        main.gcm_decrypt(key, nonce, ct, aad=b"header:v2", tag=tag)
        raise AssertionError("expected authentication failure")
    except ValueError:
        pass


def test_nonce_length_enforced() -> None:
    rng = random.Random(7)
    key = rng.randbytes(16)
    try:
        main.gcm_encrypt(key, b"short", b"pt", aad=b"")
        raise AssertionError("expected nonce length failure")
    except ValueError:
        pass


def test_packed_aead_roundtrip() -> None:
    rng = random.Random(123)
    nonce = rng.randbytes(12)
    ct = rng.randbytes(7)
    tag = rng.randbytes(16)
    packed = main.PackedAEAD(nonce=nonce, ciphertext=ct, tag=tag).to_bytes()
    parsed = main.PackedAEAD.from_bytes(packed)
    assert parsed.nonce == nonce
    assert parsed.ciphertext == ct
    assert parsed.tag == tag


def test_gcm_roundtrip_deterministic_random_cases() -> None:
    rng = random.Random(1337)
    for _ in range(20):
        key = rng.randbytes(16)
        nonce = rng.randbytes(12)
        aad = rng.randbytes(rng.randrange(0, 40))
        pt = rng.randbytes(rng.randrange(0, 80))
        ct, tag = main.gcm_encrypt(key, nonce, pt, aad=aad)
        out = main.gcm_decrypt(key, nonce, ct, aad=aad, tag=tag)
        assert out == pt


if __name__ == "__main__":
    test_vectors()
    test_gcm_rejects_modified_ciphertext()
    test_gcm_rejects_modified_aad()
    test_nonce_length_enforced()
    test_packed_aead_roundtrip()
    test_gcm_roundtrip_deterministic_random_cases()
    print("all tests pass")
