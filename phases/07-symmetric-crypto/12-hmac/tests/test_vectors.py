import hashlib
import hmac
import json
import os
import random
import sys


THIS_DIR = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(THIS_DIR, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as lesson  # noqa: E402


def _load_vectors():
    path = os.path.join(THIS_DIR, "vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        doc = json.load(f)
    return doc["vectors"]


def test_vectors():
    vectors = _load_vectors()
    for v in vectors:
        op = v["op"]
        inputs = v["inputs"]
        expected = v["expected"]

        if op == "normalize_hmac_key_sha256":
            out = lesson.normalize_hmac_key_sha256(bytes.fromhex(inputs["key_hex"]))
            assert out.hex().upper() == expected
        elif op == "hmac_sha256":
            out = lesson.hmac_sha256(bytes.fromhex(inputs["key_hex"]), bytes.fromhex(inputs["msg_hex"]))
            assert out.hex().upper() == expected
        elif op == "hmac_sha256_truncated":
            out = lesson.hmac_sha256_truncated(
                bytes.fromhex(inputs["key_hex"]), bytes.fromhex(inputs["msg_hex"]), int(inputs["tag_len"])
            )
            assert out.hex().upper() == expected
        else:
            raise AssertionError(f"unknown op: {op}")


def _randbytes(rng: random.Random, n: int) -> bytes:
    out = bytearray()
    while len(out) < n:
        out.extend(rng.getrandbits(32).to_bytes(4, "big"))
    return bytes(out[:n])


def test_matches_python_stdlib_hmac_sha256_random():
    rng = random.Random(0)
    for _ in range(250):
        key = _randbytes(rng, rng.randrange(0, 200))
        msg = _randbytes(rng, rng.randrange(0, 300))
        expected = hmac.new(key, msg, hashlib.sha256).digest()
        out = lesson.hmac_sha256(key, msg)
        assert out == expected


def test_verify_accepts_only_correct_tags():
    key = b"k"
    msg = b"m"
    tag = lesson.hmac_sha256(key, msg)
    assert lesson.verify_hmac_sha256(key, msg, tag) is True
    assert lesson.verify_hmac_sha256(key, msg + b"!", tag) is False
    assert lesson.verify_hmac_sha256(key, msg, tag[:-1] + bytes([tag[-1] ^ 0x01])) is False


def test_truncation_length_and_verification():
    key = b"key"
    msg = b"msg"
    for n in [0, 1, 2, 8, 16, 31, 32]:
        t = lesson.hmac_sha256_truncated(key, msg, n)
        assert len(t) == n
        assert lesson.verify_hmac_sha256_truncated(key, msg, t, n) is True
        assert lesson.verify_hmac_sha256_truncated(key, msg, t + b"\x00", n) is False

    try:
        lesson.hmac_sha256_truncated(key, msg, -1)
        raise AssertionError("expected HmacError for tag_len=-1")
    except lesson.HmacError:
        pass

    try:
        lesson.hmac_sha256_truncated(key, msg, 33)
        raise AssertionError("expected HmacError for tag_len=33")
    except lesson.HmacError:
        pass


def test_constant_time_equal_correctness():
    assert lesson.constant_time_equal(b"", b"") is True
    assert lesson.constant_time_equal(b"a", b"a") is True
    assert lesson.constant_time_equal(b"a", b"b") is False
    assert lesson.constant_time_equal(b"a", b"aa") is False


def test_rejects_non_bytes_inputs():
    try:
        lesson.hmac_sha256("k", b"m")  # type: ignore[arg-type]
        raise AssertionError("expected HmacError for non-bytes key")
    except lesson.HmacError:
        pass

    try:
        lesson.hmac_sha256(b"k", "m")  # type: ignore[arg-type]
        raise AssertionError("expected HmacError for non-bytes msg")
    except lesson.HmacError:
        pass


if __name__ == "__main__":
    test_vectors()
    test_matches_python_stdlib_hmac_sha256_random()
    test_verify_accepts_only_correct_tags()
    test_truncation_length_and_verification()
    test_constant_time_equal_correctness()
    test_rejects_non_bytes_inputs()
    print("all tests pass")

