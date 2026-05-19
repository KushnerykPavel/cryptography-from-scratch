import hashlib
import json
import os
import random
import sys


TESTS_DIR = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(TESTS_DIR, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as sha3  # noqa: E402


def _load_vectors() -> dict:
    path = os.path.join(TESTS_DIR, "vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def test_vectors() -> None:
    vectors = _load_vectors()["vectors"]
    for v in vectors:
        op = v["op"]
        message = bytes.fromhex(v.get("message_hex", ""))
        expected = v["expected_hex"]

        if op == "sha3_256":
            got = sha3.sha3_256(message).hex()
        elif op == "sha3_512":
            got = sha3.sha3_512(message).hex()
        elif op == "shake128":
            got = sha3.shake128(message, int(v["output_len"])).hex()
        elif op == "shake256":
            got = sha3.shake256(message, int(v["output_len"])).hex()
        else:
            raise AssertionError(f"unknown op: {op!r}")

        assert got == expected


def test_matches_hashlib_on_random_messages() -> None:
    rng = random.Random(1337)
    for _ in range(50):
        msg_len = rng.randrange(0, 400)
        msg = bytes(rng.randrange(0, 256) for _ in range(msg_len))

        assert sha3.sha3_256(msg) == hashlib.sha3_256(msg).digest()
        assert sha3.sha3_512(msg) == hashlib.sha3_512(msg).digest()

        out_len_128 = rng.randrange(0, 200)
        out_len_256 = rng.randrange(0, 200)
        assert sha3.shake128(msg, out_len_128) == hashlib.shake_128(msg).digest(out_len_128)
        assert sha3.shake256(msg, out_len_256) == hashlib.shake_256(msg).digest(out_len_256)


def test_padding_corner_case_last_byte() -> None:
    rate_bytes = 136
    message = b"A" * (rate_bytes - 1)
    padded = sha3.keccak_multirate_pad(rate_bytes, message, 0x06)
    assert len(padded) == rate_bytes
    assert padded[-1] == (0x06 ^ 0x80)

    message2 = b"B" * rate_bytes
    padded2 = sha3.keccak_multirate_pad(rate_bytes, message2, 0x06)
    assert len(padded2) == 2 * rate_bytes
    assert padded2[rate_bytes] == 0x06
    assert padded2[-1] == 0x80


def test_rejects_invalid_params() -> None:
    try:
        sha3.keccak_sponge(rate_bytes=136, message=b"", delimited_suffix=0x06, output_len=-1)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for negative output_len")

    try:
        sha3.keccak_multirate_pad(0, b"", 0x06)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for non-positive rate_bytes")


if __name__ == "__main__":
    test_vectors()
    test_matches_hashlib_on_random_messages()
    test_padding_corner_case_last_byte()
    test_rejects_invalid_params()
    print("all tests pass")
