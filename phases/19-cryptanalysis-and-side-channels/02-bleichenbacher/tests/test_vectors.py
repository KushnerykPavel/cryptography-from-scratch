import json
import os
import sys
from contextlib import contextmanager

HERE = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as bb  # noqa: E402


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

        if op == "i2osp":
            got = bb.i2osp(int(vec["x"]), int(vec["k"]))
            expected = _b(vec["expected_hex"])
        elif op == "os2ip":
            got = bb.os2ip(_b(vec["bytes_hex"]))
            expected = int(vec["expected"])
        elif op == "pkcs1v15_is_conformant":
            got = bb.pkcs1v15_is_conformant(_b(vec["em_hex"]))
            expected = bool(vec["expected"])
        elif op == "toy_prefix_encode":
            got = bb.toy_prefix_encode(_b(vec["message_hex"]), int(vec["k"]))
            expected = _b(vec["expected_hex"])
        elif op == "toy_prefix_decode":
            got = bb.toy_prefix_decode(_b(vec["em_hex"]), int(vec["message_len"]))
            expected = _b(vec["expected_hex"])
        else:
            raise ValueError(f"unknown op in vectors.json: {op}")

        assert got == expected, f"vector failed: op={op}"


def test_pkcs1v15_encode_rejects_bad_ps():
    with _raises(ValueError):
        bb.pkcs1v15_encode(b"Z", 12, b"\x00" * 8)
    with _raises(ValueError):
        bb.pkcs1v15_encode(b"Z", 12, b"\x01" * 7)


def test_bleichenbacher_toy_header_demo_recovers_message():
    key = bb._toy_rsa_key()
    msg = b"Z"
    em = bb.toy_prefix_encode(msg, key.k, header_byte=2)
    c = bb.rsa_encrypt_int(bb.os2ip(em), key.n, key.e)
    oracle = bb.header_oracle_factory(key, header_bits=8)

    recovered_em, calls = bb.bleichenbacher_recover_em(
        c, key.n, key.e, oracle, header_bits=8, max_oracle_calls=50_000
    )
    assert recovered_em == em
    assert bb.toy_prefix_decode(recovered_em, len(msg)) == msg
    assert calls < 50_000


if __name__ == "__main__":
    tests = [
        test_vectors,
        test_pkcs1v15_encode_rejects_bad_ps,
        test_bleichenbacher_toy_header_demo_recovers_message,
    ]
    for t in tests:
        t()
    print("all tests pass")
