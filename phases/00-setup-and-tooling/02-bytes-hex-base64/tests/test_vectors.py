import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import b64_decode, b64_encode, hex_decode, hex_encode


def _bytes_from_vector(v: dict) -> bytes:
    if "data_ascii" in v:
        return v["data_ascii"].encode("utf-8")
    if "data_hex" in v:
        return bytes.fromhex(v["data_hex"])
    raise AssertionError("vector must include data_ascii or data_hex")


def _expected_bytes(v: dict) -> bytes:
    if "expected_ascii" in v:
        return v["expected_ascii"].encode("utf-8")
    if "expected_hex" in v:
        return bytes.fromhex(v["expected_hex"])
    raise AssertionError("vector must include expected_ascii or expected_hex")


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]
        if op == "hex_encode":
            got = hex_encode(_bytes_from_vector(v), uppercase=bool(v.get("uppercase", False)))
            assert got == v["expected"], f"hex_encode failed: got {got}, expected {v['expected']}"
        elif op == "hex_decode":
            got = hex_decode(v["hex"])
            expected = _expected_bytes(v)
            assert got == expected, f"hex_decode failed: got {got!r}, expected {expected!r}"
        elif op == "b64_encode":
            got = b64_encode(_bytes_from_vector(v))
            assert got == v["expected"], f"b64_encode failed: got {got}, expected {v['expected']}"
        elif op == "b64_decode":
            got = b64_decode(v["b64"])
            expected = _expected_bytes(v)
            assert got == expected, f"b64_decode failed: got {got!r}, expected {expected!r}"
        else:
            raise AssertionError(f"unknown op {op}")


def test_b64_decode_rejects_non_canonical_padding():
    bad = [
        "Zg=",
        "Zg===",
        "Zm9=v",
        "Zm9v=",
        "====",
    ]
    for s in bad:
        try:
            b64_decode(s)
        except ValueError:
            pass
        else:
            raise AssertionError(f"expected ValueError for {s!r}")


def test_hex_decode_rejects_odd_length():
    try:
        hex_decode("abc")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for odd-length hex")


if __name__ == "__main__":
    test_vectors()
    test_b64_decode_rejects_non_canonical_padding()
    test_hex_decode_rejects_odd_length()
    print("all tests pass")

