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


def _msg_from_inputs(inputs: dict) -> bytes:
    if "msg_utf8" in inputs:
        return inputs["msg_utf8"].encode("utf-8")
    if "msg_hex" in inputs:
        return _b(inputs["msg_hex"])
    if "repeat_utf8" in inputs and "repeat_count" in inputs:
        unit = inputs["repeat_utf8"].encode("utf-8")
        count = int(inputs["repeat_count"])
        if count < 0:
            raise ValueError("repeat_count must be non-negative")
        return unit * count
    raise KeyError("unsupported message input format")


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

        if op == "sha256_hex":
            msg = _msg_from_inputs(inputs)
            got = impl.sha256_hex(msg)
            assert got == expected["digest_hex"]

        elif op == "sha256":
            msg = _msg_from_inputs(inputs)
            got = impl.sha256(msg)
            assert got == _b(expected["digest_hex"])

        elif op == "sha256_padding":
            got = impl.sha256_padding(int(inputs["message_len_bytes"]))
            assert got == _b(expected["padding_hex"])

        else:
            raise AssertionError(f"unknown op: {op}")


def test_matches_hashlib_for_random_inputs():
    rng = __import__("random").Random(0)
    hashlib = __import__("hashlib")

    for n in [0, 1, 2, 3, 55, 56, 57, 63, 64, 65, 127, 128, 1024]:
        msg = bytes(rng.getrandbits(8) for _ in range(n))
        assert impl.sha256(msg) == hashlib.sha256(msg).digest()


def test_streaming_equivalence():
    data = b"The quick brown fox jumps over the lazy dog"

    h = impl.SHA256()
    for chunk in [data[:1], data[1:3], data[3:8], data[8:]]:
        h.update(chunk)

    assert h.digest() == impl.sha256(data)
    assert h.hexdigest() == impl.sha256_hex(data)


def test_argument_validation():
    try:
        impl.rotr32(0, 32)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass

    try:
        impl.sha256("not-bytes")  # type: ignore[arg-type]
        raise AssertionError("expected TypeError")
    except TypeError:
        pass

    try:
        impl.SHA256().update("not-bytes")  # type: ignore[arg-type]
        raise AssertionError("expected TypeError")
    except TypeError:
        pass


if __name__ == "__main__":
    os.environ.setdefault("PYTHONHASHSEED", "0")
    test_vectors()
    test_matches_hashlib_for_random_inputs()
    test_streaming_equivalence()
    test_argument_validation()
    print("all tests pass")

