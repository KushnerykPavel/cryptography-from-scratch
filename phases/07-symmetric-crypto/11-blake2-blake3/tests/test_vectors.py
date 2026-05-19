import json
import os
import sys


HERE = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main  # noqa: E402


def _bytes_from_vector(vec: dict) -> bytes:
    if "input_ascii" in vec:
        return vec["input_ascii"].encode("utf-8")
    if "input_hex" in vec:
        return bytes.fromhex(vec["input_hex"])
    if "input_pattern_len" in vec:
        return main.blake3_test_input(int(vec["input_pattern_len"]))
    raise ValueError(f"unknown input encoding in vector: {vec}")


def _run_vector(vec: dict) -> bytes:
    op = vec["op"]
    out_len = int(vec.get("out_len", 32))

    if op == "blake2s_256":
        return main.blake2s_256(_bytes_from_vector(vec))
    if op == "blake2s_rfc7693_selftest_digest":
        return main.blake2s_rfc7693_selftest_digest()
    if op == "blake3_hash":
        return main.blake3_hash(_bytes_from_vector(vec), out_len=out_len)
    if op == "blake3_keyed_hash":
        key_ascii = vec["key_ascii"]
        return main.blake3_keyed_hash(key_ascii.encode("utf-8"), _bytes_from_vector(vec), out_len=out_len)
    if op == "blake3_derive_key":
        ctx = vec["context_string"]
        return main.blake3_derive_key(ctx, _bytes_from_vector(vec), out_len=out_len)

    raise ValueError(f"unknown op: {op}")


def test_vectors():
    path = os.path.join(HERE, "vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        doc = json.load(f)

    for vec in doc["vectors"]:
        got = _run_vector(vec)
        expected = bytes.fromhex(vec["expected_hex"])
        assert got == expected, f"{vec['op']} failed: got={got.hex()} expected={expected.hex()}"


def test_blake3_out_len_contract():
    d = b"hello world"
    for n in [0, 1, 2, 31, 32, 33, 63, 64, 65, 131]:
        assert len(main.blake3_hash(d, out_len=n)) == n


def test_blake3_keyed_hash_key_length_rejected():
    try:
        main.blake3_keyed_hash(b"short", b"msg")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for non-32-byte key")


def test_blake3_domain_separation():
    msg = b"same input"
    key = b"whats the Elvish word for friend"
    ctx = "BLAKE3 2019-12-27 16:29:52 test vectors context"

    h = main.blake3_hash(msg, out_len=32)
    kh = main.blake3_keyed_hash(key, msg, out_len=32)
    dk = main.blake3_derive_key(ctx, msg, out_len=32)

    assert h != kh
    assert h != dk
    assert kh != dk


if __name__ == "__main__":
    test_vectors()
    test_blake3_out_len_contract()
    test_blake3_keyed_hash_key_length_rejected()
    test_blake3_domain_separation()
    print("all tests pass")

