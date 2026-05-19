import json
import os
import sys

HERE = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.append(CODE_DIR)

import main as mixnet  # noqa: E402


def _b(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


def _dispatch(vec):
    op = vec["op"]
    inputs = vec["inputs"]

    if op == "encrypt_then_mac":
        return mixnet.encrypt_then_mac(_b(inputs["key_hex"]), _b(inputs["nonce_hex"]), _b(inputs["plaintext_hex"]))

    if op == "decrypt_then_verify":
        return mixnet.decrypt_then_verify(_b(inputs["key_hex"]), _b(inputs["packet_hex"]))

    if op == "onion_encrypt":
        keys = [_b(x) for x in inputs["keys_hex"]]
        nonces = [_b(x) for x in inputs["nonces_hex"]]
        return mixnet.onion_encrypt(_b(inputs["plaintext_hex"]), keys, nonces)

    if op == "peel_all":
        keys = [_b(x) for x in inputs["keys_hex"]]
        packet = _b(inputs["packet_hex"])
        cur = packet
        for k in keys:
            cur = mixnet.peel_one_layer(cur, k)
        return cur

    if op == "mix_round":
        packets = [_b(x) for x in inputs["packets_hex"]]
        hop_key = _b(inputs["hop_key_hex"])
        permutation = inputs["permutation"]
        return mixnet.mix_round(packets, hop_key, permutation)

    raise ValueError(f"unknown op: {op}")


def test_vectors():
    path = os.path.join(HERE, "vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        obj = json.load(f)

    assert "source" in obj
    vectors = obj["vectors"]
    assert isinstance(vectors, list)
    assert vectors, "vectors.json must not be empty"

    for vec in vectors:
        out = _dispatch(vec)
        exp = vec["expected"]

        if isinstance(out, bytes):
            assert out.hex() == exp["plaintext_hex"] if "plaintext_hex" in exp else exp["packet_hex"]
        elif isinstance(out, list):
            assert [x.hex() for x in out] == exp["out_packets_hex"]
        else:
            raise AssertionError(f"unexpected output type: {type(out)}")


def test_xor_bytes_roundtrip():
    x = bytes(range(32))
    y = bytes(reversed(range(32)))
    assert mixnet.xor_bytes(mixnet.xor_bytes(x, y), y) == x


def test_encrypt_rejects_bad_nonce_length():
    try:
        mixnet.encrypt_then_mac(b"k" * 32, b"short", b"hi")
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_decrypt_rejects_tamper():
    key = b"k" * 32
    nonce = b"n" * mixnet.NONCE_LEN
    packet = mixnet.encrypt_then_mac(key, nonce, b"payload")
    tampered = packet[:-1] + bytes([packet[-1] ^ 1])
    try:
        mixnet.decrypt_then_verify(key, tampered)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_cell_roundtrip_and_size():
    cell = mixnet.pack_cell("hi")
    assert len(cell) == mixnet.CELL_LEN
    assert mixnet.unpack_cell(cell) == "hi"


def test_apply_permutation_rejects_invalid():
    try:
        mixnet.apply_permutation([b"a", b"b", b"c"], [0, 0, 2])
    except ValueError:
        return
    raise AssertionError("expected ValueError")


if __name__ == "__main__":
    tests = [fn for name, fn in sorted(globals().items()) if name.startswith("test_") and callable(fn)]
    for fn in tests:
        fn()
    print("all tests pass")
