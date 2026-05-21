import json
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
CODE_DIR = (HERE / ".." / "code").resolve()
sys.path.insert(0, str(CODE_DIR))

import main as wots  # noqa: E402


def _load_vectors() -> dict:
    path = HERE / "vectors.json"
    return json.loads(path.read_text())


def _unhex(s: str) -> bytes:
    return bytes.fromhex(s)


def _fingerprint(parts: list[bytes]) -> str:
    return wots.sha256(b"".join(parts)).hex()


def _run_vector(v: dict) -> None:
    op = v["op"]
    inputs = v["inputs"]
    expected = v["expected"]

    if op == "params":
        p = wots.wots_params(inputs["n"], inputs["w"])
        got = {"len_1": p.len_1, "len_2": p.len_2, "len": p.length, "lg_w": p.lg_w}
        assert got == expected
        return

    if op == "base_w":
        got = wots.base_w(_unhex(inputs["data"]), inputs["w"], inputs["out_len"])
        assert got == expected
        return

    if op == "chain":
        got = wots.chain(_unhex(inputs["x"]), inputs["steps"]).hex()
        assert got == expected
        return

    if op == "message_digits":
        got = wots.wots_message_digits(_unhex(inputs["message"]), inputs["n"], inputs["w"])
        assert got == expected
        return

    if op == "sk_fingerprint":
        sk = wots.wots_private_key_from_seed(_unhex(inputs["sk_seed"]), inputs["n"], inputs["w"])
        assert _fingerprint(sk) == expected
        return

    if op == "pk_fingerprint":
        sk = wots.wots_private_key_from_seed(_unhex(inputs["sk_seed"]), inputs["n"], inputs["w"])
        pk = wots.wots_public_key_from_private(sk, inputs["n"], inputs["w"])
        assert _fingerprint(pk) == expected
        return

    if op == "sig_fingerprint":
        sig = wots.wots_sign(_unhex(inputs["message"]), _unhex(inputs["sk_seed"]), inputs["n"], inputs["w"])
        assert _fingerprint(sig) == expected
        return

    if op == "verify":
        n = inputs["n"]
        w = inputs["w"]
        seed = _unhex(inputs["sk_seed"])
        signed_msg = _unhex(inputs["signed_message"])
        verify_msg = _unhex(inputs["verify_message"])
        sk = wots.wots_private_key_from_seed(seed, n, w)
        pk = wots.wots_public_key_from_private(sk, n, w)
        sig = wots.wots_sign(signed_msg, seed, n, w)
        assert wots.wots_verify(sig, verify_msg, pk, n, w) is expected
        return

    raise ValueError(f"unknown op: {op}")


def test_vectors() -> None:
    doc = _load_vectors()
    for v in doc["vectors"]:
        _run_vector(v)


def test_chain_composition() -> None:
    x = bytes.fromhex("ab" * 32)
    a = 7
    b = 13
    assert wots.chain(x, a + b) == wots.chain(wots.chain(x, a), b)


def test_public_key_from_signature_roundtrip() -> None:
    msg = b"hello"
    seed = bytes.fromhex("22" * 32)
    n = 32
    w = 16
    sk = wots.wots_private_key_from_seed(seed, n, w)
    pk = wots.wots_public_key_from_private(sk, n, w)
    sig = wots.wots_sign(msg, seed, n, w)
    derived = wots.wots_public_key_from_signature(sig, msg, n, w)
    assert derived == pk


def test_reject_bad_lengths() -> None:
    msg = b"length checks"
    seed = bytes.fromhex("33" * 32)
    n = 32
    w = 16
    sk = wots.wots_private_key_from_seed(seed, n, w)
    pk = wots.wots_public_key_from_private(sk, n, w)
    sig = wots.wots_sign(msg, seed, n, w)

    try:
        wots.wots_public_key_from_signature(sig[:-1], msg, n, w)
        raise AssertionError("expected ValueError for wrong signature length")
    except ValueError:
        pass

    try:
        wots.wots_verify(sig, msg, pk[:-1], n, w)
        raise AssertionError("expected ValueError for wrong public key length")
    except ValueError:
        pass

    try:
        wots.wots_private_key_from_seed(b"short", n, w)
        raise AssertionError("expected ValueError for short seed")
    except ValueError:
        pass


def test_base_w_rejects_out_len() -> None:
    x = bytes.fromhex("1234")
    try:
        wots.base_w(x, 16, 5)
        raise AssertionError("expected ValueError for out_len too large")
    except ValueError:
        pass


def _run_all_tests() -> None:
    test_vectors()
    test_chain_composition()
    test_public_key_from_signature_roundtrip()
    test_reject_bad_lengths()
    test_base_w_rejects_out_len()


if __name__ == "__main__":
    _run_all_tests()
    print("all tests pass")
