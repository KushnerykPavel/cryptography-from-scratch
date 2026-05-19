import json
import sys
from pathlib import Path

try:
    import pytest  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    pytest = None


THIS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(THIS_DIR.parent / "code"))

import main as hc  # noqa: E402


def _load_vectors() -> dict:
    path = THIS_DIR / "vectors.json"
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _hex_to_bytes(s: str) -> bytes:
    if s == "":
        return b""
    return bytes.fromhex(s)


def _assert_raises(exc_type, fn, /, **kwargs):
    if pytest is not None:
        with pytest.raises(exc_type):
            fn(**kwargs)
        return
    try:
        fn(**kwargs)
    except exc_type:
        return
    except Exception as e:  # noqa: BLE001
        raise AssertionError(f"expected {exc_type.__name__}, got {type(e).__name__}") from e
    raise AssertionError(f"expected {exc_type.__name__} to be raised")


def test_vectors() -> None:
    data = _load_vectors()
    for v in data["vectors"]:
        op = v["op"]
        inputs = v["inputs"]

        if op == "sha256_hex":
            got = hc.sha256_hex(_hex_to_bytes(inputs["data_hex"]))
            assert got == v["expected_hex"]
            continue

        if op == "encode_commit_input_hex":
            got = hc.encode_commit_input(
                message=_hex_to_bytes(inputs["message_hex"]),
                nonce=_hex_to_bytes(inputs["nonce_hex"]),
            )
            assert got.hex() == v["expected_hex"]
            continue

        if op == "commit_hex":
            got = hc.commit(
                message=_hex_to_bytes(inputs["message_hex"]),
                nonce=_hex_to_bytes(inputs["nonce_hex"]),
            )
            assert got == v["expected_hex"]
            continue

        if op == "naive_commit_hex":
            got = hc.naive_commit(
                message=_hex_to_bytes(inputs["message_hex"]),
                nonce=_hex_to_bytes(inputs["nonce_hex"]),
            )
            assert got == v["expected_hex"]
            continue

        if op == "verify_bool":
            got = hc.verify(
                commitment_hex=inputs["commitment_hex"],
                message=_hex_to_bytes(inputs["message_hex"]),
                nonce=_hex_to_bytes(inputs["nonce_hex"]),
            )
            assert got == v["expected"]
            continue

        raise AssertionError(f"unknown op: {op}")


def test_commit_is_deterministic() -> None:
    c1 = hc.commit(message=b"m", nonce=b"r")
    c2 = hc.commit(message=b"m", nonce=b"r")
    assert c1 == c2


def test_verify_roundtrip() -> None:
    message = b"hello"
    nonce = b"\x11" * 32
    c = hc.commit(message=message, nonce=nonce)
    assert hc.verify(commitment_hex=c, message=message, nonce=nonce) is True


def test_verify_rejects_invalid_commitment_hex() -> None:
    _assert_raises(ValueError, hc.verify, commitment_hex="00", message=b"a", nonce=b"b")
    _assert_raises(ValueError, hc.verify, commitment_hex="x" * 64, message=b"a", nonce=b"b")
    _assert_raises(TypeError, hc.verify, commitment_hex=None, message=b"a", nonce=b"b")  # type: ignore[arg-type]


def test_hiding_requires_nonce_for_small_message_space() -> None:
    candidates = [b"red", b"green", b"blue", b"yellow"]
    target = b"green"
    c = hc.sha256_hex(target)
    guessed = next((m for m in candidates if hc.sha256_hex(m) == c), None)
    assert guessed == target


def test_naive_concat_has_ambiguous_openings() -> None:
    c1 = hc.naive_commit(message=b"a", nonce=b"bc")
    c2 = hc.naive_commit(message=b"ab", nonce=b"c")
    assert c1 == c2

    safe1 = hc.commit(message=b"a", nonce=b"bc")
    safe2 = hc.commit(message=b"ab", nonce=b"c")
    assert safe1 != safe2


def test_type_checks() -> None:
    _assert_raises(TypeError, hc.commit, message="m", nonce=b"r")  # type: ignore[arg-type]
    _assert_raises(TypeError, hc.commit, message=b"m", nonce="r")  # type: ignore[arg-type]


if __name__ == "__main__":
    if pytest is not None:
        raise SystemExit(pytest.main([__file__]))

    tests = [v for k, v in globals().items() if k.startswith("test_") and callable(v)]
    for t in sorted(tests, key=lambda f: f.__name__):
        t()
    print("all tests pass")

