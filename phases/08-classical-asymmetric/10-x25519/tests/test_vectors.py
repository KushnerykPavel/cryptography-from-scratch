import json
import sys
from pathlib import Path

try:
    import pytest  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    pytest = None


THIS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(THIS_DIR.parent / "code"))

import main as x  # noqa: E402


def _load_vectors() -> dict:
    path = THIS_DIR / "vectors.json"
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _hex_to_bytes(s: str) -> bytes:
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

        if op == "clamp_scalar_hex":
            got = x.clamp_scalar(_hex_to_bytes(inputs["scalar_hex"]))
            assert got.hex() == v["expected_hex"]
            continue

        if op == "x25519":
            got = x.x25519(_hex_to_bytes(inputs["scalar_hex"]), _hex_to_bytes(inputs["u_hex"]))
            assert got.hex() == v["expected_hex"]
            continue

        if op == "x25519_base":
            got = x.x25519_base(_hex_to_bytes(inputs["scalar_hex"]))
            assert got.hex() == v["expected_hex"]
            continue

        if op == "x25519_iterated":
            got = x.x25519_iterated(
                iterations=inputs["iterations"],
                k=_hex_to_bytes(inputs["k_hex"]),
                u=_hex_to_bytes(inputs["u_hex"]),
            )
            assert got.hex() == v["expected_hex"]
            continue

        raise AssertionError(f"unknown op: {op}")


def test_ecdh_commutes_deterministic() -> None:
    import random

    rng = random.Random(0)
    for _ in range(20):
        a = rng.randbytes(32)
        b = rng.randbytes(32)
        A = x.x25519_base(a)
        B = x.x25519_base(b)
        s1 = x.x25519(a, B)
        s2 = x.x25519(b, A)
        assert s1 == s2


def test_is_all_zero() -> None:
    assert x.is_all_zero(b"\x00" * 32)
    assert not x.is_all_zero(b"\x00" * 31 + b"\x01")


def test_rejects_bad_lengths() -> None:
    _assert_raises(ValueError, x.clamp_scalar, scalar=b"\x00" * 31)
    _assert_raises(ValueError, x.decode_u_coordinate, u=b"\x00" * 31)
    _assert_raises(ValueError, x.x25519, scalar=b"\x00" * 31, u_coordinate=b"\x00" * 32)
    _assert_raises(ValueError, x.x25519, scalar=b"\x00" * 32, u_coordinate=b"\x00" * 31)
    _assert_raises(ValueError, x.x25519_iterated, iterations=1, k=b"\x00" * 31, u=b"\x00" * 32)
    _assert_raises(ValueError, x.x25519_iterated, iterations=1, k=b"\x00" * 32, u=b"\x00" * 31)


def test_ecdh_all_zero_is_rejected() -> None:
    sk = bytes.fromhex(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    )
    _assert_raises(ValueError, x.ecdh_shared_secret, private_scalar=sk, peer_public_key=b"\x00" * 32)


def test_hkdf_rejects_bad_length() -> None:
    _assert_raises(ValueError, x.hkdf_sha256, ikm=b"a", salt=b"b", info=b"c", length=0)


if __name__ == "__main__":
    if pytest is not None:
        raise SystemExit(pytest.main([__file__]))

    tests = [v for k, v in globals().items() if k.startswith("test_") and callable(v)]
    for t in sorted(tests, key=lambda f: f.__name__):
        t()
    print("all tests pass")

