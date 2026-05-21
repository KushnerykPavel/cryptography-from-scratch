import json
import sys
from pathlib import Path

try:
    import pytest  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    pytest = None


THIS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(THIS_DIR.parent / "code"))

import main as lamport  # noqa: E402


def _load_vectors() -> dict:
    path = THIS_DIR / "vectors.json"
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _hex_to_bytes(s: str) -> bytes:
    if s == "":
        return b""
    return bytes.fromhex(s)


def _assert_raises(exc_type, fn, /, *args, **kwargs):
    if pytest is not None:
        with pytest.raises(exc_type):
            fn(*args, **kwargs)
        return
    try:
        fn(*args, **kwargs)
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
            got = lamport.sha256_hex(_hex_to_bytes(inputs["data_hex"]))
            assert got == v["expected_hex"]
            continue

        if op == "bits_msb_prefix":
            digest = _hex_to_bytes(inputs["data_hex"])
            bits = lamport.bits_msb(digest)
            n = int(inputs["prefix_bits"])
            got = "".join(str(b) for b in bits[:n])
            assert got == v["expected"]
            continue

        if op == "lamport_keygen_fingerprint_public":
            seed = _hex_to_bytes(inputs["seed_hex"])
            _, pk = lamport.lamport_keygen(seed=seed)
            got = lamport.lamport_fingerprint_public(pk)
            assert got == v["expected_hex"]
            continue

        if op == "lamport_sign_fingerprint_signature":
            seed = _hex_to_bytes(inputs["seed_hex"])
            message = _hex_to_bytes(inputs["message_hex"])
            sk, pk = lamport.lamport_keygen(seed=seed)
            sig = lamport.lamport_sign(message, sk)
            assert lamport.lamport_verify(message, sig, pk) is True
            assert lamport.lamport_fingerprint_signature(sig) == v["expected"]["sig_fingerprint_hex"]
            assert sig[0].hex() == v["expected"]["sig0_hex"]
            continue

        if op == "lamport_verify_bool":
            seed = _hex_to_bytes(inputs["seed_hex"])
            message = _hex_to_bytes(inputs["message_hex"])
            verify_message = _hex_to_bytes(inputs["verify_message_hex"])
            sk, pk = lamport.lamport_keygen(seed=seed)
            sig = lamport.lamport_sign(message, sk)
            got = lamport.lamport_verify(verify_message, sig, pk)
            assert got == v["expected"]
            continue

        if op == "lamport_reuse_leakage":
            seed = _hex_to_bytes(inputs["seed_hex"])
            messages = [_hex_to_bytes(x) for x in inputs["messages_hex"]]
            sk, _ = lamport.lamport_keygen(seed=seed)
            got = lamport.lamport_reuse_leakage(messages, sk)
            assert got == v["expected"]
            continue

        raise AssertionError(f"unknown op: {op}")


def test_verify_roundtrip() -> None:
    sk, pk = lamport.lamport_keygen()
    msg = b"hello"
    sig = lamport.lamport_sign(msg, sk)
    assert lamport.lamport_verify(msg, sig, pk) is True


def test_verify_rejects_message_tampering() -> None:
    sk, pk = lamport.lamport_keygen()
    msg = b"hello"
    sig = lamport.lamport_sign(msg, sk)
    assert lamport.lamport_verify(msg + b"!", sig, pk) is False


def test_keygen_is_deterministic_with_seed() -> None:
    seed = b"seed"
    _, pk1 = lamport.lamport_keygen(seed=seed)
    _, pk2 = lamport.lamport_keygen(seed=seed)
    assert lamport.lamport_fingerprint_public(pk1) == lamport.lamport_fingerprint_public(pk2)


def test_verify_rejects_wrong_signature_shape() -> None:
    sk, pk = lamport.lamport_keygen()
    msg = b"hello"
    sig = lamport.lamport_sign(msg, sk)

    assert lamport.lamport_verify(msg, sig[:-1], pk) is False
    assert lamport.lamport_verify(msg, sig + [sig[-1]], pk) is False
    assert lamport.lamport_verify(msg, [b"x"] * lamport.N_BITS, pk) is False


def test_type_checks() -> None:
    sk, pk = lamport.lamport_keygen(seed=b"seed")
    sig = lamport.lamport_sign(b"m", sk)

    _assert_raises(TypeError, lamport.lamport_sign, "m", sk)  # type: ignore[arg-type]
    _assert_raises(TypeError, lamport.lamport_sign, b"m", None)  # type: ignore[arg-type]
    _assert_raises(TypeError, lamport.lamport_verify, b"m", sig, None)  # type: ignore[arg-type]


if __name__ == "__main__":
    if pytest is not None:
        raise SystemExit(pytest.main([__file__]))

    tests = [v for k, v in globals().items() if k.startswith("test_") and callable(v)]
    for t in sorted(tests, key=lambda f: f.__name__):
        t()
    print("all tests pass")

