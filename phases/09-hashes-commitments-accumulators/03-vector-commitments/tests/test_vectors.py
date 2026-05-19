import json
import sys
from pathlib import Path

try:
    import pytest  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    pytest = None


THIS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(THIS_DIR.parent / "code"))

import main as vc  # noqa: E402


def _load_vectors() -> dict:
    path = THIS_DIR / "vectors.json"
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


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


def _utf8_list(values: list[str]) -> list[bytes]:
    return [s.encode("utf-8") for s in values]


def _parse_proof(proof_json: list[dict]) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    for step in proof_json:
        out.append((step["side"], bytes.fromhex(step["hash_hex"])))
    return out


def test_vectors() -> None:
    data = _load_vectors()
    for v in data["vectors"]:
        op = v["op"]
        inputs = v["inputs"]

        if op == "leaf_hash":
            got = vc.leaf_hash(inputs["index"], inputs["value_utf8"].encode("utf-8"))
            assert got.hex() == v["expected_hex"]
            continue

        if op == "vector_commit":
            got = vc.vector_commit(_utf8_list(inputs["values_utf8"]))
            assert got.hex() == v["expected_hex"]
            continue

        if op == "vector_open":
            expected = v["expected"]
            values = _utf8_list(inputs["values_utf8"])
            got_root, got_proof = vc.vector_open(values, inputs["index"])
            assert got_root.hex() == expected["root_hex"]
            assert got_proof == _parse_proof(expected["proof"])
            assert expected["n"] == len(values)
            assert expected["value_utf8"].encode("utf-8") == values[inputs["index"]]
            continue

        if op == "vector_verify":
            root = bytes.fromhex(inputs["root_hex"])
            proof = _parse_proof(inputs["proof"])
            got = vc.vector_verify(
                root=root,
                index=inputs["index"],
                value=inputs["value_utf8"].encode("utf-8"),
                proof=proof,
                n=inputs["n"],
            )
            assert got is v["expected_bool"]
            continue

        raise AssertionError(f"unknown op: {op}")


def test_open_verify_roundtrip_deterministic() -> None:
    import random

    rng = random.Random(0)
    for n in range(1, 35):
        values = [rng.randbytes(rng.randrange(0, 20)) for _ in range(n)]
        root = vc.vector_commit(values)
        for _ in range(3):
            i = rng.randrange(0, n)
            root2, proof = vc.vector_open(values, index=i)
            assert root2 == root
            assert vc.vector_verify(root, i, values[i], proof, n)


def test_index_binding_same_value_different_positions() -> None:
    values = [b"x", b"x", b"x"]
    root = vc.vector_commit(values)
    root0, proof0 = vc.vector_open(values, 0)
    assert root0 == root
    assert vc.vector_verify(root, 0, b"x", proof0, 3)
    assert not vc.vector_verify(root, 1, b"x", proof0, 3)


def test_length_binding_wrong_n_fails() -> None:
    values = [b"a", b"b", b"c", b"d", b"e"]
    root, proof = vc.vector_open(values, 2)
    assert vc.vector_verify(root, 2, b"c", proof, 5)
    assert not vc.vector_verify(root, 2, b"c", proof, 4)


def test_rejects_empty_vector() -> None:
    _assert_raises(ValueError, vc.vector_commit, values=[])


def test_rejects_out_of_range_open() -> None:
    _assert_raises(IndexError, vc.vector_open, values=[b"a"], index=1)


def test_rejects_bad_root_length() -> None:
    _assert_raises(ValueError, vc.vector_verify, root=b"\x00" * 31, index=0, value=b"a", proof=[], n=1)


def test_rejects_bad_proof_encoding() -> None:
    root = vc.vector_commit([b"a", b"b"])
    _assert_raises(ValueError, vc.vector_verify, root=root, index=0, value=b"a", proof=[("X", b"\x00" * 32)], n=2)
    _assert_raises(ValueError, vc.vector_verify, root=root, index=0, value=b"a", proof=[("L", b"\x00" * 31)], n=2)


if __name__ == "__main__":
    if pytest is not None:
        raise SystemExit(pytest.main([__file__]))

    tests = [v for k, v in globals().items() if k.startswith("test_") and callable(v)]
    for t in sorted(tests, key=lambda f: f.__name__):
        t()
    print("all tests pass")

