import json
import sys
from pathlib import Path

try:
    import pytest  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    pytest = None


THIS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(THIS_DIR.parent / "code"))

import main as mt  # noqa: E402


def _load_vectors() -> dict:
    path = THIS_DIR / "vectors.json"
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _hex_to_bytes(s: str) -> bytes:
    if s == "":
        return b""
    return bytes.fromhex(s)


def _proof_from_json(items: list[dict]) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    for it in items:
        out.append((it["side"], _hex_to_bytes(it["sibling_hex"])))
    return out


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
            got = mt.sha256_hex(_hex_to_bytes(inputs["data_hex"]))
            assert got == v["expected_hex"]
            continue

        if op == "encode_leaf_value_hex":
            got = mt.encode_leaf_value(value=_hex_to_bytes(inputs["value_hex"]))
            assert got.hex() == v["expected_hex"]
            continue

        if op == "hash_leaf_hex":
            got = mt.hash_leaf(value=_hex_to_bytes(inputs["value_hex"]))
            assert got.hex() == v["expected_hex"]
            continue

        if op == "hash_node_hex":
            got = mt.hash_node(
                left=_hex_to_bytes(inputs["left_hex"]),
                right=_hex_to_bytes(inputs["right_hex"]),
            )
            assert got.hex() == v["expected_hex"]
            continue

        if op == "merkle_root_hex":
            leaves = [_hex_to_bytes(x) for x in inputs["leaves_hex"]]
            got = mt.merkle_root(leaves=leaves)
            assert got.hex() == v["expected_hex"]
            continue

        if op == "merkle_proof":
            leaves = [_hex_to_bytes(x) for x in inputs["leaves_hex"]]
            got = mt.merkle_proof(leaves=leaves, index=inputs["index"])
            got_json = [{"side": side, "sibling_hex": sib.hex()} for side, sib in got]
            assert got_json == v["expected"]
            continue

        if op == "verify_merkle_proof_bool":
            proof = _proof_from_json(inputs["proof"])
            got = mt.verify_merkle_proof(
                leaf_value=_hex_to_bytes(inputs["leaf_hex"]),
                proof=proof,
                root=_hex_to_bytes(inputs["root_hex"]),
            )
            assert got == v["expected"]
            continue

        raise AssertionError(f"unknown op: {op}")


def test_merkle_root_is_deterministic() -> None:
    leaves = [b"a", b"b", b"c"]
    r1 = mt.merkle_root(leaves=leaves)
    r2 = mt.merkle_root(leaves=leaves)
    assert r1 == r2


def test_merkle_root_changes_when_leaf_changes() -> None:
    leaves1 = [b"a", b"b", b"c"]
    leaves2 = [b"a", b"b", b"d"]
    assert mt.merkle_root(leaves=leaves1) != mt.merkle_root(leaves=leaves2)


def test_proof_roundtrip_all_indices() -> None:
    leaves = [b"tx0", b"tx1", b"tx2", b"tx3", b"tx4"]
    root = mt.merkle_root(leaves=leaves)
    for i in range(len(leaves)):
        proof = mt.merkle_proof(leaves=leaves, index=i)
        assert mt.verify_merkle_proof(leaf_value=leaves[i], proof=proof, root=root) is True


def test_empty_leaves_rejected() -> None:
    _assert_raises(ValueError, mt.merkle_root, leaves=[])
    _assert_raises(ValueError, mt.build_merkle_levels, leaves=[])


def test_proof_index_out_of_range_rejected() -> None:
    leaves = [b"a"]
    _assert_raises(ValueError, mt.merkle_proof, leaves=leaves, index=-1)
    _assert_raises(ValueError, mt.merkle_proof, leaves=leaves, index=1)


def test_verify_rejects_invalid_side() -> None:
    leaves = [b"a", b"b"]
    root = mt.merkle_root(leaves=leaves)
    proof = [("up", mt.hash_leaf(value=b"b"))]
    _assert_raises(ValueError, mt.verify_merkle_proof, leaf_value=b"a", proof=proof, root=root)


if __name__ == "__main__":
    if pytest is not None:
        raise SystemExit(pytest.main([__file__]))

    tests = [v for k, v in globals().items() if k.startswith("test_") and callable(v)]
    for t in sorted(tests, key=lambda f: f.__name__):
        t()
    print("all tests pass")

