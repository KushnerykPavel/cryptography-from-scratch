import json
import sys
from pathlib import Path

try:
    import pytest  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    pytest = None


THIS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(THIS_DIR.parent / "code"))

import main as sem  # noqa: E402


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
            got = sem.sha256_hex(_hex_to_bytes(inputs["data_hex"]))
            assert got == v["expected_hex"]
            continue

        if op == "identity_commitment_hex":
            got = sem.identity_commitment(
                trapdoor=_hex_to_bytes(inputs["trapdoor_hex"]),
                nullifier=_hex_to_bytes(inputs["nullifier_hex"]),
            )
            assert got.hex() == v["expected_hex"]
            continue

        if op == "external_nullifier_hash_hex":
            got = sem.external_nullifier_hash(external_nullifier=inputs["external_nullifier"])
            assert got.hex() == v["expected_hex"]
            continue

        if op == "nullifier_hash_hex":
            got = sem.nullifier_hash(
                nullifier=_hex_to_bytes(inputs["nullifier_hex"]),
                external_nullifier=inputs["external_nullifier"],
            )
            assert got.hex() == v["expected_hex"]
            continue

        if op == "signal_hash_hex":
            got = sem.signal_hash(signal=inputs["signal"])
            assert got.hex() == v["expected_hex"]
            continue

        if op == "merkle_root_hex":
            leaves = [_hex_to_bytes(x) for x in inputs["leaves_hex"]]
            got = sem.merkle_root(leaves=leaves)
            assert got.hex() == v["expected_hex"]
            continue

        if op == "merkle_proof":
            leaves = [_hex_to_bytes(x) for x in inputs["leaves_hex"]]
            got = sem.merkle_proof(leaves=leaves, index=inputs["index"])
            got_json = [{"side": side, "sibling_hex": sib.hex()} for side, sib in got]
            assert got_json == v["expected"]
            continue

        if op == "verify_merkle_proof_bool":
            proof = _proof_from_json(inputs["proof"])
            got = sem.verify_merkle_proof(
                leaf_value=_hex_to_bytes(inputs["leaf_hex"]),
                proof=proof,
                root=_hex_to_bytes(inputs["root_hex"]),
            )
            assert got == v["expected"]
            continue

        raise AssertionError(f"unknown op: {op}")


def test_identity_requires_32_byte_secrets() -> None:
    _assert_raises(ValueError, sem.identity_commitment, trapdoor=b"\x00" * 31, nullifier=b"\x00" * 32)
    _assert_raises(ValueError, sem.identity_commitment, trapdoor=b"\x00" * 32, nullifier=b"\x00" * 33)


def test_nullifier_hash_is_scope_bound() -> None:
    nullifier = b"\x11" * 32
    a = sem.nullifier_hash(nullifier=nullifier, external_nullifier="vote:42")
    b = sem.nullifier_hash(nullifier=nullifier, external_nullifier="vote:42")
    c = sem.nullifier_hash(nullifier=nullifier, external_nullifier="vote:99")
    assert a == b
    assert a != c


def test_semaphore_rejects_double_signal_same_scope() -> None:
    identity = sem.make_identity(trapdoor=b"\x22" * 32, nullifier=b"\x33" * 32)
    group = [identity.commitment]
    registry = sem.NullifierRegistry()

    p1 = sem.make_transparent_proof(
        group_identity_commitments=group,
        member_index=0,
        identity=identity,
        external_nullifier="vote:42",
        signal="YES",
    )
    ok1, _ = sem.semaphore_verify_and_record(registry=registry, proof=p1)
    assert ok1 is True

    p2 = sem.make_transparent_proof(
        group_identity_commitments=group,
        member_index=0,
        identity=identity,
        external_nullifier="vote:42",
        signal="NO",
    )
    ok2, reason2 = sem.semaphore_verify_and_record(registry=registry, proof=p2)
    assert ok2 is False
    assert "nullifier already seen" in reason2


def test_semaphore_allows_same_identity_different_scopes() -> None:
    identity = sem.make_identity(trapdoor=b"\x22" * 32, nullifier=b"\x33" * 32)
    group = [identity.commitment]
    registry = sem.NullifierRegistry()

    p1 = sem.make_transparent_proof(
        group_identity_commitments=group,
        member_index=0,
        identity=identity,
        external_nullifier="vote:42",
        signal="YES",
    )
    ok1, _ = sem.semaphore_verify_and_record(registry=registry, proof=p1)
    assert ok1 is True

    p2 = sem.make_transparent_proof(
        group_identity_commitments=group,
        member_index=0,
        identity=identity,
        external_nullifier="vote:99",
        signal="YES",
    )
    ok2, _ = sem.semaphore_verify_and_record(registry=registry, proof=p2)
    assert ok2 is True


def test_make_transparent_proof_rejects_wrong_index() -> None:
    identity = sem.make_identity(trapdoor=b"\xaa" * 32, nullifier=b"\xbb" * 32)
    other = sem.make_identity(trapdoor=b"\xcc" * 32, nullifier=b"\xdd" * 32)
    group = [identity.commitment, other.commitment]

    _assert_raises(
        ValueError,
        sem.make_transparent_proof,
        group_identity_commitments=group,
        member_index=1,
        identity=identity,
        external_nullifier="vote:42",
        signal="YES",
    )


if __name__ == "__main__":
    if pytest is not None:
        raise SystemExit(pytest.main([__file__]))

    tests = [v for k, v in globals().items() if k.startswith("test_") and callable(v)]
    for t in sorted(tests, key=lambda f: f.__name__):
        t()
    print("all tests pass")

