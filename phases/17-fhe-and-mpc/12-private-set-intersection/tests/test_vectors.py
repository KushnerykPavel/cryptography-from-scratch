import json
import math
import sys
from pathlib import Path

try:
    import pytest  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    pytest = None


THIS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(THIS_DIR.parent / "code"))

import main as psi  # noqa: E402


def _load_vectors() -> dict:
    path = THIS_DIR / "vectors.json"
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _to_int(x) -> int:
    if isinstance(x, int):
        return x
    if isinstance(x, str):
        return int(x, 10)
    raise TypeError(f"expected int or decimal string, got {type(x).__name__}")


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

        if op == "hash_to_group_elem":
            got = psi.hash_to_group_elem(item=inputs["item"], p=_to_int(inputs["p"]))
            assert got == _to_int(v["expected"])
            continue

        if op == "modinv":
            got = psi.modinv(a=_to_int(inputs["a"]), m=_to_int(inputs["m"]))
            assert got == _to_int(v["expected"])
            continue

        if op == "commutative_enc":
            got = psi.commutative_enc(m=_to_int(inputs["m"]), e=_to_int(inputs["e"]), p=_to_int(inputs["p"]))
            assert got == _to_int(v["expected"])
            continue

        if op == "commutative_remove_layer":
            got = psi.commutative_remove_layer(c=_to_int(inputs["c"]), e=_to_int(inputs["e"]), p=_to_int(inputs["p"]))
            assert got == _to_int(v["expected"])
            continue

        if op == "psi_reveal_intersection":
            got = psi.psi_intersection(
                client_items=inputs["client_items"],
                server_items=inputs["server_items"],
                p=_to_int(inputs["p"]),
                a=_to_int(inputs["a"]),
                b=_to_int(inputs["b"]),
                reveal_intersection=True,
            )
            assert got == v["expected"]
            continue

        if op == "psi_cardinality":
            got = psi.psi_intersection(
                client_items=inputs["client_items"],
                server_items=inputs["server_items"],
                p=_to_int(inputs["p"]),
                a=_to_int(inputs["a"]),
                b=_to_int(inputs["b"]),
                reveal_intersection=False,
            )
            assert got == _to_int(v["expected"])
            continue

        if op == "bloom_indices":
            got = psi.bloom_indices(
                key=bytes.fromhex(inputs["key_hex"]),
                m_bits=_to_int(inputs["m_bits"]),
                k_hashes=_to_int(inputs["k_hashes"]),
            )
            assert got == v["expected"]
            continue

        raise AssertionError(f"unknown op: {op}")


def test_hash_to_group_elem_range() -> None:
    p = psi.DEFAULT_P
    x = psi.hash_to_group_elem(item="test@example.com", p=p)
    assert 2 <= x <= p - 2


def test_modinv_roundtrip() -> None:
    m = 101
    for a in [2, 3, 5, 17, 99]:
        inv = psi.modinv(a=a, m=m)
        assert (a * inv) % m == 1


def test_remove_layer_roundtrip_when_invertible() -> None:
    p = psi.DEFAULT_P
    phi = p - 1
    a = psi.choose_coprime_exponent(phi=phi, seed=42)
    inv_a = psi.modinv(a=a, m=phi)
    for item in ["a", "b", "c", "d"]:
        m = psi.hash_to_group_elem(item=item, p=p)
        c = psi.commutative_enc(m=m, e=a, p=p)
        m2 = pow(c, inv_a, p)
        assert m2 == m


def test_psi_matches_plain_intersection() -> None:
    client = ["alice", "bob", "bob", "carol", "dave"]
    server = ["bob", "dave", "erin", "bob"]
    got = psi.psi_intersection(
        client_items=client,
        server_items=server,
        p=psi.DEFAULT_P,
        a=psi.choose_coprime_exponent(phi=psi.DEFAULT_P - 1, seed=1),
        b=psi.choose_coprime_exponent(phi=psi.DEFAULT_P - 1, seed=2),
        reveal_intersection=True,
    )
    assert got == ["bob", "dave"]


def test_bloom_has_no_false_negatives_for_inserted_keys() -> None:
    keys = [b"a", b"b", b"c", b"d"]
    bf = psi.bloom_build(keys=keys, m_bits=256, k_hashes=3)
    for k in keys:
        assert bf.maybe_contains(k) is True


def test_bloom_rejects_bad_params() -> None:
    _assert_raises(ValueError, psi.bloom_indices, key=b"x", m_bits=0, k_hashes=1)
    _assert_raises(ValueError, psi.bloom_indices, key=b"x", m_bits=8, k_hashes=0)


def test_psi_rejects_non_coprime_exponents() -> None:
    p = psi.DEFAULT_P
    phi = p - 1
    a_bad = 2
    assert math.gcd(a_bad, phi) != 1
    _assert_raises(
        ValueError,
        psi.psi_intersection,
        client_items=["a"],
        server_items=["a"],
        p=p,
        a=a_bad,
        b=psi.choose_coprime_exponent(phi=phi, seed=3),
        reveal_intersection=True,
    )


if __name__ == "__main__":
    tests = [v for k, v in globals().items() if k.startswith("test_") and callable(v)]
    for t in sorted(tests, key=lambda f: f.__name__):
        t()
    print("all tests pass")
