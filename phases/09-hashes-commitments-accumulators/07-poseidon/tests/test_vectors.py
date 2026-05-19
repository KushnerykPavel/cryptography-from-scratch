import json
import sys
from pathlib import Path

try:
    import pytest  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    pytest = None


THIS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(THIS_DIR.parent / "code"))

import main as poseidon  # noqa: E402


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


def test_vectors() -> None:
    data = _load_vectors()
    params = poseidon.poseidon_default_params()

    for v in data["vectors"]:
        op = v["op"]

        if op == "fe_mod":
            got = poseidon.fe(v["x"], v["p"])
            assert got == v["expected"]
            continue

        if op == "fe_inv":
            got = poseidon.fe_inv(v["x"], v["p"])
            assert got == v["expected"]
            continue

        if op == "params_fingerprint":
            exp = v["expected"]
            assert params.p == exp["p"]
            assert params.t == exp["t"]
            assert params.rate == exp["rate"]
            assert params.alpha == exp["alpha"]
            assert params.full_rounds == exp["full_rounds"]
            assert params.partial_rounds == exp["partial_rounds"]
            assert params.mds[0][0] == exp["mds00"]
            assert params.round_constants[0] == exp["rc0"]
            assert params.round_constants[-1] == exp["rc_last"]
            continue

        if op == "poseidon_permute":
            got = poseidon.poseidon_permute(v["state"], params=params)
            assert got == v["expected"]
            continue

        if op == "poseidon_hash_unsafe":
            got = poseidon.poseidon_sponge_hash_unsafe(v["inputs"], params=params, domain=v["domain"])
            assert got == v["expected"]
            continue

        if op == "poseidon_hash":
            got = poseidon.poseidon_sponge_hash(v["inputs"], params=params, domain=v["domain"])
            assert got == v["expected"]
            continue

        raise AssertionError(f"unknown op: {op}")


def test_inv_rejects_zero() -> None:
    _assert_raises(ValueError, poseidon.fe_inv, x=0, p=poseidon.BN254_PRIME)


def test_permute_rejects_wrong_length() -> None:
    params = poseidon.poseidon_default_params()
    _assert_raises(ValueError, poseidon.poseidon_permute, state=[1, 2], params=params)


def test_hash_is_deterministic() -> None:
    params = poseidon.poseidon_default_params()
    h1 = poseidon.poseidon_sponge_hash([1, 2, 3], params=params, domain=0)
    h2 = poseidon.poseidon_sponge_hash([1, 2, 3], params=params, domain=0)
    assert h1 == h2


def test_unsafe_hash_has_trailing_zero_collisions() -> None:
    params = poseidon.poseidon_default_params()
    a = 123
    assert (
        poseidon.poseidon_sponge_hash_unsafe([a], params=params, domain=0)
        == poseidon.poseidon_sponge_hash_unsafe([a, 0], params=params, domain=0)
    )


def test_safe_hash_separates_lengths() -> None:
    params = poseidon.poseidon_default_params()
    a = 123
    assert (
        poseidon.poseidon_sponge_hash([a], params=params, domain=0)
        != poseidon.poseidon_sponge_hash([a, 0], params=params, domain=0)
    )


def test_domain_separation_changes_output() -> None:
    params = poseidon.poseidon_default_params()
    x = [123, 456]
    assert poseidon.poseidon_sponge_hash(x, params=params, domain=0) != poseidon.poseidon_sponge_hash(
        x, params=params, domain=1
    )


def test_type_checks() -> None:
    params = poseidon.poseidon_default_params()
    _assert_raises(TypeError, poseidon.poseidon_sponge_hash, inputs="nope", params=params)  # type: ignore[arg-type]
    _assert_raises(TypeError, poseidon.poseidon_sponge_hash, inputs=[1, "x"], params=params)  # type: ignore[list-item]


if __name__ == "__main__":
    if pytest is not None:
        raise SystemExit(pytest.main([__file__]))

    tests = [v for k, v in globals().items() if k.startswith("test_") and callable(v)]
    for t in sorted(tests, key=lambda f: f.__name__):
        t()
    print("all tests pass")

