import json
import sys
from fractions import Fraction
from pathlib import Path

try:
    import pytest  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    pytest = None


THIS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(THIS_DIR.parent / "code"))

import main as grover  # noqa: E402


def _load_vectors() -> dict:
    path = THIS_DIR / "vectors.json"
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _as_fraction(x) -> Fraction:
    if isinstance(x, Fraction):
        return x
    if isinstance(x, bool):
        raise TypeError("bool is not a Fraction")
    if isinstance(x, int):
        return Fraction(x, 1)
    if isinstance(x, str):
        s = x.strip()
        if "/" in s:
            a, b = s.split("/", 1)
            return Fraction(int(a.strip()), int(b.strip()))
        return Fraction(int(s), 1)
    raise TypeError(f"unsupported expected type: {type(x).__name__}")


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
        expected = v["expected"]

        if op == "is_power_of_two":
            got = grover.is_power_of_two(inputs["n"])
            assert got is expected
            continue

        if op == "log2_pow2":
            got = grover.log2_pow2(inputs["n"])
            assert got == expected
            continue

        if op == "classical_key_search_log2_work":
            got = grover.classical_key_search_log2_work(**inputs)
            assert got == expected
            continue

        if op == "grover_key_search_log2_work":
            got = grover.grover_key_search_log2_work(**inputs)
            assert got == _as_fraction(expected)
            continue

        if op == "min_key_bits_for_target_under_grover":
            got = grover.min_key_bits_for_target_under_grover(**inputs)
            assert got == expected
            continue

        if op == "recommend_aes_key_bits":
            got = grover.recommend_aes_key_bits(**inputs)
            assert got == expected
            continue

        if op == "hash_preimage_log2_work_classical":
            got = grover.hash_preimage_log2_work_classical(**inputs)
            assert got == expected
            continue

        if op == "hash_preimage_log2_work_grover":
            got = grover.hash_preimage_log2_work_grover(**inputs)
            assert got == _as_fraction(expected)
            continue

        if op == "hash_collision_log2_work_classical":
            got = grover.hash_collision_log2_work_classical(**inputs)
            assert got == _as_fraction(expected)
            continue

        if op == "hash_collision_log2_work_quantum_bht":
            got = grover.hash_collision_log2_work_quantum_bht(**inputs)
            assert got == _as_fraction(expected)
            continue

        raise AssertionError(f"unknown op: {op}")


def test_monotonicity_key_sizes() -> None:
    last = None
    for k in range(32, 257):
        v = grover.grover_key_search_log2_work(key_bits=k, parallelism=1)
        if last is not None:
            assert v >= last
        last = v


def test_recommend_aes_key_bits_is_monotone_in_target() -> None:
    targets = [1, 32, 63, 64, 65, 95, 96, 97, 127, 128]
    recs = [grover.recommend_aes_key_bits(target_security_bits=t) for t in targets]
    assert recs == sorted(recs)


def test_parallelism_must_be_power_of_two() -> None:
    _assert_raises(ValueError, grover.classical_key_search_log2_work, key_bits=128, parallelism=3)
    _assert_raises(ValueError, grover.grover_key_search_log2_work, key_bits=128, parallelism=3)
    _assert_raises(ValueError, grover.hash_preimage_log2_work_classical, output_bits=256, parallelism=3)
    _assert_raises(ValueError, grover.hash_preimage_log2_work_grover, output_bits=256, parallelism=3)


def test_rejects_bad_inputs() -> None:
    _assert_raises(TypeError, grover.is_power_of_two, n="8")  # type: ignore[arg-type]
    _assert_raises(ValueError, grover.log2_pow2, n=0)
    _assert_raises(ValueError, grover.grover_key_search_log2_work, key_bits=0)
    _assert_raises(ValueError, grover.hash_collision_log2_work_classical, output_bits=1)
    _assert_raises(ValueError, grover.hash_collision_log2_work_quantum_bht, output_bits=2)


if __name__ == "__main__":
    if pytest is not None:
        raise SystemExit(pytest.main([__file__]))

    tests = [v for k, v in globals().items() if k.startswith("test_") and callable(v)]
    for t in sorted(tests, key=lambda f: f.__name__):
        t()
    print("all tests pass")

