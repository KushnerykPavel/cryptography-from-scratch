import json
import sys
from pathlib import Path


LESSON_DIR = Path(__file__).resolve().parents[1]
CODE_DIR = LESSON_DIR / "code"
TESTS_DIR = LESSON_DIR / "tests"

sys.path.insert(0, str(CODE_DIR))

import main as lesson


def _load_vectors() -> list[dict]:
    vectors_path = TESTS_DIR / "vectors.json"
    data = json.loads(vectors_path.read_text(encoding="utf-8"))
    vectors = data.get("vectors")
    if not isinstance(vectors, list):
        raise TypeError("vectors.json must contain a top-level 'vectors' list")
    return vectors


def _call_op(op: str, inputs: dict):
    if op == "clamp_int":
        return lesson.clamp_int(**inputs)
    if op == "hndl_exposure_years":
        return lesson.hndl_exposure_years(**inputs)
    if op == "mosca_margin_years":
        return lesson.mosca_margin_years(**inputs)
    if op == "grover_effective_security_bits":
        return lesson.grover_effective_security_bits(**inputs)
    if op == "is_hybrid_or_pq":
        return lesson.is_hybrid_or_pq(**inputs)
    if op == "is_classical":
        return lesson.is_classical(**inputs)
    if op == "hndl_risk_score":
        use = lesson.CryptoUse(**inputs["use"])
        return lesson.hndl_risk_score(use, inputs["years_to_crqc"])
    raise ValueError(f"unknown op: {op}")


def _assert_raises(exc_type, fn, *args, **kwargs) -> None:
    try:
        fn(*args, **kwargs)
    except exc_type:
        return
    except Exception as exc:
        raise AssertionError(f"expected {exc_type.__name__}, got {type(exc).__name__}") from exc
    raise AssertionError(f"expected {exc_type.__name__} to be raised")


def test_vectors() -> None:
    for idx, vector in enumerate(_load_vectors(), start=1):
        op = vector["op"]
        inputs = vector["inputs"]
        expected = vector["expected"]
        actual = _call_op(op, inputs)
        assert actual == expected, f"vector #{idx} op={op} expected={expected} actual={actual}"


def test_hndl_exposure_years_monotonic() -> None:
    z = 10
    prior = None
    for x in range(0, 41):
        current = lesson.hndl_exposure_years(x, z)
        if prior is not None:
            assert current >= prior
        prior = current


def test_mosca_margin_basic_arithmetic() -> None:
    assert lesson.mosca_margin_years(0, 0, 0) == 0
    assert lesson.mosca_margin_years(5, 3, 10) == -2
    assert lesson.mosca_margin_years(15, 4, 10) == 9


def test_input_rejection() -> None:
    _assert_raises(ValueError, lesson.hndl_exposure_years, -1, 10)
    _assert_raises(ValueError, lesson.hndl_exposure_years, 1, -10)
    _assert_raises(ValueError, lesson.grover_effective_security_bits, -128)
    _assert_raises(ValueError, lesson.clamp_int, 1, 10, 0)
    _assert_raises(TypeError, lesson.is_classical, 123)


def test_prioritize_orders_by_score_then_name() -> None:
    uses = [
        lesson.CryptoUse(
            name="B",
            kind="in_transit",
            key_establishment_mode="classical",
            data_security_life_years=12,
            migration_years=3,
            blast_radius=3,
        ),
        lesson.CryptoUse(
            name="A",
            kind="in_transit",
            key_establishment_mode="classical",
            data_security_life_years=12,
            migration_years=3,
            blast_radius=3,
        ),
        lesson.CryptoUse(
            name="Hybrid",
            kind="in_transit",
            key_establishment_mode="hybrid",
            data_security_life_years=99,
            migration_years=99,
            blast_radius=3,
        ),
    ]
    scored = lesson.prioritize(uses, years_to_crqc=10)
    assert scored[0][0].name == "B"
    assert scored[1][0].name == "A"
    assert scored[2][0].name == "Hybrid"
    assert scored[2][1] == 0


if __name__ == "__main__":
    test_vectors()
    test_hndl_exposure_years_monotonic()
    test_mosca_margin_basic_arithmetic()
    test_input_rejection()
    test_prioritize_orders_by_score_then_name()
    print("all tests pass")
