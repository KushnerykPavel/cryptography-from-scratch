import json
import math
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (  # noqa: E402
    advantage_from_security_bits,
    compose_reductions,
    concrete_security,
    is_negligible_function,
    is_non_negligible_function,
    is_secure,
    reduction_advantage,
    required_primitive_security,
    security_bits,
)


def _run_vector(v):
    op = v["op"]
    if op == "security_bits":
        return security_bits(v["adv"])
    if op == "advantage_from_security_bits":
        return advantage_from_security_bits(v["bits"])
    if op == "reduction_advantage":
        return reduction_advantage(v["adv"], v["loss"])
    if op == "compose_reductions":
        return compose_reductions(v["losses"])
    if op == "concrete_security":
        return concrete_security(v["prim_bits"], v["loss"])
    if op == "required_primitive_security":
        return required_primitive_security(v["target"], v["loss"])
    if op == "is_secure":
        return is_secure(v["adv"], min_security_bits=v["min_bits"])
    raise AssertionError(f"unknown op {op!r}")


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        got = _run_vector(v)
        expected = v["expected"]
        if isinstance(expected, bool):
            assert got == expected, f"vector {v}: got {got!r}, want {expected!r}"
        else:
            assert math.isclose(got, expected, rel_tol=1e-9, abs_tol=1e-12), (
                f"vector {v}: got {got!r}, want {expected!r}"
            )


# --- security_bits / advantage_from_security_bits ---

def test_security_bits_round_trip():
    for bits in (0.0, 1.0, 64.0, 128.0, 256.0):
        assert math.isclose(security_bits(advantage_from_security_bits(bits)), bits, abs_tol=1e-10)


def test_security_bits_rejects_zero_and_negative():
    for bad in (0.0, -0.1):
        try:
            security_bits(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"expected ValueError for adv={bad}")


def test_security_bits_rejects_above_one():
    try:
        security_bits(1.01)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for adv > 1")


# --- reduction_advantage ---

def test_reduction_advantage_tight():
    assert reduction_advantage(0.5, 1.0) == 0.5


def test_reduction_advantage_scales():
    for adv, loss in [(0.1, 5), (0.6, 3), (1.0, 100)]:
        assert math.isclose(reduction_advantage(adv, loss), adv / loss, abs_tol=1e-12)


def test_reduction_advantage_rejects_non_positive_loss():
    try:
        reduction_advantage(0.1, 0.0)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for loss=0")


# --- compose_reductions ---

def test_compose_reductions_empty():
    assert compose_reductions([]) == 1.0


def test_compose_reductions_single():
    assert compose_reductions([7.5]) == 7.5


def test_compose_reductions_multiplicative():
    assert math.isclose(compose_reductions([2, 3, 4]), 24.0, abs_tol=1e-12)


def test_compose_reductions_rejects_non_positive():
    try:
        compose_reductions([2.0, 0.0, 3.0])
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for zero loss")


# --- concrete_security / required_primitive_security ---

def test_concrete_security_tight_is_identity():
    assert math.isclose(concrete_security(128.0, 1.0), 128.0, abs_tol=1e-12)


def test_concrete_security_loss_subtracts_log2():
    assert math.isclose(concrete_security(256.0, 64.0), 250.0, abs_tol=1e-10)


def test_required_primitive_security_tight_is_identity():
    assert math.isclose(required_primitive_security(128.0, 1.0), 128.0, abs_tol=1e-12)


def test_required_primitive_security_adds_log2():
    assert math.isclose(required_primitive_security(128.0, 64.0), 134.0, abs_tol=1e-10)


def test_concrete_and_required_are_inverses():
    for target, loss in [(128.0, 1.0), (128.0, 32.0), (256.0, 1024.0)]:
        needed = required_primitive_security(target, loss)
        achieved = concrete_security(needed, loss)
        assert math.isclose(achieved, target, abs_tol=1e-10)


# --- is_negligible_function / is_non_negligible_function ---

def test_exponential_decay_is_negligible():
    assert is_negligible_function(lambda n: 2.0 ** (-n))


def test_polynomial_inverse_is_not_negligible():
    # d=1,2: caught by default poly_degrees=(1,2,3)
    for d in (1, 2):
        fn = lambda n, d=d: 1.0 / (n ** d)
        assert not is_negligible_function(fn), f"1/n^{d} wrongly classified as negligible"
    # d=100: must supply poly_degrees=(100,) — the default (1,2,3) is a weak check
    # (1/n^100 is below 1/n^3 for n>=10, so the 3-degree witness misses it)
    fn_100 = lambda n: 1.0 / (n ** 100)
    assert not is_negligible_function(fn_100, poly_degrees=(100,))


def test_constant_is_not_negligible():
    assert not is_negligible_function(lambda n: 0.001)


def test_polynomial_inverse_is_non_negligible():
    for d in (1, 2):
        fn = lambda n, d=d: 1.0 / (n ** d)
        assert is_non_negligible_function(fn, test_range=range(10, 101), poly_degree=d)


def test_exponential_is_not_non_negligible():
    fn = lambda n: 2.0 ** (-n)
    assert not is_non_negligible_function(fn, test_range=range(10, 101), poly_degree=1)


# --- is_secure ---

def test_is_secure_128():
    assert is_secure(2.0 ** -128, min_security_bits=128.0) is False  # equal, not strictly less
    assert is_secure(2.0 ** -129, min_security_bits=128.0) is True


def test_is_secure_rejects_large_adv():
    assert not is_secure(0.5, min_security_bits=128.0)


if __name__ == "__main__":
    test_vectors()
    test_security_bits_round_trip()
    test_security_bits_rejects_zero_and_negative()
    test_security_bits_rejects_above_one()
    test_reduction_advantage_tight()
    test_reduction_advantage_scales()
    test_reduction_advantage_rejects_non_positive_loss()
    test_compose_reductions_empty()
    test_compose_reductions_single()
    test_compose_reductions_multiplicative()
    test_compose_reductions_rejects_non_positive()
    test_concrete_security_tight_is_identity()
    test_concrete_security_loss_subtracts_log2()
    test_required_primitive_security_tight_is_identity()
    test_required_primitive_security_adds_log2()
    test_concrete_and_required_are_inverses()
    test_exponential_decay_is_negligible()
    test_polynomial_inverse_is_not_negligible()
    test_constant_is_not_negligible()
    test_polynomial_inverse_is_non_negligible()
    test_exponential_is_not_non_negligible()
    test_is_secure_128()
    test_is_secure_rejects_large_adv()
    print("all tests pass")
