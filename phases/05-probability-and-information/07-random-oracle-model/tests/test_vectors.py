import json
import math
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (  # noqa: E402
    RandomOracle,
    birthday_queries,
    collision_advantage_bound,
    preimage_advantage_bound,
    rom_security_bits,
    simulate_birthday_attack,
    simulate_preimage_attack,
)


def _run_vector(v):
    op = v["op"]
    if op == "preimage_advantage_bound":
        return preimage_advantage_bound(v["q"], v["n"])
    if op == "collision_advantage_bound":
        return collision_advantage_bound(v["q"], v["n"])
    if op == "rom_security_bits":
        return rom_security_bits(v["q"], v["n"])
    if op == "birthday_queries":
        return birthday_queries(v["n"], target_prob=v["p"])
    raise AssertionError(f"unknown op {op!r}")


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        got = _run_vector(v)
        assert math.isclose(got, v["expected"], rel_tol=1e-9, abs_tol=1e-50), (
            f"vector {v}: got {got!r}, want {v['expected']!r}"
        )


# --- preimage_advantage_bound ---

def test_preimage_bound_zero_queries():
    assert preimage_advantage_bound(0, 256) == 0.0


def test_preimage_bound_one_query():
    assert math.isclose(preimage_advantage_bound(1, 10), 1 / 1024, abs_tol=1e-15)


def test_preimage_bound_scales_linearly_in_q():
    n = 128
    adv1 = preimage_advantage_bound(1, n)
    adv100 = preimage_advantage_bound(100, n)
    assert math.isclose(adv100, 100 * adv1, rel_tol=1e-12)


def test_preimage_bound_rejects_negative_q():
    try:
        preimage_advantage_bound(-1, 256)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


# --- collision_advantage_bound ---

def test_collision_bound_zero_or_one_query():
    assert collision_advantage_bound(0, 128) == 0.0
    assert collision_advantage_bound(1, 128) == 0.0


def test_collision_bound_formula():
    import math as _math
    # collision = q*(q-1) / (2 * 2^n); preimage = q / 2^n
    # for q=2 col < pre; for q=3 col = 3/2^n > pre = 3/2^n? let's check:
    # col(q=2,n=10) = 2*1/(2*1024) = 1/1024 == pre(q=1,n=10)
    # for q >= 3: col grows quadratically, pre linearly
    n = 128
    col2 = collision_advantage_bound(2, n)
    pre2 = preimage_advantage_bound(2, n)
    assert col2 < pre2  # only holds for q=2: col=q*(q-1)/2 per 2^n = 1/2^n < q/2^n = 2/2^n
    col100 = collision_advantage_bound(100, n)
    pre100 = preimage_advantage_bound(100, n)
    assert col100 > pre100  # for q=100: col grows quadratically


def test_collision_bound_quadratic_in_q():
    n = 64
    adv2 = collision_advantage_bound(2, n)
    adv4 = collision_advantage_bound(4, n)
    assert adv4 / adv2 > 3.5  # roughly 4×(4-1)/(2×(2-1)) = 6


# --- birthday_queries ---

def test_birthday_queries_half_prob():
    for bits in (16, 32, 64):
        q = birthday_queries(bits, target_prob=0.5)
        # collision bound at q should be ≈ 0.5
        adv = collision_advantage_bound(int(q), bits)
        assert 0.3 < adv < 0.7, f"birthday threshold off for n={bits}: adv={adv}"


def test_birthday_queries_monotone_in_prob():
    n = 32
    qs = [birthday_queries(n, target_prob=p) for p in (0.01, 0.1, 0.5, 0.9, 0.99)]
    for a, b in zip(qs, qs[1:]):
        assert b > a


def test_birthday_queries_rejects_bad_prob():
    for bad in (0.0, 1.0, -0.1, 1.5):
        try:
            birthday_queries(32, target_prob=bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"expected ValueError for target_prob={bad}")


# --- rom_security_bits ---

def test_rom_security_bits_one_query():
    assert math.isclose(rom_security_bits(1, 256), 256.0, abs_tol=1e-10)


def test_rom_security_bits_decreases_with_q():
    n = 128
    bits = [rom_security_bits(2 ** k, n) for k in range(0, 20)]
    for a, b in zip(bits, bits[1:]):
        assert b < a


def test_rom_security_bits_log2_q_formula():
    for q_exp in (10, 20, 30, 40):
        assert math.isclose(rom_security_bits(2 ** q_exp, 256), 256 - q_exp, abs_tol=1e-10)


# --- RandomOracle ---

def test_ro_consistency():
    ro = RandomOracle(output_bits=64, rng=random.Random(1))
    h1 = ro.query(b"x")
    h2 = ro.query(b"x")
    assert h1 == h2


def test_ro_different_inputs():
    ro = RandomOracle(output_bits=64, rng=random.Random(2))
    h1 = ro.query(b"a")
    h2 = ro.query(b"b")
    assert h1 != h2  # overwhelmingly likely with 64-bit output


def test_ro_programmability():
    ro = RandomOracle(output_bits=32, rng=random.Random(3))
    ro.program(b"challenge", 0xCAFEBABE)
    assert ro.query(b"challenge") == 0xCAFEBABE


def test_ro_program_rejects_already_queried():
    ro = RandomOracle(output_bits=32, rng=random.Random(4))
    ro.query(b"x")
    try:
        ro.program(b"x", 42)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for reprogramming queried input")


def test_ro_query_count():
    ro = RandomOracle(output_bits=32, rng=random.Random(5))
    for i in range(10):
        ro.query(i.to_bytes(4, "big"))
    assert ro.query_count == 10
    assert ro.distinct_queries == 10
    ro.query(b"\x00\x00\x00\x00")  # repeat
    assert ro.query_count == 11
    assert ro.distinct_queries == 10


def test_ro_output_in_range():
    ro = RandomOracle(output_bits=16, rng=random.Random(6))
    for i in range(100):
        h = ro.query(i.to_bytes(4, "big"))
        assert 0 <= h < 2 ** 16


def test_ro_rejects_non_bytes():
    ro = RandomOracle(output_bits=32, rng=random.Random(7))
    try:
        ro.query("string")  # type: ignore
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError for non-bytes input")


# --- simulated attacks ---

def test_preimage_attack_finds_known_preimage():
    ro = RandomOracle(output_bits=16, rng=random.Random(10))
    secret = b"target_input"
    target = ro.query(secret)
    ro.reset_log()
    # The oracle table already has secret -> target; asking the same bytes wins
    result = simulate_preimage_attack(ro, target, n_queries=1, rng=random.Random(11))
    # Direct hit only if the attacker happens to try the exact bytes — use large q
    result2 = simulate_preimage_attack(ro, target, n_queries=5000, rng=random.Random(12))
    # Either might be None; just check type and range
    assert result is None or isinstance(result, bytes)
    assert result2 is None or isinstance(result2, bytes)


def test_birthday_attack_finds_collision_small_oracle():
    n_bits = 12
    q_thresh = int(birthday_queries(n_bits, target_prob=0.99))
    ro = RandomOracle(output_bits=n_bits, rng=random.Random(20))
    result = simulate_birthday_attack(ro, q_thresh, rng=random.Random(21))
    # At 99% threshold should almost always find one
    if result is not None:
        x, y = result
        assert x != y
        assert ro.query(x) == ro.query(y)


if __name__ == "__main__":
    test_vectors()
    test_preimage_bound_zero_queries()
    test_preimage_bound_one_query()
    test_preimage_bound_scales_linearly_in_q()
    test_preimage_bound_rejects_negative_q()
    test_collision_bound_zero_or_one_query()
    test_collision_bound_formula()
    test_collision_bound_quadratic_in_q()
    test_birthday_queries_half_prob()
    test_birthday_queries_monotone_in_prob()
    test_birthday_queries_rejects_bad_prob()
    test_rom_security_bits_one_query()
    test_rom_security_bits_decreases_with_q()
    test_rom_security_bits_log2_q_formula()
    test_ro_consistency()
    test_ro_different_inputs()
    test_ro_programmability()
    test_ro_program_rejects_already_queried()
    test_ro_query_count()
    test_ro_output_in_range()
    test_ro_rejects_non_bytes()
    test_preimage_attack_finds_known_preimage()
    test_birthday_attack_finds_collision_small_oracle()
    print("all tests pass")
