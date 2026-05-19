import json
import math
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (  # noqa: E402
    GroupParams,
    SimulationResult,
    Transcript,
    real_transcript,
    run_simulation_experiment,
    simulated_transcript,
    transcript_advantage,
)

_GROUP = GroupParams(p=23, g=5)
_PK = _GROUP.keygen(3)  # 10


def _run_vector(v, group=_GROUP):
    op = v["op"]
    if op == "keygen":
        return group.keygen(v["secret"])
    if op == "group_exp":
        return group.exp(v["base"], v["exp"])
    if op == "group_inv":
        return group.inv(v["a"])
    if op == "group_mul":
        return group.mul(v["a"], v["b"])
    if op in ("verify_real", "verify_simulated", "verify_bad"):
        t = Transcript(v["R"], v["c"], v["s"])
        return t.verify(v["pk"], group)
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
            assert got == expected, f"vector {v}: got {got!r}, want {expected!r}"


# --- GroupParams ---

def test_group_keygen_identity():
    assert _GROUP.keygen(0) == 1  # g^0 = 1

def test_group_keygen_roundtrip():
    # keygen(a) * keygen(b) == keygen(a+b) in exponent
    g = _GROUP
    for a, b in [(3, 7), (1, 10), (5, 15)]:
        assert g.mul(g.keygen(a), g.keygen(b)) == g.keygen((a + b) % g.order)

def test_group_inv_is_multiplicative_inverse():
    g = _GROUP
    for a in (2, 5, 7, 10, 15, 22):
        assert g.mul(a, g.inv(a)) == 1

def test_group_exp_mod_order():
    g = _GROUP
    assert g.exp(g.g, g.order) == 1  # g^(p-1) = 1 by Fermat

def test_group_params_rejects_bad():
    try:
        GroupParams(p=4, g=2)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for p<5")


# --- Transcript.verify ---

def test_real_transcripts_verify():
    rng = random.Random(1)
    pk = _GROUP.keygen(3)
    for _ in range(20):
        t = real_transcript(3, pk, _GROUP, rng=rng)
        assert t.verify(pk, _GROUP), f"real transcript failed: {t}"

def test_simulated_transcripts_verify():
    rng = random.Random(2)
    pk = _GROUP.keygen(3)
    for _ in range(20):
        t = simulated_transcript(pk, _GROUP, rng=rng)
        assert t.verify(pk, _GROUP), f"simulated transcript failed: {t}"

def test_tampered_transcript_fails():
    pk = _GROUP.keygen(3)
    t = real_transcript(3, pk, _GROUP, rng=random.Random(10))
    bad = Transcript(t.commitment, t.challenge, (t.response + 1) % _GROUP.order)
    assert not bad.verify(pk, _GROUP)

def test_wrong_pk_fails():
    pk = _GROUP.keygen(3)
    wrong_pk = _GROUP.keygen(4)
    t = real_transcript(3, pk, _GROUP, rng=random.Random(11))
    assert not t.verify(wrong_pk, _GROUP)


# --- Special soundness (knowledge extractor) ---

def test_special_soundness_extracts_secret():
    group = _GROUP
    secret = 3
    pk = group.keygen(secret)
    rng = random.Random(42)

    # Generate two real transcripts with the same commitment R
    r = 7
    R = group.exp(group.g, r)
    c1, c2 = 4, 9
    s1 = (r + c1 * secret) % group.order
    s2 = (r + c2 * secret) % group.order
    t1 = Transcript(R, c1, s1)
    t2 = Transcript(R, c2, s2)
    assert t1.verify(pk, group)
    assert t2.verify(pk, group)
    assert c1 != c2

    # Extract: x = (s1 - s2) * (c1 - c2)^{-1} mod order
    # Note: inverse is mod order (22), not mod p (23) — group.inv uses Fermat mod p
    diff_s = (s1 - s2) % group.order
    diff_c = (c1 - c2) % group.order
    extracted = (diff_s * pow(diff_c, -1, group.order)) % group.order
    assert extracted == secret, f"extracted {extracted} != {secret}"


# --- transcript_advantage ---

def test_advantage_identical_distributions():
    pk = _GROUP.keygen(3)
    rng = random.Random(5)
    reals = [real_transcript(3, pk, _GROUP, rng=rng) for _ in range(2000)]
    sims = [simulated_transcript(pk, _GROUP, rng=rng) for _ in range(2000)]
    # A distinguisher that only reads (R, c, s) cannot have large advantage
    adv = transcript_advantage(lambda t: t.commitment % 2, reals, sims)
    assert adv < 0.1, f"parity distinguisher has suspiciously high adv={adv}"

def test_advantage_cheating_distinguisher():
    pk = _GROUP.keygen(3)
    rng = random.Random(6)
    reals = [real_transcript(3, pk, _GROUP, rng=rng) for _ in range(1000)]
    sims = [simulated_transcript(pk, _GROUP, rng=rng) for _ in range(1000)]
    # Cheater reads the .simulated flag — this is not a valid distinguisher
    adv = transcript_advantage(lambda t: 1 if t.simulated else 0, reals, sims)
    assert math.isclose(adv, 1.0, abs_tol=0.05)

def test_advantage_rejects_empty_lists():
    try:
        transcript_advantage(lambda t: 0, [], [Transcript(1, 1, 1)])
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for empty real list")


# --- run_simulation_experiment ---

def test_simulation_experiment_succeeds():
    result = run_simulation_experiment(
        _GROUP, 3, 3000,
        lambda t: t.commitment % 2,
        rng=random.Random(99),
    )
    assert result.real_verify_rate == 1.0
    assert result.sim_verify_rate == 1.0
    assert result.distinguisher_advantage < 0.1
    assert result.simulation_succeeds

def test_simulation_result_fields():
    result = run_simulation_experiment(
        _GROUP, 5, 500,
        lambda t: 0,
        rng=random.Random(7),
    )
    assert result.n_real == 500
    assert result.n_simulated == 500
    assert 0.0 <= result.distinguisher_advantage <= 1.0


if __name__ == "__main__":
    test_vectors()
    test_group_keygen_identity()
    test_group_keygen_roundtrip()
    test_group_inv_is_multiplicative_inverse()
    test_group_exp_mod_order()
    test_group_params_rejects_bad()
    test_real_transcripts_verify()
    test_simulated_transcripts_verify()
    test_tampered_transcript_fails()
    test_wrong_pk_fails()
    test_special_soundness_extracts_secret()
    test_advantage_identical_distributions()
    test_advantage_cheating_distinguisher()
    test_advantage_rejects_empty_lists()
    test_simulation_experiment_succeeds()
    test_simulation_result_fields()
    print("all tests pass")
