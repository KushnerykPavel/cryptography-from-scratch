import itertools
import json
import random
import sys
from pathlib import Path


HERE = Path(__file__).resolve()
LESSON_DIR = HERE.parent.parent
CODE_DIR = LESSON_DIR / "code"

sys.path.append(str(CODE_DIR))
import main as bgw  # noqa: E402


def _as_shares(obj):
    return [(int(i), int(v)) for i, v in obj]


def _as_json_share_list(shares):
    return [[int(i), int(v)] for i, v in shares]


def _load_vectors():
    path = HERE.parent / "vectors.json"
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _run_vector(vec):
    op = vec["op"]
    inputs = vec["inputs"]
    expected = vec["expected"]

    if op == "mod_inv":
        got = bgw.mod_inv(inputs["a"], inputs["p"])
    elif op == "mod_div":
        got = bgw.mod_div(inputs["a"], inputs["b"], inputs["p"])
    elif op == "poly_eval":
        got = bgw.poly_eval(inputs["coeffs"], inputs["x"], inputs["p"])
    elif op == "lagrange_coeffs_at_zero":
        got = bgw.lagrange_coeffs_at_zero(inputs["xs"], inputs["p"])
    elif op == "shamir_share":
        got = _as_json_share_list(
            bgw.shamir_share(
            inputs["secret"],
            inputs["n"],
            inputs["t"],
            inputs["p"],
            coeffs=inputs["coeffs"],
            )
        )
    elif op == "shamir_reconstruct":
        got = bgw.shamir_reconstruct(_as_shares(inputs["shares"]), inputs["p"])
    elif op == "shamir_add":
        got = _as_json_share_list(
            bgw.shamir_add(_as_shares(inputs["a"]), _as_shares(inputs["b"]), inputs["p"])
        )
    elif op == "shamir_scalar_mul":
        got = _as_json_share_list(
            bgw.shamir_scalar_mul(_as_shares(inputs["shares"]), inputs["k"], inputs["p"])
        )
    elif op == "bgw_multiply_secret":
        rng = random.Random(inputs["seed"])
        out_shares = bgw.bgw_multiply(
            _as_shares(inputs["a"]),
            _as_shares(inputs["b"]),
            t=inputs["t"],
            p=inputs["p"],
            rng=rng,
        )
        got = bgw.shamir_reconstruct(out_shares[: inputs["t"] + 1], inputs["p"])
    else:
        raise ValueError(f"unknown op: {op}")

    assert got == expected, f"{op}: got {got}, expected {expected}"


def test_vectors():
    data = _load_vectors()
    assert "source" in data
    assert isinstance(data["vectors"], list)
    for vec in data["vectors"]:
        _run_vector(vec)


def test_shamir_reconstruct_any_subset():
    p = 2089
    n = 7
    t = 3
    secret = 123
    shares = bgw.shamir_share(secret, n, t, p, coeffs=[secret, 7, 9, 11])
    for subset in itertools.combinations(shares, t + 1):
        assert bgw.shamir_reconstruct(subset, p) == secret % p


def test_bgw_multiply_correctness_many():
    p = 2089
    n = 5
    t = 2
    rng = random.Random(0)
    for _ in range(25):
        a = rng.randrange(0, p)
        b = rng.randrange(0, p)
        ra = random.Random(rng.randrange(0, 1_000_000))
        rb = random.Random(rng.randrange(0, 1_000_000))
        rmult = random.Random(rng.randrange(0, 1_000_000))
        sa = bgw.shamir_share(a, n, t, p, rng=ra)
        sb = bgw.shamir_share(b, n, t, p, rng=rb)
        sab = bgw.bgw_multiply(sa, sb, t=t, p=p, rng=rmult)
        rec = bgw.shamir_reconstruct(sab[: t + 1], p)
        assert rec == (a * b) % p


def test_reject_bad_inputs():
    p = 2089
    try:
        bgw.mod_inv(0, p)
        assert False, "mod_inv(0) should raise"
    except ValueError:
        pass

    try:
        bgw.shamir_share(1, 0, 0, p, coeffs=[1])
        assert False, "n=0 should raise"
    except ValueError:
        pass

    try:
        bgw.shamir_share(1, 3, 3, p, coeffs=[1, 2, 3, 4])
        assert False, "t>=n should raise"
    except ValueError:
        pass

    try:
        bgw.shamir_reconstruct([], p)
        assert False, "empty shares should raise"
    except ValueError:
        pass


if __name__ == "__main__":
    test_vectors()
    test_shamir_reconstruct_any_subset()
    test_bgw_multiply_correctness_many()
    test_reject_bad_inputs()
    print("all tests pass")
