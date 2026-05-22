import json
import os
import random
import sys


THIS_DIR = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(THIS_DIR, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as beaver  # noqa: E402


def _load_vectors():
    path = os.path.join(THIS_DIR, "vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _run_vector(v):
    op = v["op"]
    if op == "reconstruct":
        got = beaver.reconstruct(v["shares"], v["p"])
        assert got == v["expected"]
        return
    if op == "share_add":
        got = beaver.share_add(v["x_sh"], v["y_sh"], v["p"])
        assert got == v["expected"]
        return
    if op == "share_sub":
        got = beaver.share_sub(v["x_sh"], v["y_sh"], v["p"])
        assert got == v["expected"]
        return
    if op == "beaver_multiply_shares":
        z_sh, d, e = beaver.beaver_multiply_shares(
            v["x_sh"],
            v["y_sh"],
            v["a_sh"],
            v["b_sh"],
            v["c_sh"],
            v["p"],
            dealer_party=v.get("dealer_party", 0),
        )
        exp = v["expected"]
        assert z_sh == exp["z_sh"]
        assert d == exp["d"]
        assert e == exp["e"]
        assert beaver.reconstruct(z_sh, v["p"]) == exp["z_open"]
        return
    raise ValueError(f"unknown op: {op}")


def test_vectors():
    data = _load_vectors()
    vectors = data["vectors"]
    assert isinstance(vectors, list)
    for v in vectors:
        _run_vector(v)


def test_share_secret_roundtrip():
    p = 101
    n = 5
    rng = random.Random(1)
    for x in range(-250, 251, 17):
        shares = beaver.share_secret(x, n, p, rng)
        assert len(shares) == n
        assert beaver.reconstruct(shares, p) == (x % p)


def test_beaver_multiply_correctness_randomized():
    p = 101
    n = 3
    rng = random.Random(2)
    for _ in range(200):
        x = rng.randrange(-1000, 1000)
        y = rng.randrange(-1000, 1000)
        x_sh = beaver.share_secret(x, n, p, rng)
        y_sh = beaver.share_secret(y, n, p, rng)
        a_sh, b_sh, c_sh = beaver.generate_beaver_triple_shares(n, p, rng)
        z_sh, d, e = beaver.beaver_multiply_shares(x_sh, y_sh, a_sh, b_sh, c_sh, p)
        assert 0 <= d < p
        assert 0 <= e < p
        assert beaver.reconstruct(z_sh, p) == ((x % p) * (y % p)) % p


def test_error_rejection():
    p = 101
    try:
        beaver.share_secret(1, 1, p, random.Random(0))
        assert False, "expected ValueError"
    except ValueError:
        pass

    x_sh = [1, 2]
    y_sh = [3, 4, 5]
    try:
        beaver.share_add(x_sh, y_sh, p)
        assert False, "expected ValueError"
    except ValueError:
        pass

    try:
        beaver.beaver_multiply_shares(
            [1, 2], [3, 4], [1, 2], [1, 2], [1, 2], p, dealer_party=2
        )
        assert False, "expected ValueError"
    except ValueError:
        pass


def _run_all():
    test_vectors()
    test_share_secret_roundtrip()
    test_beaver_multiply_correctness_randomized()
    test_error_rejection()


if __name__ == "__main__":
    _run_all()
    print("all tests pass")

