import json
import os
import sys


THIS_DIR = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(THIS_DIR, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as spdz  # noqa: E402


def _load_vectors():
    path = os.path.join(THIS_DIR, "vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def test_vectors():
    data = _load_vectors()
    vectors = data["vectors"]

    for v in vectors:
        op = v["op"]
        inputs = v["inputs"]
        expected = v["expected"]

        if op == "mod_add":
            got = spdz.mod_add(inputs["a"], inputs["b"], inputs["p"])
            assert got == expected
        elif op == "mod_mul":
            got = spdz.mod_mul(inputs["a"], inputs["b"], inputs["p"])
            assert got == expected
        elif op == "reconstruct":
            got = spdz.reconstruct(inputs["shares"], inputs["p"])
            assert got == expected
        elif op == "beaver_multiply_shares":
            triple = (inputs["a_shares"], inputs["b_shares"], inputs["c_shares"])
            z_shares = spdz.beaver_multiply_shares(inputs["x_shares"], inputs["y_shares"], triple, inputs["p"])
            assert z_shares == expected["z_shares"]
            assert spdz.reconstruct(z_shares, inputs["p"]) == expected["opened"]
        elif op == "spdz_open":
            alpha_shares = inputs["alpha_shares"]
            auth_shares = [spdz.AuthShare(value=s["value"], mac=s["mac"]) for s in inputs["auth_shares"]]
            got = spdz.spdz_open(auth_shares, alpha_shares, inputs["p"])
            assert got == expected
        elif op == "spdz_multiply_open":
            p = inputs["p"]
            alpha_shares = inputs["alpha_shares"]
            x = [spdz.AuthShare(value=s["value"], mac=s["mac"]) for s in inputs["x_auth"]]
            y = [spdz.AuthShare(value=s["value"], mac=s["mac"]) for s in inputs["y_auth"]]
            a = [spdz.AuthShare(value=s["value"], mac=s["mac"]) for s in inputs["triple"]["a"]]
            b = [spdz.AuthShare(value=s["value"], mac=s["mac"]) for s in inputs["triple"]["b"]]
            c = [spdz.AuthShare(value=s["value"], mac=s["mac"]) for s in inputs["triple"]["c"]]
            xy = spdz.spdz_multiply(x, y, (a, b, c), alpha_shares, p)
            got = spdz.spdz_open(xy, alpha_shares, p)
            assert got == expected
        else:
            raise AssertionError(f"unknown op: {op}")


def test_additive_sharing_roundtrip():
    p = spdz.PRIME
    rng = spdz.DeterministicRng(b"sharing-roundtrip")
    for secret in [0, 1, 2, 123, p - 1, p + 5, -7]:
        shares = spdz.additive_share(secret, 3, p, rng)
        assert spdz.reconstruct(shares, p) == secret % p


def test_beaver_multiply_roundtrip():
    p = spdz.PRIME
    rng = spdz.DeterministicRng(b"beaver-roundtrip")
    n = 3
    for x, y in [(0, 0), (0, 7), (7, 0), (1, 1), (1234, 5678), (p - 1, p - 2)]:
        x_sh = spdz.additive_share(x, n, p, rng)
        y_sh = spdz.additive_share(y, n, p, rng)
        triple = spdz.beaver_triple_shares(n, p, rng)
        z_sh = spdz.beaver_multiply_shares(x_sh, y_sh, triple, p)
        assert spdz.reconstruct(z_sh, p) == (x * y) % p


def test_spdz_open_rejects_tampering():
    p = spdz.PRIME
    rng = spdz.DeterministicRng(b"spdz-tamper")
    n = 3
    alpha_shares = spdz.spdz_setup_alpha_shares(n, p, rng)
    x = spdz._auth_share_secret_dealer(1234, alpha_shares, p, rng)
    assert spdz.spdz_open(x, alpha_shares, p) == 1234

    tampered = list(x)
    tampered[0] = spdz.AuthShare(value=(tampered[0].value + 1) % p, mac=tampered[0].mac)
    try:
        spdz.spdz_open(tampered, alpha_shares, p)
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_spdz_multiply_roundtrip():
    p = spdz.PRIME
    rng = spdz.DeterministicRng(b"spdz-multiply")
    n = 3
    alpha_shares = spdz.spdz_setup_alpha_shares(n, p, rng)
    for x, y in [(2, 3), (1234, 5678), (p - 3, p - 4)]:
        xs = spdz._auth_share_secret_dealer(x, alpha_shares, p, rng)
        ys = spdz._auth_share_secret_dealer(y, alpha_shares, p, rng)
        triple = spdz.beaver_triple_auth_shares(alpha_shares, p, rng)
        xy = spdz.spdz_multiply(xs, ys, triple, alpha_shares, p)
        assert spdz.spdz_open(xy, alpha_shares, p) == (x * y) % p


def test_spdz_open_rejects_party_count_mismatch():
    p = spdz.PRIME
    alpha_shares = [1, 2, 3]
    x = [spdz.AuthShare(1, 2), spdz.AuthShare(3, 4)]
    try:
        spdz.spdz_open(x, alpha_shares, p)
        assert False, "expected ValueError"
    except ValueError:
        pass


if __name__ == "__main__":
    test_vectors()
    test_additive_sharing_roundtrip()
    test_beaver_multiply_roundtrip()
    test_spdz_open_rejects_tampering()
    test_spdz_multiply_roundtrip()
    test_spdz_open_rejects_party_count_mismatch()

    print("all tests pass")
