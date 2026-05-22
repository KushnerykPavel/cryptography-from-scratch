import json
import math
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
CODE_DIR = HERE.parent / "code"
sys.path.insert(0, str(CODE_DIR))

import main as lesson  # noqa: E402


def _load_vectors() -> dict:
    vectors_path = HERE / "vectors.json"
    return json.loads(vectors_path.read_text(encoding="utf-8"))


def test_vectors() -> None:
    data = _load_vectors()
    vectors = data["vectors"]

    for v in vectors:
        op = v["op"]
        if op == "lcm":
            assert lesson.lcm(v["a"], v["b"]) == v["expected"]
        elif op == "modinv":
            assert lesson.modinv(v["a"], v["m"]) == v["expected"]
        elif op == "paillier_keygen_from_primes":
            pub, priv = lesson.paillier_keygen_from_primes(v["p"], v["q"])
            exp = v["expected"]
            assert pub.n == exp["n"]
            assert pub.g == exp["g"]
            assert pub.n_sq == exp["n_sq"]
            assert priv.lam == exp["lam"]
            assert priv.mu == exp["mu"]
        elif op == "paillier_encrypt":
            pub, _ = lesson.paillier_keygen_from_primes(v["p"], v["q"])
            assert lesson.paillier_encrypt(v["m"], pub, r=v["r"]) == v["expected"]
        elif op == "paillier_hom_add_decrypt":
            pub, priv = lesson.paillier_keygen_from_primes(v["p"], v["q"])
            c1 = lesson.paillier_encrypt(v["m1"], pub, r=v["r1"])
            c2 = lesson.paillier_encrypt(v["m2"], pub, r=v["r2"])
            c_sum = lesson.paillier_hom_add(c1, c2, pub)
            assert lesson.paillier_decrypt(c_sum, pub, priv) == v["expected"]
        elif op == "paillier_hom_scalar_mul_decrypt":
            pub, priv = lesson.paillier_keygen_from_primes(v["p"], v["q"])
            c = lesson.paillier_encrypt(v["m"], pub, r=v["r"])
            c_scaled = lesson.paillier_hom_scalar_mul(c, v["k"], pub)
            assert lesson.paillier_decrypt(c_scaled, pub, priv) == v["expected"]
        elif op == "shamir_split":
            shares = lesson.shamir_split(
                v["secret"],
                n_shares=v["n_shares"],
                threshold=v["threshold"],
                prime=v["prime"],
                coefficients=v["coefficients"],
            )
            got = [{"x": s.x, "y": s.y} for s in shares]
            assert got == v["expected"]
        elif op == "shamir_reconstruct_at_zero":
            shares = [lesson.Share(x=s["x"], y=s["y"]) for s in v["shares"]]
            assert lesson.shamir_reconstruct_at_zero(shares, v["prime"]) == v["expected"]
        elif op == "threshold_split_paillier_private_key":
            _, priv = lesson.paillier_keygen_from_primes(v["p"], v["q"])
            shares = lesson.threshold_split_paillier_private_key(
                priv,
                n_shares=v["n_shares"],
                threshold=v["threshold"],
                prime=v["prime"],
                lam_coefficients=v["lam_coefficients"],
                mu_coefficients=v["mu_coefficients"],
            )
            got = [{"x": s.x, "lam_y": s.lam_y, "mu_y": s.mu_y} for s in shares]
            assert got == v["expected"]
        elif op == "vote_tally_cipher_and_threshold_decrypt":
            pub, priv = lesson.paillier_keygen_from_primes(v["p"], v["q"])
            tshares = lesson.threshold_split_paillier_private_key(
                priv,
                n_shares=v["n_shares"],
                threshold=v["threshold"],
                prime=v["prime"],
                lam_coefficients=v["lam_coefficients"],
                mu_coefficients=v["mu_coefficients"],
            )

            vote_ciphertexts = [
                lesson.paillier_encrypt(m, pub, r=r) for m, r in zip(v["votes"], v["rs"], strict=True)
            ]
            c_total = 1
            for c in vote_ciphertexts:
                c_total = lesson.paillier_hom_add(c_total, c, pub)

            exp = v["expected"]
            assert c_total == exp["c_total"]
            dec = lesson.threshold_decrypt_paillier(
                c_total, pub, tshares[: v["threshold"]], threshold=v["threshold"], prime=v["prime"]
            )
            assert dec == exp["total"]
        else:
            raise AssertionError(f"unknown op: {op}")


def test_properties_and_edge_cases() -> None:
    pub, priv = lesson.paillier_keygen_from_primes(101, 113)

    for m in [0, 1, 2, 42, pub.n - 1]:
        c = lesson.paillier_encrypt(m, pub, r=1)
        assert lesson.paillier_decrypt(c, pub, priv) == m

    for a in [0, 1, 5, 99]:
        for b in [0, 2, 7, 100]:
            ca = lesson.paillier_encrypt(a, pub, r=2)
            cb = lesson.paillier_encrypt(b, pub, r=3)
            csum = lesson.paillier_hom_add(ca, cb, pub)
            assert lesson.paillier_decrypt(csum, pub, priv) == (a + b) % pub.n

    shares = lesson.shamir_split(
        4242,
        n_shares=5,
        threshold=3,
        prime=lesson.SHAMIR_PRIME_127,
        coefficients=[1, 2],
    )
    assert lesson.shamir_reconstruct_at_zero([shares[0], shares[2], shares[4]], lesson.SHAMIR_PRIME_127) == 4242

    tshares = lesson.threshold_split_paillier_private_key(
        priv,
        n_shares=5,
        threshold=3,
        prime=lesson.SHAMIR_PRIME_127,
        lam_coefficients=[10, 20],
        mu_coefficients=[30, 40],
    )
    c = lesson.paillier_encrypt(7, pub, r=5)
    try:
        lesson.threshold_decrypt_paillier(c, pub, tshares[:2], threshold=3, prime=lesson.SHAMIR_PRIME_127)
        assert False, "expected not enough shares"
    except ValueError:
        pass

    assert lesson.threshold_decrypt_paillier(c, pub, tshares[:3], threshold=3, prime=lesson.SHAMIR_PRIME_127) == 7

    try:
        lesson.modinv(2, 4)
        assert False, "expected no modular inverse"
    except ValueError:
        pass

    try:
        lesson.paillier_encrypt(pub.n, pub, r=1)
        assert False, "expected message out of range"
    except ValueError:
        pass

    try:
        lesson.shamir_split(1, n_shares=2, threshold=3, prime=lesson.SHAMIR_PRIME_127)
        assert False, "expected invalid threshold"
    except ValueError:
        pass

    assert math.gcd(1, pub.n) == 1


if __name__ == "__main__":
    test_vectors()
    test_properties_and_edge_cases()
    print("all tests pass")

