import json
import sys
from pathlib import Path

try:
    import pytest  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    pytest = None


THIS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(THIS_DIR.parent / "code"))

import main as te  # noqa: E402


def _load_vectors() -> dict:
    path = THIS_DIR / "vectors.json"
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _hx(s: str) -> bytes:
    return bytes.fromhex(s)


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
    g = te.demo_group()

    for v in data["vectors"]:
        op = v["op"]
        inputs = v["inputs"]
        expected = v["expected"]

        if op == "modinv":
            got = te.modinv(inputs["a"], inputs["modulus"])
            assert got == expected
            continue

        if op == "poly_eval":
            got = te.poly_eval(inputs["coeffs"], inputs["x"], inputs["modulus"])
            assert got == expected
            continue

        if op == "lagrange_coefficients_at_zero":
            got = te.lagrange_coefficients_at_zero(inputs["x_coords"], inputs["modulus"])
            want = {int(k): int(val) for k, val in expected.items()}
            assert got == want
            continue

        if op == "shamir_make_shares":
            got = te.shamir_make_shares(
                secret=inputs["secret"],
                threshold=inputs["threshold"],
                num_shares=inputs["num_shares"],
                modulus=inputs["modulus"],
                coeffs=inputs["coeffs"],
            )
            assert got == [tuple(x) for x in expected["shares"]]
            continue

        if op == "shamir_recover_secret":
            got = te.shamir_recover_secret([tuple(x) for x in inputs["shares"]], modulus=inputs["modulus"])
            assert got == expected
            continue

        if op == "threshold_encrypt":
            pub, shares, x = te.threshold_keygen(
                group=g,
                threshold=inputs["threshold"],
                num_shares=inputs["num_shares"],
                secret_x=inputs["secret_x"],
                coeffs=inputs["coeffs"],
            )
            assert x == inputs["secret_x"]
            assert pub.y == expected["y"]

            ct = te.threshold_encrypt(
                pub,
                _hx(inputs["plaintext_hex"]),
                k=inputs["k"],
                label=inputs["label_utf8"].encode("utf-8"),
            )
            assert ct[0] == expected["c1"]
            assert ct[1].hex() == expected["masked_hex"]

            chosen = [shares[i - 1] for i in [1, 3, 4]]
            pt = te.threshold_decrypt(pub, chosen, ct, label=inputs["label_utf8"].encode("utf-8"))
            assert pt == _hx(inputs["plaintext_hex"])
            continue

        if op == "combine_partial_decryptions":
            partials = [tuple(x) for x in inputs["partials"]]
            got = te.combine_partial_decryptions(partials=partials, group=g)
            assert got == expected
            continue

        raise AssertionError(f"unknown op: {op}")


def test_lagrange_coeffs_sum_to_one() -> None:
    q = te.demo_group().q
    xs = [1, 3, 4]
    lambdas = te.lagrange_coefficients_at_zero(xs, q)
    assert sum(lambdas.values()) % q == 1


def test_shamir_two_shares_not_enough_for_degree2_demo() -> None:
    q = te.demo_group().q
    shares = [(1, 209), (2, 80), (3, 202), (4, 109), (5, 34)]
    recovered_ok = te.shamir_recover_secret([shares[0], shares[2], shares[3]], modulus=q)
    recovered_bad = te.shamir_recover_secret([shares[0], shares[2]], modulus=q)
    assert recovered_ok == 123
    assert recovered_bad != 123


def test_threshold_decrypt_rejects_not_enough_shares() -> None:
    g = te.demo_group()
    pub, shares, _ = te.threshold_keygen(group=g, threshold=3, num_shares=5, secret_x=123, coeffs=[77, 9])
    ct = te.threshold_encrypt(pub, b"hello", k=42)
    _assert_raises(ValueError, te.threshold_decrypt, pub=pub, shares=shares[:2], ct=ct)


def test_group_membership_check_rejects_non_subgroup_element() -> None:
    g = te.demo_group()
    _assert_raises(ValueError, g.validate_elem, x=2)


def test_xor_length_mismatch_rejected() -> None:
    _assert_raises(ValueError, te.xor_bytes, a=b"\x00", b=b"\x00\x00")


if __name__ == "__main__":
    test_vectors()
    test_lagrange_coeffs_sum_to_one()
    test_shamir_two_shares_not_enough_for_degree2_demo()
    test_threshold_decrypt_rejects_not_enough_shares()
    test_group_membership_check_rejects_non_subgroup_element()
    test_xor_length_mismatch_rejected()
    print("all tests pass")

