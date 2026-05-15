import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
import main  # noqa: E402


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        if op == "curve_profile":
            got = main.curve_profile(v["curve"]).to_json()
            assert got == v["expected"]
            continue

        if op == "pairing_generator":
            got = main.pairing_generator_json(v["curve"])
            assert got == v["expected"]
            continue

        if op == "bilinearity":
            got = main.bilinearity_check(v["curve"], v["a"], v["b"])
            assert got == v["expected"]
            continue

        if op == "bls_map_to_curve_g1_demo":
            got = main.bls_map_to_curve_g1_demo(v["message"].encode(), v["dst"].encode())
            assert got == v["expected"]
            continue

        if op == "bls_subgroup_forgery_demo":
            got = main.bls_subgroup_forgery_demo(v["message"].encode(), v["pk_seed"].encode())
            assert got == v["expected"]
            continue

        raise AssertionError(f"unknown op {op}")

    e_bn = main.pairing_generator(main.bn254)
    one_bn = type(e_bn).one()
    assert e_bn != one_bn
    assert (e_bn ** main.bn254.curve_order) == one_bn

    e_bls = main.pairing_generator(main.bls12_381)
    one_bls = type(e_bls).one()
    assert e_bls != one_bls
    assert (e_bls ** main.bls12_381.curve_order) == one_bls


if __name__ == "__main__":
    test_vectors()
    print("all vectors pass")

