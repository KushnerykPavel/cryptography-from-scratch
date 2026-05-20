import json
import os
import sys


THIS_DIR = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(THIS_DIR, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as groth  # noqa: E402


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

        if op == "poly_eval":
            got = groth.poly_eval(inputs["poly"], inputs["x"], inputs["mod"])
            assert got == expected
        elif op == "lagrange_interpolate":
            got = groth.lagrange_interpolate(inputs["xs"], inputs["ys"], inputs["mod"])
            assert got == expected
        elif op == "r1cs_is_satisfied":
            mod = groth.SCALAR_FIELD_MODULUS
            r1cs = groth.build_square_r1cs(mod)
            witness = groth.witness_for_square(inputs["x"], mod)
            got = groth.r1cs_is_satisfied(r1cs, witness, mod)
            assert got == expected
        elif op == "qap_remainder_is_zero":
            mod = groth.SCALAR_FIELD_MODULUS
            r1cs = groth.build_square_r1cs(mod)
            qap = groth.r1cs_to_qap(r1cs, mod)
            witness = groth.witness_for_square(inputs["x"], mod)
            inst = groth.qap_instance_polynomials(qap, witness, mod)
            got = inst["remainder"] == [0]
            assert got == expected
        elif op == "groth16_verify":
            mod = groth.SCALAR_FIELD_MODULUS
            seed = inputs["seed"].encode("utf-8")
            alpha, beta, gamma, delta, tau, r, s = groth.derive_scalars(seed, mod, 7)

            r1cs = groth.build_square_r1cs(mod)
            qap = groth.r1cs_to_qap(r1cs, mod)
            pk, vk = groth.groth16_setup_toy(qap, alpha=alpha, beta=beta, gamma=gamma, delta=delta, tau=tau, mod=mod)

            witness = groth.witness_for_square(inputs["x"], mod)
            proof = groth.groth16_prove_toy(
                qap=qap,
                pk=pk,
                witness=witness,
                r=r,
                s=s,
                alpha=alpha,
                beta=beta,
                delta=delta,
                tau=tau,
                mod=mod,
            )
            public_inputs = [witness[1]]
            ok = groth.groth16_verify_toy(vk, public_inputs, proof, mod)

            assert ok == expected["ok"]
            assert public_inputs == expected["public_inputs"]
            assert groth.as_jsonable_proof(proof) == expected["proof"]
        else:
            raise AssertionError(f"unknown op: {op}")


def test_lagrange_roundtrip_on_domain():
    mod = groth.SCALAR_FIELD_MODULUS
    xs = [1, 2, 3]
    ys = [7, 11, 42]
    poly = groth.lagrange_interpolate(xs, ys, mod)
    for x, y in zip(xs, ys):
        assert groth.poly_eval(poly, x, mod) == y % mod


def test_r1cs_rejects_inconsistent_witness():
    mod = groth.SCALAR_FIELD_MODULUS
    r1cs = groth.build_square_r1cs(mod)
    x = 12
    y = 121
    v = (x * x) % mod
    witness = [1, y, x, v]
    assert groth.r1cs_is_satisfied(r1cs, witness, mod) is False


def test_qap_remainder_nonzero_for_bad_witness():
    mod = groth.SCALAR_FIELD_MODULUS
    r1cs = groth.build_square_r1cs(mod)
    qap = groth.r1cs_to_qap(r1cs, mod)
    witness = [1, 121, 12, (12 * 12) % mod]
    inst = groth.qap_instance_polynomials(qap, witness, mod)
    assert inst["remainder"] != [0]


def test_groth16_verify_fails_when_public_input_changes():
    mod = groth.SCALAR_FIELD_MODULUS
    seed = b"toy-groth16-demo"
    alpha, beta, gamma, delta, tau, r, s = groth.derive_scalars(seed, mod, 7)

    r1cs = groth.build_square_r1cs(mod)
    qap = groth.r1cs_to_qap(r1cs, mod)
    pk, vk = groth.groth16_setup_toy(qap, alpha=alpha, beta=beta, gamma=gamma, delta=delta, tau=tau, mod=mod)

    witness = groth.witness_for_square(11, mod)
    proof = groth.groth16_prove_toy(
        qap=qap,
        pk=pk,
        witness=witness,
        r=r,
        s=s,
        alpha=alpha,
        beta=beta,
        delta=delta,
        tau=tau,
        mod=mod,
    )
    assert groth.groth16_verify_toy(vk, [witness[1]], proof, mod) is True
    assert groth.groth16_verify_toy(vk, [(witness[1] + 1) % mod], proof, mod) is False


def test_mod_inv_rejects_zero():
    mod = groth.SCALAR_FIELD_MODULUS
    try:
        groth.mod_inv(0, mod)
        assert False, "expected ZeroDivisionError"
    except ZeroDivisionError:
        pass


if __name__ == "__main__":
    try:
        import pytest  # type: ignore

        rc = pytest.main([__file__])
        if rc != 0:
            raise SystemExit(rc)
    except ImportError:
        test_vectors()
        test_lagrange_roundtrip_on_domain()
        test_r1cs_rejects_inconsistent_witness()
        test_qap_remainder_nonzero_for_bad_witness()
        test_groth16_verify_fails_when_public_input_changes()
        test_mod_inv_rejects_zero()

    print("all tests pass")

