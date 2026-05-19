import json
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
LESSON_DIR = HERE.parent
CODE_DIR = LESSON_DIR / "code"

sys.path.insert(0, str(CODE_DIR))
import main  # noqa: E402


def _load_vectors() -> dict:
    with (HERE / "vectors.json").open("r", encoding="utf-8") as f:
        return json.load(f)


def _call_vector(op: str, inputs: dict):
    if op == "hash_to_prime":
        msg = inputs["message"].encode("utf-8")
        return main.hash_to_prime(
            msg, domain=inputs.get("domain", "rsa-accum"), bits=inputs.get("bits", 32)
        )

    if op == "qr_base":
        return main.qr_base(inputs["modulus"], inputs["seed"].encode("utf-8"))

    if op == "rsa_accumulate":
        return main.rsa_accumulate(
            inputs["prime_reps"], modulus=inputs["modulus"], base=inputs["base"]
        )

    if op == "rsa_add":
        return main.rsa_add(
            inputs["acc_value"], inputs["prime_rep"], modulus=inputs["modulus"]
        )

    if op == "rsa_membership_witness":
        return main.rsa_membership_witness(
            inputs["all_prime_reps"],
            inputs["member_prime_rep"],
            modulus=inputs["modulus"],
            base=inputs["base"],
        )

    if op == "rsa_update_witness_on_add":
        return main.rsa_update_witness_on_add(
            inputs["witness"], inputs["added_prime_rep"], modulus=inputs["modulus"]
        )

    if op == "rsa_verify_membership":
        return main.rsa_verify_membership(
            inputs["acc_value"],
            inputs["witness"],
            inputs["member_prime_rep"],
            modulus=inputs["modulus"],
        )

    if op == "rsa_nonmembership_proof":
        a, d = main.rsa_nonmembership_proof(
            inputs["all_prime_reps"],
            inputs["nonmember_prime_rep"],
            modulus=inputs["modulus"],
            base=inputs["base"],
        )
        return [a, d]

    if op == "rsa_verify_nonmembership":
        return main.rsa_verify_nonmembership(
            inputs["acc_value"],
            inputs["nonmember_prime_rep"],
            inputs["proof_a"],
            inputs["proof_d"],
            modulus=inputs["modulus"],
            base=inputs["base"],
        )

    raise ValueError(f"unknown op: {op}")


def test_vectors() -> None:
    vectors = _load_vectors()
    assert "source" in vectors and isinstance(vectors["source"], str)
    for v in vectors["vectors"]:
        got = _call_vector(v["op"], v["inputs"])
        assert got == v["expected"], (v["op"], v["inputs"], got, v["expected"])


def test_membership_witness_update_roundtrip() -> None:
    modulus = 11413
    base = 1369
    primes = [3, 5, 7]

    acc = main.rsa_accumulate(primes, modulus=modulus, base=base)
    witness_5 = main.rsa_membership_witness(primes, 5, modulus=modulus, base=base)
    assert main.rsa_verify_membership(acc, witness_5, 5, modulus=modulus)

    added = 11
    acc2 = main.rsa_add(acc, added, modulus=modulus)
    witness_5_2 = main.rsa_update_witness_on_add(witness_5, added, modulus=modulus)
    assert main.rsa_verify_membership(acc2, witness_5_2, 5, modulus=modulus)


def test_nonmembership_proof_rejects_member() -> None:
    modulus = 11413
    base = 1369
    primes = [3, 5, 7]

    try:
        main.rsa_nonmembership_proof(primes, 5, modulus=modulus, base=base)
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_pow_mod_signed_negative_exponent() -> None:
    modulus = 11413
    base = 1369
    inv = main.pow_mod_signed(base, -1, modulus)
    assert (base * inv) % modulus == 1


if __name__ == "__main__":
    test_vectors()
    test_membership_witness_update_roundtrip()
    test_nonmembership_proof_rejects_member()
    test_pow_mod_signed_negative_exponent()
    print("all tests pass")

