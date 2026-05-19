import json
import random
import sys
from pathlib import Path


LESSON = Path(__file__).resolve().parents[1]
VECTORS_PATH = LESSON / "tests" / "vectors.json"

sys.path.insert(0, str(LESSON / "code"))
import main as bp  # noqa: E402


def _proof(obj) -> bp.InnerProductProof:
    return bp.InnerProductProof(Ls=list(obj["Ls"]), Rs=list(obj["Rs"]), a=obj["a"], b=obj["b"])


def call(vector):
    op = vector["op"]

    if op == "inv_q":
        return bp.inv_q(vector["x"], vector["q"])
    if op == "inner_product":
        return bp.inner_product(vector["q"], list(vector["a"]), list(vector["b"]))
    if op == "derive_generators":
        return bp.derive_generators(vector["n"], vector["q"], vector["seed"].encode("utf-8"))
    if op == "ipa_commit":
        return bp.ipa_commit(
            vector["q"],
            list(vector["G"]),
            list(vector["H"]),
            vector["Q"],
            list(vector["a"]),
            list(vector["b"]),
        )
    if op == "ipa_prove":
        P_prime, proof = bp.ipa_prove(
            vector["q"],
            list(vector["G"]),
            list(vector["H"]),
            vector["Q"],
            list(vector["a"]),
            list(vector["b"]),
        )
        return {
            "P_prime": P_prime,
            "Ls": proof.Ls,
            "Rs": proof.Rs,
            "a_final": proof.a,
            "b_final": proof.b,
        }
    if op == "ipa_verify":
        return bp.ipa_verify(
            vector["q"],
            list(vector["G"]),
            list(vector["H"]),
            vector["Q"],
            vector["P_prime"],
            _proof(vector["proof"]),
        )

    raise AssertionError(f"unknown op: {op}")


def test_vectors():
    vectors = json.loads(VECTORS_PATH.read_text())["vectors"]
    for vector in vectors:
        if "expected_error" in vector:
            try:
                call(vector)
            except ValueError as error:
                assert str(error) == vector["expected_error"]
            else:
                raise AssertionError(f"{vector['op']} did not raise")
            continue

        assert call(vector) == vector["expected"]


def test_roundtrip_random_vectors_verify():
    q = 101
    rng = random.Random(0)

    for n in (1, 2, 4, 8):
        G = bp.derive_generators(n, q, b"G")
        H = bp.derive_generators(n, q, b"H")
        Q = bp.derive_generators(1, q, b"Q")[0]

        for _ in range(200):
            a = [rng.randrange(0, q) for _ in range(n)]
            b = [rng.randrange(0, q) for _ in range(n)]
            P_prime, proof = bp.ipa_prove(q, G, H, Q, a, b)
            assert bp.ipa_verify(q, G, H, Q, P_prime, proof)


def test_tampering_breaks_verification():
    q = 101
    n = 8
    G = bp.derive_generators(n, q, b"G")
    H = bp.derive_generators(n, q, b"H")
    Q = bp.derive_generators(1, q, b"Q")[0]

    a = list(range(1, n + 1))
    b = list(range(n, 0, -1))
    P_prime, proof = bp.ipa_prove(q, G, H, Q, a, b)
    assert bp.ipa_verify(q, G, H, Q, P_prime, proof)

    proof_bad_a = bp.InnerProductProof(Ls=proof.Ls, Rs=proof.Rs, a=(proof.a + 1) % q, b=proof.b)
    assert not bp.ipa_verify(q, G, H, Q, P_prime, proof_bad_a)

    proof_bad_L = bp.InnerProductProof(
        Ls=[(proof.Ls[0] + 1) % q] + proof.Ls[1:], Rs=proof.Rs, a=proof.a, b=proof.b
    )
    assert not bp.ipa_verify(q, G, H, Q, P_prime, proof_bad_L)

    assert not bp.ipa_verify(q, G, H, Q, (P_prime + 1) % q, proof)
    assert not bp.ipa_verify(q, G, H, (Q + 1) % q, P_prime, proof)


def test_rejects_non_power_of_two_length():
    q = 101
    G = bp.derive_generators(3, q, b"G")
    H = bp.derive_generators(3, q, b"H")
    Q = bp.derive_generators(1, q, b"Q")[0]
    a = [1, 2, 3]
    b = [3, 2, 1]

    try:
        bp.ipa_prove(q, G, H, Q, a, b)
    except ValueError as error:
        assert str(error) == "vector length must be a power of two"
    else:
        raise AssertionError("expected parameter validation failure")


if __name__ == "__main__":
    test_vectors()
    test_roundtrip_random_vectors_verify()
    test_tampering_breaks_verification()
    test_rejects_non_power_of_two_length()
    print("all tests pass")

