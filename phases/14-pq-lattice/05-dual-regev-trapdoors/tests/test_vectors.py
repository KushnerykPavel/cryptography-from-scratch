import json
import os
import random
import sys


THIS_DIR = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(THIS_DIR, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as lesson  # noqa: E402


def _load_vectors():
    path = os.path.join(THIS_DIR, "vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _run_vector_case(case):
    op = case["op"]
    inputs = case["inputs"]
    expected = case["expected"]

    if op == "gadget_matrix":
        out = lesson.gadget_matrix(inputs["n"], inputs["q"])
        assert out == expected
        return

    if op == "bit_decompose_element":
        out = lesson.bit_decompose_element(inputs["x"], inputs["q"])
        assert out == expected
        return

    if op == "bit_decompose_vec":
        out = lesson.bit_decompose_vec(inputs["v"], inputs["q"])
        assert out == expected
        return

    if op == "gadget_compose_vec":
        out = lesson.gadget_compose_vec(inputs["bits"], inputs["q"])
        assert out == expected
        return

    if op == "trapdoor_generate":
        trap = lesson.trapdoor_generate(inputs["A_prime"], inputs["R"], inputs["q"])
        assert trap.A == expected["A"]
        assert trap.T == expected["T"]
        return

    if op == "trapdoor_preimage":
        trap = lesson.trapdoor_generate(inputs["A_prime"], inputs["R"], inputs["q"])
        x = lesson.trapdoor_preimage(trap, inputs["y"])
        Ax = lesson.mat_vec_mul_mod(trap.A, x, trap.q)
        assert x == expected["x"]
        assert Ax == expected["Ax_mod_q"]
        return

    raise ValueError(f"unknown op: {op}")


def test_vectors():
    data = _load_vectors()
    assert "vectors" in data and isinstance(data["vectors"], list)
    for case in data["vectors"]:
        _run_vector_case(case)


def test_gadget_roundtrip_property():
    rng = random.Random(0)
    q = 256
    n = 5
    for _ in range(200):
        y = [rng.randrange(q) for _ in range(n)]
        bits = lesson.bit_decompose_vec(y, q)
        y2 = lesson.gadget_compose_vec(bits, q)
        assert y2 == [yi % q for yi in y]


def test_trapdoor_identity_AT_equals_G():
    rng = random.Random(1)
    q = 256
    n = 2
    k = lesson._log2_int(q)
    m_prime = 4
    nk = n * k

    A_prime = [[rng.randrange(q) for _ in range(m_prime)] for _ in range(n)]
    R = [[rng.choice([-1, 0, 1]) for _ in range(nk)] for _ in range(m_prime)]
    trap = lesson.trapdoor_generate(A_prime, R, q)

    AT = lesson.mat_mul_mod(trap.A, trap.T, q)
    G = lesson.gadget_matrix(n, q)
    assert AT == G


def test_trapdoor_inverts_A_for_random_targets():
    rng = random.Random(2)
    q = 256
    n = 2
    k = lesson._log2_int(q)
    m_prime = 4
    nk = n * k

    A_prime = [[rng.randrange(q) for _ in range(m_prime)] for _ in range(n)]
    R = [[rng.choice([-1, 0, 1]) for _ in range(nk)] for _ in range(m_prime)]
    trap = lesson.trapdoor_generate(A_prime, R, q)

    for _ in range(50):
        y = [rng.randrange(q) for _ in range(n)]
        x = lesson.trapdoor_preimage(trap, y)
        Ax = lesson.mat_vec_mul_mod(trap.A, x, q)
        assert Ax == [yi % q for yi in y]
        assert lesson.max_abs(x) <= 1 + nk


def test_dual_regev_encrypt_decrypt_roundtrip():
    rng = random.Random(3)
    q = 256
    n = 2
    k = lesson._log2_int(q)
    m_prime = 4
    nk = n * k

    A_prime = [[rng.randrange(q) for _ in range(m_prime)] for _ in range(n)]
    R = [[rng.choice([-1, 0, 1]) for _ in range(nk)] for _ in range(m_prime)]
    trap = lesson.trapdoor_generate(A_prime, R, q)

    y = [rng.randrange(q) for _ in range(n)]
    x = lesson.trapdoor_preimage(trap, y)
    assert lesson.mat_vec_mul_mod(trap.A, x, q) == y

    for msg in [0, 1, 1, 0, 1]:
        ct1, ct2 = lesson.dual_regev_encrypt(trap.A, y, q, msg, rng=rng, error_bound=1)
        dec, _raw = lesson.dual_regev_decrypt(ct1, ct2, x, q)
        assert dec == msg


def test_reject_non_power_of_two_q():
    A_prime = [[1, 2], [3, 4]]
    R = [[0] * 8, [0] * 8]
    try:
        lesson.trapdoor_generate(A_prime, R, 17)
    except ValueError:
        return
    raise AssertionError("expected ValueError for non power-of-two q")


if __name__ == "__main__":
    test_vectors()
    test_gadget_roundtrip_property()
    test_trapdoor_identity_AT_equals_G()
    test_trapdoor_inverts_A_for_random_targets()
    test_dual_regev_encrypt_decrypt_roundtrip()
    test_reject_non_power_of_two_q()
    print("all tests pass")

