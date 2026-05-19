import json
import os
import sys


HERE = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main  # noqa: E402


def _load_vectors():
    path = os.path.join(HERE, "vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert "vectors" in data and isinstance(data["vectors"], list)
    return data


def _field_from_vec(v):
    return main.GF2m(m=v["m"], irr_poly=v["irr_poly"])


def test_vectors():
    data = _load_vectors()
    for v in data["vectors"]:
        op = v["op"]

        if op == "gf_add":
            field = _field_from_vec(v)
            assert field.add(v["a"], v["b"]) == v["expected"]

        elif op == "gf_mul":
            field = _field_from_vec(v)
            assert field.mul(v["a"], v["b"]) == v["expected"]

        elif op == "gf_inv":
            field = _field_from_vec(v)
            assert field.inv(v["a"]) == v["expected"]

        elif op == "gf_div":
            field = _field_from_vec(v)
            assert field.div(v["a"], v["b"]) == v["expected"]

        elif op == "poly_eval":
            field = _field_from_vec(v)
            assert main.gf_poly_eval(field, v["coeffs"], v["x"]) == v["expected"]

        elif op == "choose_support":
            field = _field_from_vec(v)
            got = main.choose_support(field, v["g_coeffs"], v["n"])
            assert got == v["expected"]

        elif op == "parity_check_bin":
            field = _field_from_vec(v)
            got = main.goppa_parity_check_bin(field, v["g_coeffs"], v["support"])
            assert got == v["expected"]

        elif op == "nullspace_basis":
            got = main.gf2_nullspace_basis(v["matrix"])
            assert got == v["expected"]

        elif op == "encode":
            got = main.encode_from_generator(v["G"], v["msg"])
            assert got == v["expected"]

        elif op == "decode_radius_t":
            decoded, err = main.brute_force_decode(v["H"], v["received"], v["t"])
            assert decoded == v["expected_decoded"]
            assert err == v["expected_error"]

        else:
            raise AssertionError(f"unknown op: {op}")


def test_gf2m_field_axioms_small():
    field = main.GF2m(m=4, irr_poly=0b10011)
    elems = list(range(field.size))

    for a in elems:
        for b in elems:
            assert field.add(a, b) == field.add(b, a)
            assert field.add(a, 0) == a
            assert field.mul(a, b) == field.mul(b, a)
            assert field.mul(a, 0) == 0
            assert field.mul(a, 1) == a

    for a in elems:
        for b in elems:
            for c in elems:
                assert field.add(field.add(a, b), c) == field.add(a, field.add(b, c))
                assert field.mul(field.mul(a, b), c) == field.mul(a, field.mul(b, c))
                left = field.mul(a, field.add(b, c))
                right = field.add(field.mul(a, b), field.mul(a, c))
                assert left == right

    for a in elems[1:]:
        inv = field.inv(a)
        assert field.mul(a, inv) == 1


def test_goppa_codewords_have_zero_syndrome():
    field = main.GF2m(m=4, irr_poly=0b10011)
    g = [1, 1, 1]
    support = main.choose_support(field, g, 10)
    H = main.goppa_parity_check_bin(field, g, support)
    G = main.gf2_nullspace_basis(H)

    for msg in ([0, 0], [0, 1], [1, 0], [1, 1]):
        c = main.encode_from_generator(G, list(msg))
        assert all(x == 0 for x in main.gf2_mat_vec_mul(H, c))


def test_toy_decode_finds_nearby_codeword():
    field = main.GF2m(m=4, irr_poly=0b10011)
    g = [1, 1, 1]
    t = len(g) - 1
    n = 10
    support = main.choose_support(field, g, n)
    H = main.goppa_parity_check_bin(field, g, support)
    G = main.gf2_nullspace_basis(H)

    msgs = ([0, 0], [0, 1], [1, 0], [1, 1])
    for msg in msgs:
        code = main.encode_from_generator(G, list(msg))

        for i in range(n):
            received = code[:]
            received[i] ^= 1
            decoded, _ = main.brute_force_decode(H, received, t=t)
            assert decoded == code

        for i in range(n):
            for j in range(i + 1, n):
                received = code[:]
                received[i] ^= 1
                received[j] ^= 1
                decoded, _ = main.brute_force_decode(H, received, t=t)
                assert decoded == code


def test_reject_bad_inputs():
    field = main.GF2m(m=4, irr_poly=0b10011)
    g = [1, 1, 1]
    support = main.choose_support(field, g, 10)

    try:
        field.inv(0)
        raise AssertionError("expected ZeroDivisionError")
    except ZeroDivisionError:
        pass

    root = None
    for a in range(field.size):
        if main.gf_poly_eval(field, g, a) == 0:
            root = a
            break
    if root is not None:
        try:
            main.goppa_parity_check_bin(field, g, [root] + support[1:])
            raise AssertionError("expected ValueError")
        except ValueError:
            pass


if __name__ == "__main__":
    test_vectors()
    test_gf2m_field_axioms_small()
    test_goppa_codewords_have_zero_syndrome()
    test_toy_decode_finds_nearby_codeword()
    test_reject_bad_inputs()
    print("all tests pass")

