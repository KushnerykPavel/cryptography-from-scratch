import json
import pathlib
import random
import sys


HERE = pathlib.Path(__file__).resolve()
LESSON_DIR = HERE.parents[1]
sys.path.insert(0, str(LESSON_DIR / "code"))

import main as lesson  # noqa: E402


def _load_vectors():
    path = HERE.parent / "vectors.json"
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def test_vectors():
    data = _load_vectors()
    assert isinstance(data.get("vectors"), list)

    group = lesson.toy_group_for_demo()

    for vec in data["vectors"]:
        op = vec["op"]
        inputs = vec["inputs"]
        expected = vec["expected"]

        if op == "poly_eval":
            y = lesson.poly_eval(inputs["coeffs"], inputs["x"], inputs["mod"])
            assert y == expected["y"]

        elif op == "poly_divmod_x_minus_z":
            q, r = lesson.poly_divmod_x_minus_z(inputs["coeffs"], inputs["z"], inputs["mod"])
            assert q == expected["quotient"]
            assert r == expected["remainder"]

        elif op == "kzg_open_verify":
            params = lesson.kzg_setup(inputs["max_degree"], group=group, s=inputs["s"])
            C = lesson.kzg_commit(params, inputs["coeffs"])
            y, pi = lesson.kzg_open(params, inputs["coeffs"], inputs["z"])
            ok = lesson.kzg_verify(params, C, inputs["z"], y, pi)

            assert C.scalar == expected["commitment_scalar"]
            assert hex(C.int_value()) == expected["commitment_value"]
            assert y == expected["y"]
            assert pi.scalar == expected["proof_scalar"]
            assert hex(pi.int_value()) == expected["proof_value"]
            assert ok is expected["verifies"]

        elif op == "kzg_verify_rejects_wrong_y":
            params = lesson.kzg_setup(inputs["max_degree"], group=group, s=inputs["s"])
            C = lesson.kzg_commit(params, inputs["coeffs"])
            y, pi = lesson.kzg_open(params, inputs["coeffs"], inputs["z"])
            assert y != inputs["y"]
            ok = lesson.kzg_verify(params, C, inputs["z"], inputs["y"], pi)
            assert ok is expected["verifies"]

        else:
            raise AssertionError(f"unknown op: {op}")


def _poly_add(a, b, mod):
    n = max(len(a), len(b))
    out = []
    for i in range(n):
        x = a[i] if i < len(a) else 0
        y = b[i] if i < len(b) else 0
        out.append((x + y) % mod)
    return lesson.poly_trim(out)


def test_properties():
    group = lesson.toy_group_for_demo()
    params = lesson.kzg_setup(16, group=group, s=17)

    f = [3, 5, 7, 11]
    g = [13, 0, 999]
    C_f = lesson.kzg_commit(params, f)
    C_g = lesson.kzg_commit(params, g)
    C_sum = lesson.kzg_commit(params, _poly_add(f, g, group.q))
    assert C_f + C_g == C_sum

    const = [42]
    C_const = lesson.kzg_commit(params, const)
    y0, pi0 = lesson.kzg_open(params, const, z=5)
    assert y0 == 42 % group.q
    assert lesson.kzg_verify(params, C_const, z=5, y=y0, proof=pi0)

    rng = random.Random(12345)
    for _ in range(50):
        deg = rng.randrange(0, 8)
        poly = [rng.randrange(0, group.q) for _ in range(deg + 1)]
        z = rng.randrange(0, group.q)
        C = lesson.kzg_commit(params, poly)
        y, pi = lesson.kzg_open(params, poly, z)
        assert lesson.kzg_verify(params, C, z, y, pi)

        assert not lesson.kzg_verify(params, C, z, (y + 1) % group.q, pi)

    try:
        lesson.kzg_commit(lesson.kzg_setup(1, group=group, s=17), [1, 2, 3])
        raise AssertionError("expected degree overflow to raise")
    except ValueError:
        pass


if __name__ == "__main__":
    test_vectors()
    test_properties()
    print("all tests pass")

