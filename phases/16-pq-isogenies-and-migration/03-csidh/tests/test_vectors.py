import json
import os
import sys


HERE = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as csidh  # noqa: E402


def _pt(obj):
    if obj.get("inf"):
        return csidh.Point.inf()
    return csidh.Point(obj["x"], obj["y"])


def _curve(obj):
    return csidh.Curve(p=obj["p"], a=obj["a"], b=obj["b"]).normalize()


def test_vectors():
    with open(os.path.join(HERE, "vectors.json"), "r", encoding="utf-8") as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        if op == "inv_mod":
            assert csidh.inv_mod(v["a"], v["p"]) == v["expected"]
            continue

        if op == "sqrt_mod":
            if v["expected"] is None:
                try:
                    csidh.sqrt_mod(v["a"], v["p"])
                except csidh.ModSqrtError:
                    pass
                else:
                    raise AssertionError("expected ModSqrtError")
            else:
                assert csidh.sqrt_mod(v["a"], v["p"]) == v["expected"]
            continue

        if op == "point_add":
            curve = _curve(v["curve"])
            got = csidh.point_add(curve, _pt(v["p1"]), _pt(v["p2"]))
            exp = _pt(v["expected"])
            assert got == exp
            continue

        if op == "scalar_mul":
            curve = _curve(v["curve"])
            got = csidh.scalar_mul(curve, v["k"], _pt(v["pt"]))
            exp = _pt(v["expected"])
            assert got == exp
            continue

        if op == "velu_codomain_curve":
            curve = _curve(v["curve"])
            gen = _pt(v["gen"])
            got_curve, _ = csidh.velu_isogeny_odd_prime(curve, gen, v["ell"])
            exp_curve = _curve(v["expected"])
            assert got_curve == exp_curve
            continue

        if op == "velu_map_point":
            curve = _curve(v["curve"])
            gen = _pt(v["gen"])
            codomain, ker = csidh.velu_isogeny_odd_prime(curve, gen, v["ell"])
            got = csidh.velu_map_point(curve, ker, _pt(v["pt"]))
            exp = _pt(v["expected"])
            assert got == exp
            assert csidh.is_on_curve(codomain, got)
            continue

        if op == "commute_demo_j":
            p = 419
            base = csidh.Curve(p=p, a=1, b=0).normalize()
            order = csidh.count_points(base)
            p3 = csidh.find_point_of_order(base, 3, order)
            p5 = csidh.find_point_of_order(base, 5, order)
            got = csidh.velu_demo_two_prime_commute(base, p3, p5)
            assert got == v["expected"]
            assert got["j_e35"] == got["j_e53"]
            continue

        raise AssertionError(f"unknown op: {op}")


def test_group_law_sanity():
    p = 419
    curve = csidh.Curve(p=p, a=1, b=0).normalize()
    order = csidh.count_points(curve)

    p3 = csidh.find_point_of_order(curve, 3, order)
    assert csidh.scalar_mul(curve, 3, p3).is_inf()
    assert not csidh.scalar_mul(curve, 1, p3).is_inf()

    r = csidh.scalar_mul(curve, 2, p3)
    assert csidh.point_add(curve, p3, r).is_inf()


def test_velu_kernel_maps_to_infinity():
    p = 419
    curve = csidh.Curve(p=p, a=1, b=0).normalize()
    order = csidh.count_points(curve)
    gen = csidh.find_point_of_order(curve, 3, order)
    _, ker = csidh.velu_isogeny_odd_prime(curve, gen, 3)

    for q in ker:
        try:
            csidh.velu_map_point(curve, ker, q)
        except ValueError:
            pass
        else:
            raise AssertionError("expected kernel point mapping to be undefined (division by zero)")


if __name__ == "__main__":
    test_vectors()
    test_group_law_sanity()
    test_velu_kernel_maps_to_infinity()
    print("all tests pass")

