import json
import os
import sys

HERE = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

from main import (  # noqa: E402
    ShortWeierstrassCurve,
    inv_mod,
    velu_isogeny_short_weierstrass,
)


def _pt(v):
    if v is None:
        return None
    return (int(v[0]), int(v[1]))


def _load_vectors():
    path = os.path.join(HERE, "vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def test_vectors():
    data = _load_vectors()
    for vec in data["vectors"]:
        op = vec["op"]
        if op == "inv_mod":
            assert inv_mod(int(vec["a"]), int(vec["p"])) == int(vec["expected"])
            continue

        if op == "point_add":
            c = vec["curve"]
            curve = ShortWeierstrassCurve(p=int(c["p"]), a=int(c["a"]), b=int(c["b"]))
            got = curve.add(_pt(vec["p1"]), _pt(vec["p2"]))
            assert got == _pt(vec["expected"])
            continue

        if op == "scalar_mul":
            c = vec["curve"]
            curve = ShortWeierstrassCurve(p=int(c["p"]), a=int(c["a"]), b=int(c["b"]))
            got = curve.mul(int(vec["k"]), _pt(vec["p1"]))
            assert got == _pt(vec["expected"])
            continue

        if op == "subgroup_points":
            c = vec["curve"]
            curve = ShortWeierstrassCurve(p=int(c["p"]), a=int(c["a"]), b=int(c["b"]))
            got = curve.subgroup_points(_pt(vec["generator"]))
            assert got == [_pt(x) for x in vec["expected"]]
            continue

        if op == "velu_codomain":
            c = vec["curve"]
            curve = ShortWeierstrassCurve(p=int(c["p"]), a=int(c["a"]), b=int(c["b"]))
            codomain, _phi, _kernel = velu_isogeny_short_weierstrass(curve, _pt(vec["kernel_generator"]))
            assert codomain.a == int(vec["expected"]["a"])
            assert codomain.b == int(vec["expected"]["b"])
            continue

        if op == "velu_map_point":
            c = vec["curve"]
            curve = ShortWeierstrassCurve(p=int(c["p"]), a=int(c["a"]), b=int(c["b"]))
            codomain, phi, _kernel = velu_isogeny_short_weierstrass(curve, _pt(vec["kernel_generator"]))
            got = phi(_pt(vec["point"]))
            assert got == _pt(vec["expected"])
            assert codomain.is_on_curve(got)
            continue

        raise ValueError(f"unknown op: {op}")


def test_inv_mod_rejects_zero():
    try:
        inv_mod(0, 101)
    except ZeroDivisionError:
        return
    raise AssertionError("expected ZeroDivisionError")


def test_isogeny_kernel_maps_to_infinity_and_homomorphism():
    curve = ShortWeierstrassCurve(p=101, a=2, b=3)
    kgen = (35, 15)
    codomain, phi, kernel = velu_isogeny_short_weierstrass(curve, kgen)

    for q in kernel:
        assert phi(q) is None

    candidates = [pt for pt in curve.enumerate_points() if pt is not None and pt not in set(kernel)]
    a = candidates[0]
    b = candidates[1]
    c = candidates[2]

    left = phi(curve.add(a, b))
    right = codomain.add(phi(a), phi(b))
    assert left == right

    left2 = phi(curve.add(a, curve.add(b, c)))
    right2 = codomain.add(phi(a), codomain.add(phi(b), phi(c)))
    assert left2 == right2


def test_codomain_has_same_point_count_in_demo():
    curve = ShortWeierstrassCurve(p=101, a=2, b=3)
    codomain, _phi, _kernel = velu_isogeny_short_weierstrass(curve, (35, 15))
    assert len(curve.enumerate_points()) == len(codomain.enumerate_points())


if __name__ == "__main__":
    tests = [(name, fn) for name, fn in sorted(globals().items()) if name.startswith("test_") and callable(fn)]
    failures = 0
    for name, fn in tests:
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            failures += 1
            print(f"{name}: FAIL ({type(e).__name__}: {e})")
    if failures == 0:
        print("all tests pass")
        raise SystemExit(0)
    raise SystemExit(1)
