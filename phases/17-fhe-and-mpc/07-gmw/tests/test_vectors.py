import json
import os
import sys


THIS_DIR = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(THIS_DIR, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as gmw  # noqa: E402


def _load_vectors():
    path = os.path.join(THIS_DIR, "vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _run_vector(v):
    op = v["op"]
    if op == "xor_share_bit_seeded":
        got = list(gmw.xor_share_bit_seeded(v["bit"], v["seed"]))
        assert got == v["expected"]
        assert got[0] ^ got[1] == v["bit"]
        return

    if op == "ot1of2_simplest_bit_seeded":
        got = gmw.ot1of2_simplest_bit_seeded(
            v["m0_bit"], v["m1_bit"], v["choice"], v["seed"]
        )
        assert got == v["expected"]
        return

    if op == "gmw_and_plain_seeded":
        z0, z1, z = gmw.gmw_and_plain_seeded(v["x"], v["y"], v["seed"])
        exp = v["expected"]
        assert z0 == exp["z0"]
        assert z1 == exp["z1"]
        assert z == exp["z"]
        assert z == (v["x"] & v["y"])
        return

    if op == "gmw_eq2_plain_seeded":
        got = gmw.gmw_eq2_plain_seeded(v["a"], v["b"], v["seed"])
        assert got == v["expected"]
        assert got == (1 if v["a"] == v["b"] else 0)
        return

    raise ValueError(f"unknown op: {op}")


def test_vectors():
    data = _load_vectors()
    vectors = data["vectors"]
    assert isinstance(vectors, list)
    for v in vectors:
        _run_vector(v)


def test_xor_sharing_roundtrip():
    for seed in range(50):
        rng = gmw.HashRNG(seed)
        for bit in (0, 1):
            s0, s1 = gmw.xor_share_bit(bit, rng)
            assert gmw.xor_reconstruct(s0, s1) == bit


def test_ot1of2_simplest_bytes_correctness():
    for seed in range(10):
        rng = gmw.HashRNG(1000 + seed)
        for choice in (0, 1):
            for m0, m1 in [(b"", b""), (b"a", b"b"), (b"hello", b"world!")]:
                got = gmw.ot1of2_simplest(m0, m1, choice, rng)
                assert got == (m0 if choice == 0 else m1)


def test_gmw_and_gate_correctness_all_bits():
    for seed in range(20):
        rng = gmw.HashRNG(2000 + seed)
        for x in (0, 1):
            for y in (0, 1):
                x_sh = gmw.xor_share_bit(x, rng)
                y_sh = gmw.xor_share_bit(y, rng)
                stats = gmw.GMWStats()
                z0, z1 = gmw.gmw_and_shares(x_sh, y_sh, rng, stats=stats)
                assert (z0 ^ z1) == (x & y)
                assert stats.and_gates == 1
                assert stats.ot_calls == 2


def test_gmw_eq2_circuit_correctness():
    circuit, out_wire = gmw.build_2bit_equality_circuit()
    for seed in range(10):
        rng = gmw.HashRNG(3000 + seed)
        for a in range(4):
            for b in range(4):
                out0, out1 = gmw.gmw_eval_circuit_2pc(
                    circuit,
                    [(a >> 0) & 1, (a >> 1) & 1],
                    [(b >> 0) & 1, (b >> 1) & 1],
                    rng,
                    out_wire,
                )
                assert (out0 ^ out1) == (1 if a == b else 0)


def test_error_rejection():
    try:
        gmw.xor_share_bit(2, gmw.HashRNG(1))
        assert False, "expected ValueError"
    except ValueError:
        pass

    try:
        gmw.ot1of2_simplest(b"a", b"b", 2, gmw.HashRNG(1))
        assert False, "expected ValueError"
    except ValueError:
        pass

    try:
        gmw.gmw_eq2_plain_seeded(4, 0, 1)
        assert False, "expected ValueError"
    except ValueError:
        pass

    circuit, out_wire = gmw.build_2bit_equality_circuit()
    try:
        gmw.gmw_eval_circuit_2pc(circuit, [0], [0, 0], gmw.HashRNG(1), out_wire)
        assert False, "expected ValueError"
    except ValueError:
        pass


def _run_all():
    test_vectors()
    test_xor_sharing_roundtrip()
    test_ot1of2_simplest_bytes_correctness()
    test_gmw_and_gate_correctness_all_bits()
    test_gmw_eq2_circuit_correctness()
    test_error_rejection()


if __name__ == "__main__":
    _run_all()
    print("all tests pass")

