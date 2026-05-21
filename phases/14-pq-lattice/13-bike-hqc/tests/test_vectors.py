import json
import random
import sys
from pathlib import Path


LESSON = Path(__file__).resolve().parents[1]
VECTORS_PATH = LESSON / "tests" / "vectors.json"

sys.path.insert(0, str(LESSON / "code"))
import main as bike  # noqa: E402


def call(vector):
    op = vector["op"]

    if op == "rotl":
        return bike.rotl(vector["x"], vector["r"], vector["k"])

    if op == "poly_mul_mod_xr1":
        return bike.poly_mul_mod_xr1(vector["a"], vector["b"], vector["r"])

    if op == "syndrome_bike_like":
        return bike.syndrome_bike_like(vector["h0"], vector["h1"], vector["e0"], vector["e1"], vector["r"])

    if op == "bitflip_decode_qcmdpc":
        res = bike.bitflip_decode_qcmdpc(
            vector["h0"], vector["h1"], vector["syndrome"], vector["r"], max_iters=vector.get("max_iters", 20)
        )
        return {"e0": res.e0, "e1": res.e1, "success": res.success, "final_syndrome": res.final_syndrome}

    if op == "rep3_encode":
        return bike.rep3_encode(vector["msg_bits"], vector["k"])

    if op == "rep3_decode":
        return bike.rep3_decode(vector["codeword"], vector["k"])

    if op == "toy_hqc_encrypt_fixed":
        pk = bike.ToyHqcKeypair(
            n=vector["n"],
            h=vector["h"],
            s=vector["s"],
            x=0,
            y=vector["y"],
            k=vector["k"],
        )
        ct = bike.toy_hqc_encrypt_fixed(pk, vector["msg_bits"], r1=vector["r1"], r2=vector["r2"], e=vector["e"])
        return {"u": ct.u, "v": ct.v}

    if op == "toy_hqc_decrypt":
        sk = bike.ToyHqcKeypair(
            n=vector["n"],
            h=vector["h"],
            s=vector["s"],
            x=0,
            y=vector["y"],
            k=vector["k"],
        )
        ct = bike.ToyHqcCiphertext(n=vector["n"], u=vector["u"], v=vector["v"])
        return bike.toy_hqc_decrypt(sk, ct)

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


def test_rotl_composition():
    rng = random.Random(0)
    for _ in range(200):
        r = rng.randrange(1, 64)
        x = rng.getrandbits(r)
        k1 = rng.randrange(0, 10 * r)
        k2 = rng.randrange(0, 10 * r)
        assert bike.rotl(bike.rotl(x, r, k1), r, k2) == bike.rotl(x, r, k1 + k2)


def test_poly_mul_is_bilinear():
    rng = random.Random(1)
    r = 17
    for _ in range(200):
        a = rng.getrandbits(r)
        b = rng.getrandbits(r)
        c = rng.getrandbits(r)
        left = bike.poly_mul_mod_xr1(a ^ b, c, r)
        right = bike.poly_mul_mod_xr1(a, c, r) ^ bike.poly_mul_mod_xr1(b, c, r)
        assert left == right


def test_syndrome_matches_column_xor():
    rng = random.Random(2)
    r = 19
    h0 = bike.sample_fixed_weight(r, 5, rng)
    h1 = bike.sample_fixed_weight(r, 5, rng)
    cols = bike.columns_from_parity_polys(h0, h1, r)

    for _ in range(200):
        e0, e1 = bike.split_weight_across_two_blocks(r, total_weight=3, rng=rng)
        s1 = bike.syndrome_bike_like(h0, h1, e0, e1, r)

        s2 = 0
        for i in bike.poly_positions(e0, r):
            s2 ^= cols[i]
        for i in bike.poly_positions(e1, r):
            s2 ^= cols[r + i]
        s2 &= bike.mask_r(r)
        assert s1 == s2


def test_bitflip_decodes_single_error_for_toy_key():
    r = 7
    h0 = bike.poly_from_positions(r, [0, 2])
    h1 = bike.poly_from_positions(r, [1, 2])
    rng = random.Random(3)

    for _ in range(200):
        e0, e1 = bike.split_weight_across_two_blocks(r, total_weight=1, rng=rng)
        s = bike.syndrome_bike_like(h0, h1, e0, e1, r)
        res = bike.bitflip_decode_qcmdpc(h0, h1, s, r, max_iters=10)
        assert res.success
        assert bike.syndrome_bike_like(h0, h1, res.e0, res.e1, r) == s
        assert bike.popcount(res.e0) + bike.popcount(res.e1) == 1


def test_toy_hqc_roundtrip_fixed_ciphertext():
    n = 21
    k = 7
    sk = bike.ToyHqcKeypair(n=n, h=1, s=1, x=0, y=0, k=k)
    msg = 0b1011010
    ct = bike.toy_hqc_encrypt_fixed(sk, msg, r1=0, r2=1 << 3, e=1 << 6)
    assert bike.toy_hqc_decrypt(sk, ct) == msg


if __name__ == "__main__":
    test_vectors()
    test_rotl_composition()
    test_poly_mul_is_bilinear()
    test_syndrome_matches_column_xor()
    test_bitflip_decodes_single_error_for_toy_key()
    test_toy_hqc_roundtrip_fixed_ciphertext()
    print("all tests pass")

