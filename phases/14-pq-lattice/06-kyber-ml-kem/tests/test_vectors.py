import json
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
CODE_DIR = (HERE / ".." / "code").resolve()
sys.path.insert(0, str(CODE_DIR))

import main as ky  # noqa: E402


def _load_vectors() -> dict:
    path = HERE / "vectors.json"
    return json.loads(path.read_text())


def _unhex(s: str) -> bytes:
    return bytes.fromhex(s)


def _run_vector(v: dict) -> None:
    op = v["op"]
    inputs = v["inputs"]
    expected = v["expected"]
    params = ky.MLKEM_512

    if op == "pack_bits":
        got = ky.pack_bits(inputs["values"], inputs["bits"]).hex()
        assert got == expected
        return

    if op == "unpack_bits":
        got = ky.unpack_bits(_unhex(inputs["data"]), inputs["bits"], inputs["count"])
        assert got == expected
        return

    if op == "compress_coeff":
        got = ky.compress_coeff(inputs["x"], inputs["d"])
        assert got == expected
        return

    if op == "decompress_coeff":
        got = ky.decompress_coeff(inputs["y"], inputs["d"])
        assert got == expected
        return

    if op == "sample_uniform_poly_first8":
        poly = ky.sample_uniform_poly(_unhex(inputs["rho"]), inputs["i"], inputs["j"])
        assert poly[:8] == expected
        return

    if op == "sample_cbd_poly_first8_centered":
        poly = ky.sample_cbd_poly(_unhex(inputs["seed"]), inputs["nonce"], inputs["eta"])
        got = [ky._centered_mod_q(x) for x in poly[:8]]
        assert got == expected
        return

    if op == "kpke_keygen":
        pk, sk = ky.kpke_keygen(_unhex(inputs["seed_d"]), params)
        assert pk.hex() == expected["pk"]
        assert sk.hex() == expected["sk"]
        return

    if op == "kpke_encrypt":
        ct = ky.kpke_encrypt(_unhex(inputs["pk"]), _unhex(inputs["m"]), _unhex(inputs["coins"]), params)
        assert ct.hex() == expected
        return

    if op == "kpke_decrypt":
        m = ky.kpke_decrypt(_unhex(inputs["sk"]), _unhex(inputs["ct"]), params)
        assert m.hex() == expected
        return

    if op == "ml_kem_keygen":
        ek, dk = ky.ml_kem_keygen(_unhex(inputs["seed"]), params)
        assert ek.hex() == expected["ek"]
        assert dk.hex() == expected["dk"]
        return

    if op == "ml_kem_encaps":
        ct, ss = ky.ml_kem_encaps(_unhex(inputs["ek"]), _unhex(inputs["seed"]), params)
        assert ct.hex() == expected["ct"]
        assert ss.hex() == expected["ss"]
        return

    if op == "ml_kem_decaps":
        ss = ky.ml_kem_decaps(_unhex(inputs["dk"]), _unhex(inputs["ct"]), params)
        assert ss.hex() == expected
        return

    if op == "ml_kem_decaps_tampered":
        ss = ky.ml_kem_decaps(_unhex(inputs["dk"]), _unhex(inputs["ct"]), params)
        assert ss.hex() == expected
        return

    raise ValueError(f"unknown op: {op}")


def test_vectors() -> None:
    doc = _load_vectors()
    for v in doc["vectors"]:
        _run_vector(v)


def test_bit_packing_roundtrip() -> None:
    values = [0, 1, 2, 3] * 17
    packed = ky.pack_bits(values, 2)
    unpacked = ky.unpack_bits(packed, 2, len(values))
    assert unpacked == values


def test_compress_decompress_is_close_mod_q() -> None:
    d = ky.MLKEM_512.dv
    bound = (ky.Q // (1 << (d + 1))) + 1
    for x in range(0, ky.Q, 37):
        x2 = ky.decompress_coeff(ky.compress_coeff(x, d), d)
        dist = abs(ky._centered_mod_q(x2 - x))
        assert dist <= bound


def test_poly_mul_identity_and_zero() -> None:
    one = [0] * ky.N
    one[0] = 1
    zero = [0] * ky.N

    a = [0] * ky.N
    a[0] = 123
    a[1] = 45
    a[ky.N - 1] = 7

    assert ky.poly_mul(a, one) == [x % ky.Q for x in a]
    assert ky.poly_mul(one, a) == [x % ky.Q for x in a]
    assert ky.poly_mul(a, zero) == zero
    assert ky.poly_mul(zero, a) == zero


def test_kpke_roundtrip() -> None:
    params = ky.MLKEM_512
    pk, sk = ky.kpke_keygen(bytes.fromhex("aa" * 32), params)
    msg = bytes.fromhex("bb" * 32)
    ct = ky.kpke_encrypt(pk, msg, bytes.fromhex("cc" * 32), params)
    assert len(pk) == 800
    assert len(sk) == 768
    assert len(ct) == 768
    assert ky.kpke_decrypt(sk, ct, params) == msg


def test_ml_kem_roundtrip_and_tamper() -> None:
    params = ky.MLKEM_512
    ek, dk = ky.ml_kem_keygen(bytes.fromhex("01" * 64), params)
    ct, ss1 = ky.ml_kem_encaps(ek, bytes.fromhex("02" * 32), params)
    ss2 = ky.ml_kem_decaps(dk, ct, params)
    assert ss1 == ss2

    ct_bad = ct[:-1] + bytes([ct[-1] ^ 1])
    ss_bad = ky.ml_kem_decaps(dk, ct_bad, params)
    assert ss_bad != ss2


def test_reject_bad_lengths() -> None:
    params = ky.MLKEM_512
    try:
        ky.kpke_encrypt(b"", b"", b"", params)
        raise AssertionError("expected ValueError for bad public key length")
    except ValueError:
        pass

    ek, dk = ky.ml_kem_keygen(bytes.fromhex("03" * 64), params)
    try:
        ky.ml_kem_encaps(ek, b"short", params)
        raise AssertionError("expected ValueError for bad encaps seed length")
    except ValueError:
        pass

    try:
        ky.ml_kem_decaps(dk, b"short", params)
        raise AssertionError("expected ValueError for bad ciphertext length")
    except ValueError:
        pass


def _run_all_tests() -> None:
    test_vectors()
    test_bit_packing_roundtrip()
    test_compress_decompress_is_close_mod_q()
    test_poly_mul_identity_and_zero()
    test_kpke_roundtrip()
    test_ml_kem_roundtrip_and_tamper()
    test_reject_bad_lengths()


if __name__ == "__main__":
    _run_all_tests()
    print("all tests pass")
