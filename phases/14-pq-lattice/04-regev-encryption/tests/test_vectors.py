import json
import os
import sys


THIS_DIR = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(THIS_DIR, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as regev  # noqa: E402


def _load_vectors():
    path = os.path.join(THIS_DIR, "vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _params_from_json(p: dict) -> regev.RegevParams:
    return regev.RegevParams(n=p["n"], m=p["m"], q=p["q"], error_bound=p.get("error_bound", 1))


def test_vectors():
    data = _load_vectors()
    vectors = data["vectors"]

    for v in vectors:
        op = v["op"]
        inputs = v["inputs"]
        expected = v["expected"]

        if op == "center_lift":
            got = regev.center_lift(inputs["x"], inputs["q"])
            assert got == expected
        elif op == "mat_vec_mul_mod":
            A = inputs["A"]
            x = tuple(inputs["x"])
            got = regev.mat_vec_mul_mod(A, x, inputs["q"])
            assert list(got) == expected
        elif op == "mat_t_vec_mul_mod":
            A = inputs["A"]
            r = tuple(inputs["r"])
            got = regev.mat_t_vec_mul_mod(A, r, inputs["q"])
            assert list(got) == expected
        elif op == "bits_from_bytes":
            data_bytes = bytes.fromhex(inputs["data"])
            got = regev.bits_from_bytes(data_bytes)
            assert got == expected
        elif op == "bytes_from_bits":
            got = regev.bytes_from_bits(inputs["bits"])
            assert got.hex() == expected
        elif op == "regev_keygen":
            params = _params_from_json(inputs["params"])
            rng = regev.Sha256CtrRng(inputs["seed"].encode("utf-8"))
            pk, sk = regev.regev_keygen(rng, params)
            assert pk.A == expected["A"]
            assert list(pk.b) == expected["b"]
            assert list(sk.s) == expected["s"]
        elif op == "regev_encrypt_bit":
            params = _params_from_json(inputs["params"])
            pkj = inputs["pk"]
            pk = regev.RegevPublicKey(A=pkj["A"], b=tuple(pkj["b"]))
            rng = regev.Sha256CtrRng(inputs["seed"].encode("utf-8"))
            u, vv = regev.regev_encrypt_bit(rng, params, pk, inputs["mu"])
            assert list(u) == expected["u"]
            assert vv == expected["v"]
        elif op == "regev_decrypt_bit":
            params = _params_from_json(inputs["params"])
            sk = regev.RegevSecretKey(s=tuple(inputs["sk"]["s"]))
            ct = (tuple(inputs["ct"]["u"]), inputs["ct"]["v"])
            got = regev.regev_decrypt_bit(params, sk, ct)
            assert got == expected
        elif op == "hybrid_encrypt":
            params = _params_from_json(inputs["params"])
            pkj = inputs["pk"]
            pk = regev.RegevPublicKey(A=pkj["A"], b=tuple(pkj["b"]))
            rng = regev.Sha256CtrRng(inputs["seed"].encode("utf-8"))
            plaintext = bytes.fromhex(inputs["plaintext"])
            payload = regev.hybrid_encrypt(rng, params, pk, plaintext, key_len=inputs["key_len"])
            assert payload["ciphertext"].hex() == expected["ciphertext"]
            got_cts = [{"u": list(u), "v": vvv} for (u, vvv) in payload["kem_ct"]]
            assert got_cts == expected["kem_ct"]
        else:
            raise AssertionError(f"unknown op: {op}")


def test_encrypt_decrypt_roundtrip_many_bits():
    params = regev.RegevParams(n=4, m=8, q=97, error_bound=1)
    rng = regev.Sha256CtrRng(b"roundtrip-seed")
    pk, sk = regev.regev_keygen(rng, params)

    bits = [rng.randbelow(2) for _ in range(64)]
    cts = regev.regev_encrypt_bits(rng, params, pk, bits)
    got = regev.regev_decrypt_bits(params, sk, cts)
    assert got == bits


def test_hybrid_roundtrip():
    params = regev.RegevParams(n=4, m=8, q=97, error_bound=1)
    rng = regev.Sha256CtrRng(b"hybrid-roundtrip")
    pk, sk = regev.regev_keygen(rng, params)

    msg = b"hello hybrid"
    payload = regev.hybrid_encrypt(rng, params, pk, msg, key_len=4)
    pt = regev.hybrid_decrypt(params, sk, payload)
    assert pt == msg


def test_bytes_bits_roundtrip():
    data = bytes.fromhex("00112233aabbccdd")
    bits = regev.bits_from_bytes(data)
    out = regev.bytes_from_bits(bits)
    assert out == data


def test_bytes_from_bits_rejects_non_multiple_of_8():
    try:
        regev.bytes_from_bits([1, 0, 1])
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_encrypt_rejects_non_bit_mu():
    params = regev.RegevParams(n=4, m=8, q=97, error_bound=1)
    rng = regev.Sha256CtrRng(b"bad-mu")
    pk, _ = regev.regev_keygen(rng, params)
    try:
        regev.regev_encrypt_bit(rng, params, pk, 2)
        assert False, "expected ValueError"
    except ValueError:
        pass


if __name__ == "__main__":
    try:
        import pytest  # type: ignore

        rc = pytest.main([__file__])
        if rc != 0:
            raise SystemExit(rc)
    except ImportError:
        test_vectors()
        test_encrypt_decrypt_roundtrip_many_bits()
        test_hybrid_roundtrip()
        test_bytes_bits_roundtrip()
        test_bytes_from_bits_rejects_non_multiple_of_8()
        test_encrypt_rejects_non_bit_mu()

    print("all tests pass")

