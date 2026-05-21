import json
import os
import random
import sys
from contextlib import contextmanager

try:
    import pytest  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    pytest = None

HERE = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as mldsa  # noqa: E402


@contextmanager
def _raises(exc_type):
    try:
        yield
    except exc_type:
        return
    raise AssertionError(f"expected {exc_type.__name__} to be raised")


def test_vectors():
    with open(os.path.join(HERE, "vectors.json"), "r", encoding="utf-8") as f:
        data = json.load(f)

    for vec in data["vectors"]:
        op = vec["op"]

        if op == "poly_mul_negacyclic":
            got = mldsa.poly_mul_negacyclic(vec["a"], vec["b"], int(vec["q"]))
        elif op == "decompose_coeff":
            got = list(mldsa.decompose_coeff(int(vec["r"]), int(vec["q"]), int(vec["alpha"])))
        elif op == "hint_roundtrip":
            q = int(vec["q"])
            alpha = int(vec["alpha"])
            r = vec["r"]
            z = vec["z"]
            hint = mldsa.make_hint(z, r, q, alpha)
            hb = mldsa.high_bits(mldsa.poly_add(r, z, q), q, alpha)
            hb2 = mldsa.use_hint(hint, r, q, alpha)
            got = {"hint": hint, "high_bits_r_plus_z": hb, "use_hint": hb2}
        elif op == "keygen_pk_encode":
            seed = bytes.fromhex(vec["seed"])
            pk, _sk = mldsa.toy_mldsa_keygen(seed)
            got = pk.encode().hex()
        elif op == "sign_det":
            seed = bytes.fromhex(vec["seed"])
            _pk, sk = mldsa.toy_mldsa_keygen(seed)
            sig = mldsa.toy_mldsa_sign_det(sk, vec["msg"].encode("utf-8"))
            got = {"c_seed": sig.c_seed.hex(), "z": sig.z, "h": sig.h}
        elif op == "verify":
            seed = bytes.fromhex(vec["seed"])
            pk, _sk = mldsa.toy_mldsa_keygen(seed)
            sig_in = vec["sig"]
            sig = mldsa.Signature(
                c_seed=bytes.fromhex(sig_in["c_seed"]), z=sig_in["z"], h=sig_in["h"]
            )
            got = mldsa.toy_mldsa_verify(pk, vec["msg"].encode("utf-8"), sig)
        else:
            raise ValueError(f"unknown op in vectors.json: {op}")

        assert got == vec["expected"], f"vector failed: op={op}"


def test_hint_roundtrip_for_small_z():
    rng = random.Random(0)
    q = mldsa.TOY_Q
    alpha = mldsa.TOY_ALPHA
    for _ in range(100):
        r = [rng.randrange(q) for _ in range(mldsa.TOY_N)]
        z = [rng.randrange(-alpha // 2, alpha // 2 + 1) % q for _ in range(mldsa.TOY_N)]
        h = mldsa.make_hint(z, r, q, alpha)
        hb = mldsa.high_bits(mldsa.poly_add(r, z, q), q, alpha)
        hb2 = mldsa.use_hint(h, r, q, alpha)
        assert hb2 == hb


def test_sign_verify_roundtrip_multiple_messages():
    seed = bytes.fromhex("11" * 32)
    pk, sk = mldsa.toy_mldsa_keygen(seed)
    for msg in [b"", b"a", b"abc", b"hello", b"\x00" * 32]:
        sig = mldsa.toy_mldsa_sign_det(sk, msg)
        assert mldsa.toy_mldsa_verify(pk, msg, sig) is True
        assert mldsa.toy_mldsa_verify(pk, msg + b"!", sig) is False


def test_verify_rejects_bad_signature_shapes():
    seed = bytes.fromhex("22" * 32)
    pk, sk = mldsa.toy_mldsa_keygen(seed)
    msg = b"shape test"
    sig = mldsa.toy_mldsa_sign_det(sk, msg)
    bad = mldsa.Signature(c_seed=sig.c_seed, z=sig.z, h=sig.h[:-1])
    assert mldsa.toy_mldsa_verify(pk, msg, bad) is False


def test_decompose_rejects_bad_alpha():
    cm = pytest.raises(ValueError) if pytest else _raises(ValueError)
    with cm:
        mldsa.decompose_coeff(0, mldsa.TOY_Q, 5)


if __name__ == "__main__":
    if pytest:
        raise SystemExit(pytest.main([__file__, "-q"]))

    tests = [
        test_vectors,
        test_hint_roundtrip_for_small_z,
        test_sign_verify_roundtrip_multiple_messages,
        test_verify_rejects_bad_signature_shapes,
        test_decompose_rejects_bad_alpha,
    ]
    for t in tests:
        t()
    print("all tests pass")
