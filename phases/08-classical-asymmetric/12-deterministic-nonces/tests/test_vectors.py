import hashlib
import json
import os
import sys


THIS_DIR = os.path.dirname(__file__)
CODE_DIR = os.path.join(THIS_DIR, "..", "code")
sys.path.insert(0, os.path.abspath(CODE_DIR))

from main import (  # noqa: E402
    dsa_sign,
    dsa_verify,
    hash_to_int,
    recover_k_from_reused_dsa_nonce,
    recover_x_from_dsa_known_k,
    rfc6979_generate_k,
)


def _hex_to_int(s: str) -> int:
    return int(s, 16)


def _load_vectors() -> dict:
    path = os.path.join(THIS_DIR, "vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _hashfunc(name: str):
    h = getattr(hashlib, name, None)
    if h is None:
        raise ValueError(f"unknown hash: {name}")
    return h


def test_vectors():
    data = _load_vectors()
    vectors = data["vectors"]

    for vec in vectors:
        op = vec["op"]
        inputs = vec["inputs"]
        expected = vec["expected"]
        hf = _hashfunc(inputs["hash"])
        msg = inputs["message_utf8"].encode("utf-8")

        if op == "rfc6979_generate_k":
            x = _hex_to_int(inputs["x_hex"])
            q = _hex_to_int(inputs["q_hex"])
            got_k = rfc6979_generate_k(x=x, q=q, message=msg, hashfunc=hf)
            assert got_k == _hex_to_int(expected["k_hex"])
        elif op == "dsa_sign":
            p = _hex_to_int(inputs["p_hex"])
            q = _hex_to_int(inputs["q_hex"])
            g = _hex_to_int(inputs["g_hex"])
            x = _hex_to_int(inputs["x_hex"])
            r, s, k = dsa_sign(p=p, q=q, g=g, x=x, message=msg, hashfunc=hf)
            assert k == _hex_to_int(expected["k_hex"])
            assert r == _hex_to_int(expected["r_hex"])
            assert s == _hex_to_int(expected["s_hex"])
        else:
            raise ValueError(f"unknown op: {op}")


def test_rfc6979_repeatable_and_in_range():
    data = _load_vectors()
    first = next(v for v in data["vectors"] if v["op"] == "rfc6979_generate_k" and v["inputs"]["message_utf8"] == "sample")
    x = _hex_to_int(first["inputs"]["x_hex"])
    q = _hex_to_int(first["inputs"]["q_hex"])
    msg = first["inputs"]["message_utf8"].encode("utf-8")

    k1 = rfc6979_generate_k(x=x, q=q, message=msg, hashfunc=hashlib.sha256)
    k2 = rfc6979_generate_k(x=x, q=q, message=msg, hashfunc=hashlib.sha256)
    assert k1 == k2
    assert 1 <= k1 < q

    k_other = rfc6979_generate_k(x=x, q=q, message=b"test", hashfunc=hashlib.sha256)
    assert k_other != k1


def test_dsa_sign_verify_roundtrip():
    data = _load_vectors()
    vec = next(v for v in data["vectors"] if v["op"] == "dsa_sign" and v["inputs"]["message_utf8"] == "sample")
    p = _hex_to_int(vec["inputs"]["p_hex"])
    q = _hex_to_int(vec["inputs"]["q_hex"])
    g = _hex_to_int(vec["inputs"]["g_hex"])
    x = _hex_to_int(vec["inputs"]["x_hex"])
    y = pow(g, x, p)

    m = b"hello deterministic nonces"
    r, s, _ = dsa_sign(p=p, q=q, g=g, x=x, message=m, hashfunc=hashlib.sha256)
    assert dsa_verify(p=p, q=q, g=g, y=y, message=m, r=r, s=s, hashfunc=hashlib.sha256)


def test_reused_nonce_key_recovery():
    data = _load_vectors()
    vec = next(v for v in data["vectors"] if v["op"] == "dsa_sign" and v["inputs"]["message_utf8"] == "sample")
    p = _hex_to_int(vec["inputs"]["p_hex"])
    q = _hex_to_int(vec["inputs"]["q_hex"])
    g = _hex_to_int(vec["inputs"]["g_hex"])
    x = _hex_to_int(vec["inputs"]["x_hex"])

    fixed_k = 42
    m1 = b"message one"
    m2 = b"message two"
    r1, s1, _ = dsa_sign(p=p, q=q, g=g, x=x, message=m1, hashfunc=hashlib.sha256, k=fixed_k)
    r2, s2, _ = dsa_sign(p=p, q=q, g=g, x=x, message=m2, hashfunc=hashlib.sha256, k=fixed_k)
    assert r1 == r2

    h1 = hash_to_int(m1, q, hashlib.sha256)
    h2 = hash_to_int(m2, q, hashlib.sha256)
    k_rec = recover_k_from_reused_dsa_nonce(q=q, h1=h1, h2=h2, s1=s1, s2=s2)
    x_rec = recover_x_from_dsa_known_k(q=q, r=r1, s=s1, h=h1, k=k_rec)

    assert k_rec == fixed_k
    assert x_rec == x


if __name__ == "__main__":
    def _run_without_pytest() -> None:
        tests = []
        for name, obj in globals().items():
            if name.startswith("test_") and callable(obj):
                tests.append((name, obj))
        for name, fn in sorted(tests):
            fn()
        print("all tests pass")

    try:
        import pytest  # type: ignore
    except Exception:  # pragma: no cover
        _run_without_pytest()
        raise SystemExit(0)
    else:
        rc = pytest.main([__file__])
        if rc == 0:
            print("all tests pass")
        raise SystemExit(rc)
