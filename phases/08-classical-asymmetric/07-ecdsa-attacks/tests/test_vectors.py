import json
import pathlib
import sys


HERE = pathlib.Path(__file__).resolve().parent
CODE_DIR = HERE.parent / "code"
sys.path.insert(0, str(CODE_DIR))

import main as ecdsa  # noqa: E402


def _as_int(x):
    if isinstance(x, int):
        return x
    if isinstance(x, str):
        return int(x, 16) if x.lower().startswith("0x") else int(x)
    raise TypeError(f"cannot parse int from {type(x)}")


def _as_bytes_from_utf8(s):
    if not isinstance(s, str):
        raise TypeError("expected utf8 string")
    return s.encode("utf-8")


def _load_vectors():
    path = HERE / "vectors.json"
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def test_vectors():
    data = _load_vectors()
    assert "vectors" in data

    for case in data["vectors"]:
        op = case["op"]
        inputs = case["inputs"]
        expected = case["expected"]

        if op == "mod_inv":
            got = ecdsa.mod_inv(_as_int(inputs["a"]), _as_int(inputs["m"]))
            assert got == _as_int(expected)
        elif op == "ecdsa_pubkey":
            got = ecdsa.ecdsa_pubkey(_as_int(inputs["priv"]))
            assert got[0] == _as_int(expected["x"])
            assert got[1] == _as_int(expected["y"])
        elif op == "ecdsa_sign_with_k":
            sig = ecdsa.ecdsa_sign_with_k(
                _as_bytes_from_utf8(inputs["msg_utf8"]),
                _as_int(inputs["priv"]),
                _as_int(inputs["k"]),
            )
            assert sig[0] == _as_int(expected["r"])
            assert sig[1] == _as_int(expected["s"])
        elif op == "ecdsa_verify":
            pub = (_as_int(inputs["pub"]["x"]), _as_int(inputs["pub"]["y"]))
            sig = (_as_int(inputs["sig"]["r"]), _as_int(inputs["sig"]["s"]))
            got = ecdsa.ecdsa_verify(_as_bytes_from_utf8(inputs["msg_utf8"]), pub, sig)
            assert got is bool(expected)
        elif op == "recover_k_from_reused_nonce":
            sig1 = (_as_int(inputs["sig1"]["r"]), _as_int(inputs["sig1"]["s"]))
            sig2 = (_as_int(inputs["sig2"]["r"]), _as_int(inputs["sig2"]["s"]))
            got = ecdsa.recover_k_from_reused_nonce(
                _as_bytes_from_utf8(inputs["msg1_utf8"]),
                sig1,
                _as_bytes_from_utf8(inputs["msg2_utf8"]),
                sig2,
            )
            assert got == _as_int(expected)
        elif op == "recover_privkey_from_reused_nonce":
            sig1 = (_as_int(inputs["sig1"]["r"]), _as_int(inputs["sig1"]["s"]))
            sig2 = (_as_int(inputs["sig2"]["r"]), _as_int(inputs["sig2"]["s"]))
            priv, k = ecdsa.recover_privkey_from_reused_nonce(
                _as_bytes_from_utf8(inputs["msg1_utf8"]),
                sig1,
                _as_bytes_from_utf8(inputs["msg2_utf8"]),
                sig2,
            )
            assert priv == _as_int(expected["priv"])
            assert k == _as_int(expected["k"])
        elif op == "recover_privkey_from_known_nonce":
            sig = (_as_int(inputs["sig"]["r"]), _as_int(inputs["sig"]["s"]))
            got = ecdsa.recover_privkey_from_known_nonce(
                _as_bytes_from_utf8(inputs["msg_utf8"]), sig, _as_int(inputs["k"])
            )
            assert got == _as_int(expected)
        elif op == "brute_force_k_from_small_range":
            got = ecdsa.brute_force_k_from_small_range(
                _as_int(inputs["r"]), _as_int(inputs["max_k"])
            )
            assert got == _as_int(expected)
        elif op == "rfc6979_nonce_sha256":
            got = ecdsa.rfc6979_nonce_sha256(
                _as_bytes_from_utf8(inputs["msg_utf8"]), _as_int(inputs["priv"])
            )
            assert got == _as_int(expected)
        else:
            raise AssertionError(f"unknown op: {op}")


def test_roundtrip_deterministic_nonce():
    msgs = [b"m0", b"m1", b"m2"]
    keys = [1, 2, 3, 0x1234, 0xBEEF]
    for d in keys:
        pub = ecdsa.ecdsa_pubkey(d)
        for msg in msgs:
            k = ecdsa.rfc6979_nonce_sha256(msg, d)
            sig = ecdsa.ecdsa_sign_with_k(msg, d, k)
            assert ecdsa.ecdsa_verify(msg, pub, sig)


def test_rejects_bad_sigs():
    d = 7
    pub = ecdsa.ecdsa_pubkey(d)
    msg = b"hello"
    k = 9
    r, s = ecdsa.ecdsa_sign_with_k(msg, d, k)

    assert not ecdsa.ecdsa_verify(msg, pub, (0, s))
    assert not ecdsa.ecdsa_verify(msg, pub, (r, 0))
    assert not ecdsa.ecdsa_verify(msg, pub, (ecdsa.SECP256K1.n, s))
    assert not ecdsa.ecdsa_verify(msg, pub, (r, ecdsa.SECP256K1.n))
    assert not ecdsa.ecdsa_verify(b"other", pub, (r, s))


def test_reused_nonce_attack_recovers_key():
    d = 123
    pub = ecdsa.ecdsa_pubkey(d)
    k = 456
    m1 = b"a"
    m2 = b"b"
    sig1 = ecdsa.ecdsa_sign_with_k(m1, d, k)
    sig2 = ecdsa.ecdsa_sign_with_k(m2, d, k)

    d_rec, k_rec = ecdsa.recover_privkey_from_reused_nonce(m1, sig1, m2, sig2)
    assert d_rec == d
    assert k_rec == k % ecdsa.SECP256K1.n
    assert ecdsa.ecdsa_verify(m1, pub, sig1)
    assert ecdsa.ecdsa_verify(m2, pub, sig2)


def test_small_nonce_bruteforce_then_key_recovery():
    d = 0x12345
    msg = b"weak"
    k = 1337
    sig = ecdsa.ecdsa_sign_with_k(msg, d, k)
    k_found = ecdsa.brute_force_k_from_small_range(sig[0], max_k=5000)
    assert k_found == k
    d_rec = ecdsa.recover_privkey_from_known_nonce(msg, sig, k_found)
    assert d_rec == d


def _run_all():
    for fn in [
        test_vectors,
        test_roundtrip_deterministic_nonce,
        test_rejects_bad_sigs,
        test_reused_nonce_attack_recovers_key,
        test_small_nonce_bruteforce_then_key_recovery,
    ]:
        fn()


if __name__ == "__main__":
    _run_all()
    print("all tests pass")

