import json
from pathlib import Path
import sys
from contextlib import contextmanager

try:
    import pytest  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    pytest = None


HERE = Path(__file__).resolve()
LESSON_DIR = HERE.parents[1]
CODE_DIR = LESSON_DIR / "code"
sys.path.insert(0, str(CODE_DIR))

import main as frodo  # noqa: E402


@contextmanager
def _raises(exc_type):
    try:
        yield
    except exc_type:
        return
    raise AssertionError(f"expected {exc_type.__name__} to be raised")


def _load_vectors() -> dict:
    path = LESSON_DIR / "tests" / "vectors.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _default_params():
    return frodo.DEFAULT_PARAMS


def test_vectors():
    params = _default_params()
    data = _load_vectors()
    assert "vectors" in data and isinstance(data["vectors"], list)

    for vec in data["vectors"]:
        op = vec["op"]
        inputs = vec["inputs"]
        expected = vec["expected"]

        if op == "encode":
            mu = bytes.fromhex(inputs["mu_hex"])
            got = frodo.encode(mu, params)
            assert got == expected["matrix"]

        elif op == "decode":
            got = frodo.decode(inputs["matrix"], params).hex()
            assert got == expected["mu_hex"]

        elif op == "sample_cbd":
            seed = bytes.fromhex(inputs["seed_hex"])
            got = frodo.sample_cbd(seed, inputs["count"], inputs["eta"])
            assert got == expected["samples"]

        elif op == "keygen_b":
            seed = bytes.fromhex(inputs["seed_hex"])
            pk, _sk = frodo.frodo_pke_keygen(seed, params)
            assert pk.seed_a.hex() == expected["seed_a_hex"]
            assert pk.b == expected["b"]

        elif op == "pke_encrypt":
            seed = bytes.fromhex(inputs["seed_hex"])
            mu = bytes.fromhex(inputs["mu_hex"])
            coins = bytes.fromhex(inputs["coins_hex"])
            pk, _sk = frodo.frodo_pke_keygen(seed, params)
            ct = frodo.frodo_pke_encrypt(pk, mu, coins, params)
            assert ct.bprime == expected["bprime"]
            assert ct.c == expected["c"]

        elif op == "pke_decrypt":
            seed = bytes.fromhex(inputs["seed_hex"])
            pk, sk = frodo.frodo_pke_keygen(seed, params)
            ct = frodo.FrodoCiphertext(bprime=inputs["bprime"], c=inputs["c"])
            mu_hat = frodo.frodo_pke_decrypt(ct, sk, params).hex()
            assert mu_hat == expected["mu_hex"]

        elif op == "kem_roundtrip":
            seed = bytes.fromhex(inputs["seed_hex"])
            encaps_seed = bytes.fromhex(inputs["encaps_seed_hex"])
            pk, sk = frodo.frodo_pke_keygen(seed, params)
            ct, ss = frodo.frodo_encaps(pk, encaps_seed, params)
            assert ct.bprime == expected["bprime"]
            assert ct.c == expected["c"]
            assert ss.hex() == expected["ss_hex"]

            ss2 = frodo.frodo_decaps(ct, sk, params)
            assert ss2.hex() == expected["ss2_hex"]
            assert ss2 == ss

        else:
            raise AssertionError(f"unknown vector op: {op}")


def test_encode_decode_roundtrip():
    params = _default_params()
    for tag in (b"mu0", b"mu1", b"mu2"):
        mu = frodo.expand_seed(tag, b"mu", params.mu_bytes())
        assert frodo.decode(frodo.encode(mu, params), params) == mu


def test_pke_roundtrip():
    params = _default_params()
    for seed_hex in (
        "00112233445566778899aabbccddeeff",
        "ffffffffffffffffffffffffffffffff",
        "00000000000000000000000000000000",
    ):
        seed = bytes.fromhex(seed_hex)
        pk, sk = frodo.frodo_pke_keygen(seed, params)
        mu = frodo.expand_seed(seed, b"mu", params.mu_bytes())
        coins = frodo.expand_seed(seed, b"coins", 16)
        ct = frodo.frodo_pke_encrypt(pk, mu, coins, params)
        mu_hat = frodo.frodo_pke_decrypt(ct, sk, params)
        assert mu_hat == mu


def test_kem_tamper_changes_key():
    params = _default_params()
    seed = bytes.fromhex("00112233445566778899aabbccddeeff")
    pk, sk = frodo.frodo_pke_keygen(seed, params)
    ct, ss = frodo.frodo_encaps(pk, seed=b"toy-encaps-seed", params=params)

    tampered = frodo.FrodoCiphertext(
        bprime=[row[:] for row in ct.bprime],
        c=[row[:] for row in ct.c],
    )
    tampered.c[0][0] = (tampered.c[0][0] + 1) % params.q

    ss_tampered = frodo.frodo_decaps(tampered, sk, params)
    assert ss_tampered != ss


def test_input_rejection():
    params = _default_params()
    with (pytest.raises(ValueError) if pytest else _raises(ValueError)):
        frodo.encode(b"\x00", params)
    with (pytest.raises(ValueError) if pytest else _raises(ValueError)):
        frodo.decode([[0]], params)


if __name__ == "__main__":
    if pytest:
        raise SystemExit(pytest.main([__file__, "-q"]))

    for fn in (
        test_vectors,
        test_encode_decode_roundtrip,
        test_pke_roundtrip,
        test_kem_tamper_changes_key,
        test_input_rejection,
    ):
        fn()
    print("all tests pass")
