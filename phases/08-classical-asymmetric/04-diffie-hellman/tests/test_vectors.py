import json
import sys
from pathlib import Path

try:
    import pytest  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    pytest = None


THIS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(THIS_DIR.parent / "code"))

import main as dh  # noqa: E402


def _load_vectors() -> dict:
    path = THIS_DIR / "vectors.json"
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _hex_to_bytes(s: str) -> bytes:
    return bytes.fromhex(s)


def _hex_to_int(s: str) -> int:
    return int(s, 16)

def _assert_raises(exc_type, fn, /, **kwargs):
    if pytest is not None:
        with pytest.raises(exc_type):
            fn(**kwargs)
        return
    try:
        fn(**kwargs)
    except exc_type:
        return
    except Exception as e:  # noqa: BLE001
        raise AssertionError(f"expected {exc_type.__name__}, got {type(e).__name__}") from e
    raise AssertionError(f"expected {exc_type.__name__} to be raised")


def test_vectors() -> None:
    data = _load_vectors()
    for v in data["vectors"]:
        op = v["op"]
        inputs = v["inputs"]

        if op == "modexp":
            got = dh.modexp(inputs["base"], inputs["exponent"], inputs["modulus"])
            assert got == v["expected"]
            continue

        if op == "dh_public_key":
            group = dh.DHGroup(name="tmp", p=inputs["p"], g=inputs["g"], q=None)
            got = dh.dh_public_key(group=group, private_key=inputs["private_key"])
            assert got == v["expected"]
            continue

        if op == "dh_shared_secret":
            group = dh.DHGroup(name="tmp", p=inputs["p"], g=2, q=None)
            got = dh.dh_shared_secret(
                group=group,
                private_key=inputs["private_key"],
                peer_public_key=inputs["peer_public_key"],
                validate_public_key=False,
            )
            assert got == v["expected"]
            continue

        if op == "hkdf_sha256_hex":
            got = dh.hkdf_sha256(
                ikm=_hex_to_bytes(inputs["ikm_hex"]),
                salt=_hex_to_bytes(inputs["salt_hex"]),
                info=_hex_to_bytes(inputs["info_hex"]),
                length=inputs["length"],
            )
            assert got.hex() == v["expected_hex"]
            continue

        if op == "rfc5114_group22_public_key":
            p = _hex_to_int(inputs["p_hex"])
            g = _hex_to_int(inputs["g_hex"])
            q = _hex_to_int(inputs["q_hex"])
            x = _hex_to_int(inputs["x_hex"])
            group = dh.DHGroup(name="RFC5114 group22", p=p, g=g, q=q)
            got = dh.dh_public_key(group=group, private_key=x)
            assert f"{got:x}".lower() == v["expected_y_hex"].lower()
            continue

        if op == "rfc5114_group22_shared_secret":
            p = _hex_to_int(inputs["p_hex"])
            q = _hex_to_int(inputs["q_hex"])
            xA = _hex_to_int(inputs["xA_hex"])
            yB = _hex_to_int(inputs["yB_hex"])
            group = dh.DHGroup(name="RFC5114 group22", p=p, g=2, q=q)
            got = dh.dh_shared_secret(group=group, private_key=xA, peer_public_key=yB, validate_public_key=True)
            assert f"{got:x}".lower() == v["expected_Z_hex"].lower()
            continue

        raise AssertionError(f"unknown op: {op}")


def test_modexp_matches_pow_small_random() -> None:
    rng = dh.secrets.SystemRandom()
    for _ in range(100):
        modulus = rng.randrange(3, 10_000)
        base = rng.randrange(0, 10_000)
        exponent = rng.randrange(0, 10_000)
        assert dh.modexp(base, exponent, modulus) == pow(base, exponent, modulus)


def test_dh_shared_secret_commutes_toy() -> None:
    group = dh.DHGroup(name="toy", p=23, g=5, q=None)
    a, b = 6, 15
    A = dh.dh_public_key(group=group, private_key=a)
    B = dh.dh_public_key(group=group, private_key=b)
    z1 = dh.dh_shared_secret(group=group, private_key=a, peer_public_key=B, validate_public_key=False)
    z2 = dh.dh_shared_secret(group=group, private_key=b, peer_public_key=A, validate_public_key=False)
    assert z1 == z2


def test_validate_public_key_rejects_out_of_range() -> None:
    group = dh.DHGroup(name="toy", p=23, g=5, q=None)
    for bad in [0, 1, 22, 23, 24, -1]:
        _assert_raises(ValueError, dh.validate_dh_public_key, group=group, public_key=bad)


def test_validate_public_key_rejects_wrong_subgroup() -> None:
    data = _load_vectors()
    first = next(v for v in data["vectors"] if v["op"] == "rfc5114_group22_public_key")
    p = _hex_to_int(first["inputs"]["p_hex"])
    g = _hex_to_int(first["inputs"]["g_hex"])
    q = _hex_to_int(first["inputs"]["q_hex"])
    group = dh.DHGroup(name="RFC5114 group22", p=p, g=g, q=q)

    bad = None
    for candidate in range(2, 500):
        if dh.modexp(candidate, q, p) != 1:
            bad = candidate
            break
    assert bad is not None
    _assert_raises(ValueError, dh.validate_dh_public_key, group=group, public_key=bad)


def test_hkdf_rejects_bad_length() -> None:
    _assert_raises(ValueError, dh.hkdf_sha256, ikm=b"a", salt=b"b", info=b"c", length=0)

if __name__ == "__main__":
    if pytest is not None:
        raise SystemExit(pytest.main([__file__]))

    tests = [v for k, v in globals().items() if k.startswith("test_") and callable(v)]
    for t in sorted(tests, key=lambda f: f.__name__):
        t()
    print("all tests pass")
