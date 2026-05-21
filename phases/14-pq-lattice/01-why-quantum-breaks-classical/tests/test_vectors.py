import json
import math
import sys
from pathlib import Path


THIS_DIR = Path(__file__).resolve().parent
CODE_DIR = (THIS_DIR / ".." / "code").resolve()
sys.path.insert(0, str(CODE_DIR))

import main


def _load_vectors() -> dict:
    with (THIS_DIR / "vectors.json").open("r", encoding="utf-8") as f:
        return json.load(f)


def _assert_close(a: float, b: float) -> None:
    assert math.isclose(a, b, rel_tol=0.0, abs_tol=1e-12), (a, b)


def test_vectors() -> None:
    data = _load_vectors()
    assert "vectors" in data and isinstance(data["vectors"], list)

    for vec in data["vectors"]:
        op = vec["op"]
        expected = vec["expected"]

        if op == "grover_effective_security_bits":
            got = main.grover_effective_security_bits(vec["classical_security_bits"])
            _assert_close(got, expected)
            continue

        if op == "grover_required_bits_for_target_security":
            got = main.grover_required_bits_for_target_security(vec["target_security_bits"])
            assert got == expected
            continue

        if op == "bht_effective_collision_security_bits":
            got = main.bht_effective_collision_security_bits(vec["hash_output_bits"])
            _assert_close(got, expected)
            continue

        if op == "modinv":
            got = main.modinv(vec["a"], vec["m"])
            assert got == expected
            continue

        if op == "rsa_keypair_from_primes":
            n, e, d = main.rsa_keypair_from_primes(vec["p"], vec["q"], e=vec["e"])
            assert {"n": n, "e": e, "d": d} == expected
            continue

        if op == "rsa_encrypt_decrypt_roundtrip":
            n, e, d = main.rsa_keypair_from_primes(vec["p"], vec["q"], e=vec["e"])
            c = main.rsa_encrypt(vec["m"], n, e)
            m2 = main.rsa_decrypt(c, n, d)
            assert {"c": c, "m": m2} == expected
            continue

        if op == "trial_division_small_factor":
            result = main.trial_division_small_factor(vec["n"])
            assert {"factor": result.factor, "steps": result.steps} == expected
            continue

        if op == "factor_semiprime_by_trial_division":
            p, q, steps = main.factor_semiprime_by_trial_division(vec["n"])
            assert {"p": p, "q": q, "steps": steps} == expected
            continue

        if op == "break_rsa_by_factoring":
            p, q, d = main.break_rsa_by_factoring(vec["n"], vec["e"])
            assert {"p": p, "q": q, "d": d} == expected
            continue

        if op == "sha256_prefix_bits":
            got = main.sha256_prefix_bits(vec["data_utf8"].encode("utf-8"), vec["prefix_bits"])
            assert got == expected
            continue

        if op == "find_sha256_prefix_preimage":
            x, queries = main.find_sha256_prefix_preimage(
                vec["prefix_bits"], vec["target_prefix"], max_tries=vec["max_tries"]
            )
            assert {"x": x, "queries": queries} == expected
            continue

        if op == "pqc_replacement_for":
            got = main.pqc_replacement_for(vec["primitive"])
            assert got == expected
            continue

        raise AssertionError(f"unknown op: {op!r}")


def test_properties_grover_roundtrip() -> None:
    for target in [0, 1, 2, 7, 32, 64, 128]:
        required = main.grover_required_bits_for_target_security(target)
        got = main.grover_effective_security_bits(required)
        _assert_close(got, float(target))


def test_properties_sha256_prefix_range() -> None:
    for prefix_bits in [0, 1, 8, 16]:
        v = main.sha256_prefix_bits(b"test", prefix_bits)
        assert 0 <= v < (1 << prefix_bits) if prefix_bits > 0 else v == 0


def test_error_rejection() -> None:
    for bits in [-1, -10]:
        try:
            main.grover_effective_security_bits(bits)
            raise AssertionError("expected ValueError")
        except ValueError:
            pass

    for m in [0, -1]:
        try:
            main.modinv(1, m)
            raise AssertionError("expected ValueError")
        except ValueError:
            pass

    try:
        main.find_sha256_prefix_preimage(prefix_bits=8, target_prefix=256, max_tries=1)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


if __name__ == "__main__":
    test_vectors()
    test_properties_grover_roundtrip()
    test_properties_sha256_prefix_range()
    test_error_rejection()
    print("all tests pass")
