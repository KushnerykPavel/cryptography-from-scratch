import json
import os
import random
import sys
from math import gcd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (
    common_modulus_attack,
    crt_combine,
    hastad_broadcast_attack,
    integer_nth_root_floor,
    is_perfect_nth_power,
    modinv,
    rsa_decrypt_int,
    rsa_encrypt_int,
    wiener_attack_recover_key,
)


def call(vector):
    op = vector["op"]

    if op == "modinv":
        return modinv(vector["a"], vector["n"])
    if op == "crt_combine":
        pairs = [(int(a), int(n)) for a, n in vector["pairs"]]
        x, n = crt_combine(pairs)
        return [x, n]
    if op == "integer_nth_root_floor":
        return integer_nth_root_floor(vector["x"], vector["n"])
    if op == "is_perfect_nth_power":
        return is_perfect_nth_power(vector["x"], vector["n"])
    if op == "common_modulus_attack":
        return common_modulus_attack(
            n=vector["n"],
            e1=vector["e1"],
            e2=vector["e2"],
            c1=vector["c1"],
            c2=vector["c2"],
        )
    if op == "hastad_broadcast_attack":
        return hastad_broadcast_attack(cs=vector["cs"], ns=vector["ns"], e=vector["e"])
    if op == "wiener_attack_recover_key":
        key = wiener_attack_recover_key(e=vector["e"], n=vector["n"])
        return None if key is None else list(key)

    raise AssertionError(f"unknown op {op}")


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    assert isinstance(data["source"], str)
    assert isinstance(data["vectors"], list)

    for v in data["vectors"]:
        op = v["op"]
        try:
            got = call(v)
        except ValueError as exc:
            assert v.get("expected_error") == str(exc), (
                f"{op} wrong error: got {exc!s}, expected {v.get('expected_error')}"
            )
            continue

        assert got == v["expected"], f"{op} failed: got {got}, expected {v['expected']}"


def test_properties_modinv():
    for n in [3, 5, 97, 101, 65537]:
        for a in [1, 2, 3, 5, 42, n - 1, n + 1]:
            aa = a % n
            if gcd(aa, n) != 1:
                continue
            inv = modinv(aa, n)
            assert (aa * inv) % n == 1


def test_properties_crt_roundtrip():
    rng = random.Random(0)
    primes = [101, 103, 107, 109, 113]
    for _ in range(25):
        moduli = rng.sample(primes, 3)
        remainders = [rng.randrange(0, m) for m in moduli]
        x, n = crt_combine(list(zip(remainders, moduli)))
        assert n == moduli[0] * moduli[1] * moduli[2]
        for a_i, n_i in zip(remainders, moduli):
            assert x % n_i == a_i % n_i


def test_properties_integer_nth_root():
    rng = random.Random(1)
    for n in [2, 3, 5]:
        for _ in range(50):
            x = rng.randrange(0, 10**12)
            r = integer_nth_root_floor(x, n)
            assert r**n <= x
            assert (r + 1) ** n > x


def test_properties_common_modulus_attack_recovers_plaintext():
    n = 101 * 113
    m = 42
    e1, e2 = 17, 13
    c1 = rsa_encrypt_int(m, e1, n)
    c2 = rsa_encrypt_int(m, e2, n)
    assert common_modulus_attack(n=n, e1=e1, e2=e2, c1=c1, c2=c2) == m


def test_properties_hastad_rejects_non_perfect_power():
    ns = [101 * 107, 113 * 131, 137 * 149]
    e = 3
    m = 1234
    cs = [rsa_encrypt_int(m, e, n_i) for n_i in ns]
    assert hastad_broadcast_attack(cs=cs, ns=ns, e=e) == m

    cs_bad = list(cs)
    cs_bad[0] = (cs_bad[0] + 1) % ns[0]
    try:
        hastad_broadcast_attack(cs=cs_bad, ns=ns, e=e)
    except ValueError as exc:
        assert str(exc) == "combined value is not a perfect e-th power"
    else:
        raise AssertionError("expected hastad_broadcast_attack to reject")


def test_properties_wiener_recovery_and_non_recovery():
    p, q = 101, 107
    n = p * q
    phi = (p - 1) * (q - 1)

    d_small = 3
    e_small = modinv(d_small, phi)
    key = wiener_attack_recover_key(e=e_small, n=n)
    assert key is not None
    rp, rq, rd = key
    assert rp * rq == n
    assert rd == d_small

    msg = 99
    c = rsa_encrypt_int(msg, e_small, n)
    assert rsa_decrypt_int(c, rd, n) == msg

    e_safe = 17
    key2 = wiener_attack_recover_key(e=e_safe, n=n)
    assert key2 is None


if __name__ == "__main__":
    test_vectors()
    test_properties_modinv()
    test_properties_crt_roundtrip()
    test_properties_integer_nth_root()
    test_properties_common_modulus_attack_recovers_plaintext()
    test_properties_hastad_rejects_non_perfect_power()
    test_properties_wiener_recovery_and_non_recovery()
    print("all tests pass")

