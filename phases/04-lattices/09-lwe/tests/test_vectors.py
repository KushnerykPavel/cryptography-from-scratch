import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))

from main import (
    LWEParams,
    Sha256CtrRng,
    lwe_decrypt_bit,
    lwe_encrypt_bit,
    lwe_keygen,
    recover_ternary_secret_bruteforce,
)


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        try:
            params = LWEParams(
                n=v["params"]["n"],
                m=v["params"]["m"],
                q=v["params"]["q"],
                error_bound=v["params"].get("error_bound", 1),
            )

            if op == "keygen":
                rng = Sha256CtrRng(bytes.fromhex(v["seed_hex"]))
                pk, sk = lwe_keygen(rng, params)
                got = {"A": pk.A, "b": list(pk.b), "s": list(sk.s)}
            elif op == "encdec":
                rng = Sha256CtrRng(bytes.fromhex(v["seed_hex"]))
                pk, sk = lwe_keygen(rng, params)
                ct = lwe_encrypt_bit(rng, params, pk, v["mu"])
                got = {
                    "ct": {"u": list(ct[0]), "v": ct[1]},
                    "mu_hat": lwe_decrypt_bit(params, sk, ct),
                }
            elif op == "attack":
                rng = Sha256CtrRng(bytes.fromhex(v["seed_hex"]))
                pk, _sk = lwe_keygen(rng, params)
                rec = recover_ternary_secret_bruteforce(params=params, A=pk.A, b=pk.b)
                got = None if rec is None else list(rec)
            else:
                raise AssertionError(f"unknown op {op}")
        except (ValueError, TypeError) as exc:
            assert v.get("expected_error") == str(exc), (
                f"{op} wrong error: got {exc!s}, expected {v.get('expected_error')}"
            )
            continue

        assert got == v["expected"], f"{op} failed: got {got}, expected {v['expected']}"


if __name__ == "__main__":
    test_vectors()
    print("all vectors pass")
