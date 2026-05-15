import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))

from main import (  # noqa: E402
    MLWEParams,
    RLWEParams,
    Sha256CtrRng,
    mlwe_decrypt_bit,
    mlwe_encrypt_bit,
    mlwe_keygen,
    recover_ternary_mlwe_secret_bruteforce,
    recover_ternary_rlwe_secret_bruteforce,
    rlwe_decrypt_bit,
    rlwe_encrypt_bit,
    rlwe_keygen,
)


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        try:
            seed = bytes.fromhex(v["seed_hex"])
            rng = Sha256CtrRng(seed)

            if op.startswith("rlwe_"):
                params = RLWEParams(
                    n=v["params"]["n"],
                    q=v["params"]["q"],
                    error_bound=v["params"].get("error_bound", 1),
                )
                if op == "rlwe_keygen":
                    pk, sk = rlwe_keygen(rng, params)
                    got = {"a": list(pk.a), "b": list(pk.b), "s": list(sk.s)}
                elif op == "rlwe_encdec":
                    pk, sk = rlwe_keygen(rng, params)
                    ct = rlwe_encrypt_bit(rng, params, pk, v["mu"])
                    got = {
                        "ct": {"u": list(ct[0]), "v": list(ct[1])},
                        "mu_hat": rlwe_decrypt_bit(params, sk, ct),
                    }
                elif op == "rlwe_attack":
                    pk, _sk = rlwe_keygen(rng, params)
                    rec = recover_ternary_rlwe_secret_bruteforce(params=params, a=pk.a, b=pk.b)
                    got = None if rec is None else list(rec)
                else:
                    raise AssertionError(f"unknown op {op}")
            elif op.startswith("mlwe_"):
                params = MLWEParams(
                    k=v["params"]["k"],
                    n=v["params"]["n"],
                    q=v["params"]["q"],
                    error_bound=v["params"].get("error_bound", 1),
                )
                if op == "mlwe_keygen":
                    pk, sk = mlwe_keygen(rng, params)
                    got = {"a": [[*p] for p in pk.a], "b": [*pk.b], "s": [[*p] for p in sk.s]}
                elif op == "mlwe_encdec":
                    pk, sk = mlwe_keygen(rng, params)
                    ct = mlwe_encrypt_bit(rng, params, pk, v["mu"])
                    got = {
                        "ct": {"u": [[*p] for p in ct[0]], "v": [*ct[1]]},
                        "mu_hat": mlwe_decrypt_bit(params, sk, ct),
                    }
                elif op == "mlwe_attack":
                    pk, _sk = mlwe_keygen(rng, params)
                    rec = recover_ternary_mlwe_secret_bruteforce(params=params, a=pk.a, b=pk.b)
                    got = None if rec is None else [[*p] for p in rec]
                else:
                    raise AssertionError(f"unknown op {op}")
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

