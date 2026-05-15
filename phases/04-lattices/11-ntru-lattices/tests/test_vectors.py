import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))

from main import (  # noqa: E402
    NTRUParams,
    Sha256CtrRng,
    ntru_keygen,
    ntru_secret_is_in_lattice,
    recover_ntru_secret_via_lll,
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

            params = NTRUParams(
                n=v["params"]["n"],
                q=v["params"]["q"],
                f_ones=v["params"]["f_ones"],
                f_negs=v["params"]["f_negs"],
                g_ones=v["params"]["g_ones"],
                g_negs=v["params"]["g_negs"],
            )

            if op == "ntru_keygen":
                pk, sk = ntru_keygen(rng, params)
                got = {"h": [*pk.h], "f": [*sk.f], "g": [*sk.g]}
            elif op == "ntru_relation":
                pk, sk = ntru_keygen(rng, params)
                got = ntru_secret_is_in_lattice(sk, pk, params.q)
            elif op == "ntru_attack_lll":
                pk, sk = ntru_keygen(rng, params)
                rec = recover_ntru_secret_via_lll(pk=pk, q=params.q)
                got = {
                    "recovered": {"f": [*rec.f], "g": [*rec.g]},
                    "relation_holds": ntru_secret_is_in_lattice(rec, pk, params.q),
                    "recovered_norm2": sum(x * x for x in rec.f) + sum(x * x for x in rec.g),
                    "original_norm2": sum(x * x for x in sk.f) + sum(x * x for x in sk.g),
                }
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

