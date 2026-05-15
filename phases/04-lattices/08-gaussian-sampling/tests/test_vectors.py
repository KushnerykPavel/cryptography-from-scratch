import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import Sha256CtrRng, build_discrete_gaussian_cdf, sample_discrete_gaussian_vector


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        try:
            if op == "build":
                sampler = build_discrete_gaussian_cdf(
                    sigma=v["sigma"],
                    center=v.get("center", 0),
                    tail=v.get("tail"),
                    precision=v.get("precision", 80),
                )
                got = {
                    "support": [sampler.values[0], sampler.values[-1]],
                    "support_len": len(sampler.values),
                    "cdf_last": sampler.cdf_ends[-1],
                }
            elif op == "sample":
                rng = Sha256CtrRng(bytes.fromhex(v["seed_hex"]))
                sampler = build_discrete_gaussian_cdf(
                    sigma=v["sigma"],
                    center=v.get("center", 0),
                    tail=v.get("tail"),
                    precision=v.get("precision", 80),
                )
                got = [sampler.sample(rng) for _ in range(v["count"])]
            elif op == "sample_vec":
                rng = Sha256CtrRng(bytes.fromhex(v["seed_hex"]))
                got = list(
                    sample_discrete_gaussian_vector(
                        rng=rng,
                        dim=v["dim"],
                        sigma=v["sigma"],
                        center=v.get("center", 0),
                        tail=v.get("tail"),
                    )
                )
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

