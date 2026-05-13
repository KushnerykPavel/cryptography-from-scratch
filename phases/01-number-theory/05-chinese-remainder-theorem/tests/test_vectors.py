import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import crt, garner, rsa_crt_decrypt, rsa_crt_recombine


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        try:
            if op == "crt":
                got = crt(v["residues"], v["moduli"])
            elif op == "garner":
                got = garner(v["residues"], v["moduli"])
            elif op == "rsa_crt_recombine":
                got = rsa_crt_recombine(v["m_p"], v["m_q"], v["p"], v["q"])
            elif op == "rsa_crt_decrypt":
                got = rsa_crt_decrypt(v["ciphertext"], v["d"], v["p"], v["q"])
            else:
                raise AssertionError(f"unknown op {op}")
        except ValueError as exc:
            assert v.get("expected_error") == str(exc), (
                f"{op} wrong error: got {exc!s}, expected {v.get('expected_error')}"
            )
            continue

        expected = v["expected"]
        if isinstance(expected, list):
            expected = tuple(expected)
        assert got == expected, f"{op} failed: got {got}, expected {expected}"


if __name__ == "__main__":
    test_vectors()
    print("all vectors pass")
