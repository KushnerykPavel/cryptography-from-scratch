import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import parse_threat_model_spec, render_threat_model_markdown


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]
        if op == "render":
            spec = parse_threat_model_spec(v["spec"])
            got = render_threat_model_markdown(spec)
            assert got == v["expected"], f"render failed: got {got!r}, expected {v['expected']!r}"
        elif op == "parse_error":
            try:
                parse_threat_model_spec(v["spec"])
            except ValueError as exc:
                assert str(exc) == v["expected_error"], (
                    f"wrong error: got {exc!s}, expected {v['expected_error']}"
                )
            else:
                raise AssertionError("expected ValueError")
        else:
            raise AssertionError(f"unknown op {op}")


if __name__ == "__main__":
    test_vectors()
    print("all vectors pass")

