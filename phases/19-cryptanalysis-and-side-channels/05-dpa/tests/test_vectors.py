import json
import os
import sys

HERE = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as dpa  # noqa: E402


def test_vectors():
    with open(os.path.join(HERE, "vectors.json"), "r", encoding="utf-8") as f:
        data = json.load(f)

    for vec in data["vectors"]:
        op = vec["op"]
        if op == "hamming_weight":
            got = dpa.hamming_weight(int(vec["x"]))
        elif op == "leakage_model":
            got = dpa.leakage_model(int(vec["pt"]), int(vec["k"]))
        elif op == "pearson_corr":
            got = dpa.pearson_corr([float(x) for x in vec["xs"]], [float(y) for y in vec["ys"]])
        else:
            raise ValueError(f"unknown op in vectors.json: {op}")
        if op == "pearson_corr":
            assert abs(got - float(vec["expected"])) < 1e-12, f"vector failed: op={op}"
        else:
            assert got == vec["expected"], f"vector failed: op={op}"


def test_cpa_recovers_key_byte_noiseless():
    key_byte = 0x3A
    traces = dpa.simulate_traces(key_byte, range(256))
    got_k, _ = dpa.recover_key_byte_cpa(traces)
    assert got_k == key_byte


if __name__ == "__main__":
    tests = [
        test_vectors,
        test_cpa_recovers_key_byte_noiseless,
    ]
    for t in tests:
        t()
    print("all tests pass")
