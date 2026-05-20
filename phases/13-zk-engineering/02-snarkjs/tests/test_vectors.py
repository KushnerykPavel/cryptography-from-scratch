import json
import os
import sys


THIS_DIR = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(THIS_DIR, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as snark  # noqa: E402


def _load_vectors():
    path = os.path.join(THIS_DIR, "vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def test_vectors():
    data = _load_vectors()
    vectors = data["vectors"]

    for v in vectors:
        op = v["op"]
        inputs = v["inputs"]
        expected = v["expected"]

        if op == "canonical_json_dumps":
            got = snark.canonical_json_dumps(inputs["obj"])
            assert got == expected
        elif op == "sha256_hex":
            got = snark.sha256_hex(inputs["text"].encode("utf-8"))
            assert got == expected
        elif op == "normalize_g1_point":
            got = snark.normalize_g1_point(inputs["point"], field=inputs["field"])
            assert list(got) == expected
        elif op == "sha256_json_vk":
            got = snark.sha256_json(inputs["verification_key"])
            assert got == expected
        elif op == "sha256_json_public":
            got = snark.sha256_json(inputs["public_signals"])
            assert got == expected
        elif op == "sha256_json_proof":
            got = snark.sha256_json(inputs["proof"])
            assert got == expected
        elif op == "bundle_manifest_hashes":
            bundle = snark.validate_groth16_bundle(
                verification_key=inputs["verification_key"],
                public_signals=inputs["public_signals"],
                proof=inputs["proof"],
            )
            manifest = snark.build_bundle_manifest(bundle)
            assert manifest["sha256"] == expected
        else:
            raise AssertionError(f"unknown op: {op}")


def test_canonical_json_dumps_is_stable_over_key_ordering():
    obj1 = {"b": 1, "a": 2, "c": {"y": 9, "x": 8}}
    obj2 = {"c": {"x": 8, "y": 9}, "a": 2, "b": 1}
    assert snark.canonical_json_dumps(obj1) == snark.canonical_json_dumps(obj2)


def test_sha256_json_is_stable_for_equivalent_objects():
    obj1 = {"k": [3, 2, 1], "z": {"b": 2, "a": 1}}
    obj2 = {"z": {"a": 1, "b": 2}, "k": [3, 2, 1]}
    assert snark.sha256_json(obj1) == snark.sha256_json(obj2)


def test_validate_bundle_rejects_ic_length_mismatch():
    vk = {
        "protocol": "groth16",
        "curve": "bn128",
        "nPublic": 2,
        "vk_alpha_1": ["1", "2"],
        "vk_beta_2": [["3", "4"], ["5", "6"]],
        "vk_gamma_2": [["7", "8"], ["9", "10"]],
        "vk_delta_2": [["11", "12"], ["13", "14"]],
        "IC": [["15", "16"], ["17", "18"]],  # should be 3 points for nPublic=2
    }
    public = ["42", "1337"]
    proof = {
        "protocol": "groth16",
        "curve": "bn128",
        "pi_a": ["21", "22", "1"],
        "pi_b": [["23", "24"], ["25", "26"], ["1", "0"]],
        "pi_c": ["27", "28", "1"],
    }

    try:
        snark.validate_groth16_bundle(verification_key=vk, public_signals=public, proof=proof)
        assert False, "expected ValueError"
    except ValueError as e:
        assert "IC length mismatch" in str(e)


def test_validate_bundle_rejects_non_decimal_public_signal():
    vk = {
        "protocol": "groth16",
        "curve": "bn128",
        "nPublic": 1,
        "vk_alpha_1": ["1", "2"],
        "vk_beta_2": [["3", "4"], ["5", "6"]],
        "vk_gamma_2": [["7", "8"], ["9", "10"]],
        "vk_delta_2": [["11", "12"], ["13", "14"]],
        "IC": [["15", "16"], ["17", "18"]],
    }
    public = ["not-a-number"]
    proof = {
        "protocol": "groth16",
        "curve": "bn128",
        "pi_a": ["21", "22", "1"],
        "pi_b": [["23", "24"], ["25", "26"], ["1", "0"]],
        "pi_c": ["27", "28", "1"],
    }

    try:
        snark.validate_groth16_bundle(verification_key=vk, public_signals=public, proof=proof)
        assert False, "expected ValueError"
    except ValueError as e:
        assert "public_signals[0]" in str(e)


def test_validate_bundle_rejects_curve_mismatch():
    vk = {
        "protocol": "groth16",
        "curve": "bn128",
        "nPublic": 0,
        "vk_alpha_1": ["1", "2"],
        "vk_beta_2": [["3", "4"], ["5", "6"]],
        "vk_gamma_2": [["7", "8"], ["9", "10"]],
        "vk_delta_2": [["11", "12"], ["13", "14"]],
        "IC": [["15", "16"]],
    }
    public = []
    proof = {
        "protocol": "groth16",
        "curve": "bls12-381",
        "pi_a": ["21", "22", "1"],
        "pi_b": [["23", "24"], ["25", "26"], ["1", "0"]],
        "pi_c": ["27", "28", "1"],
    }

    try:
        snark.validate_groth16_bundle(verification_key=vk, public_signals=public, proof=proof)
        assert False, "expected ValueError"
    except ValueError as e:
        assert "curve mismatch" in str(e)


if __name__ == "__main__":
    try:
        import pytest  # type: ignore

        rc = pytest.main([__file__])
        if rc != 0:
            raise SystemExit(rc)
    except ImportError:
        test_vectors()
        test_canonical_json_dumps_is_stable_over_key_ordering()
        test_sha256_json_is_stable_for_equivalent_objects()
        test_validate_bundle_rejects_ic_length_mismatch()
        test_validate_bundle_rejects_non_decimal_public_signal()
        test_validate_bundle_rejects_curve_mismatch()

    print("all tests pass")

