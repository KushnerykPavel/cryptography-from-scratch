import json
import os
import random
import sys


HERE = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as hd  # noqa: E402


def load_vectors():
    path = os.path.join(HERE, "vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def from_hex(s: str) -> bytes:
    if not isinstance(s, str):
        raise TypeError("hex input must be a string")
    return bytes.fromhex(s)


def run_vector(v):
    op = v["op"]
    inputs = v.get("inputs", {})
    expected = v["expected"]

    if op == "hamming_weight":
        got = hd.hamming_weight(inputs["v"])
        assert got == expected
        return

    if op == "hamming_distance":
        got = hd.hamming_distance(inputs["a"], inputs["b"])
        assert got == expected
        return

    if op == "hamming_distance_bytes":
        a = from_hex(inputs["a_hex"])
        b = from_hex(inputs["b_hex"])
        got = hd.hamming_distance_bytes(a, b)
        assert got == expected
        return

    if op == "normalized_hamming_distance_bytes":
        a = from_hex(inputs["a_hex"])
        b = from_hex(inputs["b_hex"])
        got = hd.normalized_hamming_distance_bytes(a, b)
        assert got == expected
        return

    if op == "minimum_distance":
        got = hd.minimum_distance(inputs["codewords"])
        assert got == expected
        return

    if op == "max_detectable_errors":
        got = hd.max_detectable_errors(inputs["d_min"])
        assert got == expected
        return

    if op == "max_correctable_errors":
        got = hd.max_correctable_errors(inputs["d_min"])
        assert got == expected
        return

    if op == "nearest_neighbor_decode":
        decoded, dist = hd.nearest_neighbor_decode(inputs["received"], inputs["codewords"])
        assert decoded == expected["decoded"]
        assert dist == expected["distance"]
        return

    raise ValueError(f"unknown op: {op}")


def test_vectors():
    data = load_vectors()
    for v in data["vectors"]:
        run_vector(v)


def gen_bits(rng: random.Random, n: int) -> list[int]:
    return [rng.randrange(2) for _ in range(n)]


def test_hamming_distance_properties_small_random():
    rng = random.Random(1337)
    for n in range(0, 12):
        for _ in range(100):
            a = gen_bits(rng, n)
            b = gen_bits(rng, n)
            c = gen_bits(rng, n)

            dab = hd.hamming_distance(a, b)
            dba = hd.hamming_distance(b, a)
            dac = hd.hamming_distance(a, c)
            dbc = hd.hamming_distance(b, c)

            assert dab == dba
            assert dab >= 0
            assert hd.hamming_distance(a, a) == 0
            assert dab <= dac + dbc


def test_byte_distance_matches_bitvector_distance_for_single_byte():
    for x in range(256):
        for y in range(256):
            d = hd.hamming_distance_bytes(bytes([x]), bytes([y]))
            expected = (x ^ y).bit_count()
            assert d == expected


def test_minimum_distance_simple_codes():
    repetition3 = [[0, 0, 0], [1, 1, 1]]
    d_min = hd.minimum_distance(repetition3)
    assert d_min == 3
    assert hd.max_detectable_errors(d_min) == 2
    assert hd.max_correctable_errors(d_min) == 1

    code_00_11 = [[0, 0], [1, 1]]
    assert hd.minimum_distance(code_00_11) == 2
    assert hd.max_correctable_errors(2) == 0


def test_nearest_neighbor_decodes_within_correction_radius_repetition3():
    codewords = [[0, 0, 0], [1, 1, 1]]
    for received in ([0, 0, 0], [0, 1, 0], [1, 1, 1], [1, 0, 1]):
        decoded, dist = hd.nearest_neighbor_decode(list(received), codewords)
        assert decoded in codewords
        assert dist == min(hd.hamming_distance(list(received), c) for c in codewords)


def test_nearest_neighbor_ambiguity_is_rejected():
    codewords = [[0, 0], [1, 1]]
    try:
        hd.nearest_neighbor_decode([0, 1], codewords)
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_rejects_wrong_lengths_and_non_binary_inputs():
    try:
        hd.hamming_distance([0], [0, 1])
        assert False, "expected ValueError"
    except ValueError:
        pass

    try:
        hd.hamming_distance_bytes(b"a", b"ab")
        assert False, "expected ValueError"
    except ValueError:
        pass

    try:
        hd.hamming_weight([2])
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_normalized_distance_rejects_empty():
    try:
        hd.normalized_hamming_distance_bytes(b"", b"")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_minimum_distance_requires_at_least_two_codewords():
    try:
        hd.minimum_distance([[0, 0, 0]])
        assert False, "expected ValueError"
    except ValueError:
        pass


if __name__ == "__main__":
    test_vectors()
    test_hamming_distance_properties_small_random()
    test_byte_distance_matches_bitvector_distance_for_single_byte()
    test_minimum_distance_simple_codes()
    test_nearest_neighbor_decodes_within_correction_radius_repetition3()
    test_nearest_neighbor_ambiguity_is_rejected()
    test_rejects_wrong_lengths_and_non_binary_inputs()
    test_normalized_distance_rejects_empty()
    test_minimum_distance_requires_at_least_two_codewords()
    print("all tests pass")

