import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (
    flip_bit,
    hamming74_correct_single_bit,
    hamming74_decode,
    hamming74_encode,
    hamming74_is_codeword,
    hamming74_parity_check_matrix,
    hamming74_syndrome,
    syndrome_to_position,
)


def _all_messages_4() -> list[list[int]]:
    out: list[list[int]] = []
    for x in range(1 << 4):
        out.append([(x >> (3 - i)) & 1 for i in range(4)])
    return out


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        if op == "hamming74_parity_check_matrix":
            got = hamming74_parity_check_matrix()
        elif op == "hamming74_encode":
            got = hamming74_encode(v["message"])
        elif op == "hamming74_syndrome":
            got = hamming74_syndrome(v["received"])
        elif op == "syndrome_to_position":
            got = syndrome_to_position(v["syndrome"])
        elif op == "hamming74_correct_single_bit":
            corrected, flipped_pos = hamming74_correct_single_bit(v["received"])
            got = {"corrected": corrected, "flipped_pos": flipped_pos}
        elif op == "hamming74_decode":
            message, corrected, flipped_pos = hamming74_decode(v["received"])
            got = {"message": message, "corrected": corrected, "flipped_pos": flipped_pos}
        elif op == "hamming74_is_codeword":
            got = hamming74_is_codeword(v["word"])
        else:
            raise AssertionError(f"unknown op: {op}")

        assert got == v["expected"], f"{op} failed: got {got}, expected {v['expected']}"


def test_roundtrip_exhaustive():
    for msg in _all_messages_4():
        code = hamming74_encode(msg)
        got_msg, corrected, flipped = hamming74_decode(code)
        assert flipped is None
        assert corrected == code
        assert got_msg == msg
        assert hamming74_is_codeword(code)


def test_single_bit_correction_exhaustive():
    for msg in _all_messages_4():
        code = hamming74_encode(msg)
        for pos in range(1, 8):
            received = flip_bit(code, position=pos)

            s = hamming74_syndrome(received)
            assert syndrome_to_position(s) == pos

            got_msg, corrected, flipped = hamming74_decode(received)
            assert flipped == pos
            assert corrected == code
            assert got_msg == msg


def test_input_validation():
    try:
        hamming74_encode([0, 1, 0])
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for wrong message length")

    try:
        hamming74_encode([0, 1, 2, 0])
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for non-binary bit")

    try:
        hamming74_syndrome([0, 1, 0])
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for wrong received length")

    try:
        syndrome_to_position([0, 0, 0, 0])
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for wrong syndrome length")


if __name__ == "__main__":
    test_vectors()
    test_roundtrip_exhaustive()
    test_single_bit_correction_exhaustive()
    test_input_validation()
    print("all tests pass")

