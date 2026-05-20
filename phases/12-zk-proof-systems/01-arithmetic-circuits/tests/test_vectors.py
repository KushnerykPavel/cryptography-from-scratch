import json
import random
import sys
from pathlib import Path


LESSON = Path(__file__).resolve().parents[1]
VECTORS_PATH = LESSON / "tests" / "vectors.json"

sys.path.insert(0, str(LESSON / "code"))
import main as ac  # noqa: E402


def call(vector):
    op = vector["op"]

    if op == "is_prime":
        return ac.is_prime(vector["n"])

    if op == "mod_inv":
        return ac.mod_inv(vector["a"], vector["mod"])

    if op == "PrimeField":
        _ = ac.PrimeField(vector["mod"])
        return True

    if op == "field_add":
        f = ac.PrimeField(vector["mod"])
        return f.add(vector["a"], vector["b"])
    if op == "field_mul":
        f = ac.PrimeField(vector["mod"])
        return f.mul(vector["a"], vector["b"])
    if op == "field_pow":
        f = ac.PrimeField(vector["mod"])
        return f.pow(vector["a"], vector["e"])

    if op == "eval_x3_plus_x_plus_5":
        f = ac.PrimeField(vector["mod"])
        c = ac.build_x3_plus_x_plus_5(f)
        w = c.evaluate([vector["x"]])
        return {"output": w[c.output_wire], "witness": w}

    if op == "check_witness":
        f = ac.PrimeField(vector["mod"])
        c = ac.build_x3_plus_x_plus_5(f)
        return c.check_witness(vector["witness"], inputs=[vector["x"]], expected_output=vector["witness"][c.output_wire])

    raise AssertionError(f"unknown op: {op}")


def test_vectors():
    vectors = json.loads(VECTORS_PATH.read_text())["vectors"]
    for vector in vectors:
        if "expected_error" in vector:
            try:
                call(vector)
            except ValueError as error:
                assert str(error) == vector["expected_error"]
            else:
                raise AssertionError(f"{vector['op']} did not raise")
            continue

        assert call(vector) == vector["expected"]


def test_evaluate_then_check_witness_roundtrip():
    f = ac.PrimeField(97)
    c = ac.build_x3_plus_x_plus_5(f)
    rng = random.Random(0)

    for _ in range(200):
        x = rng.randrange(0, f.mod)
        w = c.evaluate([x])
        assert c.check_witness(w, inputs=[x], expected_output=w[c.output_wire])


def test_wrong_number_of_inputs_rejected():
    f = ac.PrimeField(97)
    c = ac.build_x3_plus_x_plus_5(f)
    try:
        c.evaluate([])
    except ValueError as error:
        assert str(error) == "wrong number of inputs"
    else:
        raise AssertionError("expected wrong-input-count error")


def test_bad_witness_length_rejected():
    f = ac.PrimeField(97)
    c = ac.build_x3_plus_x_plus_5(f)
    try:
        c.check_witness([0, 1, 2])
    except ValueError as error:
        assert str(error) == "bad witness length"
    else:
        raise AssertionError("expected bad-witness-length error")


if __name__ == "__main__":
    test_vectors()
    test_evaluate_then_check_witness_roundtrip()
    test_wrong_number_of_inputs_rejected()
    test_bad_witness_length_rejected()
    print("all tests pass")

