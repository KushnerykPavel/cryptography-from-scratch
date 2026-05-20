import json
import pathlib
import random
import sys


THIS_DIR = pathlib.Path(__file__).resolve().parent
CODE_DIR = THIS_DIR.parent / "code"
sys.path.insert(0, str(CODE_DIR))

import main as noir  # noqa: E402


def _load_vectors():
    path = THIS_DIR / "vectors.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _run_vector(vector):
    op = vector["op"]
    inputs = vector.get("inputs", {})
    expected = vector.get("expected")

    if op == "field_add":
        got = noir.field_add(inputs["a"], inputs["b"])
        assert got == expected
        return

    if op == "field_sub":
        got = noir.field_sub(inputs["a"], inputs["b"])
        assert got == expected
        return

    if op == "field_mul":
        got = noir.field_mul(inputs["a"], inputs["b"])
        assert got == expected
        return

    if op == "range_check_bits":
        got = noir.range_check_bits(inputs["value"], inputs["bits"])
        assert got == expected
        return

    if op == "circuit_satisfied":
        program = inputs["program"]
        if program == "linear_and_mul":
            stmts = noir.demo_program_linear_and_mul()
            env = noir.execute_program(stmts, {"x": inputs["x"], "y": inputs["y"]})
        elif program == "u32_add":
            stmts = noir.demo_program_u32_add()
            env = noir.execute_program(stmts, {"a": inputs["a"], "b": inputs["b"]})
        else:
            raise ValueError(f"unknown program: {program}")

        circuit = noir.compile_to_circuit(stmts)
        witness = noir.witness_from_env(circuit, env)
        got = noir.circuit_is_satisfied(circuit, witness)
        assert got == expected
        return

    if op == "unconstrained_accepts_malicious":
        stmts = noir.demo_program_unconstrained_product(also_constrain=False)
        circuit = noir.compile_to_circuit(stmts)
        env = noir.execute_program(stmts, {"x": inputs["x"], "y": inputs["y"]})
        witness = noir.witness_from_env(circuit, env)
        noir.set_witness_value(circuit, witness, "out", inputs["malicious_out"])
        got = noir.circuit_is_satisfied(circuit, witness)
        assert got == expected
        return

    if op == "constrained_rejects_malicious":
        stmts = noir.demo_program_unconstrained_product(also_constrain=True)
        circuit = noir.compile_to_circuit(stmts)
        env = noir.execute_program(stmts, {"x": inputs["x"], "y": inputs["y"]})
        witness = noir.witness_from_env(circuit, env)
        noir.set_witness_value(circuit, witness, "out", inputs["malicious_out"])
        got = noir.circuit_is_satisfied(circuit, witness)
        assert got == expected
        return

    raise ValueError(f"unknown op: {op}")


def test_vectors():
    data = _load_vectors()
    for vector in data["vectors"]:
        _run_vector(vector)


def test_field_properties():
    rng = random.Random(0)
    p = noir.DEFAULT_FIELD_MODULUS
    for _ in range(200):
        a = rng.randrange(0, p)
        b = rng.randrange(0, p)
        c = rng.randrange(0, p)
        assert noir.field_add(a, b, p) == noir.field_add(b, a, p)
        assert noir.field_mul(a, b, p) == noir.field_mul(b, a, p)
        left = noir.field_mul(a, noir.field_add(b, c, p), p)
        right = noir.field_add(noir.field_mul(a, b, p), noir.field_mul(a, c, p), p)
        assert left == right


def test_range_check_monotone_in_bits():
    rng = random.Random(1)
    for _ in range(200):
        v = rng.randrange(0, 1 << 20)
        b1 = rng.randrange(1, 20)
        b2 = rng.randrange(b1, 21)
        if noir.range_check_bits(v, b1):
            assert noir.range_check_bits(v, b2)


def test_roundtrip_compile_execute_satisfy():
    rng = random.Random(2)

    stmts = noir.demo_program_linear_and_mul()
    circuit = noir.compile_to_circuit(stmts)
    for _ in range(50):
        x = rng.randrange(0, 10_000)
        y = rng.randrange(0, 10_000)
        env = noir.execute_program(stmts, {"x": x, "y": y})
        witness = noir.witness_from_env(circuit, env)
        assert noir.circuit_is_satisfied(circuit, witness)

    u32_stmts = noir.demo_program_u32_add()
    u32_circuit = noir.compile_to_circuit(u32_stmts)
    for _ in range(50):
        a = rng.randrange(0, 1 << 32)
        b = rng.randrange(0, (1 << 32) - a)
        env = noir.execute_program(u32_stmts, {"a": a, "b": b})
        witness = noir.witness_from_env(u32_circuit, env)
        assert noir.circuit_is_satisfied(u32_circuit, witness)


def test_rejects_wrong_witness_shape():
    stmts = noir.demo_program_linear_and_mul()
    circuit = noir.compile_to_circuit(stmts)
    env = noir.execute_program(stmts, {"x": 1, "y": 2})
    witness = noir.witness_from_env(circuit, env)

    assert not noir.circuit_is_satisfied(circuit, witness[:-1])
    witness2 = list(witness)
    witness2[0] = 0
    assert not noir.circuit_is_satisfied(circuit, witness2)


if __name__ == "__main__":
    test_vectors()
    test_field_properties()
    test_range_check_monotone_in_bits()
    test_roundtrip_compile_execute_satisfy()
    test_rejects_wrong_witness_shape()
    print("all tests pass")
