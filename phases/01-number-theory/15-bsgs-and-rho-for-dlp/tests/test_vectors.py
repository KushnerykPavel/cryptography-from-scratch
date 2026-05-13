import importlib.util
import json
import sys
from pathlib import Path


LESSON = Path(__file__).resolve().parents[1]
MODULE_PATH = LESSON / "code" / "main.py"
VECTORS_PATH = LESSON / "tests" / "vectors.json"


spec = importlib.util.spec_from_file_location("bsgs_rho_main", MODULE_PATH)
main = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = main
spec.loader.exec_module(main)


def state_to_dict(state):
    return {"value": state.value, "a": state.a, "b": state.b}


def normalize(value):
    if isinstance(value, tuple):
        return [normalize(item) for item in value]
    if isinstance(value, list):
        return [normalize(item) for item in value]
    if isinstance(value, dict):
        return {str(key): normalize(item) for key, item in value.items()}
    return value


def call(vector):
    op = vector["op"]

    if op == "ceil_sqrt":
        return main.ceil_sqrt(vector["n"])
    if op == "mod_inverse":
        return main.mod_inverse(vector["a"], vector["modulus"])
    if op == "solve_linear_congruence":
        return main.solve_linear_congruence(
            vector["multiplier"], vector["rhs"], vector["modulus"]
        )
    if op == "baby_step_table":
        return main.baby_step_table(vector["p"], vector["g"], vector["order"])
    if op == "baby_step_giant_step":
        return main.baby_step_giant_step(
            vector["p"], vector["g"], vector["h"], vector["order"]
        )
    if op == "rho_step":
        state = main.RhoState(
            vector["state"]["value"], vector["state"]["a"], vector["state"]["b"]
        )
        return state_to_dict(
            main.rho_step(state, vector["p"], vector["g"], vector["h"], vector["order"])
        )
    if op == "recover_from_collision":
        left = main.RhoState(
            vector["left"]["value"], vector["left"]["a"], vector["left"]["b"]
        )
        right = main.RhoState(
            vector["right"]["value"], vector["right"]["a"], vector["right"]["b"]
        )
        return main.recover_from_collision(
            vector["p"], vector["g"], vector["h"], vector["order"], left, right
        )
    if op == "pollard_rho_dlp":
        return main.pollard_rho_dlp(
            vector["p"],
            vector["g"],
            vector["h"],
            vector["order"],
            vector.get("max_steps", 10_000),
            vector.get("retries", 16),
        )
    if op == "discrete_log":
        return main.discrete_log(
            vector["p"], vector["g"], vector["h"], vector["order"], vector["method"]
        )

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

        assert normalize(call(vector)) == normalize(vector["expected"])


if __name__ == "__main__":
    test_vectors()
    print("vector harness passed")
