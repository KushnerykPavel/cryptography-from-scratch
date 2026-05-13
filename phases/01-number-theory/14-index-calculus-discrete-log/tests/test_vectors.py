import importlib.util
import json
import sys
from pathlib import Path


LESSON = Path(__file__).resolve().parents[1]
MODULE_PATH = LESSON / "code" / "main.py"
VECTORS_PATH = LESSON / "tests" / "vectors.json"


spec = importlib.util.spec_from_file_location("index_calculus_main", MODULE_PATH)
main = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = main
spec.loader.exec_module(main)


def relation_to_dict(relation):
    return {
        "exponent": relation.exponent,
        "value": relation.value,
        "exponents": relation.exponents,
    }


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

    if op == "primes_up_to":
        return main.primes_up_to(vector["limit"])
    if op == "prime_factors":
        return main.prime_factors(vector["n"])
    if op == "is_prime":
        return main.is_prime(vector["n"])
    if op == "mod_inverse":
        return main.mod_inverse(vector["a"], vector["modulus"])
    if op == "primitive_root":
        return main.primitive_root(vector["p"])
    if op == "subgroup_generator":
        return main.subgroup_generator(vector["p"], vector["q"])
    if op == "factor_base_for_subgroup":
        return main.factor_base_for_subgroup(vector["p"], vector["q"], vector["bound"])
    if op == "factor_over_base":
        return main.factor_over_base(vector["value"], vector["base"])
    if op == "collect_relations":
        relations = main.collect_relations(
            vector["p"], vector["g"], vector["q"], vector["base"], vector["needed"]
        )
        return [relation_to_dict(relation) for relation in relations]
    if op == "solve_linear_mod_prime":
        return main.solve_linear_mod_prime(vector["matrix"], vector["rhs"], vector["modulus"])
    if op == "factor_base_logs":
        return main.factor_base_logs(vector["p"], vector["g"], vector["q"], vector["base"])
    if op == "descend_target":
        logs = {int(key): value for key, value in vector["logs"].items()}
        return main.descend_target(
            vector["p"], vector["g"], vector["q"], vector["h"], vector["base"], logs
        )
    if op == "index_calculus_log":
        return main.index_calculus_log(
            vector["p"], vector["g"], vector["q"], vector["h"], vector["bound"]
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
