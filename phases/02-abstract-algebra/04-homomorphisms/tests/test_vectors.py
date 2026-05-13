import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (
    add_mod,
    first_isomorphism_size_check,
    generated_subgroup,
    homomorphism_report,
    image,
    inverse_isomorphism_table,
    is_homomorphism,
    is_injective_homomorphism,
    is_isomorphism,
    is_surjective_homomorphism,
    kernel,
    mul_mod,
    preserves_repetition,
    residues_mod,
    units_mod,
)


def normalize(value):
    if isinstance(value, dict):
        return {str(k): normalize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [normalize(v) for v in value]
    return value


def add_group(n):
    elements = residues_mod(n)
    operation = lambda a, b: add_mod(a, b, n)
    return elements, operation


def exponent_subgroup(base, modulus):
    elements = generated_subgroup(
        base,
        units_mod(modulus),
        lambda a, b: mul_mod(a, b, modulus),
    )
    operation = lambda a, b: mul_mod(a, b, modulus)
    return elements, operation


def build_case(v):
    if v["case"] == "add_reduce":
        domain, domain_op = add_group(v["domain_n"])
        codomain, codomain_op = add_group(v["codomain_n"])
        mapping = lambda x: x % v["codomain_n"]
    elif v["case"] == "add_multiply":
        domain, domain_op = add_group(v["domain_n"])
        codomain, codomain_op = add_group(v["codomain_n"])
        mapping = lambda x: (v["factor"] * x) % v["codomain_n"]
    elif v["case"] == "add_multiply_subgroup":
        domain, domain_op = add_group(v["domain_n"])
        codomain = [
            (v["factor"] * x) % v["codomain_n"] for x in range(v["domain_n"])
        ]
        codomain_op = lambda a, b: add_mod(a, b, v["codomain_n"])
        mapping = lambda x: (v["factor"] * x) % v["codomain_n"]
    elif v["case"] == "exponent_map":
        domain, domain_op = add_group(v["domain_n"])
        codomain, codomain_op = exponent_subgroup(v["base"], v["modulus"])
        mapping = lambda x: pow(v["base"], x, v["modulus"])
    else:
        raise AssertionError(f"unknown case {v['case']}")
    return domain, codomain, domain_op, codomain_op, mapping


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        domain, codomain, domain_op, codomain_op, mapping = build_case(v)
        op = v["op"]

        try:
            if op == "is_homomorphism":
                got = is_homomorphism(
                    domain,
                    codomain,
                    domain_op,
                    codomain_op,
                    mapping,
                )
            elif op == "kernel":
                got = kernel(domain, codomain, domain_op, codomain_op, mapping)
            elif op == "image":
                got = image(domain, codomain, domain_op, codomain_op, mapping)
            elif op == "injective":
                got = is_injective_homomorphism(
                    domain,
                    codomain,
                    domain_op,
                    codomain_op,
                    mapping,
                )
            elif op == "surjective":
                got = is_surjective_homomorphism(
                    domain,
                    codomain,
                    domain_op,
                    codomain_op,
                    mapping,
                )
            elif op == "isomorphism":
                got = is_isomorphism(
                    domain,
                    codomain,
                    domain_op,
                    codomain_op,
                    mapping,
                )
            elif op == "inverse_isomorphism_table":
                got = inverse_isomorphism_table(
                    domain,
                    codomain,
                    domain_op,
                    codomain_op,
                    mapping,
                )
            elif op == "first_isomorphism_size_check":
                got = first_isomorphism_size_check(
                    domain,
                    codomain,
                    domain_op,
                    codomain_op,
                    mapping,
                )
            elif op == "preserves_repetition":
                got = preserves_repetition(
                    v["element"],
                    v["exponent"],
                    domain,
                    codomain,
                    domain_op,
                    codomain_op,
                    mapping,
                )
            elif op == "homomorphism_report":
                got = homomorphism_report(
                    domain,
                    codomain,
                    domain_op,
                    codomain_op,
                    mapping,
                )
            else:
                raise AssertionError(f"unknown op {op}")
        except ValueError as exc:
            assert v.get("expected_error") == str(exc), (
                f"{op} wrong error: got {exc!s}, expected {v.get('expected_error')}"
            )
            continue

        assert normalize(got) == normalize(v["expected"]), (
            f"{op} failed: got {normalize(got)}, expected {normalize(v['expected'])}"
        )


if __name__ == "__main__":
    test_vectors()
    print("all vectors pass")
