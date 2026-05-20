import json
import os
import random
import sys


HERE = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.append(CODE_DIR)

import main as deep_fri  # noqa: E402


def _load_vectors():
    path = os.path.join(HERE, "vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _poly_even_odd(coeffs):
    g = coeffs[0::2]
    h = coeffs[1::2]
    return g, h


def _poly_add_scaled(a, b, scale, p):
    n = max(len(a), len(b))
    out = [0] * n
    for i in range(n):
        if i < len(a):
            out[i] = (out[i] + a[i]) % p
        if i < len(b):
            out[i] = (out[i] + scale * b[i]) % p
    return out


def test_vectors():
    data = _load_vectors()
    assert "vectors" in data and isinstance(data["vectors"], list)

    for v in data["vectors"]:
        op = v["op"]
        if op == "f_inv":
            got = deep_fri.f_inv(v["a"], v["p"])
            assert got == v["expected"]
        elif op == "poly_eval":
            got = deep_fri.poly_eval(v["coeffs"], v["x"], v["p"])
            assert got == v["expected"]
        elif op == "deep_quotient_values":
            got = deep_fri.deep_quotient_values(v["p"], v["domain"], v["values"], v["z"], v["fz"])
            assert got == v["expected"]
        elif op == "fri_fold_layer":
            dom, vals = deep_fri.fri_fold_layer(v["p"], v["domain"], v["values"], v["beta"])
            assert dom == v["expected"]["domain"]
            assert vals == v["expected"]["values"]
        elif op == "merkle_root":
            tree, root = deep_fri.merkle_commit_field(v["values"])
            assert deep_fri.merkle_root(tree) == root
            assert root.hex() == v["expected_root_hex"]
        elif op == "merkle_proof_verify":
            tree, root = deep_fri.merkle_commit_field(v["values"])
            assert root.hex() == v["expected_root_hex"]
            proof = [(bytes.fromhex(x["hash_hex"]), bool(x["sib_on_left"])) for x in v["proof"]]
            leaf = deep_fri._field_to_bytes(v["values"][v["index"]])
            got = deep_fri.merkle_verify(leaf, v["index"], proof, root)
            assert got == v["expected"]
        else:
            raise AssertionError(f"unknown op: {op}")


def test_f_inv_roundtrip():
    p = 12289
    rng = random.Random(2026)
    for _ in range(200):
        a = rng.randrange(1, p)
        inv = deep_fri.f_inv(a, p)
        assert (a * inv) % p == 1


def test_deep_quotient_recovers_f_on_domain():
    p = 12289
    n = 32
    domain = deep_fri.subgroup_domain(p, n)
    coeffs = [3, 5, 7, 11, 13]
    f_values = deep_fri.poly_eval_many(coeffs, domain, p)
    z = 10122
    assert z not in set(domain)
    fz = deep_fri.poly_eval(coeffs, z, p)
    q_values = deep_fri.deep_quotient_values(p, domain, f_values, z, fz)
    for x, fx, qx in zip(domain, f_values, q_values):
        assert (qx * ((x - z) % p) + fz) % p == fx


def test_fri_fold_matches_coeff_decomposition():
    p = 12289
    n = 64
    rng = random.Random(1338)
    domain = deep_fri.subgroup_domain(p, n)
    beta = rng.randrange(0, p)
    coeffs = [rng.randrange(0, p) for _ in range(17)]
    values = deep_fri.poly_eval_many(coeffs, domain, p)

    g, h = _poly_even_odd(coeffs)
    next_coeffs = _poly_add_scaled(g, h, beta, p)
    next_domain, next_values = deep_fri.fri_fold_layer(p, domain, values, beta)

    for y, got in zip(next_domain, next_values):
        expected = deep_fri.poly_eval(next_coeffs, y, p)
        assert got == expected


def test_deep_fri_verify_accepts_and_rejects():
    p = 12289
    n = 64
    rng = random.Random(1337)
    domain = deep_fri.subgroup_domain(p, n)
    coeffs = [3, 5, 7, 11, 13]
    f_values = deep_fri.poly_eval_many(coeffs, domain, p)
    z = 10122
    assert z not in set(domain)
    fz = deep_fri.poly_eval(coeffs, z, p)

    betas = [rng.randrange(0, p) for _ in range(6)]
    q_domains, q_layers = deep_fri.deep_fri_build(p, domain, f_values, z, fz, betas)
    q_trees = []
    q_roots = []
    for layer in q_layers:
        tree, root = deep_fri.merkle_commit_field(layer)
        q_trees.append(tree)
        q_roots.append(root)
    f_tree, f_root = deep_fri.merkle_commit_field(f_values)

    queries = [rng.randrange(0, n) for _ in range(5)]
    openings = []
    for q_idx in queries:
        opening = {
            "f0": (f_values[q_idx], deep_fri.merkle_proof(f_tree, q_idx)),
            "q0": (q_layers[0][q_idx], deep_fri.merkle_proof(q_trees[0], q_idx)),
        }
        idx = q_idx
        for r in range(len(betas)):
            layer_n = len(q_domains[r])
            half = layer_n // 2
            base = idx % half
            sib = base + half
            opening[f"q{r}a"] = (q_layers[r][base], deep_fri.merkle_proof(q_trees[r], base))
            opening[f"q{r}b"] = (q_layers[r][sib], deep_fri.merkle_proof(q_trees[r], sib))
            opening[f"q{r+1}"] = (
                q_layers[r + 1][base],
                deep_fri.merkle_proof(q_trees[r + 1], base),
            )
            idx = base
        openings.append(opening)

    assert deep_fri.deep_fri_verify(
        p, domain, f_root, q_domains, q_roots, z, fz, betas, queries, openings
    )

    q_layers_bad = [layer[:] for layer in q_layers]
    q_layers_bad[0][queries[0]] = (q_layers_bad[0][queries[0]] + 1) % p
    q_trees_bad = []
    q_roots_bad = []
    for layer in q_layers_bad:
        tree, root = deep_fri.merkle_commit_field(layer)
        q_trees_bad.append(tree)
        q_roots_bad.append(root)

    openings_bad = []
    for q_idx in queries:
        opening = {
            "f0": (f_values[q_idx], deep_fri.merkle_proof(f_tree, q_idx)),
            "q0": (q_layers_bad[0][q_idx], deep_fri.merkle_proof(q_trees_bad[0], q_idx)),
        }
        idx = q_idx
        for r in range(len(betas)):
            layer_n = len(q_domains[r])
            half = layer_n // 2
            base = idx % half
            sib = base + half
            opening[f"q{r}a"] = (q_layers_bad[r][base], deep_fri.merkle_proof(q_trees_bad[r], base))
            opening[f"q{r}b"] = (q_layers_bad[r][sib], deep_fri.merkle_proof(q_trees_bad[r], sib))
            opening[f"q{r+1}"] = (
                q_layers_bad[r + 1][base],
                deep_fri.merkle_proof(q_trees_bad[r + 1], base),
            )
            idx = base
        openings_bad.append(opening)

    assert not deep_fri.deep_fri_verify(
        p, domain, f_root, q_domains, q_roots_bad, z, fz, betas, queries, openings_bad
    )


if __name__ == "__main__":
    test_vectors()
    test_f_inv_roundtrip()
    test_deep_quotient_recovers_f_on_domain()
    test_fri_fold_matches_coeff_decomposition()
    test_deep_fri_verify_accepts_and_rejects()
    print("all tests pass")

