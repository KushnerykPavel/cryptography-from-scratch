"""DEEP-FRI (toy) — quotient at an out-of-domain point, then run FRI.

Run: python3 code/main.py
"""

import hashlib
import random


def factorize(n):
    out = []
    d = 2
    while d * d <= n:
        if n % d == 0:
            out.append(d)
            while n % d == 0:
                n //= d
        d += 1 if d == 2 else 2
    if n > 1:
        out.append(n)
    return out


def primitive_root(p):
    factors = factorize(p - 1)
    for g in range(2, p - 1):
        ok = True
        for q in factors:
            if pow(g, (p - 1) // q, p) == 1:
                ok = False
                break
        if ok:
            return g
    raise ValueError("no primitive root found")


def root_of_unity(p, n):
    if (p - 1) % n != 0:
        raise ValueError("n must divide p-1")
    g = primitive_root(p)
    w = pow(g, (p - 1) // n, p)
    if pow(w, n, p) != 1:
        raise ValueError("bad root")
    if n > 1 and pow(w, n // 2, p) == 1:
        raise ValueError("root does not have exact order n")
    return w


def subgroup_domain(p, n):
    w = root_of_unity(p, n)
    dom = [1]
    for _ in range(1, n):
        dom.append((dom[-1] * w) % p)
    return dom


def f_inv(a, p):
    a %= p
    if a == 0:
        raise ValueError("division by zero")
    return pow(a, p - 2, p)


def poly_eval(coeffs, x, p):
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % p
    return acc


def poly_eval_many(coeffs, xs, p):
    return [poly_eval(coeffs, x, p) for x in xs]


def deep_quotient_values(p, domain, values, z, fz):
    out = []
    for x, fx in zip(domain, values):
        out.append(((fx - fz) % p) * f_inv((x - z) % p, p) % p)
    return out


def fri_fold_layer(p, domain, values, beta):
    n = len(values)
    if n % 2 != 0:
        raise ValueError("layer size must be even")
    half = n // 2
    inv2 = (p + 1) // 2
    next_domain = [(domain[i] * domain[i]) % p for i in range(half)]
    next_values = []
    for i in range(half):
        x = domain[i]
        a = values[i]
        b = values[i + half]
        g = (a + b) % p * inv2 % p
        h = (a - b) % p * inv2 % p * f_inv(x, p) % p
        next_values.append((g + beta * h) % p)
    return next_domain, next_values


def _sha256(data):
    return hashlib.sha256(data).digest()


def _field_to_bytes(x):
    return int(x).to_bytes(32, "big")


def merkle_build(leaves):
    if not leaves:
        raise ValueError("empty tree")
    level = [_sha256(b"\x00" + leaf) for leaf in leaves]
    levels = [level]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level = level + [level[-1]]
        nxt = []
        for i in range(0, len(level), 2):
            nxt.append(_sha256(b"\x01" + level[i] + level[i + 1]))
        level = nxt
        levels.append(level)
    return levels


def merkle_root(tree):
    return tree[-1][0]


def merkle_proof(tree, index):
    proof = []
    idx = index
    for level in tree[:-1]:
        if idx % 2 == 0:
            sib = level[idx + 1] if idx + 1 < len(level) else level[idx]
            proof.append((sib, False))
        else:
            sib = level[idx - 1]
            proof.append((sib, True))
        idx //= 2
    return proof


def merkle_verify(leaf, index, proof, root):
    h = _sha256(b"\x00" + leaf)
    idx = index
    for sib, sib_on_left in proof:
        if sib_on_left:
            h = _sha256(b"\x01" + sib + h)
        else:
            h = _sha256(b"\x01" + h + sib)
        idx //= 2
    return h == root


def merkle_commit_field(values):
    tree = merkle_build([_field_to_bytes(v) for v in values])
    return tree, merkle_root(tree)


def deep_fri_build(p, domain, f_values, z, fz, betas):
    q0 = deep_quotient_values(p, domain, f_values, z, fz)
    q_domains = [domain]
    q_layers = [q0]
    for beta in betas:
        domain, q0 = fri_fold_layer(p, domain, q0, beta)
        q_domains.append(domain)
        q_layers.append(q0)
    return q_domains, q_layers


def deep_fri_verify(p, f_domain, f_root, q_domains, q_roots, z, fz, betas, queries, openings):
    if len(q_domains) != len(q_roots):
        raise ValueError("domains/roots mismatch")
    if len(q_domains) != len(betas) + 1:
        raise ValueError("betas mismatch")
    if len(openings) != len(queries):
        raise ValueError("openings mismatch")

    for q_idx, opening in zip(queries, openings):
        fx, fx_proof = opening["f0"]
        qx, qx_proof = opening["q0"]
        if not merkle_verify(_field_to_bytes(fx), q_idx, fx_proof, f_root):
            return False
        if not merkle_verify(_field_to_bytes(qx), q_idx, qx_proof, q_roots[0]):
            return False

        x = f_domain[q_idx]
        if (qx * ((x - z) % p) + fz) % p != fx:
            return False

        idx = q_idx
        for r, beta in enumerate(betas):
            layer_n = len(q_domains[r])
            half = layer_n // 2
            base = idx % half
            sib = base + half
            q_i, q_i_proof = opening[f"q{r}a"]
            q_s, q_s_proof = opening[f"q{r}b"]
            q_next, q_next_proof = opening[f"q{r+1}"]

            if not merkle_verify(_field_to_bytes(q_i), base, q_i_proof, q_roots[r]):
                return False
            if not merkle_verify(_field_to_bytes(q_s), sib, q_s_proof, q_roots[r]):
                return False

            next_idx = base
            if not merkle_verify(_field_to_bytes(q_next), next_idx, q_next_proof, q_roots[r + 1]):
                return False

            x = q_domains[r][next_idx]
            inv2 = (p + 1) // 2
            g = (q_i + q_s) % p * inv2 % p
            h = (q_i - q_s) % p * inv2 % p * f_inv(x, p) % p
            expected = (g + beta * h) % p
            if expected != q_next:
                return False

            idx = next_idx

    return True


def main():
    p = 12289
    n = 64
    rng = random.Random(1337)

    print("=== Step 1: build a power-of-two subgroup domain ===")
    domain = subgroup_domain(p, n)
    neg1 = domain[n // 2]
    print(f"  field prime p={p}, domain size n={n}")
    print(f"  -1 in domain? {neg1 == (p - 1)}  (domain[n/2]={neg1})")
    print(f"  sample domain[0..5]: {domain[:6]}")
    print(f"  pairing: x=domain[3]={domain[3]}  -x={(p-domain[3])%p}  is domain[3+n/2]={domain[3+n//2]}")

    print()
    print("=== Step 2: deep-quotient at an out-of-domain point z ===")
    f_coeffs = [3, 5, 7, 11, 13]
    f_values = poly_eval_many(f_coeffs, domain, p)
    used = set(domain)
    z = rng.randrange(1, p)
    while z in used:
        z = rng.randrange(1, p)
    fz = poly_eval(f_coeffs, z, p)
    q_values = deep_quotient_values(p, domain, f_values, z, fz)
    i = 9
    x = domain[i]
    recon = (q_values[i] * ((x - z) % p) + fz) % p
    print(f"  poly degree={len(f_coeffs)-1}, pick z={z} (not in domain), f(z)={fz}")
    print(f"  q(x)=(f(x)-f(z))/(x-z) has degree one lower; check at i={i}:")
    print(f"    x={x}  f(x)={f_values[i]}  q(x)={q_values[i]}  q(x)*(x-z)+f(z)={recon}")

    print()
    print("=== Step 3: one FRI folding round on q(x) evaluations ===")
    beta0 = rng.randrange(0, p)
    d1, q1 = fri_fold_layer(p, domain, q_values, beta0)
    j = 7
    a = q_values[j]
    b = q_values[j + n // 2]
    inv2 = (p + 1) // 2
    g = (a + b) % p * inv2 % p
    h = (a - b) % p * inv2 % p * f_inv(domain[j], p) % p
    print(f"  beta0={beta0}")
    print(f"  fold check at j={j}: q1[j]={q1[j]}  expected={((g + beta0*h)%p)}")
    print(f"  next-domain sample[0..5]: {d1[:6]}")

    print()
    print("=== Step 4: Merkle-commit each FRI layer and verify one opening ===")
    betas = [rng.randrange(0, p) for _ in range(6)]
    q_domains, q_layers = deep_fri_build(p, domain, f_values, z, fz, betas)
    q_trees = []
    q_roots = []
    for layer in q_layers:
        tree, root = merkle_commit_field(layer)
        q_trees.append(tree)
        q_roots.append(root)
    f_tree, f_root = merkle_commit_field(f_values)

    idx = 13
    leaf = _field_to_bytes(q_layers[0][idx])
    proof = merkle_proof(q_trees[0], idx)
    ok = merkle_verify(leaf, idx, proof, q_roots[0])
    print(f"  q0 Merkle root: {q_roots[0].hex()[:16]}...")
    print(f"  opening at idx={idx} verifies? {ok}")

    print()
    print("=== Step 5: end-to-end toy DEEP-FRI verification (accept + reject) ===")
    queries = [rng.randrange(0, n // 2) for _ in range(4)]
    openings = []
    for q_idx in queries:
        opening = {
            "f0": (f_values[q_idx], merkle_proof(f_tree, q_idx)),
            "q0": (q_layers[0][q_idx], merkle_proof(q_trees[0], q_idx)),
        }
        idx = q_idx
        for r in range(len(betas)):
            layer_n = len(q_domains[r])
            half = layer_n // 2
            base = idx % half
            sib = base + half
            opening[f"q{r}a"] = (q_layers[r][base], merkle_proof(q_trees[r], base))
            opening[f"q{r}b"] = (q_layers[r][sib], merkle_proof(q_trees[r], sib))
            opening[f"q{r+1}"] = (q_layers[r + 1][base], merkle_proof(q_trees[r + 1], base))
            idx = base
        openings.append(opening)

    accept = deep_fri_verify(p, domain, f_root, q_domains, q_roots, z, fz, betas, queries, openings)
    print(f"  honest proof accepts? {accept}")

    q_layers_bad = [layer[:] for layer in q_layers]
    q_layers_bad[0][queries[0]] = (q_layers_bad[0][queries[0]] + 1) % p
    q_trees_bad = []
    q_roots_bad = []
    for layer in q_layers_bad:
        tree, root = merkle_commit_field(layer)
        q_trees_bad.append(tree)
        q_roots_bad.append(root)
    openings_bad = []
    for q_idx in queries:
        opening = {
            "f0": (f_values[q_idx], merkle_proof(f_tree, q_idx)),
            "q0": (q_layers_bad[0][q_idx], merkle_proof(q_trees_bad[0], q_idx)),
        }
        idx = q_idx
        for r in range(len(betas)):
            layer_n = len(q_domains[r])
            half = layer_n // 2
            base = idx % half
            sib = base + half
            opening[f"q{r}a"] = (q_layers_bad[r][base], merkle_proof(q_trees_bad[r], base))
            opening[f"q{r}b"] = (q_layers_bad[r][sib], merkle_proof(q_trees_bad[r], sib))
            opening[f"q{r+1}"] = (
                q_layers_bad[r + 1][base],
                merkle_proof(q_trees_bad[r + 1], base),
            )
            idx = base
        openings_bad.append(opening)

    reject = deep_fri_verify(
        p, domain, f_root, q_domains, q_roots_bad, z, fz, betas, queries, openings_bad
    )
    print(f"  tampered proof accepts? {reject}")


if __name__ == "__main__":
    main()
