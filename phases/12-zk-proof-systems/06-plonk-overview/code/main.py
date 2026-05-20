"""
Toy PLONK overview: gates + copy constraints + arithmetization into polynomials (no commitments).

Run:
  python3 code/main.py

This is an educational implementation. It is not constant-time and not production-safe.
"""

from dataclasses import dataclass


def egcd(a, b):
    x0, y0, x1, y1 = 1, 0, 0, 1
    while b != 0:
        q = a // b
        a, b = b, a - q * b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def inv_mod(a, p):
    if p <= 1:
        raise ValueError("modulus must be > 1")
    a %= p
    if a == 0:
        raise ValueError("not invertible modulo p")
    g, x, _ = egcd(a, p)
    if g != 1:
        raise ValueError("not invertible modulo p")
    return x % p


def _mod(x, p):
    return x % p


def poly_trim(coeffs):
    out = list(coeffs)
    while len(out) > 1 and out[-1] == 0:
        out.pop()
    return out


def poly_add(a, b, p):
    n = max(len(a), len(b))
    out = [0] * n
    for i in range(n):
        out[i] = ((a[i] if i < len(a) else 0) + (b[i] if i < len(b) else 0)) % p
    return poly_trim(out)


def poly_scale(a, k, p):
    return poly_trim([(k * c) % p for c in a])


def poly_mul(a, b, p):
    if not a or not b:
        return [0]
    out = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        for j, bj in enumerate(b):
            out[i + j] = (out[i + j] + ai * bj) % p
    return poly_trim(out)


def poly_eval(coeffs, x, p):
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % p
    return acc


def lagrange_interpolate(xs, ys, p):
    if len(xs) != len(ys):
        raise ValueError("xs and ys must have the same length")
    if len(xs) == 0:
        raise ValueError("need at least one point")
    if len(set(xs)) != len(xs):
        raise ValueError("xs must be distinct")

    total = [0]
    for i, xi in enumerate(xs):
        numer = [1]
        denom = 1
        for j, xj in enumerate(xs):
            if i == j:
                continue
            numer = poly_mul(numer, [(-xj) % p, 1], p)
            denom = (denom * (xi - xj)) % p
        scale = (ys[i] * inv_mod(denom, p)) % p
        total = poly_add(total, poly_scale(numer, scale, p), p)
    return poly_trim(total)


def find_primitive_root_of_unity(p, n):
    if n <= 1:
        raise ValueError("n must be > 1")
    if (p - 1) % n != 0:
        raise ValueError("n must divide p-1")

    for w in range(2, p):
        if pow(w, n, p) != 1:
            continue
        if pow(w, n // 2, p) == 1:
            continue
        return w
    raise ValueError("no primitive n-th root found")


def evaluation_domain(p, n, omega):
    if n <= 0:
        raise ValueError("n must be positive")
    xs = [1]
    for _ in range(1, n):
        xs.append((xs[-1] * omega) % p)
    return xs


@dataclass(frozen=True)
class PlonkColumns:
    qL: list[int]
    qR: list[int]
    qM: list[int]
    qO: list[int]
    qC: list[int]


@dataclass(frozen=True)
class PlonkWitness:
    a: list[int]
    b: list[int]
    c: list[int]


def gate_constraint_values(cols, w, p):
    n = len(w.a)
    if not (len(w.b) == len(w.c) == len(cols.qL) == len(cols.qR) == len(cols.qM) == len(cols.qO) == len(cols.qC) == n):
        raise ValueError("all columns must have the same length")
    out = []
    for i in range(n):
        val = (
            cols.qL[i] * w.a[i]
            + cols.qR[i] * w.b[i]
            + cols.qM[i] * w.a[i] * w.b[i]
            + cols.qO[i] * w.c[i]
            + cols.qC[i]
        ) % p
        out.append(val)
    return out


def slot_id_labels(xs, p, k1=2, k2=3):
    ids_a = [(1 * x) % p for x in xs]
    ids_b = [(k1 * x) % p for x in xs]
    ids_c = [(k2 * x) % p for x in xs]
    return ids_a, ids_b, ids_c


def permutation_sigma_columns(n, xs, p, copy_cycles, k1=2, k2=3):
    ids_a, ids_b, ids_c = slot_id_labels(xs, p, k1=k1, k2=k2)
    ids = ids_a + ids_b + ids_c

    perm = list(range(3 * n))
    for cycle in copy_cycles:
        if len(cycle) < 2:
            raise ValueError("each copy cycle must have at least 2 slots")
        for slot in cycle:
            if not (0 <= slot < 3 * n):
                raise ValueError("slot index out of range")
        for idx, slot in enumerate(cycle):
            perm[slot] = cycle[(idx + 1) % len(cycle)]

    sigma_labels = [ids[perm[i]] for i in range(3 * n)]
    sigma_a = sigma_labels[0:n]
    sigma_b = sigma_labels[n : 2 * n]
    sigma_c = sigma_labels[2 * n : 3 * n]
    return sigma_a, sigma_b, sigma_c


def compute_grand_product_z(cols, w, sigma_a, sigma_b, sigma_c, xs, p, beta, gamma, k1=2, k2=3):
    n = len(xs)
    if not (len(w.a) == len(w.b) == len(w.c) == len(sigma_a) == len(sigma_b) == len(sigma_c) == n):
        raise ValueError("all columns must have the same length n")

    ids_a, ids_b, ids_c = slot_id_labels(xs, p, k1=k1, k2=k2)
    z = [1]
    for i in range(n):
        num = (
            (w.a[i] + beta * ids_a[i] + gamma)
            * (w.b[i] + beta * ids_b[i] + gamma)
            * (w.c[i] + beta * ids_c[i] + gamma)
        ) % p
        den = (
            (w.a[i] + beta * sigma_a[i] + gamma)
            * (w.b[i] + beta * sigma_b[i] + gamma)
            * (w.c[i] + beta * sigma_c[i] + gamma)
        ) % p
        z.append((z[-1] * num * inv_mod(den, p)) % p)
    return z


def toy_plonk_instance(p=97, n=4):
    omega = find_primitive_root_of_unity(p, n)
    xs = evaluation_domain(p, n, omega)

    x = 3
    z = (x * x) % p
    y = (z + x + 5) % p

    w = PlonkWitness(
        a=[x, z, 0, 0],
        b=[x, x, 0, 0],
        c=[z, y, 0, 0],
    )

    cols = PlonkColumns(
        qL=[0, 1, 0, 0],
        qR=[0, 1, 0, 0],
        qM=[1, 0, 0, 0],
        qO=[(-1) % p, (-1) % p, 0, 0],
        qC=[0, 5, 0, 0],
    )

    copy_cycles = [
        [0, n + 0, n + 1],  # x: a0, b0, b1
        [2 * n + 0, 1],  # z: c0, a1
    ]

    sigma_a, sigma_b, sigma_c = permutation_sigma_columns(n, xs, p, copy_cycles)
    return {
        "p": p,
        "n": n,
        "omega": omega,
        "xs": xs,
        "cols": cols,
        "witness": w,
        "sigma_a": sigma_a,
        "sigma_b": sigma_b,
        "sigma_c": sigma_c,
        "public": {"y": y},
    }


def _step(n, name):
    print(f"=== Step {n}: {name} ===")


def main():
    inst = toy_plonk_instance()
    p = inst["p"]
    n = inst["n"]
    omega = inst["omega"]
    xs = inst["xs"]
    cols = inst["cols"]
    w = inst["witness"]
    sigma_a = inst["sigma_a"]
    sigma_b = inst["sigma_b"]
    sigma_c = inst["sigma_c"]

    _step(1, "Evaluation domain + polynomial interpolation")
    print(f"field prime p = {p}")
    print(f"domain size n = {n}")
    print(f"primitive n-th root of unity omega = {omega}")
    print(f"domain points x_i = omega^i mod p = {xs}")
    a_poly = lagrange_interpolate(xs, w.a, p)
    print(f"A(X) interpolated from a-column evals = {a_poly}  (coeffs low→high)")
    print(f"A(omega^1) = {poly_eval(a_poly, xs[1], p)}")

    _step(2, "PLONK gate constraints via selectors")
    gate_vals = gate_constraint_values(cols, w, p)
    print("gate constraint values per row (want all 0):", gate_vals)

    _step(3, "Copy constraints via permutation grand product")
    print("sigma_a:", sigma_a)
    print("sigma_b:", sigma_b)
    print("sigma_c:", sigma_c)
    beta, gamma = 7, 9
    z = compute_grand_product_z(cols, w, sigma_a, sigma_b, sigma_c, xs, p, beta=beta, gamma=gamma)
    print(f"beta={beta}, gamma={gamma}")
    print("grand product Z evaluations (including Z(1)=1):", z)
    print("final Z after n steps (want 1):", z[-1])

    _step(4, "Arithmetization summary: columns become polynomials")
    ql_poly = lagrange_interpolate(xs, cols.qL, p)
    qr_poly = lagrange_interpolate(xs, cols.qR, p)
    qm_poly = lagrange_interpolate(xs, cols.qM, p)
    qo_poly = lagrange_interpolate(xs, cols.qO, p)
    qc_poly = lagrange_interpolate(xs, cols.qC, p)
    b_poly = lagrange_interpolate(xs, w.b, p)
    c_poly = lagrange_interpolate(xs, w.c, p)
    g_evals = gate_constraint_values(cols, w, p)
    g_poly = lagrange_interpolate(xs, g_evals, p)

    print("qL(X) =", ql_poly)
    print("qR(X) =", qr_poly)
    print("qM(X) =", qm_poly)
    print("qO(X) =", qo_poly)
    print("qC(X) =", qc_poly)
    print("B(X)  =", b_poly)
    print("C(X)  =", c_poly)
    print("Gate polynomial G(X) evals on domain =", g_evals)
    print("Gate polynomial G(X) =", g_poly)

    print()
    print("Public output y =", inst["public"]["y"])


if __name__ == "__main__":
    main()
