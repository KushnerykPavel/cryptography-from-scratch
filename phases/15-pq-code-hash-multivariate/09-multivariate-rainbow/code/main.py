"""
Toy Rainbow-style multivariate (MQ) signature demo.

Run:
  python3 code/main.py

This lesson builds a small, fully runnable "Rainbow-like" signature scheme over a
prime field GF(p) using:
  - a layered Oil-and-Vinegar (OV) central map F that is easy to invert
  - two secret invertible affine maps S (output) and T (input) that hide F
  - a public key P = S ∘ F ∘ T, which looks like random quadratic polynomials

Educational implementation. Not constant-time. Not production-safe.
Rainbow is historically important but broken; use this only to learn the trapdoor idea.
"""

from __future__ import annotations

import hashlib
import json
import random
from dataclasses import dataclass


def modp(x, p):
    return x % p


def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def mod_inv(a, p):
    a = a % p
    if a == 0:
        raise ZeroDivisionError("no inverse for 0")
    g, x, _ = egcd(a, p)
    if g != 1:
        raise ZeroDivisionError("not invertible")
    return x % p


def mat_identity(n):
    return [[1 if i == j else 0 for j in range(n)] for i in range(n)]


def mat_vec_mul(A, x, p):
    out = []
    for row in A:
        acc = 0
        for a, xi in zip(row, x):
            acc = (acc + a * xi) % p
        out.append(acc)
    return out


def mat_mul(A, B, p):
    n = len(A)
    m = len(B[0])
    k = len(B)
    out = [[0 for _ in range(m)] for _ in range(n)]
    for i in range(n):
        for j in range(m):
            acc = 0
            for t in range(k):
                acc = (acc + A[i][t] * B[t][j]) % p
            out[i][j] = acc
    return out


def mat_inv(A, p):
    n = len(A)
    M = [row[:] + eye_row[:] for row, eye_row in zip(A, mat_identity(n))]

    for col in range(n):
        pivot = None
        for r in range(col, n):
            if M[r][col] % p != 0:
                pivot = r
                break
        if pivot is None:
            raise ValueError("matrix not invertible")
        if pivot != col:
            M[col], M[pivot] = M[pivot], M[col]

        inv_piv = mod_inv(M[col][col], p)
        for c in range(2 * n):
            M[col][c] = (M[col][c] * inv_piv) % p

        for r in range(n):
            if r == col:
                continue
            factor = M[r][col] % p
            if factor == 0:
                continue
            for c in range(2 * n):
                M[r][c] = (M[r][c] - factor * M[col][c]) % p

    return [row[n:] for row in M]


def solve_linear_system(A, b, p):
    n = len(A)
    M = [A[i][:] + [b[i] % p] for i in range(n)]

    for col in range(n):
        pivot = None
        for r in range(col, n):
            if M[r][col] % p != 0:
                pivot = r
                break
        if pivot is None:
            return None
        if pivot != col:
            M[col], M[pivot] = M[pivot], M[col]

        inv_piv = mod_inv(M[col][col], p)
        for c in range(col, n + 1):
            M[col][c] = (M[col][c] * inv_piv) % p

        for r in range(n):
            if r == col:
                continue
            factor = M[r][col] % p
            if factor == 0:
                continue
            for c in range(col, n + 1):
                M[r][c] = (M[r][c] - factor * M[col][c]) % p

    return [M[i][n] % p for i in range(n)]


def hash_to_field_elems(message, p, m, domain=b"rainbow-toy-v1"):
    out = []
    counter = 0
    while len(out) < m:
        h = hashlib.sha256()
        h.update(domain)
        h.update(b"|")
        h.update(message)
        h.update(b"|")
        h.update(counter.to_bytes(4, "big"))
        digest = h.digest()
        for i in range(0, len(digest), 4):
            if len(out) >= m:
                break
            out.append(int.from_bytes(digest[i : i + 4], "big") % p)
        counter += 1
    return out


def _linear_polynomial(constant, coeffs):
    return {"c": constant, "a": coeffs}


def _mul_linear_polys(u, v, p):
    c1, a1 = u["c"] % p, u["a"]
    c2, a2 = v["c"] % p, v["a"]
    n = len(a1)
    q = [[0 for _ in range(n)] for _ in range(n)]
    l = [0 for _ in range(n)]
    c = (c1 * c2) % p

    for i in range(n):
        l[i] = (c1 * a2[i] + c2 * a1[i]) % p

    for i in range(n):
        for j in range(i, n):
            if i == j:
                q[i][j] = (q[i][j] + a1[i] * a2[j]) % p
            else:
                q[i][j] = (q[i][j] + a1[i] * a2[j] + a1[j] * a2[i]) % p
    return q, l, c


def _add_scaled_quadratic(acc_q, acc_l, acc_c, q, l, c, scale, p):
    n = len(acc_l)
    scale %= p
    if scale == 0:
        return
    for i in range(n):
        acc_l[i] = (acc_l[i] + scale * l[i]) % p
    for i in range(n):
        for j in range(i, n):
            acc_q[i][j] = (acc_q[i][j] + scale * q[i][j]) % p
    acc_c[0] = (acc_c[0] + scale * c) % p


@dataclass(frozen=True)
class AffineMap:
    A: list[list[int]]
    b: list[int]
    p: int

    def apply(self, x):
        y = mat_vec_mul(self.A, x, self.p)
        return [(yi + bi) % self.p for yi, bi in zip(y, self.b)]

    def inverse(self):
        Ainv = mat_inv(self.A, self.p)
        binv = mat_vec_mul(Ainv, [(-bi) % self.p for bi in self.b], self.p)
        return AffineMap(Ainv, binv, self.p)


@dataclass(frozen=True)
class QuadraticMap:
    q: list[list[list[int]]]
    l: list[list[int]]
    c: list[int]
    p: int

    def m(self):
        return len(self.q)

    def n(self):
        return len(self.l[0]) if self.l else 0

    def evaluate(self, x):
        p = self.p
        n = self.n()
        out = []
        for k in range(self.m()):
            acc = self.c[k] % p
            lk = self.l[k]
            qk = self.q[k]
            for i in range(n):
                acc = (acc + lk[i] * x[i]) % p
            for i in range(n):
                xi = x[i]
                for j in range(i, n):
                    acc = (acc + qk[i][j] * xi * x[j]) % p
            out.append(acc)
        return out

    def nonzero_quadratic_terms(self):
        n = self.n()
        total = 0
        for k in range(self.m()):
            for i in range(n):
                for j in range(i, n):
                    if self.q[k][i][j] % self.p != 0:
                        total += 1
        return total


def compose_quadratic_with_affine_input(F, T):
    p = F.p
    m = F.m()
    n = T.inverse().A and len(T.A[0])  # input dim

    t_polys = []
    for a in range(len(T.b)):
        coeffs = [T.A[a][i] % p for i in range(n)]
        t_polys.append(_linear_polynomial(T.b[a] % p, coeffs))

    new_q = [[[0 for _ in range(n)] for _ in range(n)] for _ in range(m)]
    new_l = [[0 for _ in range(n)] for _ in range(m)]
    new_c = [0 for _ in range(m)]

    for k in range(m):
        acc_q = [[0 for _ in range(n)] for _ in range(n)]
        acc_l = [0 for _ in range(n)]
        acc_c = [0]

        for a in range(F.n()):
            scale = F.l[k][a]
            if scale % p != 0:
                poly = t_polys[a]
                _add_scaled_quadratic(
                    acc_q,
                    acc_l,
                    acc_c,
                    [[0 for _ in range(n)] for _ in range(n)],
                    poly["a"],
                    poly["c"],
                    scale,
                    p,
                )

        for a in range(F.n()):
            for b in range(a, F.n()):
                scale = F.q[k][a][b]
                if scale % p == 0:
                    continue
                qtmp, ltmp, ctmp = _mul_linear_polys(t_polys[a], t_polys[b], p)
                _add_scaled_quadratic(acc_q, acc_l, acc_c, qtmp, ltmp, ctmp, scale, p)

        acc_c[0] = (acc_c[0] + F.c[k]) % p

        new_q[k] = acc_q
        new_l[k] = acc_l
        new_c[k] = acc_c[0]

    for k in range(m):
        for i in range(n):
            for j in range(i):
                new_q[k][i][j] = 0
    return QuadraticMap(new_q, new_l, new_c, p)


def apply_output_affine_to_quadratic(F, S):
    p = F.p
    m = F.m()
    n = F.n()

    new_q = [[[0 for _ in range(n)] for _ in range(n)] for _ in range(m)]
    new_l = [[0 for _ in range(n)] for _ in range(m)]
    new_c = [0 for _ in range(m)]

    for r in range(m):
        for k in range(m):
            a = S.A[r][k] % p
            if a == 0:
                continue
            for i in range(n):
                new_l[r][i] = (new_l[r][i] + a * F.l[k][i]) % p
            for i in range(n):
                for j in range(i, n):
                    new_q[r][i][j] = (new_q[r][i][j] + a * F.q[k][i][j]) % p
            new_c[r] = (new_c[r] + a * F.c[k]) % p
        new_c[r] = (new_c[r] + S.b[r]) % p

    return QuadraticMap(new_q, new_l, new_c, p)


def random_invertible_matrix(rng, size, p):
    while True:
        A = [[rng.randrange(p) for _ in range(size)] for _ in range(size)]
        try:
            _ = mat_inv(A, p)
            return A
        except ValueError:
            continue


def random_affine_map(rng, dim, p):
    A = random_invertible_matrix(rng, dim, p)
    b = [rng.randrange(p) for _ in range(dim)]
    return AffineMap(A, b, p)


def _random_invertible_linear_block(rng, size, p):
    return random_invertible_matrix(rng, size, p)


@dataclass(frozen=True)
class RainbowToyParams:
    p: int = 31
    v1: int = 2
    o1: int = 2
    o2: int = 2

    def n(self):
        return self.v1 + self.o1 + self.o2

    def m(self):
        return self.o1 + self.o2


@dataclass(frozen=True)
class LayeredOVCentralMap:
    params: RainbowToyParams
    F: QuadraticMap

    def invert(self, y, vinegar_seed, max_tries=64):
        p = self.params.p
        v1, o1, o2 = self.params.v1, self.params.o1, self.params.o2
        n = self.params.n()

        layer1_out = list(range(0, o1))
        layer2_out = list(range(o1, o1 + o2))

        layer1_oils = list(range(v1, v1 + o1))
        layer2_oils = list(range(v1 + o1, v1 + o1 + o2))

        for attempt in range(max_tries):
            x = [0 for _ in range(n)]
            vvals = vinegar_values(vinegar_seed, attempt, p, v1)
            for i in range(v1):
                x[i] = vvals[i]

            o1_vals = self._solve_layer(layer1_out, layer1_oils, x, y[:o1])
            if o1_vals is None:
                continue
            for idx, val in zip(layer1_oils, o1_vals):
                x[idx] = val

            o2_vals = self._solve_layer(layer2_out, layer2_oils, x, y[o1:])
            if o2_vals is None:
                continue
            for idx, val in zip(layer2_oils, o2_vals):
                x[idx] = val

            if self.F.evaluate(x) == [yi % p for yi in y]:
                return x

        raise ValueError("could not invert central map (increase max_tries)")

    def _solve_layer(self, poly_indices, oil_indices, x_partial, y_target):
        p = self.params.p
        n = self.params.n()
        k = len(oil_indices)
        if k == 0:
            return []

        A = [[0 for _ in range(k)] for _ in range(k)]
        b = [0 for _ in range(k)]

        for row, poly_idx in enumerate(poly_indices):
            base = x_partial[:]
            for oi in oil_indices:
                base[oi] = 0
            base_val = self.F.evaluate(base)[poly_idx]
            rhs = (y_target[row] - base_val) % p
            b[row] = rhs

            for col, oi in enumerate(oil_indices):
                test = base[:]
                test[oi] = 1
                coeff = (self.F.evaluate(test)[poly_idx] - base_val) % p
                A[row][col] = coeff

        return solve_linear_system(A, b, p)


@dataclass(frozen=True)
class RainbowToySecretKey:
    params: RainbowToyParams
    S: AffineMap
    T: AffineMap
    central: LayeredOVCentralMap
    seed: bytes


@dataclass(frozen=True)
class RainbowToyPublicKey:
    params: RainbowToyParams
    P: QuadraticMap


def vinegar_values(seed, attempt, p, count):
    out = []
    for i in range(count):
        h = hashlib.sha256()
        h.update(seed)
        h.update(b"|")
        h.update(attempt.to_bytes(4, "big"))
        h.update(b"|")
        h.update(i.to_bytes(4, "big"))
        out.append(int.from_bytes(h.digest()[:4], "big") % p)
    return out


def rainbow_toy_keygen(seed, params=RainbowToyParams()):
    rng = random.Random(int.from_bytes(hashlib.sha256(seed).digest()[:8], "big"))
    p = params.p
    n = params.n()
    m = params.m()

    q = [[[0 for _ in range(n)] for _ in range(n)] for _ in range(m)]
    l = [[0 for _ in range(n)] for _ in range(m)]
    c = [0 for _ in range(m)]

    v1, o1, o2 = params.v1, params.o1, params.o2
    oils1 = list(range(v1, v1 + o1))
    oils2 = list(range(v1 + o1, v1 + o1 + o2))

    M1 = _random_invertible_linear_block(rng, o1, p)
    M2 = _random_invertible_linear_block(rng, o2, p)

    for k in range(o1):
        for i in range(v1):
            for j in range(i, v1):
                q[k][i][j] = rng.randrange(p)
        for j, oi in enumerate(oils1):
            l[k][oi] = M1[k][j] % p
        for i in range(v1):
            l[k][i] = rng.randrange(p)
        c[k] = rng.randrange(p)

    v2 = v1 + o1
    for k2 in range(o2):
        k = o1 + k2
        for i in range(v2):
            for j in range(i, v2):
                q[k][i][j] = rng.randrange(p)
        for j, oi in enumerate(oils2):
            l[k][oi] = M2[k2][j] % p
        for i in range(v2):
            l[k][i] = rng.randrange(p)
        c[k] = rng.randrange(p)

    F = QuadraticMap(q, l, c, p)
    central = LayeredOVCentralMap(params=params, F=F)
    S = random_affine_map(rng, m, p)
    T = random_affine_map(rng, n, p)

    G = compose_quadratic_with_affine_input(F, T)
    P = apply_output_affine_to_quadratic(G, S)

    pk = RainbowToyPublicKey(params=params, P=P)
    sk = RainbowToySecretKey(params=params, S=S, T=T, central=central, seed=seed)
    return pk, sk


def rainbow_toy_sign(sk, message):
    p = sk.params.p
    y = hash_to_field_elems(message, p, sk.params.m())

    y0 = sk.S.inverse().apply(y)
    vinegar_seed = hashlib.sha256(sk.seed + b"|" + message).digest()
    x = sk.central.invert(y0, vinegar_seed=vinegar_seed)
    sig = sk.T.inverse().apply(x)
    return sig


def rainbow_toy_verify(pk, message, signature):
    p = pk.params.p
    y = hash_to_field_elems(message, p, pk.params.m())
    y2 = pk.P.evaluate(signature)
    return [yi % p for yi in y2] == [yi % p for yi in y]


def pretty_vec(v):
    return "[" + ", ".join(str(x) for x in v) + "]"


def main():
    params = RainbowToyParams()
    seed = b"rainbow-toy-seed"
    message = b"hello, multivariate signatures"

    print("=== Step 1: Finite-field plumbing (GF(p)) ===")
    p = params.p
    a, b = 7, 19
    print(f"p={p}")
    print(f"{a}+{b} mod p = {(a + b) % p}")
    print(f"{a}*{b} mod p = {(a * b) % p}")
    print(f"inv({a}) mod p = {mod_inv(a, p)}")

    print("\n=== Step 2: Quadratic maps (public keys are polynomials) ===")
    pk, sk = rainbow_toy_keygen(seed, params=params)
    print(f"central F quadratic terms: {sk.central.F.nonzero_quadratic_terms()}")
    print(f"public  P quadratic terms: {pk.P.nonzero_quadratic_terms()}")

    print("\n=== Step 3: Layered Oil-and-Vinegar (Rainbow-style) inversion ===")
    target = hash_to_field_elems(message, p, params.m())
    target0 = sk.S.inverse().apply(target)
    vinegar_seed = hashlib.sha256(sk.seed + b"|" + message).digest()
    preimage = sk.central.invert(target0, vinegar_seed=vinegar_seed)
    check = sk.central.F.evaluate(preimage)
    print(f"target (after S^-1): {pretty_vec(target0)}")
    print(f"F(preimage):          {pretty_vec(check)}")
    print(f"preimage x:           {pretty_vec(preimage)}")

    print("\n=== Step 4: Toy signature (keygen / sign / verify) ===")
    sig = rainbow_toy_sign(sk, message)
    ok = rainbow_toy_verify(pk, message, sig)
    print(f"H(m):                 {pretty_vec(target)}")
    print(f"signature s:          {pretty_vec(sig)}")
    print(f"P(s):                 {pretty_vec(pk.P.evaluate(sig))}")
    print(f"verify:               {ok}")

    tampered = sig[:]
    tampered[0] = (tampered[0] + 1) % p
    ok2 = rainbow_toy_verify(pk, message, tampered)
    print(f"verify(tampered):     {ok2}")

    artifact = {
        "p": p,
        "n": params.n(),
        "m": params.m(),
        "message": message.decode("utf-8"),
        "digest": target,
        "signature": sig,
        "verify": ok,
    }
    print("\n(artifact snippet) " + json.dumps(artifact, indent=2))


if __name__ == "__main__":
    main()
