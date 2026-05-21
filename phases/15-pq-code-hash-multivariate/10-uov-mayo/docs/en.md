# UOV & MAYO — Modern Multivariate
> Hide a solvable linear system inside a quadratic map.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** Phase 15, Lesson 09 (Multivariate / Rainbow); modular arithmetic; Gaussian elimination  
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** why Oil-and-Vinegar (OV) polynomials become linear after fixing vinegar variables
- **Compute** the polar form `P'(x,y) = P(x+y) - P(x) - P(y)` for a quadratic map and interpret it as a bilinear map
- **Implement** a toy OV/UOV-style sign/verify loop over a small prime field using Gaussian elimination
- **Distinguish** the UOV setting `o = m` from the MAYO setting `o < m` and why naïve signing breaks in the latter
- **Apply** a practical review checklist to spot common implementation and security failures in multivariate signatures

## The Problem

You want post-quantum signatures that are fast to verify and have compact signatures. Multivariate signatures deliver on the speed and signature size, but historically they’ve had a painful drawback: **big public keys** (lots of quadratic coefficients).

UOV (Unbalanced Oil-and-Vinegar) is a “classic” multivariate design that shows the core trapdoor idea cleanly: build a quadratic map that *looks hard to invert* unless you know a secret decomposition into oil and vinegar variables. However, the public key still tends to be large.

MAYO is a modern approach that targets the key-size problem by shrinking the “oil space” in a way that would normally break the UOV signing algorithm — and then restoring signability by **whipping up** the map into a larger one. This lesson gives you the minimal math + code to understand *why that works*.

## The Concept

### OV structure: why signing reduces to linear algebra

An OV map is a vector of quadratic polynomials:

- `P : F_p^(v+o) -> F_p^m`
- the input splits into **vinegar** variables `x_0..x_{v-1}` and **oil** variables `x_v..x_{v+o-1}`

The trapdoor is: choose polynomials so that **every quadratic term contains at least one vinegar variable**. In other words:

- vinegar×vinegar terms: allowed  
- vinegar×oil terms: allowed  
- oil×oil terms: forbidden  
- (in the simplest “vanishing oil space” form used here) constants and oil-only linear terms are also forbidden

That last choice makes the **oil subspace** special:

- if the vinegar part is zero, the output is always zero: `P([0..0, oil]) = 0`

Now the signing trick:

1. Hash the message to a target vector `t in F_p^m`.
2. Choose a random vinegar vector `v`.
3. Solve for an oil vector `o` so that `P(v + o) = t`.

Once `v` is fixed, each polynomial is **linear in the oil variables**, so step (3) becomes solving a linear system over `F_p`.

### UOV vs MAYO: what breaks and what “whipping” fixes

In the classic OV/UOV trapdoor, the oil-space dimension `o` is typically at least `m` (often `o = m`), so the linear system has enough unknowns to be solvable frequently.

MAYO chooses a public map that still has an oil space, but with **`o < m`**. Then the naïve equation `P(v + o) = t` becomes:

- `m` equations in only `o` unknowns → usually **no solution**

The MAYO idea is to build a new map `P*` from `P`:

```
P*(x1,...,xk) = sum_i P(x_i) + sum_{i<j} P'(x_i, x_j)
P'(x,y) = P(x+y) - P(x) - P(y)
```

If `P` is quadratic, then `P'` is bilinear. If `P` vanishes on the oil space `O`, then choosing `o_i in O` makes `P(o_i)=0` and (crucially) keeps the whipped equation linear in the oil variables. With `k` blocks, you now solve:

- `m` equations in `k*o` unknowns

Pick `k` so that `k*o >= m` (often `k*o > m`) and signing becomes likely again.

## Build It

### Step 1: Finite field + linear solver
You need just enough finite-field linear algebra to solve `A x = b (mod p)`. We use a small prime `p` and implement Gaussian elimination.

```python
def inv_modp(a: int, p: int) -> int:
    a = a % p
    if a == 0:
        raise ZeroDivisionError("no inverse for 0 mod p")

    t, new_t = 0, 1
    r, new_r = p, a
    while new_r != 0:
        q = r // new_r
        t, new_t = new_t, t - q * new_t
        r, new_r = new_r, r - q * new_r

    if r != 1:
        raise ZeroDivisionError("a is not invertible mod p")
    return t % p


def mat_vec_mul(matrix: Sequence[Sequence[int]], vector: Sequence[int], p: int) -> List[int]:
    if not matrix:
        return []
    cols = len(matrix[0])
    if len(vector) != cols:
        raise ValueError("dimension mismatch for mat-vec multiply")
    out: List[int] = []
    for row in matrix:
        if len(row) != cols:
            raise ValueError("ragged matrix")
        acc = 0
        for a, b in zip(row, vector):
            acc += a * b
        out.append(acc % p)
    return out


def solve_linear_system_modp(
    matrix: Sequence[Sequence[int]], rhs: Sequence[int], p: int
) -> Optional[List[int]]:
    """
    Solve A x = b over GF(p) using Gaussian elimination.

    Returns one solution (free vars set to 0) or None if inconsistent.
    Works for rectangular A.
    """
    rows = len(matrix)
    if rows != len(rhs):
        raise ValueError("row count mismatch")
    cols = len(matrix[0]) if rows else 0
    if any(len(row) != cols for row in matrix):
        raise ValueError("ragged matrix")

    aug = [[matrix[i][j] % p for j in range(cols)] + [rhs[i] % p] for i in range(rows)]

    pivot_row = 0
    pivot_cols: List[int] = []
    for col in range(cols):
        pivot = None
        for r in range(pivot_row, rows):
            if aug[r][col] % p != 0:
                pivot = r
                break
        if pivot is None:
            continue
        aug[pivot_row], aug[pivot] = aug[pivot], aug[pivot_row]

        inv_pivot = inv_modp(aug[pivot_row][col], p)
        for j in range(col, cols + 1):
            aug[pivot_row][j] = (aug[pivot_row][j] * inv_pivot) % p

        for r in range(rows):
            if r == pivot_row:
                continue
            factor = aug[r][col] % p
            if factor == 0:
                continue
            for j in range(col, cols + 1):
                aug[r][j] = (aug[r][j] - factor * aug[pivot_row][j]) % p

        pivot_cols.append(col)
        pivot_row += 1
        if pivot_row == rows:
            break

    for r in range(rows):
        all_zero = all(aug[r][c] % p == 0 for c in range(cols))
        if all_zero and (aug[r][cols] % p != 0):
            return None

    solution = [0] * cols
    for r, c in enumerate(pivot_cols):
        solution[c] = aug[r][cols] % p
    return solution
```

This is the single most important building block: OV/UOV/MAYO signing is “just” repeated linear solves over a small field.

### Step 2: OV map evaluation + polar form
We model an OV map that vanishes on the oil subspace by ensuring every term contains a vinegar variable. Then we define the polar form `P'` from evaluations of `P`.

```python
@dataclass(frozen=True)
class OVMap:
    """
    Oil-and-Vinegar quadratic map P: F_p^(v+o) -> F_p^m, with the trapdoor property:
    P(oil_only) = 0 for all vectors whose vinegar part is 0.

    That is ensured by construction: every term contains at least one vinegar variable.
    """

    p: int
    v: int
    o: int
    m: int
    vv: List[List[List[int]]]  # vv[poly][a][b] for 0<=a<=b<v, lower triangle is 0
    vo: List[List[List[int]]]  # vo[poly][a][k] for vinegar index a and oil index k
    lin_v: List[List[int]]  # lin_v[poly][a] for vinegar linear terms

    @property
    def n(self) -> int:
        return self.v + self.o


def ov_map_random(p: int, v: int, o: int, m: int, rng: random.Random) -> OVMap:
    vv: List[List[List[int]]] = []
    vo: List[List[List[int]]] = []
    lin_v: List[List[int]] = []
    for _ in range(m):
        vv_poly = [[0 for _ in range(v)] for _ in range(v)]
        for a in range(v):
            for b in range(a, v):
                vv_poly[a][b] = rng.randrange(p)
        vo_poly = [[rng.randrange(p) for _ in range(o)] for _ in range(v)]
        lin_v_poly = [rng.randrange(p) for _ in range(v)]
        vv.append(vv_poly)
        vo.append(vo_poly)
        lin_v.append(lin_v_poly)
    return OVMap(p=p, v=v, o=o, m=m, vv=vv, vo=vo, lin_v=lin_v)


def ov_eval(ov_map: OVMap, x: Sequence[int]) -> List[int]:
    if len(x) != ov_map.n:
        raise ValueError("input length mismatch")
    p = ov_map.p
    vinegar = x[: ov_map.v]
    oil = x[ov_map.v :]
    out: List[int] = []
    for poly_index in range(ov_map.m):
        acc = 0
        vv_poly = ov_map.vv[poly_index]
        vo_poly = ov_map.vo[poly_index]
        lin_v_poly = ov_map.lin_v[poly_index]

        for a in range(ov_map.v):
            va = vinegar[a] % p
            acc += lin_v_poly[a] * va
            for b in range(a, ov_map.v):
                acc += vv_poly[a][b] * va * (vinegar[b] % p)
            for k in range(ov_map.o):
                acc += vo_poly[a][k] * va * (oil[k] % p)

        out.append(acc % p)
    return out


def ov_polar(ov_map: OVMap, x: Sequence[int], y: Sequence[int]) -> List[int]:
    p = ov_map.p
    return vec_sub(ov_eval(ov_map, vec_add(x, y, p)), vec_add(ov_eval(ov_map, x), ov_eval(ov_map, y), p), p)
```

The polar form is how MAYO turns “quadratic” into “bilinear,” which is how you keep signing linear.

### Step 3: Toy UOV (o = m) sign/verify
When `o = m`, fixing vinegar variables gives (approximately) a square linear system in the oil variables, so naïve OV signing is plausible.

```python
def uov_linear_system_for_oil(ov_map: OVMap, vinegar: Sequence[int], target: Sequence[int]) -> Tuple[List[List[int]], List[int]]:
    """
    Build the linear system A * oil = b for a fixed vinegar and desired target output.
    """
    if len(vinegar) != ov_map.v:
        raise ValueError("vinegar length mismatch")
    if len(target) != ov_map.m:
        raise ValueError("target length mismatch")

    p = ov_map.p
    constant = ov_eval(ov_map, list(vinegar) + [0] * ov_map.o)
    rhs = vec_sub(target, constant, p)

    matrix: List[List[int]] = [[0 for _ in range(ov_map.o)] for _ in range(ov_map.m)]
    for poly_index in range(ov_map.m):
        for k in range(ov_map.o):
            coeff = 0
            for a in range(ov_map.v):
                coeff += ov_map.vo[poly_index][a][k] * (vinegar[a] % p)
            matrix[poly_index][k] = coeff % p
    return matrix, rhs


@dataclass(frozen=True)
class ToyUOVKeypair:
    p: int
    ov_map: OVMap
    s: List[List[int]]
    s_inv: List[List[int]]
    t: List[List[int]]
    t_inv: List[List[int]]


def uov_keygen(seed: int, p: int, v: int, o: int) -> ToyUOVKeypair:
    """
    Generate a toy UOV keypair.

    For the toy, we set m=o so the classic OV trapdoor gives an (attempted) square
    linear system in the oil variables.
    """
    rng = random.Random(seed)
    ov_map = ov_map_random(p=p, v=v, o=o, m=o, rng=rng)

    s = random_invertible_matrix(ov_map.n, p, rng)
    s_inv = mat_inverse(s, p)
    if s_inv is None:
        raise RuntimeError("unexpected: failed to invert S")

    t = random_invertible_matrix(ov_map.m, p, rng)
    t_inv = mat_inverse(t, p)
    if t_inv is None:
        raise RuntimeError("unexpected: failed to invert T")

    return ToyUOVKeypair(p=p, ov_map=ov_map, s=s, s_inv=s_inv, t=t, t_inv=t_inv)


def uov_public_eval(keypair: ToyUOVKeypair, signature: Sequence[int]) -> List[int]:
    x_prime = mat_vec_mul(keypair.s, signature, keypair.p)
    y_prime = ov_eval(keypair.ov_map, x_prime)
    return mat_vec_mul(keypair.t, y_prime, keypair.p)


def uov_sign(keypair: ToyUOVKeypair, message: bytes, rng_seed: int, max_attempts: int = 256) -> List[int]:
    """
    Toy UOV signing:
    - hash message to target in F_p^m
    - invert secret output transform T
    - sample random vinegar, solve linear system for oil
    - apply secret input transform S^{-1}
    """
    rng = random.Random(rng_seed)
    p = keypair.p

    target = hash_to_field_vec(message, p, keypair.ov_map.m, domain=b"uov")
    target_prime = mat_vec_mul(keypair.t_inv, target, p)

    for _ in range(max_attempts):
        vinegar = [rng.randrange(p) for _ in range(keypair.ov_map.v)]
        matrix, rhs = uov_linear_system_for_oil(keypair.ov_map, vinegar, target_prime)
        oil = solve_linear_system_modp(matrix, rhs, p)
        if oil is None:
            continue
        x_prime = vinegar + oil
        return mat_vec_mul(keypair.s_inv, x_prime, p)

    raise ValueError("failed to find a signature (toy params too small / unlucky RNG)")


def uov_verify(keypair: ToyUOVKeypair, message: bytes, signature: Sequence[int]) -> bool:
    p = keypair.p
    target = hash_to_field_vec(message, p, keypair.ov_map.m, domain=b"uov")
    return uov_public_eval(keypair, signature) == target
```

This is the OV trapdoor in its purest form: pick vinegar, then solve a linear system for oil.

### Step 4: Toy MAYO (o < m) via whipped map
When `o < m`, a single-block signing equation is overdetermined and almost always inconsistent. MAYO restores signability by “whipping up” the map into a `k`-block map so you solve `m` equations in `k*o` unknowns.

```python
def mayo_whipped_eval(ov_map: OVMap, blocks: Sequence[Sequence[int]]) -> List[int]:
    """
    Toy MAYO whipped map:
      P*(x1,...,xk) = sum_i P(x_i) + sum_{i<j} P'(x_i, x_j)
    with E-matrices = identity (for teaching only).
    """
    p = ov_map.p
    k = len(blocks)
    if k == 0:
        return [0] * ov_map.m
    if any(len(block) != ov_map.n for block in blocks):
        raise ValueError("block size mismatch")

    acc = [0] * ov_map.m
    for i in range(k):
        acc = vec_add(acc, ov_eval(ov_map, blocks[i]), p)
    for i in range(k):
        for j in range(i + 1, k):
            acc = vec_add(acc, ov_polar(ov_map, blocks[i], blocks[j]), p)
    return acc


def mayo_build_oil_system(
    ov_map: OVMap, vinegar_blocks: Sequence[Sequence[int]], target: Sequence[int]
) -> Tuple[List[List[int]], List[int], List[int]]:
    """
    Build A * oil_vec = b for the whipped map equation:
      P*(v1+o1, ..., vk+ok) = target

    This uses "probing": because the expression is linear in the oil variables (for OV maps
    that vanish on the oil space), each column can be recovered by flipping one oil basis
    coordinate to 1.
    """
    p = ov_map.p
    k = len(vinegar_blocks)
    if k == 0:
        raise ValueError("need at least one block")
    if len(target) != ov_map.m:
        raise ValueError("target length mismatch")
    if any(len(vb) != ov_map.v for vb in vinegar_blocks):
        raise ValueError("vinegar block length mismatch")

    base_blocks = [list(vb) + [0] * ov_map.o for vb in vinegar_blocks]
    base_value = mayo_whipped_eval(ov_map, base_blocks)
    rhs = vec_sub(target, base_value, p)

    num_vars = k * ov_map.o
    matrix = [[0 for _ in range(num_vars)] for _ in range(ov_map.m)]

    for var_index in range(num_vars):
        blocks = [block[:] for block in base_blocks]
        block_index = var_index // ov_map.o
        oil_index = var_index % ov_map.o
        blocks[block_index][ov_map.v + oil_index] = 1
        value = mayo_whipped_eval(ov_map, blocks)
        col = vec_sub(value, base_value, p)
        for eq in range(ov_map.m):
            matrix[eq][var_index] = col[eq]

    return matrix, rhs, base_value


def mayo_sign(
    ov_map: OVMap, message: bytes, k: int, rng_seed: int, max_attempts: int = 256
) -> List[int]:
    """
    Toy MAYO signing:
    - hash message to target in F_p^m
    - choose k random vinegar blocks
    - solve m linear equations in k*o oil variables using the whipped map
    - output signature as a flat vector of length k*n (block concatenation)
    """
    if k <= 0:
        raise ValueError("k must be positive")
    rng = random.Random(rng_seed)
    p = ov_map.p

    target = hash_to_field_vec(message, p, ov_map.m, domain=b"mayo")
    for _ in range(max_attempts):
        vinegar_blocks = [[rng.randrange(p) for _ in range(ov_map.v)] for _ in range(k)]
        matrix, rhs, _ = mayo_build_oil_system(ov_map, vinegar_blocks, target)
        oil_vec = solve_linear_system_modp(matrix, rhs, p)
        if oil_vec is None:
            continue
        blocks: List[List[int]] = []
        for block_index in range(k):
            oil_block = oil_vec[block_index * ov_map.o : (block_index + 1) * ov_map.o]
            blocks.append(vinegar_blocks[block_index] + oil_block)
        signature_flat: List[int] = []
        for block in blocks:
            signature_flat.extend([x % p for x in block])
        return signature_flat

    raise ValueError("failed to find a signature (toy params too small / unlucky RNG)")


def mayo_verify(ov_map: OVMap, message: bytes, k: int, signature_flat: Sequence[int]) -> bool:
    p = ov_map.p
    target = hash_to_field_vec(message, p, ov_map.m, domain=b"mayo")
    if len(signature_flat) != k * ov_map.n:
        return False
    blocks = [
        list(signature_flat[i * ov_map.n : (i + 1) * ov_map.n]) for i in range(k)
    ]
    return mayo_whipped_eval(ov_map, blocks) == target
```

Run it:

`python3 code/main.py`

## Use It

In real systems you don’t implement MAYO/UOV from scratch — you use audited implementations and the scheme spec.

Suggested references / implementations:

- **MAYO**:
  - C reference implementation: `PQCMayo/MAYO-C`
  - Rust crate: `pq_mayo`
  - Integration: `liboqs` has a MAYO implementation (check your exact version / parameter set support)
- **UOV**:
  - UOV NIST submission specs + reference implementations (Round-1/Round-2 packages)

## Pitfalls

1. **Forgetting the salt / domain separation in hashing**: real schemes hash `msg || salt` into `F_q^m`. A deterministic “hash-to-field” is educational, but not what you ship.
2. **Breaking the oil-space property**: if you accidentally introduce oil-only terms, signing is no longer a linear solve.
3. **Characteristic-2 gotchas**: polar forms behave differently in characteristic 2; this lesson uses an odd prime field to keep intuition clean.
4. **Side-channel leakage**: naïve Gaussian elimination + retries can leak information through timing and memory access patterns.
5. **Treating toy algebra as security**: the parameters here are tiny so you can see the mechanics — they provide *no* security.

## Ship It

This lesson ships a reusable review artifact:

- `outputs/skill-multivariate-signature-review.md`

Use it as a PR review checklist when you see multivariate signature code, or paste it into an LLM to guide a structured security review.

## Exercises

1. **Easy.** Run `python3 code/main.py`. Observe that Step 3 verifies successfully, while Step 4 shows single-block signing failing and whipped signing succeeding.
2. **Medium.** Change MAYO’s `k` in `main()` (try `k=2`, `k=3`, `k=4`) and measure how often signing succeeds for your toy parameters.
3. **Hard.** Extend `mayo_whipped_eval` to accept non-identity “emulsifier” matrices `E_ij` and show (empirically) how `rank(A)` changes as you vary them.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Multivariate Quadratic (MQ) | “Solve quadratic equations” | The public key is a system of quadratic polynomials over a small finite field |
| Vinegar variables | “Random padding variables” | Variables you freely choose so the remaining system becomes linear |
| Oil variables / oil space `O` | “The secret subspace” | A linear subspace on which `P(o) = 0`, enabling linear signing equations |
| Polar form / differential `P'` | “Derivative” | A bilinear map derived from a quadratic map: `P'(x,y)=P(x+y)-P(x)-P(y)` |
| Whipped map `P*` | “k copies of P” | A larger map that increases the effective oil dimension to `k*o` while keeping signing linear |

## Further Reading

- J. Patarin, *The Oil and Vinegar signature scheme* (1997) — introduces the OV trapdoor idea.
- A. Kipnis, J. Patarin, L. Goubin, *Unbalanced Oil and Vinegar Signature Schemes* (EUROCRYPT 1999) — the UOV construction and parameter intuition.
- W. Beullens, *MAYO: Practical Post-Quantum Signatures from Oil-and-Vinegar Maps* (SAC 2021 / LNCS 13203, 2022; ePrint 2021/1144) — “whipping up” to keep keys small while preserving signability.
