# PLONK from Scratch (Toy, No Commitments)
> One gate identity + one permutation identity = a PLONKish circuit check.

**Type:** Build
**Languages:** Python
**Prerequisites:** `phases/11-zero-knowledge-foundations/04-fiat-shamir/`, `phases/11-zero-knowledge-foundations/05-chaum-pedersen/` (field math + transcripts)
**Time:** ~90 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain PLONK’s “gate constraints” table model
- Compute a roots-of-unity evaluation domain for a tiny prime field
- Implement the grand product `Z` recurrence for copy constraints
- Distinguish “PLONK arithmetization” from “PLONK proof system” (commitments/openings)
- Apply Fiat–Shamir to derive verifier challenges from a transcript

## The Problem

Modern zkSNARKs don’t just prove “some constraints hold” — they prove *one big polynomial identity* holds at a random point, which is how you get succinct verification. PLONK is the bridge from “a circuit with wires” to “a small set of polynomials the verifier checks”.

If you don’t understand PLONK’s two core checks (the gate identity and the permutation/copy identity), you’ll get lost as soon as you read real proof-system code: “selectors”, “wiring”, “sigma polynomials”, “grand product”, “vanishing polynomial”, “opening at ζ”, etc.

This lesson gives you a runnable toy PLONK checker: no elliptic curves, no commitments, just the algebra that makes PLONK *work*.

## The Concept

PLONK represents a circuit as a table with 3 witness columns (`a, b, c`) and 5 selector columns (`qL, qR, qM, qO, qC`).

Each row is a gate. The *universal* (generic) gate equation is:

`qL[i]*a[i] + qR[i]*b[i] + qM[i]*a[i]*b[i] + qO[i]*c[i] + qC[i] = 0`

That’s “gate constraints”.

The second ingredient is “copy constraints”: the same variable can appear in multiple places (for example `a[0]` and `b[1]` are both the value `x`). PLONK enforces these equalities with a *permutation argument*. Intuition:

- Take every cell in the witness table (all `a[i], b[i], c[i]`) and give it a unique “identity tag”.
- Define a permutation `σ` that maps each cell to “the other place this same variable lives”.
- Build a grand product `Z` that will equal `1` at the end **only if** the wiring permutation is consistent.

Real PLONK then commits to witness/selector/permutation polynomials and proves openings at one random point `ζ`. We skip commitments here: the goal is to internalize the algebra, not ship a SNARK.

## Build It

### Step 1: Field arithmetic + roots of unity
```python
def modinv(a: int, p: int) -> int:
    a %= p
    if a == 0:
        raise ZeroDivisionError("inverse of 0")
    return pow(a, p - 2, p)


def is_power_of_two(n: int) -> bool:
    return n > 0 and (n & (n - 1)) == 0


def find_primitive_root(p: int) -> int:
    if p < 3:
        raise ValueError("p must be an odd prime")
    phi = p - 1
    factors: List[int] = []
    x = phi
    f = 2
    while f * f <= x:
        if x % f == 0:
            factors.append(f)
            while x % f == 0:
                x //= f
        f += 1
    if x > 1:
        factors.append(x)

    for g in range(2, p):
        ok = True
        for q in factors:
            if pow(g, phi // q, p) == 1:
                ok = False
                break
        if ok:
            return g
    raise ValueError("no primitive root found")


def primitive_root_of_unity(p: int, n: int) -> int:
    if (p - 1) % n != 0:
        raise ValueError("n must divide p-1")
    g = find_primitive_root(p)
    w = pow(g, (p - 1) // n, p)
    if pow(w, n, p) != 1 or pow(w, n // 2, p) == 1:
        raise ValueError("failed to find primitive n-th root of unity")
    return w
```
This picks a tiny prime field `F_p` and an evaluation domain `H = {1, ω, ω², …}`. In real PLONK, most polynomials are represented as evaluations on `H`.

### Step 2: Polynomials (just enough for tests + intuition)
```python
def eval_poly(coeffs: Sequence[int], x: int, p: int) -> int:
    acc = 0
    power = 1
    x %= p
    for c in coeffs:
        acc = (acc + (c % p) * power) % p
        power = (power * x) % p
    return acc


def poly_mul(a: Sequence[int], b: Sequence[int], p: int) -> List[int]:
    if not a or not b:
        return []
    out = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        for j, bj in enumerate(b):
            out[i + j] = (out[i + j] + (ai % p) * (bj % p)) % p
    return trim_poly(out, p)


def trim_poly(a: Sequence[int], p: int) -> List[int]:
    out = list(a)
    while out and out[-1] % p == 0:
        out.pop()
    return out


def poly_add(a: Sequence[int], b: Sequence[int], p: int) -> List[int]:
    n = max(len(a), len(b))
    out = [0] * n
    for i in range(n):
        out[i] = ((a[i] if i < len(a) else 0) + (b[i] if i < len(b) else 0)) % p
    return trim_poly(out, p)


def poly_scale(a: Sequence[int], k: int, p: int) -> List[int]:
    return trim_poly([(k * (c % p)) % p for c in a], p)


def lagrange_interpolate(xs: Sequence[int], ys: Sequence[int], p: int) -> List[int]:
    if len(xs) != len(ys):
        raise ValueError("xs and ys length mismatch")
    n = len(xs)
    if n == 0:
        return []

    for i in range(n):
        for j in range(i + 1, n):
            if xs[i] % p == xs[j] % p:
                raise ValueError("duplicate x values")

    result: List[int] = []
    for i in range(n):
        numer = [1]
        denom = 1
        xi = xs[i] % p
        for j in range(n):
            if i == j:
                continue
            xj = xs[j] % p
            numer = poly_mul(numer, [(-xj) % p, 1], p)
            denom = (denom * ((xi - xj) % p)) % p
        li = poly_scale(numer, (ys[i] % p) * modinv(denom, p), p)
        result = poly_add(result, li, p)
    return trim_poly(result, p)
```
PLONK implementations use FFTs/NTTs for speed. We keep it simple: polynomial evaluation and interpolation are enough to support our tests and the mental model.

### Step 3: A tiny circuit as gate constraints
```python
def build_toy_circuit_witness(p: int, n: int) -> Dict[str, List[int]]:
    if n < 3:
        raise ValueError("need n>=3 for this toy circuit")
    x = 3 % p
    y = 11 % p
    z = (x * y) % p
    t = (z + x) % p
    u = (t + 5) % p

    a = [0] * n
    b = [0] * n
    c = [0] * n

    a[0], b[0], c[0] = x, y, z
    a[1], b[1], c[1] = z, x, t
    a[2], b[2], c[2] = t, 5 % p, u

    ql = [0] * n
    qr = [0] * n
    qm = [0] * n
    qo = [0] * n
    qc = [0] * n

    ql[1], qr[1], qo[1] = 1, 1, (-1) % p
    ql[2], qr[2], qo[2] = 1, 1, (-1) % p
    qm[0], qo[0] = 1, (-1) % p

    return {
        "a": a,
        "b": b,
        "c": c,
        "ql": ql,
        "qr": qr,
        "qm": qm,
        "qo": qo,
        "qc": qc,
        "public_u": [u],
    }


def check_gate_constraints(
    witness: Dict[str, List[int]], roots: Sequence[int], p: int
) -> bool:
    a = witness["a"]
    b = witness["b"]
    c = witness["c"]
    ql = witness["ql"]
    qr = witness["qr"]
    qm = witness["qm"]
    qo = witness["qo"]
    qc = witness["qc"]

    n = len(roots)
    for i in range(n):
        lhs = (
            ql[i] * a[i]
            + qr[i] * b[i]
            + qm[i] * a[i] * b[i]
            + qo[i] * c[i]
            + qc[i]
        ) % p
        if lhs != 0:
            return False
    return True
```
This is the “generic gate”: row 0 is a multiplication gate, rows 1–2 are addition gates, and the remaining rows are unused (all-zero selectors).

### Step 4: Copy constraints via the grand product `Z`
```python
def derive_permutation_mapping(n: int) -> List[int]:
    perm = list(range(3 * n))

    def swap(pos1: int, pos2: int) -> None:
        perm[pos1], perm[pos2] = perm[pos2], perm[pos1]

    swap(0 * n + 0, 1 * n + 1)
    swap(2 * n + 0, 0 * n + 1)
    swap(2 * n + 1, 0 * n + 2)
    return perm


def compute_grand_product_z(
    a: Sequence[int],
    b: Sequence[int],
    c: Sequence[int],
    perm: Sequence[int],
    beta: int,
    gamma: int,
    roots: Sequence[int],
    p: int,
) -> List[int]:
    n = len(roots)
    if not (len(a) == len(b) == len(c) == n):
        raise ValueError("witness length must equal domain size")
    if len(perm) != 3 * n:
        raise ValueError("perm length must be 3n")

    id_pos = [(wire, i) for wire in range(3) for i in range(n)]
    z = [0] * (n + 1)
    z[0] = 1

    for i in range(n):
        num = 1
        den = 1
        for wire in range(3):
            v = [a, b, c][wire][i] % p
            x_id = roots[i] * (wire + 1) % p

            w2, j2 = id_pos[perm[wire * n + i]]
            x_sigma = roots[j2] * (w2 + 1) % p

            num = (num * ((v + beta * x_id + gamma) % p)) % p
            den = (den * ((v + beta * x_sigma + gamma) % p)) % p
        z[i + 1] = (z[i] * num * modinv(den, p)) % p

    return z


def check_permutation_constraints(
    witness: Dict[str, List[int]],
    perm: Sequence[int],
    roots: Sequence[int],
    beta: int,
    gamma: int,
    p: int,
) -> bool:
    a = witness["a"]
    b = witness["b"]
    c = witness["c"]
    z = compute_grand_product_z(a, b, c, perm, beta, gamma, roots, p)
    if z[0] % p != 1 or z[-1] % p != 1:
        return False

    n = len(roots)
    id_pos = [(wire, i) for wire in range(3) for i in range(n)]

    for i in range(n):
        num = 1
        den = 1
        for wire in range(3):
            v = [a, b, c][wire][i] % p
            x_id = roots[i] * (wire + 1) % p
            w2, j2 = id_pos[perm[wire * n + i]]
            x_sigma = roots[j2] * (w2 + 1) % p
            num = (num * ((v + beta * x_id + gamma) % p)) % p
            den = (den * ((v + beta * x_sigma + gamma) % p)) % p

        if (z[i + 1] * den - z[i] * num) % p != 0:
            return False
    return True
```
`β` and `γ` are random challenges (derived later via Fiat–Shamir). They make it overwhelmingly unlikely that an incorrect wiring accidentally passes the product check.

### Step 5: Fiat–Shamir and an end-to-end “prove + verify”
```python
@dataclass(frozen=True)
class Transcript:
    state: bytes = b""

    def absorb_ints(self, label: str, ints: Iterable[int]) -> "Transcript":
        h = hashlib.sha256()
        h.update(self.state)
        h.update(label.encode("utf-8"))
        for v in ints:
            h.update(int(v).to_bytes(32, "big", signed=False))
        return Transcript(h.digest())

    def challenge(self, label: str, p: int) -> Tuple["Transcript", int]:
        t2 = self.absorb_ints(label, [])
        c = int.from_bytes(t2.state, "big") % p
        return t2, c


def prove_and_verify_toy_plonk(p: int, n: int) -> bool:
    if not is_power_of_two(n):
        raise ValueError("n must be a power of two")
    w = primitive_root_of_unity(p, n)
    roots = [pow(w, i, p) for i in range(n)]

    witness = build_toy_circuit_witness(p, n)
    perm = derive_permutation_mapping(n)
    transcript = Transcript()
    transcript = transcript.absorb_ints("witness_a", witness["a"])
    transcript = transcript.absorb_ints("witness_b", witness["b"])
    transcript = transcript.absorb_ints("witness_c", witness["c"])
    transcript = transcript.absorb_ints("selectors", witness["ql"] + witness["qr"] + witness["qm"])
    transcript = transcript.absorb_ints("perm", perm)

    transcript, beta = transcript.challenge("beta", p)
    transcript, gamma = transcript.challenge("gamma", p)

    gates_ok = check_gate_constraints(witness, roots, p)
    perm_ok = check_permutation_constraints(witness, perm, roots, beta, gamma, p)
    return gates_ok and perm_ok
```
This is the “shape” of a real verifier: derive challenges from a transcript, then check the gate identity and the permutation identity. In production, this happens using *committed* polynomials opened at a random point instead of full tables.

Run it:
`python3 code/main.py`

## Use It

Real systems add (at least) two big pieces we skipped:

- **Polynomial commitments** (KZG or IPA) so the prover can commit to witness polynomials without revealing them.
- **Opening proofs** so the verifier only checks a few evaluations at a random point `ζ` (succinct verification).

Where you’ll see PLONKish arithmetization in the wild:

- `halo2` (Zcash) — PLONKish arithmetization + commitment scheme choices (IPA/KZG depending on ecosystem)
- `barretenberg` (Aztec) — UltraPlonk / related PLONK-family provers
- `gnark` (Go) — PLONK variants in a practical ZK library

## Pitfalls

- Forgetting that “PLONK” = arithmetization + commitments + openings: implementing just the gate/permutation algebra isn’t a SNARK yet.
- Mixing representations: selector/witness values “per-row evaluations” vs “polynomial coefficients” (and silently evaluating on the wrong domain).
- Getting the permutation wrong: a single off-by-one in the `σ` wiring makes `Z` look random; debugging without a small toy case is brutal.
- Transcript bugs: if you forget to absorb some prover message before deriving a challenge, the proof can become malleable.
- Domain size assumptions: production implementations require power-of-two domains for FFTs and must handle padding carefully.

## Ship It

Save the reusable checklist:

- Open `outputs/plonk-implementation-review-checklist.md`
- Use it as a PR review prompt when you (or a teammate) touch: gate constraints, copy constraints, transcript/challenges, or polynomial openings in a PLONKish codebase.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that `Z` becomes `1` and stays `1` once the circuit stops using rows.
2. Medium. In `code/main.py`, break one copy constraint (e.g., change `b[1]`) and confirm `check_permutation_constraints(...)` turns `False`.
3. Hard. Extend `prove_and_verify_toy_plonk` to also derive an `alpha` challenge and combine the two checks into one “linearized” check (you’re moving toward a real quotient polynomial).

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Arithmetization | “Turn a circuit into polynomials” | A specific encoding of a circuit so verification becomes checking polynomial identities |
| Selector | “Gate type flags” | Per-row coefficients (`qL,qR,qM,qO,qC`) that choose which arithmetic rule a row enforces |
| Copy constraint | “Wires must match” | Equalities between table cells (the same variable reused across the circuit) |
| Permutation `σ` | “Wiring” | A mapping that links each cell to where the same variable appears elsewhere |
| Grand product `Z` | “Permutation check polynomial” | A running product that equals `1` at the end only if the wiring permutation is consistent |
| Fiat–Shamir | “Make it non-interactive” | Hash the transcript to sample verifier randomness (`β,γ,…`) without interaction |

## Further Reading

- Gabizon, Williamson, Ciobotaru, *PLONK: Permutations over Lagrange-bases for Oecumenical Noninteractive arguments of Knowledge* (2019) — the original protocol definition.
- Zcash, *The halo2 Book* (ongoing) — practical PLONKish arithmetization and implementation notes.
- “How to PLONK” (zksecurity.xyz) (ongoing) — an implementation-driven walkthrough of the permutation argument.
