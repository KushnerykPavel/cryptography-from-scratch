# Groth16 from Scratch
> One pairing equation turns “I know a witness” into three group elements.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** `phases/12-zk-proof-systems/02-r1cs/`, `phases/12-zk-proof-systems/03-qap/`, `phases/12-zk-proof-systems/04-pinocchio/`  
**Time:** ~120 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** why Groth16 verification is a single pairing equation (and what bilinearity buys you).
- **Compute** the QAP divisibility check `A(x)B(x) - C(x) = h(x)t(x)` for a concrete witness.
- **Implement** a toy Groth16 `setup/prove/verify` flow that matches the real structure (but is not cryptographically secure).
- **Distinguish** public inputs vs private witness in Groth16 (`gamma` vs `delta` separation).
- **Apply** a practical verifier review checklist to avoid real-world integration bugs.

## The Problem
You want to verify a computation that’s *too big* to re-run: a rollup batch, a private identity check, or a complex on-chain predicate. You also want the verifier to be cheap: a contract can’t afford to replay thousands of constraints.

Groth16 is the “classic” answer: the proof is constant-size (3 group elements), and verification boils down to a small number of pairings. But the math is easy to get lost in: R1CS → QAP → a secret evaluation point `τ` → group elements → one final equation.

Without this lesson, you can’t reliably reason about what a Groth16 verifying key *means*, what parts depend on public inputs, what “toxic waste” is, or how the prover’s three elements `A, B, C` are shaped so the verifier only needs a single check.

## The Concept
Groth16 is a pairing-based SNARK for QAPs. The high-level story:

1. Start from an R1CS instance (constraints over a witness vector `w`).
2. Convert it to a QAP:
   - polynomials `u_i(x), v_i(x), w_i(x)` for each variable `i`
   - a vanishing polynomial `t(x)` for the constraint domain
   - a witness is valid iff `A(x)B(x) - C(x)` is divisible by `t(x)`
3. The trusted setup samples secret scalars (think `τ, α, β, γ, δ`) and publishes only **group elements** derived from them.
4. The prover produces three group elements `(A ∈ G1, B ∈ G2, C ∈ G1)` such that the verifier can check:

   `e(A, B) = e(α, β) · e(vk_x, γ) · e(C, δ)`

   where `vk_x` is a linear combination of “IC” points with public inputs.

### Why pairings show up
A bilinear pairing is a map `e: G1 × G2 → GT` with bilinearity:

- `e(P1 + P2, Q) = e(P1, Q) · e(P2, Q)`
- `e(P, Q1 + Q2) = e(P, Q1) · e(P, Q2)`

So: **linear combinations** in `G1`/`G2` become **products** in `GT`.

In this lesson we use a toy pairing over a tiny subgroup:

`e(g^a, g^b) = g^(a·b)`

It’s not secure, but it makes the algebra concrete.

## Build It

### Step 1: Toy field + polynomials
```python
def mod_inv(x: int, mod: int) -> int:
    x = x % mod
    if x == 0:
        raise ZeroDivisionError("no inverse for 0")
    return pow(x, -1, mod)


def mod_div(a: int, b: int, mod: int) -> int:
    return (a % mod) * mod_inv(b, mod) % mod


def poly_trim(poly: List[int]) -> List[int]:
    while len(poly) > 1 and poly[-1] == 0:
        poly.pop()
    return poly


def poly_add(a: Sequence[int], b: Sequence[int], mod: int) -> List[int]:
    out = []
    n = max(len(a), len(b))
    for i in range(n):
        av = a[i] if i < len(a) else 0
        bv = b[i] if i < len(b) else 0
        out.append((av + bv) % mod)
    return poly_trim(out)


def poly_scale(a: Sequence[int], k: int, mod: int) -> List[int]:
    k %= mod
    return poly_trim([(k * c) % mod for c in a] if a else [0])


def poly_mul(a: Sequence[int], b: Sequence[int], mod: int) -> List[int]:
    if not a or not b:
        return [0]
    out = [0] * (len(a) + len(b) - 1)
    for i, av in enumerate(a):
        if av == 0:
            continue
        for j, bv in enumerate(b):
            out[i + j] = (out[i + j] + av * bv) % mod
    return poly_trim(out)


def poly_eval(poly: Sequence[int], x: int, mod: int) -> int:
    x %= mod
    acc = 0
    power = 1
    for c in poly:
        acc = (acc + c * power) % mod
        power = (power * x) % mod
    return acc


def lagrange_interpolate(xs: Sequence[int], ys: Sequence[int], mod: int) -> List[int]:
    if len(xs) != len(ys):
        raise ValueError("xs and ys must have the same length")
    if len(xs) == 0:
        raise ValueError("need at least one point")

    xs = [x % mod for x in xs]
    ys = [y % mod for y in ys]

    out = [0]
    for j in range(len(xs)):
        numer = [1]
        denom = 1
        xj = xs[j]
        for m in range(len(xs)):
            if m == j:
                continue
            xm = xs[m]
            numer = poly_mul(numer, [(-xm) % mod, 1], mod)  # (x - xm)
            denom = (denom * ((xj - xm) % mod)) % mod
        scale = mod_div(ys[j], denom, mod)
        out = poly_add(out, poly_scale(numer, scale, mod), mod)
    return poly_trim(out)
```
Groth16 ultimately lives over a finite field, and QAPs are polynomial statements. This step builds just enough field + polynomial machinery to interpolate polynomials (from constraint rows) and evaluate them at points.

### Step 2: R1CS for y = x^2
```python
@dataclass(frozen=True)
class R1CS:
    a: List[List[int]]
    b: List[List[int]]
    c: List[List[int]]
    num_public: int  # number of public variables excluding the constant 1
    var_names: List[str]

    @property
    def num_constraints(self) -> int:
        return len(self.a)

    @property
    def num_vars(self) -> int:
        return len(self.var_names)


def dot(a: Sequence[int], b: Sequence[int], mod: int) -> int:
    if len(a) != len(b):
        raise ValueError("dot: length mismatch")
    return sum((ai * bi) % mod for ai, bi in zip(a, b)) % mod


def r1cs_is_satisfied(r1cs: R1CS, witness: Sequence[int], mod: int) -> bool:
    if len(witness) != r1cs.num_vars:
        raise ValueError("witness length mismatch")
    for row_a, row_b, row_c in zip(r1cs.a, r1cs.b, r1cs.c):
        left = dot(row_a, witness, mod)
        right = dot(row_b, witness, mod)
        out = dot(row_c, witness, mod)
        if (left * right - out) % mod != 0:
            return False
    return True


def build_square_r1cs(mod: int) -> R1CS:
    # witness = [1, y, x, v] where v = x*x and y = v
    var_names = ["one", "y", "x", "v"]

    a = [
        [0, 0, 1, 0],  # x
        [0, 0, 0, 1],  # v
    ]
    b = [
        [0, 0, 1, 0],  # x
        [1, 0, 0, 0],  # 1
    ]
    c = [
        [0, 0, 0, 1],  # v
        [0, 1, 0, 0],  # y
    ]

    def norm_mat(m: List[List[int]]) -> List[List[int]]:
        return [[v % mod for v in row] for row in m]

    return R1CS(a=norm_mat(a), b=norm_mat(b), c=norm_mat(c), num_public=1, var_names=var_names)


def witness_for_square(x: int, mod: int) -> List[int]:
    x %= mod
    v = (x * x) % mod
    y = v
    return [1, y, x, v]
```
R1CS is the “constraint language” Groth16 consumes (after conversion). Here we build a tiny circuit: prove knowledge of `x` such that the public output `y` equals `x^2`.

### Step 3: QAP and divisibility check
```python
@dataclass(frozen=True)
class QAP:
    u_polys: List[List[int]]
    v_polys: List[List[int]]
    w_polys: List[List[int]]
    t_poly: List[int]
    domain: List[int]
    num_public: int
    var_names: List[str]

    @property
    def num_vars(self) -> int:
        return len(self.var_names)


def vanishing_poly(domain_xs: Sequence[int], mod: int) -> List[int]:
    out = [1]
    for x in domain_xs:
        out = poly_mul(out, [(-x) % mod, 1], mod)
    return poly_trim(out)


def r1cs_to_qap(r1cs: R1CS, mod: int) -> QAP:
    n = r1cs.num_constraints
    domain = list(range(1, n + 1))  # [1,2,...,n]

    u_polys: List[List[int]] = []
    v_polys: List[List[int]] = []
    w_polys: List[List[int]] = []

    for var_i in range(r1cs.num_vars):
        u_values = [r1cs.a[j][var_i] % mod for j in range(n)]
        v_values = [r1cs.b[j][var_i] % mod for j in range(n)]
        w_values = [r1cs.c[j][var_i] % mod for j in range(n)]
        u_polys.append(lagrange_interpolate(domain, u_values, mod))
        v_polys.append(lagrange_interpolate(domain, v_values, mod))
        w_polys.append(lagrange_interpolate(domain, w_values, mod))

    t_poly = vanishing_poly(domain, mod)
    return QAP(
        u_polys=u_polys,
        v_polys=v_polys,
        w_polys=w_polys,
        t_poly=t_poly,
        domain=domain,
        num_public=r1cs.num_public,
        var_names=r1cs.var_names,
    )


def qap_instance_polynomials(qap: QAP, witness: Sequence[int], mod: int) -> dict:
    if len(witness) != qap.num_vars:
        raise ValueError("witness length mismatch")

    a_poly = [0]
    b_poly = [0]
    c_poly = [0]
    for wi, u_i, v_i, w_i in zip(witness, qap.u_polys, qap.v_polys, qap.w_polys):
        a_poly = poly_add(a_poly, poly_scale(u_i, wi, mod), mod)
        b_poly = poly_add(b_poly, poly_scale(v_i, wi, mod), mod)
        c_poly = poly_add(c_poly, poly_scale(w_i, wi, mod), mod)

    p_poly = poly_sub(poly_mul(a_poly, b_poly, mod), c_poly, mod)
    h_poly, rem = poly_divmod(p_poly, qap.t_poly, mod)
    return {
        "a_poly": a_poly,
        "b_poly": b_poly,
        "c_poly": c_poly,
        "p_poly": p_poly,
        "h_poly": h_poly,
        "remainder": rem,
    }
```
This is the SNARK-friendly reformulation: you combine the per-variable polynomials using the witness, then check that `A(x)B(x) - C(x)` is divisible by the vanishing polynomial `t(x)`. The quotient `h(x)` is what the prover “proves exists”.

### Step 4: Toy Groth16 (setup / prove / verify)
```python
def derive_scalars(seed: bytes, mod: int, count: int) -> List[int]:
    out: List[int] = []
    for i in range(count):
        h = hashlib.sha256(seed + b":" + str(i).encode("ascii")).digest()
        v = int.from_bytes(h, "big") % mod
        if v == 0:
            v = 1
        out.append(v)
    return out


def find_subgroup_generator(p: int, q: int) -> int:
    for g in range(2, p - 1):
        if pow(g, q, p) == 1 and g % p != 1:
            return g
    raise ValueError("no subgroup generator found")


@dataclass(frozen=True)
class GroupParams:
    p: int
    q: int
    g: int

    def elt(self, exp: int) -> int:
        return pow(self.g, exp % self.q, self.p)


@dataclass(frozen=True)
class G1:
    params: GroupParams
    exp: int

    def __mul__(self, other: "G1") -> "G1":
        if self.params != other.params:
            raise ValueError("G1 params mismatch")
        return G1(self.params, (self.exp + other.exp) % self.params.q)

    def __pow__(self, scalar: int) -> "G1":
        return G1(self.params, (self.exp * (scalar % self.params.q)) % self.params.q)

    def value(self) -> int:
        return self.params.elt(self.exp)


@dataclass(frozen=True)
class G2:
    params: GroupParams
    exp: int

    def __mul__(self, other: "G2") -> "G2":
        if self.params != other.params:
            raise ValueError("G2 params mismatch")
        return G2(self.params, (self.exp + other.exp) % self.params.q)

    def __pow__(self, scalar: int) -> "G2":
        return G2(self.params, (self.exp * (scalar % self.params.q)) % self.params.q)

    def value(self) -> int:
        return self.params.elt(self.exp)


@dataclass(frozen=True)
class GT:
    params: GroupParams
    exp: int

    def __mul__(self, other: "GT") -> "GT":
        if self.params != other.params:
            raise ValueError("GT params mismatch")
        return GT(self.params, (self.exp + other.exp) % self.params.q)

    def value(self) -> int:
        return self.params.elt(self.exp)


def pairing(a: G1, b: G2) -> GT:
    if a.params != b.params:
        raise ValueError("pairing params mismatch")
    q = a.params.q
    return GT(a.params, (a.exp * b.exp) % q)


@dataclass(frozen=True)
class ProvingKey:
    params: GroupParams
    num_public: int
    alpha_g1: G1
    beta_g1: G1
    beta_g2: G2
    gamma_g2: G2
    delta_g1: G1
    delta_g2: G2
    u_tau_g1: List[G1]
    v_tau_g1: List[G1]
    v_tau_g2: List[G2]
    k_delta_g1: List[G1]  # for private vars only (i > num_public)
    t_tau_powers_over_delta_g1: List[G1]  # i=0..deg(t)-2: (tau^i * t(tau) / delta) in G1


@dataclass(frozen=True)
class VerifyingKey:
    params: GroupParams
    num_public: int
    alpha_g1: G1
    beta_g2: G2
    gamma_g2: G2
    delta_g2: G2
    ic_g1: List[G1]  # length = num_public + 1 (includes the constant "1" slot)


@dataclass(frozen=True)
class Proof:
    a_g1: G1
    b_g2: G2
    c_g1: G1


def groth16_setup_toy(qap: QAP, alpha: int, beta: int, gamma: int, delta: int, tau: int, mod: int) -> Tuple[ProvingKey, VerifyingKey]:
    if gamma % mod == 0:
        raise ValueError("gamma must be non-zero")
    if delta % mod == 0:
        raise ValueError("delta must be non-zero")

    g = find_subgroup_generator(GROUP_MODULUS, SCALAR_FIELD_MODULUS)
    params = GroupParams(p=GROUP_MODULUS, q=SCALAR_FIELD_MODULUS, g=g)

    def g1(exp: int) -> G1:
        return G1(params, exp % params.q)

    def g2(exp: int) -> G2:
        return G2(params, exp % params.q)

    alpha %= mod
    beta %= mod
    gamma %= mod
    delta %= mod
    tau %= mod

    u_tau = [poly_eval(u, tau, mod) for u in qap.u_polys]
    v_tau = [poly_eval(v, tau, mod) for v in qap.v_polys]
    w_tau = [poly_eval(w, tau, mod) for w in qap.w_polys]
    t_tau = poly_eval(qap.t_poly, tau, mod)

    alpha_g1 = g1(alpha)
    beta_g1 = g1(beta)
    beta_g2 = g2(beta)
    gamma_g2 = g2(gamma)
    delta_g1 = g1(delta)
    delta_g2 = g2(delta)

    u_tau_g1 = [g1(v) for v in u_tau]
    v_tau_g1 = [g1(v) for v in v_tau]
    v_tau_g2 = [g2(v) for v in v_tau]

    ic_g1: List[G1] = []
    for i in range(qap.num_public + 1):  # includes i=0 (constant 1)
        term = (beta * u_tau[i] + alpha * v_tau[i] + w_tau[i]) % mod
        ic_g1.append(g1(mod_div(term, gamma, mod)))

    k_delta_g1: List[G1] = []
    for i in range(qap.num_public + 1, qap.num_vars):
        term = (beta * u_tau[i] + alpha * v_tau[i] + w_tau[i]) % mod
        k_delta_g1.append(g1(mod_div(term, delta, mod)))

    deg_t = len(qap.t_poly) - 1
    t_tau_powers_over_delta_g1: List[G1] = []
    for i in range(max(0, deg_t - 1)):  # 0..deg(t)-2
        tau_i = pow(tau, i, mod)
        t_tau_powers_over_delta_g1.append(g1(mod_div(t_tau * tau_i, delta, mod)))

    pk = ProvingKey(
        params=params,
        num_public=qap.num_public,
        alpha_g1=alpha_g1,
        beta_g1=beta_g1,
        beta_g2=beta_g2,
        gamma_g2=gamma_g2,
        delta_g1=delta_g1,
        delta_g2=delta_g2,
        u_tau_g1=u_tau_g1,
        v_tau_g1=v_tau_g1,
        v_tau_g2=v_tau_g2,
        k_delta_g1=k_delta_g1,
        t_tau_powers_over_delta_g1=t_tau_powers_over_delta_g1,
    )
    vk = VerifyingKey(
        params=params,
        num_public=qap.num_public,
        alpha_g1=alpha_g1,
        beta_g2=beta_g2,
        gamma_g2=gamma_g2,
        delta_g2=delta_g2,
        ic_g1=ic_g1,
    )
    return pk, vk


def groth16_prove_toy(qap: QAP, pk: ProvingKey, witness: Sequence[int], r: int, s: int, alpha: int, beta: int, delta: int, tau: int, mod: int) -> Proof:
    if len(witness) != qap.num_vars:
        raise ValueError("witness length mismatch")
    if witness[0] % mod != 1:
        raise ValueError("witness[0] must be 1 (the constant slot)")

    u_tau = [poly_eval(u, tau, mod) for u in qap.u_polys]
    v_tau = [poly_eval(v, tau, mod) for v in qap.v_polys]
    w_tau = [poly_eval(w, tau, mod) for w in qap.w_polys]
    t_tau = poly_eval(qap.t_poly, tau, mod)

    a_scalar = (alpha + sum((wi * ui) % mod for wi, ui in zip(witness, u_tau)) + (r % mod) * delta) % mod
    b_scalar = (beta + sum((wi * vi) % mod for wi, vi in zip(witness, v_tau)) + (s % mod) * delta) % mod

    inst = qap_instance_polynomials(qap, witness, mod)
    if inst["remainder"] != [0]:
        raise ValueError("witness does not satisfy QAP divisibility")
    h_tau = poly_eval(inst["h_poly"], tau, mod)

    private_sum = 0
    for i in range(qap.num_public + 1, qap.num_vars):
        private_sum = (private_sum + witness[i] * ((beta * u_tau[i] + alpha * v_tau[i] + w_tau[i]) % mod)) % mod

    c_scalar = (
        mod_div(private_sum + (h_tau * t_tau) % mod, delta, mod)
        + (a_scalar * (s % mod)) % mod
        + (b_scalar * (r % mod)) % mod
        - ((r % mod) * (s % mod) % mod) * delta
    ) % mod

    return Proof(
        a_g1=G1(pk.params, a_scalar),
        b_g2=G2(pk.params, b_scalar),
        c_g1=G1(pk.params, c_scalar),
    )


def groth16_verify_toy(vk: VerifyingKey, public_inputs: Sequence[int], proof: Proof, mod: int) -> bool:
    if len(public_inputs) != vk.num_public:
        raise ValueError("public input length mismatch")

    # vk_x = IC[0] + sum_i input[i-1] * IC[i]
    vk_x = vk.ic_g1[0]
    for i, inp in enumerate(public_inputs, start=1):
        vk_x = vk_x * (vk.ic_g1[i] ** (inp % mod))

    left = pairing(proof.a_g1, proof.b_g2)
    right = pairing(vk.alpha_g1, vk.beta_g2) * pairing(vk_x, vk.gamma_g2) * pairing(proof.c_g1, vk.delta_g2)
    return left.exp % vk.params.q == right.exp % vk.params.q
```
This is where everything snaps together: the prover produces three elements, and the verifier checks one bilinear equation. In a real Groth16 implementation, `setup` and `prove` build `A, B, C` so this exact check holds without revealing the private witness.

Run it:
python3 code/main.py

## Use It
Real implementations don’t use toy groups or toy pairings. Use audited tooling:

- **Circuits → R1CS**: Circom + snarkjs, ZoKrates, gnark, arkworks constraint systems.
- **Groth16 prover/verifier**:
  - `snarkjs groth16 prove/verify` (Circom ecosystem)
  - `ark-groth16` (Rust, arkworks ecosystem)
  - `gnark` (Go)
  - Zcash’s `bellman`/`pairing` ecosystem (historical + production usage)

Rule of thumb: keep your “from-scratch” implementation for understanding only, and wire production systems to a battle-tested library.

## Pitfalls
- **Public input ordering**: mixing the order between circuit, prover, and verifier silently breaks security or correctness.
- **Missing field-size checks**: public inputs must be reduced/validated mod the curve’s scalar field.
- **IC off-by-one**: `IC[0]` is the constant slot; public inputs multiply `IC[1..]`.
- **Circuit changes require new setup**: Groth16 is circuit-specific; reusing keys after changing constraints is wrong.
- **Misconfigured verifying keys**: if critical elements aren’t independent (e.g., `γ` and `δ` accidentally the same), the pairing equation can lose binding and lead to forgeries.

## Ship It
Save (and reuse) the checklist:

- Open `outputs/groth16-review-checklist.md`.
- Use it as a PR review template whenever you touch a Groth16 verifier, verifying key, or public input encoding.
- Keep it next to your verifier code and link it in code reviews (“Checklist used: ✅”).

## Exercises
1. **Easy:** Run `python3 code/main.py`. Observe that the correct witness verifies and the mismatched public input fails.
2. **Medium:** Modify the circuit to prove `y = x^3` (add constraints), regenerate the QAP, and update the Groth16 demo to still pass.
3. **Hard:** Implement a cross-check harness: generate a proof with `snarkjs` (or `ark-groth16`) for a tiny circuit and verify it with the same library in a separate process, ensuring public input ordering and field checks are correct.

## Key Terms
| Term | What people say | What it actually means |
|------|------------------|------------------------|
| R1CS | “constraints” | A set of multiplicative constraints over linear forms in a witness vector. |
| QAP | “polynomial form of R1CS” | Polynomials whose satisfaction is checked by divisibility by a vanishing polynomial. |
| `t(x)` | “vanishing polynomial” | A polynomial that is zero on the constraint domain points. |
| `h(x)` | “quotient polynomial” | The polynomial that exists iff the witness satisfies all constraints (divisibility holds). |
| Trusted setup | “ceremony” | Procedure that samples trapdoor scalars and publishes only derived group elements; secrecy is critical. |
| IC / `vk_x` | “public input commitment” | A G1 linear combination derived only from public inputs and the verifying key. |

## Further Reading
- Jens Groth, *On the Size of Pairing-based Non-interactive Arguments* (2016) — The original Groth16 construction.
- Ariel Gabizon, Zachary J. Williamson, Oana Ciobotaru, *PLONK* (2019) — A universal-setup alternative (helpful for contrast).
- “An overview of the Groth16 proof system” (LambdaClass, 2021) — A practitioner-friendly walk-through of the main equations.
