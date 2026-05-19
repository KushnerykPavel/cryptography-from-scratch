# Universal vs Trusted Setup
> Trusted setup isn’t “bad” — it’s a specific risk model you must be able to audit.

**Type:** Learn  
**Languages:** Python  
**Prerequisites:** `11-zero-knowledge-foundations/04-fiat-shamir`, `11-zero-knowledge-foundations/09-inner-product-argument` (recommended), basic modular arithmetic  
**Time:** ~45 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain what “toxic waste” is and why leaking it breaks soundness
- Distinguish circuit-specific trusted setup vs universal (reusable) setup
- Compute (in a toy model) how a Powers-of-Tau ceremony updates an SRS
- Implement a minimal commitment/open/verify loop that depends on setup parameters
- Apply an audit checklist to decide whether a setup model fits a product

## The Problem
You’re about to ship a ZK system: a bridge, a rollup, a proof-of-reserves, a privacy feature, or an identity primitive. Someone asks: “Does this require a trusted setup?” If you can’t answer precisely, you can’t evaluate the biggest single operational risk in many SNARK deployments.

Teams repeatedly get burned by the same failure modes: running a per-circuit ceremony every time a circuit changes, accidentally reusing parameters across incompatible circuits, or assuming that “a big ceremony on YouTube” is sufficient without understanding what must be verified and what can still go wrong. The result is either a system that silently depends on a compromised setup, or a system that can’t be maintained because the ceremony burden is too high.

This lesson gives you a concrete mental model (with runnable code) for what the setup actually enables, what “universal” really means, and why “updatable” changes the trust assumption from “everyone must be honest” to “at least one contributor must be honest”.

## The Concept
There are three ideas that commonly get conflated:

1) **Trusted setup vs transparent setup** (do we need secret randomness?)

- **Trusted setup:** some secret trapdoor (often written `τ`) is sampled during parameter generation, and must be destroyed. If it leaks, an attacker can often forge proofs (soundness breaks).
- **Transparent setup (a.k.a. public-coin):** parameters are derived from public randomness (hashes, transcripts, Fiat–Shamir). There is no toxic waste to leak.

2) **Circuit-specific vs universal setup** (how often do we have to redo it?)

- **Circuit-specific:** parameters are tied to a single circuit. Change the circuit → redo setup.
- **Universal:** one setup supports many circuits, up to a size bound. You “trim/derive” per-circuit parameters without new toxic waste.

3) **Single-party vs multi-party / updatable setup** (what’s the trust model?)

- **Single-party:** one party samples the trapdoor and promises to delete it.
- **Multi-party / updatable:** many parties contribute randomness. Security holds if **at least one** contributor is honest and deletes their secret.

### A practical decision table
| Dimension | Option | What you get | What you pay |
|---|---|---|---|
| Setup secrecy | Transparent | No toxic waste, easier ops | Often larger proofs / different assumptions |
| Setup secrecy | Trusted | Very small proofs (often), fast verify | Toxic waste risk + ceremony verification |
| Reusability | Circuit-specific | Can be highly optimized | New ceremony per circuit change |
| Reusability | Universal | One ceremony for many circuits | Must size bound correctly; still toxic waste (if trusted) |
| Trust model | Updatable | “1 honest contributor” security | Ceremony tooling + transcript verification |

In the **Build It**, we’ll use a toy polynomial commitment (KZG-like) to demonstrate:
- Setup publishes “powers of `τ`” without revealing `τ`.
- Verification works without knowing `τ`.
- If `τ` leaks, you can forge openings (soundness collapses).
- A Powers-of-Tau ceremony updates the SRS without revealing the final `τ`.
- A universal SRS can be trimmed per circuit.

## Build It

### Step 1: A Trusted Setup Creates Toxic Waste
We’ll start with basic finite-field utilities and polynomial operations modulo a small prime `q`. The important part is `poly_div_by_linear`: it constructs the quotient polynomial you need for a KZG-style opening proof.

```python
def mod_inv(a: int, m: int) -> int:
    a %= m
    if a == 0:
        raise ValueError("inverse does not exist for 0")
    t0, t1 = 0, 1
    r0, r1 = m, a
    while r1 != 0:
        q = r0 // r1
        t0, t1 = t1, t0 - q * t1
        r0, r1 = r1, r0 - q * r1
    if r0 != 1:
        raise ValueError("inverse does not exist")
    return t0 % m


def poly_eval(coeffs_asc: List[int], x: int, mod: int) -> int:
    x %= mod
    acc = 0
    power = 1
    for c in coeffs_asc:
        acc = (acc + (c % mod) * power) % mod
        power = (power * x) % mod
    return acc


def poly_div_by_linear(coeffs_asc: List[int], x0: int, mod: int) -> Tuple[List[int], int]:
    if len(coeffs_asc) == 0:
        raise ValueError("empty polynomial")
    if len(coeffs_asc) == 1:
        return [], coeffs_asc[0] % mod
    x0 %= mod
    a_desc = list(reversed([c % mod for c in coeffs_asc]))
    b_desc: List[int] = []
    for i, a in enumerate(a_desc):
        if i == 0:
            b_desc.append(a)
            continue
        b_desc.append((a + b_desc[i - 1] * x0) % mod)
    remainder = b_desc[-1]
    q_desc = b_desc[:-1]
    q_asc = list(reversed(q_desc))
    return q_asc, remainder
```

### Step 2: Commit / Open / Verify (Toy KZG)
Now we implement a toy pairing group and a KZG-like polynomial commitment. This is not cryptographically secure: we implement the “pairing” by taking discrete logs in a tiny group so you can see the logic end-to-end.

```python
from dataclasses import dataclass
from typing import Dict, Iterable, List, Tuple


def _dlog_table(base: int, p: int, q: int) -> Dict[int, int]:
    table: Dict[int, int] = {}
    acc = 1
    for e in range(q):
        if acc in table:
            raise ValueError("base does not have order q")
        table[acc] = e
        acc = (acc * base) % p
    return table


@dataclass(frozen=True)
class ToyPairingGroup:
    p: int
    q: int
    g1: int
    g2: int
    gt: int
    dlog_g1: Dict[int, int]
    dlog_g2: Dict[int, int]

    def mul(self, a: int, b: int) -> int:
        return (a * b) % self.p

    def inv(self, a: int) -> int:
        a %= self.p
        if a == 0:
            raise ValueError("no inverse for 0 in multiplicative group")
        return pow(a, self.p - 2, self.p)

    def div(self, a: int, b: int) -> int:
        return self.mul(a, self.inv(b))

    def exp(self, a: int, e: int) -> int:
        return pow(a, e % self.q, self.p)

    def g1_exp(self, e: int) -> int:
        return self.exp(self.g1, e)

    def g2_exp(self, e: int) -> int:
        return self.exp(self.g2, e)

    def pairing(self, a_g1: int, b_g2: int) -> int:
        try:
            a = self.dlog_g1[a_g1]
            b = self.dlog_g2[b_g2]
        except KeyError as e:
            raise ValueError("element not in expected subgroup") from e
        return self.exp(self.gt, (a * b) % self.q)


@dataclass(frozen=True)
class KZGParams:
    group: ToyPairingGroup
    max_degree: int
    g1_powers_of_tau: List[int]
    g2_tau: int


def kzg_setup(max_degree: int, tau: int, group: ToyPairingGroup) -> KZGParams:
    if max_degree < 0:
        raise ValueError("max_degree must be >= 0")
    tau %= group.q
    powers: List[int] = []
    tau_power = 1
    for _ in range(max_degree + 1):
        powers.append(group.g1_exp(tau_power))
        tau_power = (tau_power * tau) % group.q
    g2_tau = group.g2_exp(tau)
    return KZGParams(group=group, max_degree=max_degree, g1_powers_of_tau=powers, g2_tau=g2_tau)


def kzg_trim(params: KZGParams, max_degree: int) -> KZGParams:
    if max_degree < 0:
        raise ValueError("max_degree must be >= 0")
    if max_degree > params.max_degree:
        raise ValueError("cannot trim to larger degree")
    return KZGParams(
        group=params.group,
        max_degree=max_degree,
        g1_powers_of_tau=params.g1_powers_of_tau[: max_degree + 1],
        g2_tau=params.g2_tau,
    )


def kzg_commit(coeffs_asc: List[int], params: KZGParams) -> int:
    if len(coeffs_asc) == 0:
        raise ValueError("empty polynomial")
    if len(coeffs_asc) - 1 > params.max_degree:
        raise ValueError("polynomial degree exceeds SRS bound")
    g = params.group
    acc = 1
    for i, c in enumerate(coeffs_asc):
        acc = g.mul(acc, g.exp(params.g1_powers_of_tau[i], c))
    return acc


def kzg_open(coeffs_asc: List[int], x: int, params: KZGParams) -> Tuple[int, int]:
    g = params.group
    x %= g.q
    y = poly_eval(coeffs_asc, x, g.q)
    quot, rem = poly_div_by_linear(coeffs_asc, x, g.q)
    if rem != y:
        raise ValueError("internal error: remainder mismatch")
    proof = kzg_commit(quot if len(quot) > 0 else [0], kzg_trim(params, max(params.max_degree - 1, 0)))
    return y, proof


def kzg_verify(commitment: int, x: int, y: int, proof: int, params: KZGParams) -> bool:
    g = params.group
    x %= g.q
    y %= g.q
    left = g.pairing(g.div(commitment, g.g1_exp(y)), g.g2)
    denom = g.div(params.g2_tau, g.g2_exp(x))
    right = g.pairing(proof, denom)
    return left == right


def default_toy_group() -> ToyPairingGroup:
    p = 2027
    q = 1013
    g1 = 3
    g2 = 9
    gt = 3
    dlog_g1 = _dlog_table(g1, p, q)
    dlog_g2 = _dlog_table(g2, p, q)
    return ToyPairingGroup(p=p, q=q, g1=g1, g2=g2, gt=gt, dlog_g1=dlog_g1, dlog_g2=dlog_g2)
```

### Step 3: Updatable (Multi-Party) Setup
In a Powers-of-Tau ceremony, each contributor applies a secret multiplier `δ`. The ceremony transcript is public, but the secret `δ` is deleted. If at least one contributor behaves honestly, the final `τ` is unknown to attackers.

```python
def pot_update(params: KZGParams, delta: int) -> KZGParams:
    g = params.group
    delta %= g.q
    if delta == 0:
        raise ValueError("delta must be non-zero")
    new_powers: List[int] = []
    delta_power = 1
    for elem in params.g1_powers_of_tau:
        new_powers.append(g.exp(elem, delta_power))
        delta_power = (delta_power * delta) % g.q
    new_g2_tau = g.exp(params.g2_tau, delta)
    return KZGParams(group=g, max_degree=params.max_degree, g1_powers_of_tau=new_powers, g2_tau=new_g2_tau)


def pot_apply_updates(params: KZGParams, deltas: Iterable[int]) -> KZGParams:
    out = params
    for d in deltas:
        out = pot_update(out, d)
    return out
```

### Step 4: Universal Setup vs Per-Circuit Setup (and the Toxic-Waste Failure Mode)
A universal SRS supports many circuits up to a degree bound. “Trimming” produces a per-circuit parameter set without new toxic waste. But the toxic waste still exists: if `τ` is known, openings can be forged.

```python
def forge_opening_with_toxic_waste(
    commitment: int, x: int, y_fake: int, tau: int, params: KZGParams
) -> int:
    g = params.group
    x %= g.q
    y_fake %= g.q
    tau %= g.q
    denom = (tau - x) % g.q
    denom_inv = mod_inv(denom, g.q)
    numerator = g.div(commitment, g.g1_exp(y_fake))
    return g.exp(numerator, denom_inv)
```

Run it:

```bash
python3 code/main.py
```

## Use It
Real systems don’t implement pairings via discrete logs — they use pairing-friendly elliptic curves and carefully engineered libraries. But the same operational questions show up.

- **Circuit-specific trusted setup (common in practice):**
  - `snarkjs` Groth16 flows produce circuit-tied proving/verifying keys (`.zkey`) and need a new setup when the circuit changes.
- **Universal + updatable trusted setup:**
  - “Powers of Tau” ceremonies produce a reusable SRS up to a size bound; later you derive circuit-specific artifacts from it.
  - Common in “plonkish” ecosystems (PLONK variants, Marlin/Sonic-style lines) that use KZG-like polynomial commitments.
- **Transparent setup (no toxic waste):**
  - Hash-based systems (e.g., STARK-style constructions) derive parameters from public randomness; there is no secret `τ` to destroy.

Practical tip: when you evaluate a ZK stack, treat “setup” as an engineering surface: how parameters are generated, how they’re versioned, how you verify the transcript, and how you rotate/migrate if you change circuits.

## Pitfalls
- Treating “universal” as “no trusted setup”: universal setups can still have toxic waste; they’re just reusable.
- Under-sizing the universal bound: you later need a bigger SRS, and now you’re forced to migrate parameters or re-run ceremony.
- Not verifying ceremony transcripts: you “trust the YouTube video” but never validate the actual artifacts you downloaded.
- Mixing parameters across circuits / versions: a circuit change with stale keys can be catastrophic (accepting invalid proofs or bricking verification).
- Ignoring upgrade paths: if your circuit will change frequently, circuit-specific setup is operationally expensive.

## Ship It
Save `outputs/zk-setup-audit-checklist.md` somewhere you can reuse it (PR reviews, design docs, threat models). Use it to choose a setup model (transparent vs trusted; universal vs per-circuit; updatable vs single-party), review a ceremony plan, and check parameter versioning and rotation strategy.

## Exercises
1. Easy. Run `python3 code/main.py`. Observe that the forged opening verifies when `τ` is known.
2. Medium. Change the universal bound from `8` to a smaller number and try to commit a polynomial that exceeds it. Make it fail loudly and confirm the tests still pass.
3. Hard. Write a short engineering note that argues for one setup model for a hypothetical product (e.g., “ZK KYC proof”, “rollup validity proof”, “proof-of-reserves”). Use the checklist from `outputs/` and include a rotation/migration plan.

## Key Terms
| Term | What people say | What it actually means |
|---|---|---|
| Trusted setup | “We ran a ceremony” | Secret randomness was used to generate public parameters; if the secret leaks, soundness may break |
| Toxic waste | “The secret” | The setup trapdoor (often `τ`) and related secrets that must be destroyed |
| Circuit-specific setup | “Per-circuit keys” | Parameters are tied to a single circuit; any circuit change invalidates them |
| Universal setup | “One setup for all” | One setup supports many circuits up to a size bound; per-circuit derivations don’t add toxic waste |
| Updatable setup | “Many contributors” | Anyone can contribute randomness; security holds if at least one contributor deletes their secret |
| Transparent setup | “No trusted setup” | Parameters come from public randomness; no toxic waste exists to leak |

## Further Reading
- Vitalik Buterin, “How do trusted setups work?” (2022) — a clear conceptual walkthrough of Powers of Tau and toxic waste
- Ben-Sasson et al., “Scalable, transparent, and post-quantum secure computational integrity” (STARKs) — why “transparent” is a different design point
- “The PLONK paper” (2019) — universal setup and modern plonkish design (read with an implementation guide)
