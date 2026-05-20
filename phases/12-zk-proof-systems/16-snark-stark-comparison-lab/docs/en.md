# ZK Proof Systems — Groth16 vs PLONK vs STARK

> Same statement, three proof systems — choose your trade-off.

**Type:** Build / Lab
**Languages:** Python
**Prerequisites:** `12-zk-proof-systems/05-groth16`, `12-zk-proof-systems/07-plonk-implement`, `12-zk-proof-systems/13-deep-fri`
**Time:** ~90 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- **Explain** why Groth16 requires a circuit-specific trusted setup while PLONK needs only a universal one.
- **Contrast** proof sizes: Groth16's constant 3 elements vs PLONK's ~15 vs STARK's O(log²n) hashes.
- **Identify** the security assumptions each system relies on and why STARK is post-quantum safe.
- **Implement** simulated provers and verifiers for all three systems against the same arithmetic circuit.
- **Choose** the right system given concrete constraints: proof size, setup trust, verification cost, and PQ safety.

## The Problem

Suppose you want to prove you know a secret `x` such that `x³ + x + 5 = y` for some public value `y`. The statement is simple — three arithmetic gates — but the choice of proof system matters enormously in practice. Different systems make fundamentally different trade-offs in trusted-setup cost, proof size, verification time, and cryptographic assumptions.

A developer picking a ZK proof system in 2024 faces real decisions: Does the circuit change frequently (ruling out Groth16's per-circuit ceremony)? Is post-quantum safety required (ruling out pairing-based systems)? Is proof size the bottleneck (favoring Groth16 or PLONK over STARK)? Is the verifier on-chain with strict gas limits (favoring constant-size proofs)?

This lab answers those questions by running all three systems against the same three-gate circuit and comparing them side by side. You will see concretely why each design choice propagates through to the prover, the verifier, and the proof artifact.

## The Concept

### The circuit

We prove `x³ + x + 5 = y` using three gates over a field `F_p`:

| Gate | Type | Constraint |
|------|------|-----------|
| 1    | Multiply | `x · x = x²` |
| 2    | Multiply | `x² · x = x³` |
| 3    | Linear   | `x³ + x + 5 = y` |

Witness for `x = 3, p = 101`: `x=3, x²=9, x³=27, y=35`.

### Comparison matrix

| Property | Groth16 | PLONK | STARK |
|----------|---------|-------|-------|
| Trusted setup | Circuit-specific | Universal (one-time per bound) | None (transparent) |
| Setup size | O(n) per circuit | O(n_max) once | 0 |
| Proof size | 3 group elements | ~15 field elements | O(log²n) hash values |
| Cryptographic assumptions | Discrete log + pairing | Discrete log + pairing | Collision-resistant hash |
| Post-quantum safe | No | No | Yes |
| Verify cost | O(1) pairing checks | O(1) + O(log n) | O(log²n) |
| Prover cost | O(n log n) | O(n log n) | O(n log²n) |

### Trusted setup intuition

Groth16's setup is "circuit-specific" because the structured reference string (SRS) encodes the QAP polynomials for one particular circuit. Change one gate and you need a new ceremony. PLONK separates circuit description from the SRS: any circuit up to `n_max` gates can reuse the same universal SRS — the circuit is compiled into selector polynomials at proof time, not setup time. STARK needs no SRS at all: the prover commits to the execution trace using a Merkle tree, and soundness follows from the collision resistance of the hash function.

### Why STARK is post-quantum safe

Groth16 and PLONK rely on the hardness of the discrete logarithm problem in elliptic curve groups and on the existence of bilinear pairings. A large-scale quantum computer running Shor's algorithm can solve discrete log in polynomial time, breaking both. STARK's security rests only on the collision resistance of the hash function. No efficient quantum algorithm for breaking SHA-256 is known, making STARKs "post-quantum safe" under current understanding.

## Build It

### Step 1: Circuit and witness

Define the circuit as three explicit gate constraints and a function to build the witness:

```python
MODULUS = 101

def circuit_witness(x: int, p: int = MODULUS) -> dict:
    x = x % p
    x2 = (x * x) % p
    x3 = (x2 * x) % p
    y = (x3 + x + 5) % p
    return {"x": x, "x2": x2, "x3": x3, "y": y}

def circuit_check(w: dict, p: int = MODULUS) -> bool:
    if (w["x"] * w["x"]) % p != w["x2"] % p:
        return False
    if (w["x2"] * w["x"]) % p != w["x3"] % p:
        return False
    if (w["x3"] + w["x"] + 5) % p != w["y"] % p:
        return False
    return True
```

Gate 3 is a PLONK-style linear constraint: `ql·a + qr·b + qc·5 - c = 0` with `ql = qr = qc = 1`, `a = x³`, `b = x`, `c = y`.

### Step 2: Groth16 — circuit-specific trusted setup

Groth16's key insight: the prover evaluates QAP (Quadratic Arithmetic Program) polynomials at a secret point `tau` during setup and produces group elements in G1/G2. The proof is always three group elements regardless of circuit size.

```python
class Groth16SetupParams:
    def __init__(self, tau_powers, alpha, beta, gamma, delta, p):
        self.tau_powers = tau_powers  # [1, tau, tau², …]
        self.alpha = alpha; self.beta = beta
        self.gamma = gamma; self.delta = delta
        self.p = p

def groth16_setup(n_gates, tau, alpha, beta, gamma, delta, p):
    tau_powers = [pow(tau, i, p) for i in range(n_gates + 1)]
    return Groth16SetupParams(tau_powers, alpha % p, beta % p,
                              gamma % p, delta % p, p)
```

The prover computes `A`, `B` from SRS evaluations and solves for `C` so that the verification equation holds:

```
A · B ≡ alpha·beta + y·gamma + C·delta  (mod p)
```

In a real Groth16 this is a pairing equation in G1/G2; here it is scalar arithmetic in `F_p`. The toxic waste `tau` must be deleted after setup — anyone who retains it can forge proofs.

### Step 3: PLONK — universal trusted setup

PLONK compiles any circuit into selector polynomials `ql, qr, qo, qm, qc` and permutation polynomials `S_σ`. The SRS `[τ⁰, τ¹, …, τⁿ]` is fixed once and reused:

```python
def plonk_setup(n_max: int, tau: int, p: int) -> dict:
    srs = [pow(tau, i, p) for i in range(n_max + 1)]
    return {"srs": srs, "tau": tau % p, "p": p, "n_max": n_max}
```

The prover commits to wire polynomials `a(X), b(X), c(X)`, runs the permutation argument (to enforce copy constraints like "`a` at gate 2 equals `b` at gate 1"), and computes a quotient polynomial `t(X)` that certifies all constraints are satisfied. A Fiat-Shamir challenge `zeta` is derived by hashing all commitments, then the prover opens polynomials at `zeta`:

```python
# Gate 3 identity: a(zeta) + b(zeta) + 5 - c(zeta) = 0
gate_check = (ev["a_z"] + ev["b_z"] + 5 - ev["c_z"]) % p
```

The verifier checks this identity plus two KZG opening proofs, requiring only two pairing checks in a real implementation.

### Step 4: STARK — no trusted setup

A STARK proves the correct execution of an arithmetic intermediate representation (AIR). The prover commits to the execution trace using a Merkle tree and then runs FRI to prove the constraint polynomial is low-degree:

```python
def stark_prove(w: dict, y: int, p: int) -> StarkProof:
    trace = [w["x"], w["x2"], w["x3"], w["y"]]
    trace_leaves = [_sha256b(b"\x00", int_to_bytes(v)) for v in trace]
    trace_root = _sha256b(b"\x01", *trace_leaves)
    # ... constraint commitments, FRI layers, query responses
```

No secret parameters appear anywhere. The verifier recomputes the Fiat-Shamir challenges from the proof transcript and checks that each FRI folding step is consistent with the committed roots. The proof size grows as `O(log²n)` because each of the `O(log n)` FRI layers requires `O(log n)` Merkle paths per query.

### Step 5: Comparison

Run all three and observe the trade-offs:

```python
def main():
    w = circuit_witness(3)
    # setup + prove + verify each system
    # print comparison table
```

Expected output for `x=3, p=101, tau=7`:

- Groth16: `A=91, B=33, C=82`, 3 proof elements, verify True
- PLONK: 15 proof elements (3+1+3+6+2), verify True
- STARK: 11 proof elements (hash values), verify True

## Use It

Real implementations of these systems are available in production-quality libraries:

- **Groth16 — gnark (Go):** `github.com/consensys/gnark`. Write the circuit in Go, compile with `groth16.Setup`, then `groth16.Prove` / `groth16.Verify`. Proofs are ~128 bytes on BN254.
- **PLONK — Halo2 (Rust):** `github.com/zcash/halo2`. Uses a variant called "UltraPLONK" with lookup gates. No pairing-based trusted setup in the recursive variant (uses IPA instead of KZG).
- **STARK — Winterfell (Rust):** `github.com/novifinancial/winterfell`. Exposes an `Air` trait for defining constraint systems; handles FRI, DEEP composition, and Merkle commitments internally.

## Pitfalls

- **Trusted setup ceremonies:** If even one participant in a Groth16 MPC ceremony retains their toxic waste, all proofs are forgeable. The security of the system is "1-of-N honest". Large ceremonies (Zcash Sapling, Hermez) had hundreds of participants to make this impractical.
- **Degree bounds:** PLONK's quotient polynomial must fit within the SRS degree bound. If your circuit exceeds `n_max` gates, the universal SRS is unusable without a new setup. Always estimate gate count before choosing `n_max`.
- **Proof aggregation:** Groth16 proofs are aggregatable (SnarkPack), making them attractive for batching many proofs on-chain. STARKs can use recursive composition (e.g., Plonky2, a PLONK+FRI hybrid) to achieve similar goals with post-quantum safety.
- **Field size mismatch:** The toy code uses `p=101`, a 7-bit prime. Real systems use 254-bit primes (BN254 for Groth16/PLONK) or 64-bit Goldilocks/Mersenne primes (STARK). Results from this toy are not interoperable with production systems.

## Ship It

This lesson ships a reusable reference cheatsheet:

- `outputs/zk-systems-comparison-cheatsheet.md`

Use it when choosing a ZK proof system for a new project to quickly rule out systems that don't fit your constraints (trusted setup availability, proof size budget, PQ requirements, verification gas cost).

## Exercises

1. **Easy.** Run `python3 code/main.py`. Confirm all three verify return `True` and the proof element counts match the comparison table. Then change `x` to 5 and verify `y = (125 + 5 + 5) % 101 = 34`. All three systems should still accept.
2. **Medium.** Extend `circuit_witness` and `circuit_check` to handle the cubic `x⁵ + x + 5 = y` (two extra multiplication gates). Update the Groth16 setup to `n_gates=5` and rerun. Observe how proof size stays at 3 for Groth16 but the SRS grows.
3. **Hard.** Implement a "soundness attack": given `Groth16SetupParams` including the toxic waste `tau`, forge a proof for a false statement `y = w["y"] + 1` (i.e., construct `A, B, C` satisfying `A*B ≡ alpha*beta + y_fake*gamma + C*delta` without knowing a valid witness). Explain why deleting `tau` after setup prevents this attack in a real system.

## Key Terms

| Term | What people say | What it actually means |
|------|-----------------|------------------------|
| Trusted setup | "The ceremony" | A one-time MPC computation that produces public parameters; security holds as long as at least one participant discards their secret ("toxic waste"). |
| QAP | "Quadratic Arithmetic Program" | A way to encode arithmetic circuit satisfiability as a polynomial divisibility check; Groth16 works by evaluating QAP polynomials at a secret point. |
| Universal SRS | "Updatable, universal setup" | A structured reference string valid for all circuits up to a size bound, so different circuits share one setup instead of each requiring its own ceremony. |
| Post-quantum safe | "PQ-safe" | The system's security does not rely on problems (discrete log, factoring) solvable by a quantum computer running Shor's algorithm. |
| FRI | "Fast Reed-Solomon IOP of Proximity" | The core polynomial commitment used in STARKs; proves that a committed vector is close to a low-degree polynomial using log-depth folding and Merkle opening queries. |

## Further Reading

- Groth, Jens. *On the Size of Pairing-based Non-interactive Arguments* (Eurocrypt 2016) — the original Groth16 paper, proving optimality of the 3-element proof.
- Gabizon, Ariel, Zachary J. Williamson, and Oana Ciobanu. *PLONK: Permutations over Lagrange-bases for Oecumenical Noninteractive arguments of Knowledge* (ePrint 2019/953) — the PLONK protocol with universal trusted setup and permutation argument.
- Ben-Sasson, Eli, et al. *Scalable, transparent, and post-quantum secure computational integrity* (ePrint 2018/046) — the original STARK paper introducing the transparent, hash-based proof system.
