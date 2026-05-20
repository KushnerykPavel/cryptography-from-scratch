# SP1 & Jolt — STARK-Based zkVMs

> Prove a huge trace by checking one random point.

**Type:** Build
**Languages:** Python
**Prerequisites:** finite fields, hashes, Phase 12 · 15 (folding schemes intuition)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- **Explain** why zkVMs turn execution into a trace + constraints instead of a single giant circuit.
- **Compute** transition-constraint violations for a simple trace.
- **Implement** multilinear-extension evaluation by folding an evaluation table.
- **Distinguish** what sumcheck proves (a sum claim) from what a polynomial commitment proves (an evaluation claim).
- **Apply** Fiat–Shamir transcript discipline (binding + domain separation) to derive verifier challenges safely.

## The Problem

You want to prove you executed a program correctly — not a toy circuit with 10,000 constraints, but a real program with millions to billions of “steps”: CPU instruction transitions, memory reads/writes, syscall effects, and cryptographic precompiles. If you try to encode that as a single monolithic circuit, two things break fast: prover memory (the witness is huge) and engineering velocity (every change is a circuit rewrite).

zkVMs flip the workflow. They run the program normally, record an **execution trace**, and then prove (succinctly) that the trace satisfies a set of **local constraints** (“this row transitions to the next row correctly”, “this read matches some prior write”, “this instruction opcode is legal”, …). SP1 is a RISC‑V zkVM; Jolt is a lookup-first zkVM. Both aim to make “prove program execution” a normal developer operation.

The catch: a trace can be enormous. You cannot have the verifier check every row. The core trick used by sumcheck-first designs (Jolt, and SP1’s newer multilinear direction) is: **reduce many local checks to a small number of random-point checks** via multilinear polynomials and sumcheck.

## The Concept

Think in four layers:

1. **Trace**: a table of states per step. For a CPU this is registers + memory buses; for our toy it’s two registers `(A, B)`.
2. **Constraints**: equations that must hold row-to-row. Example: `A_next = B` and `B_next = A + B`.
3. **Multilinear encoding (MLE)**: take a vector of values indexed by step number and view it as a multilinear polynomial over `{0,1}^k` by interpolation. This lets you talk about the whole trace with algebra, not loops.
4. **Sumcheck**: an interactive protocol that convinces a verifier that a claimed sum over the Boolean hypercube is correct, while the verifier only does cheap checks per round plus one final evaluation of the underlying polynomial.

In practice, modern zkVMs then add:

- **Fiat–Shamir transcript** to remove interaction (hash the transcript to get challenges).
- **Polynomial commitments** so the verifier can check a final evaluation without seeing the whole table.

This lesson implements a toy version of the “trace → multilinear table → sumcheck” spine, in pure Python stdlib.

## Build It

### Step 1: Trace a tiny VM

```python
def fib_trace(a0: int, a1: int, steps: int, p: int = FIELD_PRIME) -> List[Tuple[int, int]]:
    if steps < 0:
        raise ValueError("steps must be >= 0")
    a = a0 % p
    b = a1 % p
    trace = [(a, b)]
    for _ in range(steps):
        a, b = b, (a + b) % p
        trace.append((a, b))
    return trace
```

This is the smallest possible “execution trace”: two registers updated by a fixed transition function. A real zkVM trace has dozens to hundreds of columns; the key is that every row is derived from the previous row by deterministic rules.

### Step 2: Turn constraints into a violation table

```python
def fib_transition_violations(
    trace: Sequence[Tuple[int, int]], p: int = FIELD_PRIME
) -> List[Tuple[int, int]]:
    if len(trace) < 2:
        return []
    out: List[Tuple[int, int]] = []
    for t in range(len(trace) - 1):
        a_t, b_t = trace[t]
        a_next, b_next = trace[t + 1]
        c1 = (a_next - b_t) % p
        c2 = (b_next - (a_t + b_t)) % p
        out.append((c1, c2))
    return out


def combine_violations(violations: Sequence[Tuple[int, int]], alpha: int, p: int = FIELD_PRIME) -> List[int]:
    return [(c1 + alpha * c2) % p for (c1, c2) in violations]


def geometric_weights(values: Sequence[int], gamma: int, p: int = FIELD_PRIME) -> List[int]:
    out: List[int] = []
    acc = 1
    for v in values:
        out.append((v * acc) % p)
        acc = (acc * gamma) % p
    return out
```

`fib_transition_violations` computes two constraint residuals per row. `combine_violations` collapses multiple constraints into one using a random scalar `alpha` (if any constraint is wrong, the combined value is nonzero with high probability). `geometric_weights` multiplies each step by `gamma^t` so a sum can’t “accidentally cancel” across different step indices.

### Step 3: Evaluate the multilinear extension (MLE)

```python
def next_power_of_two(n: int) -> int:
    if n <= 1:
        return 1
    return 1 << (n - 1).bit_length()


def is_power_of_two(n: int) -> bool:
    return n > 0 and (n & (n - 1) == 0)


def pad_to_pow2(values: Sequence[int], pad_value: int = 0) -> List[int]:
    target = next_power_of_two(len(values))
    out = list(values)
    out.extend([pad_value] * (target - len(out)))
    return out


def mle_eval(evals: Sequence[int], r: Sequence[int], p: int = FIELD_PRIME) -> int:
    if not is_power_of_two(len(evals)):
        raise ValueError("evals length must be a power of two")
    n = int(math.log2(len(evals)))
    if len(r) != n:
        raise ValueError(f"r must have length {n}")
    work = [v % p for v in evals]
    for i in range(n):
        ri = r[i] % p
        one_minus = (1 - ri) % p
        nxt = []
        for j in range(0, len(work), 2):
            a0 = work[j]
            a1 = work[j + 1]
            nxt.append((one_minus * a0 + ri * a1) % p)
        work = nxt
    return work[0]
```

This is the core multilinear trick: an array of `2^n` values becomes an `n`‑variate multilinear polynomial. Evaluating it at a random point `r ∈ F^n` is just repeated “pair folding”: `(a0, a1) ↦ (1−r)a0 + r a1`.

### Step 4: Prove the weighted-sum claim via sumcheck

```python
def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _enc_u64(x: int) -> bytes:
    if x < 0 or x >= 2**64:
        raise ValueError("u64 out of range")
    return x.to_bytes(8, "big")


def _enc_bytes(b: bytes) -> bytes:
    return _enc_u64(len(b)) + b


def _enc_str(s: str) -> bytes:
    return _enc_bytes(s.encode("utf-8"))


class Transcript:
    def __init__(self, label: str):
        self._state = _sha256(_enc_str("domain_sep") + _enc_str(label))

    def append(self, label: str, data: bytes) -> None:
        self._state = _sha256(self._state + _enc_str(label) + _enc_bytes(data))

    def challenge_scalar(self, label: str, p: int = FIELD_PRIME) -> int:
        digest = _sha256(self._state + _enc_str("challenge") + _enc_str(label))
        return int.from_bytes(digest, "big") % p


@dataclass(frozen=True)
class SumcheckProof:
    round_evals: List[Tuple[int, int]]


def sumcheck_prove_multilinear(
    evals: Sequence[int], claimed_sum: int, transcript: Transcript, p: int = FIELD_PRIME
) -> Tuple[SumcheckProof, List[int]]:
    if not is_power_of_two(len(evals)):
        raise ValueError("evals length must be a power of two")
    work = [v % p for v in evals]
    n = int(math.log2(len(work)))
    claim = claimed_sum % p
    r: List[int] = []
    msgs: List[Tuple[int, int]] = []
    for round_idx in range(n):
        s0 = sum(work[0::2]) % p
        s1 = sum(work[1::2]) % p
        if (s0 + s1) % p != claim:
            raise ValueError("claimed_sum is inconsistent with eval table")
        msgs.append((s0, s1))
        transcript.append(f"sumcheck_round_{round_idx}", _enc_u64(s0) + _enc_u64(s1))
        ri = transcript.challenge_scalar(f"r_{round_idx}", p)
        r.append(ri)
        claim = (s0 + ri * ((s1 - s0) % p)) % p

        one_minus = (1 - ri) % p
        nxt = []
        for j in range(0, len(work), 2):
            a0 = work[j]
            a1 = work[j + 1]
            nxt.append((one_minus * a0 + ri * a1) % p)
        work = nxt

    if len(work) != 1:
        raise AssertionError("internal error: folding should end at length 1")
    if work[0] != claim:
        raise AssertionError("internal error: final claim mismatch")
    return SumcheckProof(round_evals=msgs), r


def sumcheck_verify_multilinear(
    evals: Sequence[int],
    claimed_sum: int,
    proof: SumcheckProof,
    transcript: Transcript,
    p: int = FIELD_PRIME,
) -> bool:
    if not is_power_of_two(len(evals)):
        raise ValueError("evals length must be a power of two")
    n = int(math.log2(len(evals)))
    if len(proof.round_evals) != n:
        return False

    claim = claimed_sum % p
    r: List[int] = []
    for round_idx, (s0, s1) in enumerate(proof.round_evals):
        s0 %= p
        s1 %= p
        if (s0 + s1) % p != claim:
            return False
        transcript.append(f"sumcheck_round_{round_idx}", _enc_u64(s0) + _enc_u64(s1))
        ri = transcript.challenge_scalar(f"r_{round_idx}", p)
        r.append(ri)
        claim = (s0 + ri * ((s1 - s0) % p)) % p

    return claim == mle_eval(evals, r, p)
```

Sumcheck reduces a `2^n`-sized sum claim to `n` rounds of small messages plus one final evaluation check. In real systems, that final evaluation is enforced with a polynomial commitment; here we do it directly with `mle_eval` so you can see the mechanics end-to-end.

Run it:

```bash
python3 code/main.py
```

## Use It

Production-grade zkVMs do the same steps, just at scale:

- **SP1 (Succinct)**: prove RISC‑V program execution with a STARK-ish proving stack; newer multilinear directions use sumcheck/GKR-style components for scalability.
- **Jolt (a16z)**: a sumcheck-first zkVM architecture; heavy use of multilinear polynomials, batched sumchecks, and a multilinear polynomial commitment scheme.
- **RISC0 / OpenVM / zkWasm variants**: alternative zkVMs with different arithmetizations and commitment choices (univariate FRI-style vs multilinear sumcheck-first).

Concrete mapping from this toy to real systems:

- `trace` table → full CPU trace (registers, memory buses, range checks, hash chips).
- `violations` → AIR/constraint composition polynomials or lookup constraints.
- `mle_eval` folding → evaluation of committed multilinear polynomials at verifier challenges.
- `Transcript` → Fiat–Shamir challengers with strict domain separation.

## Pitfalls

- **Bit order mismatch (LSB/MSB)**: your evaluation-table order must match your folding order, or the verifier checks the wrong polynomial.
- **Forgetting to bind challenges to a commitment**: if `alpha`, `gamma`, or `r_i` aren’t derived from a transcript that includes the trace commitment, the prover can “choose” challenges after seeing them.
- **Padding bugs**: sumcheck assumes a Boolean hypercube of size `2^n`; padding a non-power-of-two trace with the wrong value silently changes the statement.
- **Field too small**: soundness relies on “randomly chosen” field elements; tiny moduli make accidental cancellations likely.
- **No domain separation**: reusing transcript labels across subprotocols can couple challenges in unsafe ways.

## Ship It

Save a reusable review checklist for sumcheck-first zkVM code reviews:

- Open `outputs/sumcheck_first_zkvm_review_checklist.md`.
- Use it in PR reviews for: transcript handling, variable ordering, padding rules, and “final evaluation” plumbing (PCS openings).

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that the valid trace verifies and the tampered trace fails.
2. Medium. Extend the VM: add a third register `C_next = A + 2B`. Add its constraint and collapse 3 constraints via `alpha` (e.g., `c1 + alpha*c2 + alpha^2*c3`).
3. Hard. Production integration: read an open-source sumcheck implementation (e.g. `arkworks-rs/sumcheck`) and map its API concepts to this lesson’s `SumcheckProof` and `Transcript`.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Execution trace | “All the steps the VM ran” | A table of witness values indexed by time/step. |
| Constraint | “A rule that must hold” | A polynomial equation that should evaluate to 0 on every valid row. |
| Multilinear extension (MLE) | “Turn an array into a polynomial” | The unique multilinear polynomial matching a vector on `{0,1}^n`. |
| Sumcheck | “Prove a sum over the cube” | A protocol that reduces a hypercube-sum claim to one random-point evaluation. |
| Fiat–Shamir transcript | “Hash the transcript” | Derive verifier challenges by hashing all prior messages with domain separation. |

## Further Reading

- Arun, Setty, Thaler, *Jolt: SNARKs for Virtual Machines via Lookups* (2024) — lookup-first zkVM with sumcheck-based proving.
- JoltBook, *How Jolt Works* (ongoing) — engineering-focused walkthrough of sumcheck-first zkVM structure.
- Thaler, *The Unreasonable Power of the Sum-Check Protocol* (2020) — why sumcheck is a workhorse primitive for succinct proofs.
