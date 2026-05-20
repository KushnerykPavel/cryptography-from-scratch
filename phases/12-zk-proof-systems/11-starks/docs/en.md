# STARKs from Scratch — AIR, Trace, and Merkle Commitments

> A STARK is “a program trace + algebraic constraints + commitments + random spot checks” — and the missing magic is the low-degree test.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 02 (mod p arithmetic), Phase 06 (polynomials over fields), Phase 08 (hashes + Merkle trees), Phase 12 · 07 (Toy PLONK), Phase 12 · 10 (Halo2)
**Time:** ~120 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- **Explain** what a trace table is and why STARKs start there.
- **Compute** Fibonacci AIR boundary and transition constraints on a trace.
- **Implement** a Merkle commitment and openings for trace rows.
- **Distinguish** spot-check soundness from a full STARK’s low-degree soundness (FRI).
- **Apply** Fiat–Shamir to deterministically sample query positions from a commitment.

## The Problem

You want to prove a long computation happened correctly — “this rollup state transition is valid”, “this zkVM executed the program”, “this fraud proof step is consistent” — without revealing every intermediate step. In SNARK-style systems, you typically compile the computation into an algebraic form (R1CS/QAP/PLONK-ish), then use polynomial commitments and a proof system that is short and fast to verify but often relies on elliptic-curve assumptions and may require a trusted setup.

STARKs take a different path: **turn the computation into an execution trace table**, then express correctness as **algebraic constraints over that table** (an AIR). The prover commits to the table and answers a few random queries. The verifier checks the constraints only at the queried positions — and (in real STARKs) uses a low-degree test to ensure the committed table really is a low-degree encoding of a valid trace, not an arbitrary table engineered to pass a few checks.

If you can’t write an AIR, you can’t even state what “correct execution” means in a STARK. If you can’t commit to a trace and open positions, you can’t build the IOP-shaped proof interface that makes STARKs scalable.

## The Concept

A STARK centers on three objects:

1. **Trace table.** A rectangular table of field elements: rows are time steps, columns are “registers”.
2. **AIR constraints.** Algebraic equations that must hold on the trace:
   - boundary constraints (what must be true at row 0 / last row)
   - transition constraints (what must be true from row *i* to row *i+1*)
3. **Commit-and-query proof interface.** Commit to the whole trace (typically via polynomial evaluation on a domain, then Merkle). Then the verifier asks for a few positions and checks the constraints there.

For Fibonacci with two registers `(x0, x1)`, a trace looks like this:

```
row i:     (x0, x1)
row i+1:   (y0, y1)

transition: y0 = x1
            y1 = x0 + x1     (all mod p)
```

The “spot-check” idea is simple: if a dishonest prover changes some rows, it will likely violate the transition constraint at many positions. If the verifier samples a few positions uniformly, the prover is caught with high probability. But this is not enough for a real STARK: a prover could commit to an arbitrary table that passes a few local checks. The missing enforcement is: **the committed object must be a low-degree polynomial codeword**, and **FRI** is the low-degree test used in modern STARKs.

This lesson implements the *shape* of a STARK (trace + AIR + Merkle + Fiat–Shamir queries) and makes explicit what FRI adds later.

## Build It

### Step 1: Trace table (Fibonacci)

```python
def fib_trace(a0: int, a1: int, steps: int, p: int) -> List[Tuple[int, int]]:
    if steps < 2:
        raise ValueError("steps must be >= 2")
    x0 = a0 % p
    x1 = a1 % p
    out: List[Tuple[int, int]] = [(x0, x1)]
    for _ in range(steps - 1):
        x0, x1 = x1, (x0 + x1) % p
        out.append((x0, x1))
    return out


def demo_print_trace(trace: Sequence[Tuple[int, int]], rows: int) -> None:
    print("row | x0        | x1")
    print("----+-----------+-----------")
    for i, (x0, x1) in enumerate(trace[:rows]):
        print(f"{i:>3} | {x0:>9} | {x1:>9}")
```

This builds the concrete object STARKs reason about: a sequence of states. The important move is conceptual: you’re not “proving a program” yet — you’re committing to a table of field elements that claims to be the program’s execution.

### Step 2: AIR constraints (boundary + transition)

```python
def fib_air_boundary(trace: Sequence[Tuple[int, int]], a0: int, a1: int, p: int) -> bool:
    if not trace:
        return False
    return trace[0][0] % p == a0 % p and trace[0][1] % p == a1 % p


def fib_air_transition_ok(curr: Tuple[int, int], nxt: Tuple[int, int], p: int) -> bool:
    x0, x1 = curr
    y0, y1 = nxt
    if y0 % p != x1 % p:
        return False
    return y1 % p == (x0 + x1) % p


def fib_air_all_transitions(trace: Sequence[Tuple[int, int]], p: int) -> bool:
    return all(fib_air_transition_ok(trace[i], trace[i + 1], p) for i in range(len(trace) - 1))
```

This is the AIR: a tiny set of algebraic equalities that define “valid execution”. In real STARKs these constraints are combined into polynomials and checked at random points; here we keep it concrete and check row-to-row.

### Step 3: Merkle commitment to the trace

```python
def hash256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def u64be(x: int) -> bytes:
    if x < 0:
        raise ValueError("u64be expects non-negative")
    if x >= 1 << 64:
        raise ValueError("u64be expects < 2^64")
    return x.to_bytes(8, "big", signed=False)


def hash_leaf(payload: bytes) -> bytes:
    return hash256(b"\x00" + payload)


def hash_node(left: bytes, right: bytes) -> bytes:
    return hash256(b"\x01" + left + right)


def merkle_build(leaf_payloads: Sequence[bytes]) -> List[List[bytes]]:
    if not leaf_payloads:
        raise ValueError("empty tree")
    level = [hash_leaf(p) for p in leaf_payloads]
    levels = [level]
    while len(level) > 1:
        nxt: List[bytes] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(hash_node(left, right))
        level = nxt
        levels.append(level)
    return levels


def merkle_root(levels: Sequence[Sequence[bytes]]) -> bytes:
    if not levels or not levels[-1]:
        raise ValueError("invalid merkle levels")
    return levels[-1][0]


def merkle_open(levels: Sequence[Sequence[bytes]], index: int) -> List[Tuple[bytes, int]]:
    if index < 0 or index >= len(levels[0]):
        raise IndexError("leaf index out of range")
    path: List[Tuple[bytes, int]] = []
    idx = index
    for level in levels[:-1]:
        is_right = idx & 1
        sib_idx = idx - 1 if is_right else idx + 1
        sibling = level[sib_idx] if sib_idx < len(level) else level[idx]
        path.append((sibling, is_right))
        idx //= 2
    return path


def merkle_verify(root: bytes, leaf_payload: bytes, index: int, path: Sequence[Tuple[bytes, int]]) -> bool:
    acc = hash_leaf(leaf_payload)
    idx = index
    for sibling, is_right in path:
        if is_right:
            acc = hash_node(sibling, acc)
        else:
            acc = hash_node(acc, sibling)
        idx //= 2
    return acc == root


def trace_row_payload(row: Tuple[int, int]) -> bytes:
    return u64be(row[0]) + u64be(row[1])
```

The prover now has a binding commitment to the entire trace. A Merkle opening lets the verifier check “these specific row values are really part of the committed trace” without downloading the whole table.

### Step 4: Fiat–Shamir sampling + spot-check proof

```python
def fs_challenges(root: bytes, n: int, count: int) -> List[int]:
    if n <= 0:
        raise ValueError("n must be positive")
    if count < 0:
        raise ValueError("count must be non-negative")
    out: List[int] = []
    ctr = 0
    while len(out) < count:
        digest = hash256(b"fs" + root + u64be(ctr))
        x = int.from_bytes(digest[:8], "big") % n
        if x not in out:
            out.append(x)
        ctr += 1
    return out


@dataclass(frozen=True)
class StarkProof:
    p: int
    steps: int
    a0: int
    a1: int
    root: str
    boundary: dict
    queries: List[dict]


def prove_fib(a0: int, a1: int, steps: int, p: int, query_count: int) -> StarkProof:
    trace = fib_trace(a0, a1, steps, p)
    leaves = [trace_row_payload(r) for r in trace]
    levels = merkle_build(leaves)
    root = merkle_root(levels)
    qs = fs_challenges(root, n=len(trace) - 1, count=query_count)

    row0 = trace[0]
    boundary = {
        "row0": list(row0),
        "path0": [(sib.hex(), side) for sib, side in merkle_open(levels, 0)],
    }

    queries: List[dict] = []
    for i in qs:
        row_i = trace[i]
        row_ip1 = trace[i + 1]
        leaf_i = trace_row_payload(row_i)
        leaf_ip1 = trace_row_payload(row_ip1)
        path_i = [(sib.hex(), side) for sib, side in merkle_open(levels, i)]
        path_ip1 = [(sib.hex(), side) for sib, side in merkle_open(levels, i + 1)]
        queries.append(
            {
                "i": i,
                "row_i": list(row_i),
                "row_ip1": list(row_ip1),
                "path_i": path_i,
                "path_ip1": path_ip1,
            }
        )

    return StarkProof(
        p=p,
        steps=steps,
        a0=a0,
        a1=a1,
        root=root.hex(),
        boundary=boundary,
        queries=queries,
    )


def verify_fib(proof: StarkProof, query_count: int) -> bool:
    if proof.p != P:
        return False
    if proof.steps < 2:
        return False
    root = bytes.fromhex(proof.root)
    if not proof.queries:
        return False

    qs = fs_challenges(root, n=proof.steps - 1, count=query_count)
    if [q["i"] for q in proof.queries] != qs:
        return False

    row0 = (int(proof.boundary["row0"][0]) % proof.p, int(proof.boundary["row0"][1]) % proof.p)
    path0 = [(bytes.fromhex(h), int(side)) for h, side in proof.boundary["path0"]]
    if not merkle_verify(root, trace_row_payload(row0), 0, path0):
        return False
    if not fib_air_boundary([row0], proof.a0, proof.a1, proof.p):
        return False

    for q in proof.queries:
        i = q["i"]
        row_i = (int(q["row_i"][0]) % proof.p, int(q["row_i"][1]) % proof.p)
        row_ip1 = (int(q["row_ip1"][0]) % proof.p, int(q["row_ip1"][1]) % proof.p)

        leaf_i = trace_row_payload(row_i)
        leaf_ip1 = trace_row_payload(row_ip1)
        path_i = [(bytes.fromhex(h), int(side)) for h, side in q["path_i"]]
        path_ip1 = [(bytes.fromhex(h), int(side)) for h, side in q["path_ip1"]]

        if not merkle_verify(root, leaf_i, i, path_i):
            return False
        if not merkle_verify(root, leaf_ip1, i + 1, path_ip1):
            return False
        if not fib_air_transition_ok(row_i, row_ip1, proof.p):
            return False

    return True
```

This is the “IOP shape”: commit to a big object, derive random challenges from the commitment (Fiat–Shamir), and open only the parts the verifier asks for. Real STARKs add FRI to force the committed object to be a low-degree codeword.

### Step 5: What this is (and what it is not)

The demo in `code/main.py` prints the exact takeaway: **this protocol is STARK-shaped**, but without a low-degree test it is not a full STARK. In the next lessons you’ll build FRI, then plug it in to replace “I trust this is a polynomial codeword” with “I checked it efficiently”.

Run it:

`python3 code/main.py`

## Use It

Where this shows up in real stacks:

| You built | Production equivalent |
|---|---|
| Trace table | VM trace / execution trace (zkVMs, rollups, Cairo/Miden-style systems) |
| AIR constraints | Constraint system over registers (transition + boundary + periodic constraints) |
| Merkle commitment + openings | Commitment to evaluations + authentication paths for queried positions |
| Fiat–Shamir queries | Transcript-based challenge sampling (hash-to-field, query indices) |
| (Missing) low-degree test | FRI (and variants) to enforce polynomial codeword structure |

If you want a real STARK implementation to study next:

- **Winterfell (Rust)** — educational STARK library focused on AIR-style proving.
- **Cairo / STARK provers** — industrial stacks where “write an AIR” is the core developer workflow.
- **Plonky3 / modern STARK frameworks** — newer modular proof stacks that factor out commitment layers and folding/FRI components.

## Pitfalls

1. **No boundary opening.** If the verifier never checks row 0 (or the last row), a prover can “start from a different initial state” and still pass local transitions.
2. **Sampling duplicate positions.** Duplicates reduce coverage and silently weaken soundness.
3. **Merkle ambiguity without domain separation.** Hashing leaves and internal nodes the same way can enable structural collisions in toy settings.
4. **Spot checks without low-degree enforcement.** A prover can craft a table that passes a few local checks but is not a valid low-degree encoding of any trace polynomial.
5. **Fiat–Shamir misuse.** Challenge derivation must bind to the commitment and be unambiguous (stable encoding, domain separation).

## Ship It

Save `outputs/prompt-stark-air-review-checklist.md` and use it as a PR review prompt when someone proposes a new AIR / trace layout (or when you’re designing one). It forces you to answer the questions that determine whether a STARK design is actually checkable: what are the registers, what are the constraints, what is committed, what is opened, and what does FRI need to enforce.

## Exercises

1. Easy: Run `code/main.py`. Observe how changing `steps` changes the Merkle root and the sampled query indices.
2. Medium: Extend the trace to three registers `(x0, x1, x2)` where `x2 = x0 * x1` each step, and add an AIR transition constraint that enforces it.
3. Hard: Replace the Merkle-tree row commitment with a column-oriented commitment (commit each column separately). Update the proof so a query opens the needed cells across columns, and compare proof size.

## Key Terms

| Term | What people say | What it actually means |
|---|---|---|
| Trace | “execution table” | The prover’s claimed per-step register values for the computation |
| AIR | “constraints” | Algebraic equations over trace values (boundary + transition + periodic) |
| Boundary constraint | “initial/final checks” | Constraints that pin specific rows (often row 0 / last row) |
| Transition constraint | “step rule” | Constraints linking row *i* to row *i+1* |
| Merkle commitment | “hash the table” | Bind to many values with a short root; open a few values with paths |
| Fiat–Shamir | “make it non-interactive” | Turn verifier randomness into hashes of the transcript/commitments |
| Low-degree test | “prove it’s a polynomial” | Check the committed evaluations come from a low-degree polynomial |
| FRI | “the STARK engine” | The specific low-degree IOP used by many STARKs to get scalability |

## Further Reading

- Eli Ben-Sasson et al., *Scalable, transparent, and post-quantum secure computational integrity* (2018) — the STARK paper family; AIR + IOP + FRI.
- Vitalik Buterin, *STARKs, part 1–3* (blog series) — intuition and design vocabulary for traces and constraints.
- StarkWare, *Cairo whitepaper / docs* — how AIR-style constraints show up in a production zkVM DSL.
