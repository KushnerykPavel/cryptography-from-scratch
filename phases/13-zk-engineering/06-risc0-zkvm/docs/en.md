# zkVMs — RISC0 from User to Internals (Toy Model)

> A receipt binds a program identity (`image_id`) to a public output (`journal`) without re-running the program.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 08 (hashes + Merkle trees), Phase 12 · 11 (STARKs trace + Merkle commitments)
**Time:** ~120 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- **Explain** what a zkVM receipt is (and what it binds).
- **Compute** a program identity hash (`image_id`) from a guest program.
- **Implement** a tiny “guest VM” that produces a public `journal`.
- **Distinguish** re-execution verification from trace-commitment spot-check verification.
- **Apply** a receipt review checklist to avoid common zkVM integration bugs.

## The Problem

You want to ship “proof-carrying computation”: a prover runs a program with some private inputs (trade secrets, user data, witness values) and produces a short artifact that convinces a verifier the program ran correctly and produced a public result.

Without a zkVM, you often end up with brittle, handwritten circuits or ad-hoc proof logic. Without a *receipt* abstraction, you also lose the key safety property: the proof must be tied to **exactly** the code you intended to run and **exactly** the public outputs you intended to reveal. “A proof verified” is meaningless unless you know *what* it proved.

RISC0 packages this as a developer workflow: compile a guest program, get an `image_id`, run the guest to produce a `journal`, then verify a `receipt` against `(image_id, journal)` on the host.

## The Concept

Real zkVMs (like RISC0) are sophisticated: they execute a real ISA (RISC-V), generate a zero-knowledge proof of correct execution, and verify that proof efficiently. But you can understand the **interfaces** with a smaller model.

Think in layers:

1. **Guest program identity (`image_id`).** A stable hash of the exact code being proven. If the guest code changes, the `image_id` must change.
2. **Execution trace.** The per-step states the guest passed through (conceptually: a trace table). Real systems prove constraints about this trace without revealing it.
3. **Public output (`journal`).** The only bytes the guest intentionally reveals. The receipt must bind to the journal.
4. **Receipt.** “This `image_id` produced this `journal`.” In real zkVMs, the receipt includes a zk proof. In this toy model, we’ll commit to the trace via a Merkle root and **spot-check** a few transitions to simulate a verifier that does not re-run the whole trace.

Important: this toy is **not zero-knowledge**. We include private inputs inside the receipt so verification can recompute steps. That’s exactly what real zkVMs avoid.

## Build It

### Step 1: Commit to an execution trace (Merkle + openings)

```python
def hash256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def u32be(x: int) -> bytes:
    if x < 0:
        raise ValueError("u32be expects non-negative")
    if x >= 1 << 32:
        raise ValueError("u32be expects < 2^32")
    return x.to_bytes(4, "big", signed=False)


def enc_bytes(b: bytes) -> bytes:
    return u32be(len(b)) + b


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


def fs_positions(seed: bytes, n: int, count: int) -> List[int]:
    if n <= 0:
        raise ValueError("n must be positive")
    if count < 0:
        raise ValueError("count must be non-negative")
    out: List[int] = []
    ctr = 0
    while len(out) < count:
        digest = hash256(b"fs" + seed + u32be(ctr))
        x = int.from_bytes(digest[:4], "big") % n
        if x not in out:
            out.append(x)
        ctr += 1
    return out
```

Merkle roots are the simplest “bind many things with one hash” tool. A receipt typically commits to a lot of hidden data (an execution trace, memory accesses, etc.). Openings (Merkle paths) let a verifier sample-check a few positions without seeing everything.

### Step 2: Define a guest program and compute its `image_id`

```python
@dataclass(frozen=True)
class Instr:
    op: str
    arg: int | None = None


_OPCODES = {
    "PUSH_PUBLIC": 1,
    "PUSH_PRIVATE": 2,
    "SHA256": 3,
    "EQ": 4,
    "ASSERT": 5,
    "COMMIT": 6,
    "HALT": 7,
}


def encode_program(program: Sequence[Instr]) -> bytes:
    out = bytearray()
    for ins in program:
        if ins.op not in _OPCODES:
            raise ValueError(f"unknown op: {ins.op}")
        out.append(_OPCODES[ins.op])
        if ins.op in {"PUSH_PUBLIC", "PUSH_PRIVATE"}:
            if ins.arg is None:
                raise ValueError(f"{ins.op} expects arg")
            out += u32be(ins.arg)
        else:
            if ins.arg is not None:
                raise ValueError(f"{ins.op} does not take arg")
    return bytes(out)


def image_id(program: Sequence[Instr]) -> bytes:
    return hash256(b"toy-risc0-image" + encode_program(program))
```

In RISC0, you typically talk about proving “this guest binary” (an ELF) and you verify against its `image_id`. The only thing you really need here is: **program bytes → hash**. If you prove the wrong program, the `image_id` won’t match what your verifier expects.

### Step 3: Execute the guest and record a trace + `journal`

```python
@dataclass(frozen=True)
class State:
    pc: int
    stack: Tuple[bytes, ...]
    journal: Tuple[bytes, ...]


def stack_digest(stack: Sequence[bytes]) -> bytes:
    buf = bytearray(b"stack")
    for item in stack:
        buf += enc_bytes(item)
    return hash256(bytes(buf))


def journal_digest(journal: Sequence[bytes]) -> bytes:
    buf = bytearray(b"journal")
    for item in journal:
        buf += enc_bytes(item)
    return hash256(bytes(buf))


def state_leaf_payload(st: State) -> bytes:
    return u32be(st.pc) + stack_digest(st.stack) + journal_digest(st.journal)


def vm_step(program: Sequence[Instr], st: State, public_inputs: Sequence[bytes], private_inputs: Sequence[bytes]) -> State:
    if st.pc < 0 or st.pc >= len(program):
        raise ValueError("pc out of range")
    ins = program[st.pc]
    stack = list(st.stack)
    journal = list(st.journal)

    def pop() -> bytes:
        if not stack:
            raise ValueError("stack underflow")
        return stack.pop()

    if ins.op == "PUSH_PUBLIC":
        idx = int(ins.arg)  # type: ignore[arg-type]
        stack.append(public_inputs[idx])
        return State(pc=st.pc + 1, stack=tuple(stack), journal=tuple(journal))

    if ins.op == "PUSH_PRIVATE":
        idx = int(ins.arg)  # type: ignore[arg-type]
        stack.append(private_inputs[idx])
        return State(pc=st.pc + 1, stack=tuple(stack), journal=tuple(journal))

    if ins.op == "SHA256":
        x = pop()
        stack.append(hash256(x))
        return State(pc=st.pc + 1, stack=tuple(stack), journal=tuple(journal))

    if ins.op == "EQ":
        b = pop()
        a = pop()
        stack.append(b"\x01" if a == b else b"\x00")
        return State(pc=st.pc + 1, stack=tuple(stack), journal=tuple(journal))

    if ins.op == "ASSERT":
        x = pop()
        if x != b"\x01":
            raise ValueError("assert failed")
        return State(pc=st.pc + 1, stack=tuple(stack), journal=tuple(journal))

    if ins.op == "COMMIT":
        x = pop()
        journal.append(x)
        return State(pc=st.pc + 1, stack=tuple(stack), journal=tuple(journal))

    if ins.op == "HALT":
        return State(pc=st.pc, stack=tuple(stack), journal=tuple(journal))

    raise AssertionError("unreachable")


@dataclass(frozen=True)
class Execution:
    trace: Tuple[State, ...]
    halted: bool


def run_program(
    program: Sequence[Instr],
    public_inputs: Sequence[bytes],
    private_inputs: Sequence[bytes],
    max_steps: int = 10_000,
) -> Execution:
    st = State(pc=0, stack=tuple(), journal=tuple())
    trace: List[State] = [st]
    for _ in range(max_steps):
        ins = program[st.pc]
        nxt = vm_step(program, st, public_inputs=public_inputs, private_inputs=private_inputs)
        trace.append(nxt)
        st = nxt
        if ins.op == "HALT":
            return Execution(trace=tuple(trace), halted=True)
    return Execution(trace=tuple(trace), halted=False)
```

The `journal` is the zkVM idea that “the guest decides what becomes public”. A safe host interface treats the `journal` as the *only* output channel.

### Step 4: Produce and verify a toy receipt

```python
@dataclass(frozen=True)
class TraceProof:
    i: int
    st_i: State
    st_ip1: State
    leaf_i: bytes
    leaf_ip1: bytes
    path_i: Tuple[Tuple[bytes, int], ...]
    path_ip1: Tuple[Tuple[bytes, int], ...]


@dataclass(frozen=True)
class ToyReceipt:
    image_id: bytes
    public_inputs: Tuple[bytes, ...]
    private_inputs: Tuple[bytes, ...]
    journal: Tuple[bytes, ...]
    trace_root: bytes
    query_positions: Tuple[int, ...]
    proofs: Tuple[TraceProof, ...]


def prove_execution(
    program: Sequence[Instr],
    public_inputs: Sequence[bytes],
    private_inputs: Sequence[bytes],
    query_count: int = 8,
) -> ToyReceipt:
    img = image_id(program)
    ex = run_program(program, public_inputs=public_inputs, private_inputs=private_inputs)
    if not ex.halted:
        raise ValueError("program did not halt")

    leaves = [state_leaf_payload(s) for s in ex.trace]
    levels = merkle_build(leaves)
    root = merkle_root(levels)
    qs = fs_positions(seed=img + root + journal_digest(ex.trace[-1].journal), n=len(ex.trace) - 1, count=query_count)

    proofs: List[TraceProof] = []
    for i in qs:
        st_i = ex.trace[i]
        st_ip1 = ex.trace[i + 1]
        leaf_i = leaves[i]
        leaf_ip1 = leaves[i + 1]
        path_i = tuple(merkle_open(levels, i))
        path_ip1 = tuple(merkle_open(levels, i + 1))
        proofs.append(
            TraceProof(
                i=i,
                st_i=st_i,
                st_ip1=st_ip1,
                leaf_i=leaf_i,
                leaf_ip1=leaf_ip1,
                path_i=path_i,
                path_ip1=path_ip1,
            )
        )

    return ToyReceipt(
        image_id=img,
        public_inputs=tuple(public_inputs),
        private_inputs=tuple(private_inputs),
        journal=ex.trace[-1].journal,
        trace_root=root,
        query_positions=tuple(qs),
        proofs=tuple(proofs),
    )


def verify_receipt(
    receipt: ToyReceipt,
    program: Sequence[Instr],
    expected_journal: Sequence[bytes] | None = None,
) -> bool:
    if receipt.image_id != image_id(program):
        return False
    if expected_journal is not None and tuple(expected_journal) != receipt.journal:
        return False
    if len(receipt.query_positions) != len(receipt.proofs):
        return False
    if tuple(pr.i for pr in receipt.proofs) != receipt.query_positions:
        return False
    if len(set(receipt.query_positions)) != len(receipt.query_positions):
        return False

    for pr in receipt.proofs:
        if pr.i < 0:
            return False
        if pr.st_i.pc != pr.i:
            return False
        if pr.st_ip1.pc != pr.i + 1 and program[pr.st_i.pc].op != "HALT":
            return False
        if state_leaf_payload(pr.st_i) != pr.leaf_i:
            return False
        if state_leaf_payload(pr.st_ip1) != pr.leaf_ip1:
            return False
        if not merkle_verify(receipt.trace_root, pr.leaf_i, pr.i, pr.path_i):
            return False
        if not merkle_verify(receipt.trace_root, pr.leaf_ip1, pr.i + 1, pr.path_ip1):
            return False

        try:
            recomputed = vm_step(
                program,
                pr.st_i,
                public_inputs=receipt.public_inputs,
                private_inputs=receipt.private_inputs,
            )
        except Exception:
            return False

        if recomputed != pr.st_ip1:
            return False

    return True
```

This shows what “verify without re-running the whole trace” looks like at a high level: commit to a long trace, sample a few steps, and check those steps are consistent. A real zkVM uses a zero-knowledge proof to avoid revealing private inputs and to make verification fast and sound.

Run it:

```bash
python3 code/main.py
```

## Use It

In real RISC0-based systems, the flow looks like:

- **Guest:** write code that `commit`s outputs to a `journal`.
- **Build:** compile the guest and record the resulting `image_id`.
- **Prove:** run the guest with inputs to produce a `receipt`.
- **Verify:** on the host, verify the receipt against the expected `image_id` and parse the `journal`.

Production equivalents (high level):

- `image_id` → the hash/ID of the compiled guest image.
- `journal` → public bytes committed by the guest (the only safe output channel).
- `receipt.verify(image_id)` → verifier ensures the receipt matches the intended guest.

## Pitfalls

1. **Verifying “some receipt” instead of “this program’s receipt”.** Always pin verification to a specific `image_id`.
2. **Treating `journal` as “debug output”.** Anything in the journal is public; keep it minimal and intentional.
3. **Non-determinism in the guest.** Clocks, randomness, and host environment leaks break reproducibility and can cause proof failures.
4. **Unclear public/private split.** Accidentally making a secret public (or vice versa) is an integration bug, not a crypto bug.
5. **Version skew.** Guest binary, `image_id`, and verifier expectations must be kept in lockstep across builds and deployments.

## Ship It

Save and use the receipt review checklist in `outputs/risc0-receipt-review-checklist.md`:

- Paste it into PR reviews for any change that touches guest code, host verification code, or the public `journal` schema.
- Use it as an “integration threat model” before you ship a zkVM-backed feature.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe how `image_id` changes if you change the program.
2. Medium. Extend the toy VM with one new opcode (e.g., `DUP` or `DROP`) and add a new deterministic vector in `tests/vectors.json`.
3. Hard. Sketch a production RISC0 integration plan: define the guest `journal` schema, how the host pins the expected `image_id`, and what CI checks prevent version skew.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| `image_id` | “Hash of the program” | A stable identifier for exactly the code being proven. |
| `journal` | “Guest output” | The intentionally public bytes emitted by the guest. |
| receipt | “The proof” | A binding artifact that ties program identity to public outputs (plus a proof in real zkVMs). |
| execution trace | “All steps of execution” | The per-step states a prover claims occurred; proofs constrain this trace. |
| Merkle commitment | “Commit to the trace” | Bind to many leaves via one root, open a few leaves with short paths. |

## Further Reading

- RISC Zero, *RISC Zero Documentation* — Concepts: receipt, image ID, journal, and the host/guest workflow.
- RISC-V Foundation, *The RISC-V ISA Manual* — Background on the instruction set many zkVMs emulate.
- Ben-Sasson et al., *Scalable, transparent, and post-quantum secure computational integrity* (2018) — STARKs: trace + commitments + spot checks.
