"""
Toy zkVM receipt flow inspired by RISC0 — stdlib Python.

This lesson simulates the *shape* of a zkVM like RISC0:
  - a guest program is hashed into an immutable `image_id`
  - the guest runs with public + private inputs and writes a public `journal`
  - the prover produces a `receipt` that binds `image_id` and `journal`
  - the verifier spot-checks a committed execution trace (Merkle + random queries)

This is educational. It is not zero-knowledge and it is not production-safe.

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Iterable, List, Sequence, Tuple


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


def receipt_to_jsonable(receipt: ToyReceipt) -> dict:
    def st_to_dict(st: State) -> dict:
        return {
            "pc": st.pc,
            "stack": [x.hex() for x in st.stack],
            "journal": [x.hex() for x in st.journal],
        }

    return {
        "image_id": receipt.image_id.hex(),
        "trace_root": receipt.trace_root.hex(),
        "public_inputs": [x.hex() for x in receipt.public_inputs],
        "private_inputs": [x.hex() for x in receipt.private_inputs],
        "journal": [x.hex() for x in receipt.journal],
        "query_positions": list(receipt.query_positions),
        "proofs": [
            {
                "i": pr.i,
                "st_i": st_to_dict(pr.st_i),
                "st_ip1": st_to_dict(pr.st_ip1),
                "leaf_i": pr.leaf_i.hex(),
                "leaf_ip1": pr.leaf_ip1.hex(),
                "path_i": [(sib.hex(), side) for sib, side in pr.path_i],
                "path_ip1": [(sib.hex(), side) for sib, side in pr.path_ip1],
            }
            for pr in receipt.proofs
        ],
    }


def demo_program_preimage_check() -> List[Instr]:
    return [
        Instr("PUSH_PRIVATE", 0),
        Instr("SHA256"),
        Instr("PUSH_PUBLIC", 0),
        Instr("EQ"),
        Instr("ASSERT"),
        Instr("PUSH_PUBLIC", 1),
        Instr("COMMIT"),
        Instr("HALT"),
    ]


def _print_hex(label: str, b: bytes) -> None:
    print(f"{label}: {b.hex()}")


def main() -> None:
    program = demo_program_preimage_check()
    img = image_id(program)

    secret = b"correct horse battery staple"
    commitment = hash256(secret)
    public_ok = [commitment, b"ok"]
    private_ok = [secret]

    print("=== Step 1: Image ID (program identity) ===")
    _print_hex("image_id", img)

    print("\n=== Step 2: Execute guest (public + private inputs) ===")
    ex = run_program(program, public_inputs=public_ok, private_inputs=private_ok)
    if not ex.halted:
        raise SystemExit("program did not halt")
    print(f"steps: {len(ex.trace) - 1}")
    print("journal:", [x.decode("utf-8", errors="replace") for x in ex.trace[-1].journal])

    print("\n=== Step 3: Prove (commit trace + open random steps) ===")
    receipt = prove_execution(program, public_inputs=public_ok, private_inputs=private_ok, query_count=6)
    _print_hex("trace_root", receipt.trace_root)
    print("query_positions:", list(receipt.query_positions))
    print("receipt.json (truncated):")
    rendered = json.dumps(receipt_to_jsonable(receipt), indent=2)
    print(rendered[:700] + ("..." if len(rendered) > 700 else ""))

    print("\n=== Step 4: Verify receipt (binds image_id + journal) ===")
    ok = verify_receipt(receipt, program=program, expected_journal=[b"ok"])
    print("verify:", ok)

    print("\nTamper demo: change journal -> verification fails")
    bad_receipt = ToyReceipt(
        image_id=receipt.image_id,
        public_inputs=receipt.public_inputs,
        private_inputs=receipt.private_inputs,
        journal=(b"not ok",),
        trace_root=receipt.trace_root,
        query_positions=receipt.query_positions,
        proofs=receipt.proofs,
    )
    print("verify(tampered):", verify_receipt(bad_receipt, program=program, expected_journal=[b"ok"]))


if __name__ == "__main__":
    main()
