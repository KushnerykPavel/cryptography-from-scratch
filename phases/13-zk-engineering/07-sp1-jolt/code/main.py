"""
SP1 & Jolt (toy) — Trace → Multilinear Encoding → Sumcheck.

This script builds a tiny "VM trace" (a Fibonacci state machine), encodes its
transition constraints as a multilinear polynomial in evaluation form, and runs
a Fiat–Shamir (hash-based) sumcheck proof that a weighted sum of violations is 0.

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from typing import Iterable, List, Sequence, Tuple


FIELD_PRIME = 2305843009213693951  # 2^61 - 1 (a Mersenne prime)


def mod(x: int, p: int = FIELD_PRIME) -> int:
    return x % p


def mod_add(a: int, b: int, p: int = FIELD_PRIME) -> int:
    return (a + b) % p


def mod_sub(a: int, b: int, p: int = FIELD_PRIME) -> int:
    return (a - b) % p


def mod_mul(a: int, b: int, p: int = FIELD_PRIME) -> int:
    return (a * b) % p


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


def commit_list(values: Sequence[int]) -> bytes:
    h = hashlib.sha256()
    h.update(_enc_str("commit_list_v1"))
    h.update(_enc_u64(len(values)))
    for v in values:
        h.update(_enc_u64(v % (2**64)))
    return h.digest()


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


def _print_table(rows: Sequence[Tuple[int, ...]], headers: Sequence[str], max_rows: int = 8) -> None:
    show = list(rows[:max_rows])
    widths = [len(h) for h in headers]
    for r in show:
        for i, v in enumerate(r):
            widths[i] = max(widths[i], len(str(v)))
    fmt = "  ".join("{:" + str(w) + "}" for w in widths)
    print(fmt.format(*headers))
    print(fmt.format(*("-" * w for w in widths)))
    for r in show:
        print(fmt.format(*r))
    if len(rows) > max_rows:
        print(f"... ({len(rows) - max_rows} more rows)")


def demo_prove_trace_is_valid(
    trace: Sequence[Tuple[int, int]],
    p: int = FIELD_PRIME,
    *,
    label: str,
) -> Tuple[bool, dict]:
    flat_trace = [x for pair in trace for x in pair]
    tr = Transcript(label)
    tr.append("trace_commitment", commit_list(flat_trace))

    violations2 = fib_transition_violations(trace, p)
    alpha = tr.challenge_scalar("alpha", p)
    scalar_violations = combine_violations(violations2, alpha, p)
    gamma = tr.challenge_scalar("gamma", p)
    weighted = geometric_weights(scalar_violations, gamma, p)
    table = pad_to_pow2(weighted, 0)

    claimed_sum = 0
    proof = None
    prover_error = None
    try:
        prover_tr = Transcript(label)
        prover_tr.append("trace_commitment", commit_list(flat_trace))
        prover_tr.challenge_scalar("alpha", p)
        prover_tr.challenge_scalar("gamma", p)
        proof, _r = sumcheck_prove_multilinear(table, claimed_sum, prover_tr, p)
    except Exception as e:  # pragma: no cover
        prover_error = f"{type(e).__name__}: {e}"

    ok = False
    if proof is not None:
        verifier_tr = Transcript(label)
        verifier_tr.append("trace_commitment", commit_list(flat_trace))
        verifier_tr.challenge_scalar("alpha", p)
        verifier_tr.challenge_scalar("gamma", p)
        ok = sumcheck_verify_multilinear(table, claimed_sum, proof, verifier_tr, p)
    debug = {
        "p": p,
        "alpha": alpha,
        "gamma": gamma,
        "num_steps": len(trace) - 1,
        "padded_len": len(table),
        "actual_weighted_sum": sum(table) % p,
        "rounds": 0 if proof is None else len(proof.round_evals),
        "prover_error": prover_error,
    }
    return ok, debug


def main() -> None:
    p = FIELD_PRIME

    print("=== Step 1: Trace a tiny VM ===")
    a0, a1, steps = 1, 1, 8
    trace = fib_trace(a0, a1, steps, p)
    _print_table([(t, a, b) for t, (a, b) in enumerate(trace)], headers=("t", "A", "B"))

    print("\n=== Step 2: Turn constraints into a violation table ===")
    v2 = fib_transition_violations(trace, p)
    _print_table([(t, c1, c2) for t, (c1, c2) in enumerate(v2)], headers=("t", "c1", "c2"))
    print(f"nonzero violations: {sum(1 for c1, c2 in v2 if (c1 % p) != 0 or (c2 % p) != 0)}")

    print("\n=== Step 3: Evaluate the multilinear extension (MLE) ===")
    tr = Transcript("sp1-jolt-demo")
    tr.append("trace_commitment", commit_list([x for pair in trace for x in pair]))
    alpha = tr.challenge_scalar("alpha", p)
    gamma = tr.challenge_scalar("gamma", p)
    scalar = combine_violations(v2, alpha, p)
    weighted = geometric_weights(scalar, gamma, p)
    table = pad_to_pow2(weighted, 0)
    r = [tr.challenge_scalar(f"eval_r_{i}", p) for i in range(int(math.log2(len(table))))]
    val_at_r = mle_eval(table, r, p)
    print(f"p = {p}")
    print(f"alpha = {alpha}")
    print(f"gamma = {gamma}")
    print(f"padded_len = {len(table)} (next power of two)")
    print(f"MLE(table)(r) = {val_at_r}")

    print("\n=== Step 4: Prove the weighted-sum claim via sumcheck ===")
    ok, debug = demo_prove_trace_is_valid(trace, p, label="sp1-jolt-demo")
    print(f"sumcheck verify (valid trace): {ok}")
    print(json.dumps(debug, indent=2, sort_keys=True))

    bad = list(trace)
    bad[3] = (bad[3][0], (bad[3][1] + 12345) % p)
    ok2, debug2 = demo_prove_trace_is_valid(bad, p, label="sp1-jolt-demo")
    print("\nTampered trace row t=3 (B += 12345):")
    print(f"sumcheck verify (tampered trace): {ok2}")
    print(json.dumps(debug2, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
