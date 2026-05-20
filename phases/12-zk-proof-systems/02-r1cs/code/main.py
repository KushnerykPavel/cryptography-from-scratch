"""R1CS (Rank-1 Constraint Systems) — a tiny from-scratch checker.

This script builds a small R1CS instance over a prime field and checks whether
different witnesses satisfy the constraints. It's a *constraint system*, not a
zero-knowledge proof system.

Run: python3 code/main.py
"""

from __future__ import annotations


def modp(x: int, p: int) -> int:
    return x % p


def inv_mod(a: int, p: int) -> int:
    a = a % p
    if a == 0:
        raise ValueError("0 has no inverse mod p")

    t, new_t = 0, 1
    r, new_r = p, a
    while new_r != 0:
        q = r // new_r
        t, new_t = new_t, t - q * new_t
        r, new_r = new_r, r - q * new_r
    if r != 1:
        raise ValueError("a is not invertible mod p")
    return t % p


def normalize_witness(witness: list[int], p: int) -> list[int]:
    if not witness:
        raise ValueError("witness must have at least one element (w[0] == 1)")
    if witness[0] != 1:
        raise ValueError("witness[0] must be 1 (the constant wire)")
    return [w % p for w in witness]


def eval_lc(terms: list[tuple[int, int]], witness: list[int], p: int) -> int:
    acc = 0
    for idx, coeff in terms:
        if idx < 0 or idx >= len(witness):
            raise IndexError(f"witness index out of range: {idx}")
        acc = (acc + (coeff % p) * witness[idx]) % p
    return acc


def check_constraint(constraint: dict, witness: list[int], p: int) -> bool:
    a = eval_lc(constraint["A"], witness, p)
    b = eval_lc(constraint["B"], witness, p)
    c = eval_lc(constraint["C"], witness, p)
    return (a * b - c) % p == 0


def check_r1cs(constraints: list[dict], witness: list[int], p: int) -> bool:
    witness = normalize_witness(witness, p)
    return all(check_constraint(con, witness, p) for con in constraints)


def first_unsatisfied(constraints: list[dict], witness: list[int], p: int) -> int | None:
    witness = normalize_witness(witness, p)
    for i, con in enumerate(constraints):
        if not check_constraint(con, witness, p):
            return i
    return None


def constraint_trace(constraint: dict, witness: list[int], p: int) -> tuple[int, int, int]:
    witness = normalize_witness(witness, p)
    a = eval_lc(constraint["A"], witness, p)
    b = eval_lc(constraint["B"], witness, p)
    c = eval_lc(constraint["C"], witness, p)
    return a, b, c


def r1cs_for_out_equals_xplusy_times_xminusy() -> tuple[int, list[dict], list[int]]:
    p = 101

    x = 9
    y = 4
    s = x + y
    d = x - y
    out = s * d

    # Wire layout (standard convention):
    # w[0] = 1 (constant)
    # w[1] = x
    # w[2] = y
    # w[3] = s = x + y
    # w[4] = d = x - y
    # w[5] = out = s * d
    w = [1, x, y, s, d, out]

    constraints = [
        # (x + y) * 1 = s
        {"A": [(1, 1), (2, 1)], "B": [(0, 1)], "C": [(3, 1)]},
        # (x - y) * 1 = d
        {"A": [(1, 1), (2, -1)], "B": [(0, 1)], "C": [(4, 1)]},
        # s * d = out
        {"A": [(3, 1)], "B": [(4, 1)], "C": [(5, 1)]},
    ]

    return p, constraints, w


def main():
    p, constraints, w = r1cs_for_out_equals_xplusy_times_xminusy()
    w = normalize_witness(w, p)

    print("=== Step 1: prime-field arithmetic (everything is mod p) ===")
    a = 42
    inv_a = inv_mod(a, p)
    print(f"  p = {p}")
    print(f"  a = {a}, inv(a) = {inv_a}, a*inv(a) mod p = {(a * inv_a) % p}")
    print(f"  (-3) mod p = {modp(-3, p)}")

    print()
    print("=== Step 2: linear combinations evaluate on a witness ===")
    lc_x_plus_y = [(1, 1), (2, 1)]
    lc_x_minus_y = [(1, 1), (2, -1)]
    print(f"  witness w = {w}")
    print(f"  (x + y)(w) = {eval_lc(lc_x_plus_y, w, p)}")
    print(f"  (x - y)(w) = {eval_lc(lc_x_minus_y, w, p)}")

    print()
    print("=== Step 3: an R1CS constraint is (A(w) * B(w) == C(w)) ===")
    con0 = constraints[0]
    a0, b0, c0 = constraint_trace(con0, w, p)
    print(f"  constraint 0: A(w)={a0}, B(w)={b0}, C(w)={c0} -> satisfied={check_constraint(con0, w, p)}")

    w_bad = w.copy()
    w_bad[3] = (w_bad[3] + 1) % p
    bad_idx = first_unsatisfied(constraints, w_bad, p)
    print(f"  tweak witness: set s = s+1 -> first_unsatisfied = {bad_idx}")
    if bad_idx is not None:
        a_bad, b_bad, c_bad = constraint_trace(constraints[bad_idx], w_bad, p)
        print(f"  failing trace: A(w)={a_bad}, B(w)={b_bad}, C(w)={c_bad}")

    print()
    print("=== Step 4: a whole circuit becomes a list of constraints ===")
    ok = check_r1cs(constraints, w, p)
    ok_bad = check_r1cs(constraints, w_bad, p)
    print(f"  constraints: {len(constraints)}")
    print(f"  satisfied (good witness) = {ok}")
    print(f"  satisfied (bad witness)  = {ok_bad}")
    print(f"  output wire out = w[5] = {w[5]} (for x=9, y=4, out=(x+y)*(x-y)=65)")


if __name__ == "__main__":
    main()
