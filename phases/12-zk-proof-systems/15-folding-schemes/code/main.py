"""Nova folding scheme (toy) — fold two relaxed R1CS instances into one.

Run: python3 code/main.py
"""


# ---------------------------------------------------------------------------
# Field / vector / matrix helpers
# ---------------------------------------------------------------------------

def finv(a: int, p: int) -> int:
    """Modular inverse via Fermat's little theorem (p must be prime)."""
    a %= p
    if a == 0:
        raise ZeroDivisionError("inverse of 0 does not exist")
    return pow(a, p - 2, p)


def vadd(a: list, b: list, p: int) -> list:
    """Component-wise addition over F_p."""
    return [(x + y) % p for x, y in zip(a, b)]


def vsub(a: list, b: list, p: int) -> list:
    """Component-wise subtraction over F_p."""
    return [(x - y) % p for x, y in zip(a, b)]


def vscale(a: list, k: int, p: int) -> list:
    """Scalar multiplication over F_p."""
    return [(k * x) % p for x in a]


def hadamard(a: list, b: list, p: int) -> list:
    """Component-wise (Hadamard) product over F_p."""
    return [(x * y) % p for x, y in zip(a, b)]


def matvec(M: list, v: list, p: int) -> list:
    """Matrix-vector product over F_p.  M is a list of rows."""
    return [
        sum(M[i][j] * v[j] for j in range(len(v))) % p
        for i in range(len(M))
    ]


# ---------------------------------------------------------------------------
# R1CS definition — squaring gate: a * a = b
# ---------------------------------------------------------------------------

def make_squaring_r1cs():
    """Return (A, B, C) for the constraint a*a = b, witness z = [a, b].

    A = [[1, 0]]  selects a
    B = [[1, 0]]  selects a
    C = [[0, 1]]  selects b
    Constraint: (Az) o (Bz) = Cz  <=>  a * a = b
    """
    A = [[1, 0]]
    B = [[1, 0]]
    C = [[0, 1]]
    return A, B, C


def r1cs_witness(a: int, p: int) -> list:
    """Return the satisfying witness z = [a, a^2] for the squaring gate."""
    return [a % p, (a * a) % p]


# ---------------------------------------------------------------------------
# Relaxed R1CS check
# ---------------------------------------------------------------------------

def check_relaxed_r1cs(A, B, C, z, u, E, p) -> bool:
    """Return True iff (Az o Bz) == u*Cz + E  over F_p.

    A "fresh" instance has u=1, E=[0,...,0], which reduces to the
    ordinary R1CS check (Az o Bz) == Cz.
    """
    Az = matvec(A, z, p)
    Bz = matvec(B, z, p)
    Cz = matvec(C, z, p)
    lhs = hadamard(Az, Bz, p)
    rhs = vadd(vscale(Cz, u, p), E, p)
    return lhs == rhs


# ---------------------------------------------------------------------------
# Nova folding
# ---------------------------------------------------------------------------

def compute_cross_term(A, B, C, z1, u1, z2, u2, p) -> list:
    """Compute T = (Az1 o Bz2) + (Az2 o Bz1) - u1*Cz2 - u2*Cz1.

    For the squaring gate with fresh instances (u1=u2=1, E1=E2=0) this
    simplifies to:
        T = [2*a1*a2 - a1^2 - a2^2] = [-(a1 - a2)^2]

    T is the "cross term" that corrects for the non-linearity introduced
    when we linearly combine two witnesses.
    """
    Az1 = matvec(A, z1, p)
    Bz1 = matvec(B, z1, p)
    Cz1 = matvec(C, z1, p)
    Az2 = matvec(A, z2, p)
    Bz2 = matvec(B, z2, p)
    Cz2 = matvec(C, z2, p)
    t1 = hadamard(Az1, Bz2, p)           # Az1 o Bz2
    t2 = hadamard(Az2, Bz1, p)           # Az2 o Bz1
    t3 = vscale(Cz2, u1, p)              # u1 * Cz2
    t4 = vscale(Cz1, u2, p)              # u2 * Cz1
    return vsub(vadd(t1, t2, p), vadd(t3, t4, p), p)


def nova_fold(A, B, C, z1, u1, E1, z2, u2, E2, r, p):
    """Fold two relaxed R1CS instances into one using random challenge r.

    Folding equations:
        z_fold = z1 + r * z2
        u_fold = u1 + r * u2
        E_fold = E1 + r * T + r^2 * E2
    where T is the cross term.

    Returns (z_fold, u_fold, E_fold, T).
    """
    T = compute_cross_term(A, B, C, z1, u1, z2, u2, p)
    z_fold = vadd(z1, vscale(z2, r, p), p)
    u_fold = (u1 + r * u2) % p
    r2 = (r * r) % p
    E_fold = vadd(vadd(E1, vscale(T, r, p), p),
                  vscale(E2, r2, p), p)
    return z_fold, u_fold, E_fold, T


# ---------------------------------------------------------------------------
# main — five demonstration steps
# ---------------------------------------------------------------------------

def main():
    p = 101  # small prime for easy hand-verification

    A, B, C = make_squaring_r1cs()

    # ------------------------------------------------------------------
    print("=== Step 1: R1CS structure and satisfiability for a=7 ===")
    z7 = r1cs_witness(7, p)
    print(f"  Field prime p={p}")
    print(f"  A={A}  B={B}  C={C}")
    print(f"  Witness z=[a, a^2]=[{z7[0]}, {z7[1]}]")
    ok = check_relaxed_r1cs(A, B, C, z7, 1, [0], p)
    print(f"  Satisfies R1CS (u=1, E=[0])? {ok}")
    z7_bad = [7, 48]
    ok_bad = check_relaxed_r1cs(A, B, C, z7_bad, 1, [0], p)
    print(f"  Bad witness [7, 48] satisfies? {ok_bad}")

    # ------------------------------------------------------------------
    print()
    print("=== Step 2: Two fresh instances (a1=3, a2=5) ===")
    a1, a2 = 3, 5
    z1 = r1cs_witness(a1, p)
    z2 = r1cs_witness(a2, p)
    ok1 = check_relaxed_r1cs(A, B, C, z1, 1, [0], p)
    ok2 = check_relaxed_r1cs(A, B, C, z2, 1, [0], p)
    print(f"  Instance 1: z={z1}  satisfies? {ok1}")
    print(f"  Instance 2: z={z2}  satisfies? {ok2}")

    # ------------------------------------------------------------------
    print()
    print("=== Step 3: Compute cross term T ===")
    T = compute_cross_term(A, B, C, z1, 1, z2, 1, p)
    expected_T = [-(a1 - a2) ** 2 % p]
    print(f"  T = {T}")
    print(f"  Expected -(a1-a2)^2 = -({a1}-{a2})^2 = {-(a1-a2)**2} "
          f"mod {p} = {expected_T}")
    print(f"  T matches expected? {T == expected_T}")

    # ------------------------------------------------------------------
    print()
    print("=== Step 4: Nova fold with r=17, verify folded instance ===")
    r = 17
    z_fold, u_fold, E_fold, _ = nova_fold(A, B, C,
                                           z1, 1, [0],
                                           z2, 1, [0],
                                           r, p)
    print(f"  r={r}")
    print(f"  z_fold = {z_fold}  (expected [88, 30])")
    print(f"  u_fold = {u_fold}  (expected 18)")
    print(f"  E_fold = {E_fold}  (expected [33])")
    ok_fold = check_relaxed_r1cs(A, B, C, z_fold, u_fold, E_fold, p)
    print(f"  Folded instance satisfies relaxed R1CS? {ok_fold}")

    # Algebra sanity: (a1 + r*a2)^2 == (1+r)*(a1^2 + r*a2^2) + r*T_raw
    lhs_chk = pow(a1 + r * a2, 2)
    T_raw = 2 * a1 * a2 - a1 ** 2 - a2 ** 2
    rhs_chk = (1 + r) * (a1 ** 2 + r * a2 ** 2) + r * T_raw
    print(f"  Algebra check (a1+r*a2)^2 == (1+r)*(a1^2+r*a2^2)+r*T_raw? "
          f"{lhs_chk == rhs_chk}")

    # ------------------------------------------------------------------
    print()
    print("=== Step 5: Chain of 4 folds (a values 3, 5, 11, 17) ===")
    a_vals = [3, 5, 11, 17]
    r_chain = 17

    instances = [(r1cs_witness(a, p), 1, [0]) for a in a_vals]

    z_cur, u_cur, E_cur = instances[0]
    for i in range(1, len(a_vals)):
        z_next, u_next, E_next = instances[i]
        z_cur, u_cur, E_cur, _ = nova_fold(
            A, B, C,
            z_cur, u_cur, E_cur,
            z_next, u_next, E_next,
            r_chain, p,
        )
        ok_i = check_relaxed_r1cs(A, B, C, z_cur, u_cur, E_cur, p)
        print(f"  After fold {i}: z={z_cur}  u={u_cur}  E={E_cur}  valid={ok_i}")

    final_ok = check_relaxed_r1cs(A, B, C, z_cur, u_cur, E_cur, p)
    print(f"  Final folded instance satisfies relaxed R1CS? {final_ok}")


if __name__ == "__main__":
    main()
