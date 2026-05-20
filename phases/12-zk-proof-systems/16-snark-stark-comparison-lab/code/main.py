"""ZK Proof Systems Lab — Groth16 vs PLONK vs STARK (toy simulation).

Same circuit: prove x³ + x + 5 = y  (public y, private x).
Run: python3 code/main.py
"""

import hashlib
import random

MODULUS = 101  # small prime for all field arithmetic

# ---------------------------------------------------------------------------
# PART 1 — Circuit representation
# ---------------------------------------------------------------------------

def circuit_witness(x: int, p: int = MODULUS) -> dict:
    """Return {x, x2, x3, y} — the witness for x³ + x + 5 = y (mod p)."""
    x = x % p
    x2 = (x * x) % p
    x3 = (x2 * x) % p
    y = (x3 + x + 5) % p
    return {"x": x, "x2": x2, "x3": x3, "y": y}


def circuit_check(w: dict, p: int = MODULUS) -> bool:
    """Verify all 3 gate constraints.

    Gate 1 (mul): x * x = x2
    Gate 2 (mul): x2 * x = x3
    Gate 3 (lin): x3 + x + 5 = y  (PLONK-style: ql*x3 + qr*x + qc*5 - y = 0)
    """
    if (w["x"] * w["x"]) % p != w["x2"] % p:
        return False
    if (w["x2"] * w["x"]) % p != w["x3"] % p:
        return False
    if (w["x3"] + w["x"] + 5) % p != w["y"] % p:
        return False
    return True


# ---------------------------------------------------------------------------
# PART 2 — Groth16-style (structural simulation)
# ---------------------------------------------------------------------------

class Groth16SetupParams:
    """Simulated Groth16 trusted-setup parameters."""

    def __init__(self, tau_powers, alpha, beta, gamma, delta, p):
        self.tau_powers = tau_powers  # [1, tau, tau², …] length = n_gates+1
        self.alpha = alpha
        self.beta = beta
        self.gamma = gamma
        self.delta = delta
        self.p = p


class Groth16Proof:
    """A Groth16 proof: exactly 3 'group elements' (simulated in F_p)."""

    def __init__(self, A: int, B: int, C: int):
        self.A = A
        self.B = B
        self.C = C


def groth16_setup(
    n_gates: int,
    tau: int,
    alpha: int,
    beta: int,
    gamma: int,
    delta: int,
    p: int,
) -> Groth16SetupParams:
    """Simulate trusted setup.  tau is 'toxic waste' (deleted after real setup)."""
    tau_powers = [pow(tau, i, p) for i in range(n_gates + 1)]
    return Groth16SetupParams(tau_powers, alpha % p, beta % p, gamma % p, delta % p, p)


def groth16_prove(
    params: Groth16SetupParams,
    w: dict,
    y: int,
    p: int,
) -> Groth16Proof:
    """Simulate a Groth16 proof.

    In a real Groth16 the prover evaluates QAP polynomials at tau and computes
    group elements.  Here we pick a deterministic A and B from the SRS and
    compute C to satisfy the simulated verification equation:

        A * B ≡ alpha * beta + y * gamma + C * delta  (mod p)
    """
    # Deterministic A and B derived from witness + SRS to avoid randomness
    A = (params.tau_powers[0] * w["x3"] + params.tau_powers[1] * w["x2"] + 1) % p
    B = (params.tau_powers[1] * w["x"] + params.alpha + 1) % p

    # Solve for C: C*delta ≡ A*B - alpha*beta - y*gamma  (mod p)
    rhs = (A * B - params.alpha * params.beta - y * params.gamma) % p
    delta_inv = pow(params.delta, p - 2, p)
    C = rhs * delta_inv % p

    return Groth16Proof(A, B, C)


def groth16_verify(
    params: Groth16SetupParams,
    proof: Groth16Proof,
    y: int,
    p: int,
) -> bool:
    """Simulate verification.

    Real Groth16: e(A,B) = e(alpha,beta) · e(IC,gamma) · e(C,delta).
    Simulated: check A*B ≡ alpha*beta + y*gamma + C*delta (mod p).
    """
    lhs = proof.A * proof.B % p
    rhs = (params.alpha * params.beta + y * params.gamma + proof.C * params.delta) % p
    return lhs == rhs


def groth16_proof_elements(proof: Groth16Proof) -> int:
    return 3


# ---------------------------------------------------------------------------
# PART 3 — PLONK-style (structural simulation)
# ---------------------------------------------------------------------------

class PlonkProof:
    """Simulated PLONK proof (all values are field elements, commitments simulated)."""

    def __init__(
        self,
        wire_coms: list,   # 3: [a], [b], [c]
        perm_com: int,     # 1: [z]
        quot_coms: list,   # 3: t1, t2, t3
        evaluations: dict, # 6: a(z),b(z),c(z),s1(z),s2(z),z(z·w)
        opening_proofs: list,  # 2: KZG-style openings
    ):
        self.wire_coms = wire_coms
        self.perm_com = perm_com
        self.quot_coms = quot_coms
        self.evaluations = evaluations
        self.opening_proofs = opening_proofs


def plonk_setup(n_max: int, tau: int, p: int) -> dict:
    """Universal SRS: [tau^0 … tau^n_max].  Reusable across circuits."""
    srs = [pow(tau, i, p) for i in range(n_max + 1)]
    return {"srs": srs, "tau": tau % p, "p": p, "n_max": n_max}


def plonk_prove(setup: dict, w: dict, y: int, p: int) -> PlonkProof:
    """Simulate PLONK prover.

    Real PLONK: commit to wire polynomials, run permutation argument, compute
    quotient polynomial, evaluate at challenge zeta, produce KZG opening proofs.
    Here we derive all values deterministically from w and the SRS.
    """
    srs = setup["srs"]
    tau = setup["tau"]

    # Wire commitments: inner product of wire values with SRS
    a_val = w["x3"]   # left wire of gate 3
    b_val = w["x"]    # right wire of gate 3
    c_val = y         # output wire of gate 3 (public)

    com_a = (srs[0] * a_val + srs[1]) % p
    com_b = (srs[0] * b_val + srs[1]) % p
    com_c = (srs[0] * c_val + srs[1]) % p
    wire_coms = [com_a, com_b, com_c]

    # Permutation polynomial commitment
    # sigma encodes the copy constraints linking wires across gates
    perm_com = (srs[1] * (w["x2"] + 1) + srs[0]) % p

    # Quotient polynomial: t(X) = gate_poly(X) / Z_H(X)
    # Simulated: three evaluations of t split into t1, t2, t3
    gate_sat = (a_val + b_val + 5 - y) % p  # gate 3 linear constraint residual
    t1 = (srs[0] * a_val + gate_sat + 1) % p
    t2 = (srs[1] * b_val + 1) % p
    t3 = (srs[0] * c_val + srs[1]) % p
    quot_coms = [t1, t2, t3]

    # Challenge point zeta (Fiat-Shamir simulation: hash of all commitments)
    zeta_input = (
        wire_coms[0].to_bytes(4, "big")
        + wire_coms[1].to_bytes(4, "big")
        + wire_coms[2].to_bytes(4, "big")
        + perm_com.to_bytes(4, "big")
    )
    zeta = int.from_bytes(hashlib.sha256(zeta_input).digest()[:4], "big") % p

    # Evaluations at zeta.
    # In real PLONK these are polynomial evaluations; here we treat each wire
    # polynomial as the constant poly equal to its wire value, so a(zeta)=a_val
    # for all zeta.  This keeps the gate identity a(z)+b(z)+5-c(z)==0 intact.
    a_z = a_val
    b_z = b_val
    c_z = c_val
    s1_z = (srs[0] * zeta + 1) % p  # permutation selector polynomial at zeta
    s2_z = (srs[1] * zeta + 1) % p
    # z(zeta * omega): permutation accumulator evaluated one step ahead
    omega = 2
    z_zw = ((w["x2"] + 1) * (zeta * omega % p) + 1) % p
    evaluations = {
        "a_z": a_z, "b_z": b_z, "c_z": c_z,
        "s1_z": s1_z, "s2_z": s2_z, "z_zw": z_zw,
    }

    # Opening proofs: W_zeta and W_zeta_omega (KZG-style quotient commitments).
    # Simulated: (com - eval) / (tau - zeta)  mod p, matching what the verifier
    # will reconstruct from the same commitment and evaluation.
    tau_minus_zeta = (tau - zeta) % p
    zeta_inv = pow(tau_minus_zeta, p - 2, p) if tau_minus_zeta != 0 else 1
    w_zeta = ((com_a - a_z) * zeta_inv) % p
    w_zeta_omega = ((perm_com - z_zw) * zeta_inv) % p
    opening_proofs = [w_zeta, w_zeta_omega]

    return PlonkProof(wire_coms, perm_com, quot_coms, evaluations, opening_proofs)


def plonk_verify(setup: dict, proof: PlonkProof, y: int, p: int) -> bool:
    """Simulate PLONK verify.

    Real PLONK: 2 pairing checks + scalar field arithmetic.
    Simulated: recompute challenge zeta and check the gate polynomial identity.
    """
    srs = setup["srs"]

    # Recompute zeta exactly as prover did
    zeta_input = (
        proof.wire_coms[0].to_bytes(4, "big")
        + proof.wire_coms[1].to_bytes(4, "big")
        + proof.wire_coms[2].to_bytes(4, "big")
        + proof.perm_com.to_bytes(4, "big")
    )
    zeta = int.from_bytes(hashlib.sha256(zeta_input).digest()[:4], "big") % p

    ev = proof.evaluations

    # Gate 3 identity at zeta: ql*a(z) + qr*b(z) + qc*5 - c(z) == 0  (mod p)
    # ql = qr = qc = 1 for our linear gate
    gate_check = (ev["a_z"] + ev["b_z"] + 5 - ev["c_z"]) % p

    # Opening consistency check: W_zeta should relate com_a to a(zeta)
    tau = setup["tau"]
    zeta_inv = pow((tau - zeta) % p, p - 2, p) if (tau - zeta) % p != 0 else 1
    expected_w_zeta = ((proof.wire_coms[0] - ev["a_z"]) * zeta_inv) % p

    return gate_check == 0 and expected_w_zeta == proof.opening_proofs[0]


def plonk_proof_elements(proof: PlonkProof) -> int:
    return (
        len(proof.wire_coms)
        + 1  # perm_com
        + len(proof.quot_coms)
        + len(proof.evaluations)
        + len(proof.opening_proofs)
    )


# ---------------------------------------------------------------------------
# PART 4 — STARK-style (hash-based, no trusted setup)
# ---------------------------------------------------------------------------

class StarkProof:
    """Simulated STARK proof: all commitment material is hash-based."""

    def __init__(
        self,
        trace_root: bytes,
        constraint_root: bytes,
        fri_layer_roots: list,
        query_responses: list,
    ):
        self.trace_root = trace_root
        self.constraint_root = constraint_root
        self.fri_layer_roots = fri_layer_roots    # list[bytes]
        self.query_responses = query_responses     # list[bytes]


def _sha256b(*parts: bytes) -> bytes:
    return hashlib.sha256(b"".join(parts)).digest()


def int_to_bytes(x: int) -> bytes:
    return x.to_bytes(4, "big")


def stark_prove(w: dict, y: int, p: int) -> StarkProof:
    """No trusted setup.  Commit to execution trace, simulate FRI layers."""
    # --- Execution trace (4 registers: x, x2, x3, y) ---
    trace = [w["x"], w["x2"], w["x3"], w["y"]]
    trace_leaves = [_sha256b(b"\x00", int_to_bytes(v)) for v in trace]
    trace_root = _sha256b(b"\x01", *trace_leaves)

    # --- Constraint evaluations (one per gate) ---
    c1 = (w["x"] * w["x"] - w["x2"]) % p   # gate 1: x*x - x2
    c2 = (w["x2"] * w["x"] - w["x3"]) % p  # gate 2: x2*x - x3
    c3 = (w["x3"] + w["x"] + 5 - w["y"]) % p  # gate 3: linear
    constraints = [c1, c2, c3]
    constr_leaves = [_sha256b(b"\x00", int_to_bytes(v)) for v in constraints]
    constraint_root = _sha256b(b"\x01", *constr_leaves)

    # --- FRI simulation: 3 layers (log2(8) = 3 for an 8-element domain) ---
    # Each layer is a hash of the previous root folded with a channel challenge
    channel = _sha256b(trace_root, constraint_root)
    fri_layer_roots = []
    current = channel
    for i in range(3):
        layer_root = _sha256b(b"\x02", current, i.to_bytes(1, "big"))
        fri_layer_roots.append(layer_root)
        current = layer_root

    # --- Query responses (security_param=2 queries × log2(8)=3 hashes each) ---
    query_responses = []
    for q in range(2):
        for depth in range(3):
            resp = _sha256b(
                b"\x03",
                fri_layer_roots[depth],
                q.to_bytes(1, "big"),
                depth.to_bytes(1, "big"),
            )
            query_responses.append(resp)

    return StarkProof(trace_root, constraint_root, fri_layer_roots, query_responses)


def stark_verify(proof: StarkProof, y: int, p: int) -> bool:
    """Hash-only verification: check structural consistency and FRI chain."""
    # All roots must be 32-byte digests
    if len(proof.trace_root) != 32:
        return False
    if len(proof.constraint_root) != 32:
        return False
    if len(proof.fri_layer_roots) != 3:
        return False
    if len(proof.query_responses) != 6:
        return False

    # Recompute FRI channel and verify layer chain
    channel = _sha256b(proof.trace_root, proof.constraint_root)
    current = channel
    for i, layer_root in enumerate(proof.fri_layer_roots):
        expected = _sha256b(b"\x02", current, i.to_bytes(1, "big"))
        if layer_root != expected:
            return False
        current = layer_root

    # Verify query responses
    for q in range(2):
        for depth in range(3):
            idx = q * 3 + depth
            expected = _sha256b(
                b"\x03",
                proof.fri_layer_roots[depth],
                q.to_bytes(1, "big"),
                depth.to_bytes(1, "big"),
            )
            if proof.query_responses[idx] != expected:
                return False

    return True


def stark_proof_elements(proof: StarkProof) -> int:
    """Count hash values (each 32 bytes) in proof."""
    return (
        1  # trace_root
        + 1  # constraint_root
        + len(proof.fri_layer_roots)
        + len(proof.query_responses)
    )


# ---------------------------------------------------------------------------
# PART 5 — main() — run all three systems and print comparison table
# ---------------------------------------------------------------------------

def main():
    p = MODULUS
    x = 3

    print("=== ZK Proof Systems Lab — Groth16 vs PLONK vs STARK ===")
    print()

    # --- Circuit ---
    print("=== Step 1: Circuit witness for x =", x, "===")
    w = circuit_witness(x, p)
    print(f"  x={w['x']}, x2={w['x2']}, x3={w['x3']}, y={w['y']}")
    print(f"  circuit_check (valid witness):   {circuit_check(w, p)}")
    w_bad = dict(w)
    w_bad["y"] = (w["y"] + 1) % p
    print(f"  circuit_check (y+1, invalid):    {circuit_check(w_bad, p)}")
    print()

    # --- Groth16 ---
    print("=== Step 2: Groth16 (circuit-specific trusted setup) ===")
    tau, alpha, beta, gamma, delta = 7, 11, 13, 17, 19
    g16_params = groth16_setup(3, tau, alpha, beta, gamma, delta, p)
    g16_proof = groth16_prove(g16_params, w, w["y"], p)
    g16_ok = groth16_verify(g16_params, g16_proof, w["y"], p)
    print(f"  A={g16_proof.A}, B={g16_proof.B}, C={g16_proof.C}")
    print(f"  proof elements: {groth16_proof_elements(g16_proof)}")
    print(f"  verify (honest proof): {g16_ok}")
    print(f"  SRS size: {len(g16_params.tau_powers)} field elements (O(n_gates))")
    print()

    # --- PLONK ---
    print("=== Step 3: PLONK (universal trusted setup) ===")
    plonk_srs = plonk_setup(8, tau, p)
    plonk_proof = plonk_prove(plonk_srs, w, w["y"], p)
    plonk_ok = plonk_verify(plonk_srs, plonk_proof, w["y"], p)
    plonk_elems = plonk_proof_elements(plonk_proof)
    print(f"  wire_coms:   {plonk_proof.wire_coms}")
    print(f"  perm_com:    {plonk_proof.perm_com}")
    print(f"  quot_coms:   {plonk_proof.quot_coms}")
    print(f"  evaluations: {plonk_proof.evaluations}")
    print(f"  openings:    {plonk_proof.opening_proofs}")
    print(f"  proof elements: {plonk_elems}  (wire_coms=3, perm=1, quot=3, evals=6, openings=2)")
    print(f"  verify (honest proof): {plonk_ok}")
    print(f"  SRS size: {len(plonk_srs['srs'])} field elements (O(n_max), universal)")
    print()

    # --- STARK ---
    print("=== Step 4: STARK (no trusted setup, hash-based) ===")
    stark_proof = stark_prove(w, w["y"], p)
    stark_ok = stark_verify(stark_proof, w["y"], p)
    stark_elems = stark_proof_elements(stark_proof)
    print(f"  trace_root:       {stark_proof.trace_root.hex()[:16]}...")
    print(f"  constraint_root:  {stark_proof.constraint_root.hex()[:16]}...")
    print(f"  fri_layer_roots:  {len(stark_proof.fri_layer_roots)} hashes")
    print(f"  query_responses:  {len(stark_proof.query_responses)} hashes")
    print(f"  proof elements (hash values): {stark_elems}")
    print(f"  verify (honest proof): {stark_ok}")
    print()

    # --- Comparison table ---
    print("=== Comparison Table ===")
    header = f"{'System':<10} {'Setup':<22} {'Setup size':<14} {'Proof size':<16} {'Assumptions':<22} {'PQ-safe':<10} {'Verify cost'}"
    print(header)
    print("-" * len(header))
    rows = [
        ("Groth16", "Circuit-specific", "O(n) SRS",    f"{groth16_proof_elements(g16_proof)} elements",  "DL + pairing",  "No",  "O(1) pairings"),
        ("PLONK",   "Universal",        "O(n) SRS",    f"{plonk_elems} elements",                         "DL + pairing",  "No",  "O(1)+O(log n)"),
        ("STARK",   "None",             "0 (transparent)", f"{stark_elems} hashes (O(log²n))",             "Hash only",     "Yes", "O(log²n)"),
    ]
    for r in rows:
        print(f"{r[0]:<10} {r[1]:<22} {r[2]:<14} {r[3]:<16} {r[4]:<22} {r[5]:<10} {r[6]}")
    print()

    print("Key trade-offs:")
    print("  Groth16 — smallest proof (3 elements), but circuit-specific ceremony required.")
    print("  PLONK   — universal setup amortises cost, slightly larger proof (~15 elements).")
    print("  STARK   — no trusted setup, post-quantum safe, but proof is larger (O(log²n) hashes).")


if __name__ == "__main__":
    main()
