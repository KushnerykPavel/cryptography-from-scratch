"""
ZK Voting System — educational implementation.

Run:
  python3 code/main.py

This capstone builds a simplified private e-voting system using:
  - ElGamal encryption over a prime-order subgroup (homomorphic tally)
  - Disjunctive Schnorr or-proof with Fiat-Shamir to prove each vote is in {0, 1}
  - A bulletin board of encrypted votes
  - Homomorphic addition of ciphertexts, then a single threshold-style decryption

Group parameters: p=1019 (safe prime), q=509 (subgroup order), g=4 (generator).
These are intentionally small so the brute-force tally decode runs instantly.
Real systems use ≥2048-bit (DH) or 256-bit (EC) groups.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import List, Optional, Tuple


# ---------------------------------------------------------------------------
# Group parameters
# p = 2*q + 1, both prime (safe prime).  g = 4 generates the order-q subgroup.
# g = 2^2 mod p; every quadratic residue mod a safe prime has order q or 1.
# ---------------------------------------------------------------------------
P: int = 1019   # safe prime
Q: int = 509    # subgroup order  (p = 2*Q + 1)
G: int = 4      # generator of the order-Q subgroup (G = 2^2 mod P)

# Sanity checks (run once at import time)
assert (P - 1) // 2 == Q
assert pow(G, Q, P) == 1
assert G != 1

MAX_VOTERS: int = 1000  # upper bound for brute-force tally decode


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def _modinv(a: int, m: int) -> int:
    """Modular inverse via Fermat (m must be prime)."""
    return pow(a, m - 2, m)


def _sha256_int(*parts: object) -> int:
    """Hash arbitrary objects into a non-negative integer (Fiat-Shamir oracle)."""
    h = hashlib.sha256()
    for part in parts:
        h.update(str(part).encode())
        h.update(b"|")
    return int(h.hexdigest(), 16)


# ---------------------------------------------------------------------------
# ElGamal key generation
# ---------------------------------------------------------------------------

def keygen() -> Tuple[int, int]:
    """Return (private_key x, public_key h) where h = G^x mod P."""
    x = secrets.randbelow(Q - 1) + 1   # x in [1, Q-1]
    h = pow(G, x, P)
    return x, h


# ---------------------------------------------------------------------------
# ElGamal encryption / decryption
# ---------------------------------------------------------------------------

@dataclass
class Ciphertext:
    """An ElGamal ciphertext (C1, C2) = (G^r, h^r * G^vote)."""
    c1: int
    c2: int


def elgamal_encrypt(vote: int, pk: int, r: Optional[int] = None) -> Tuple[Ciphertext, int]:
    """
    Encrypt a vote (0 or 1) under public key pk.

    Returns (ciphertext, randomness r) so callers can reproduce the ciphertext
    for proofs.  If r is None, a fresh random r is drawn.
    """
    if vote not in (0, 1):
        raise ValueError("vote must be 0 or 1")
    if r is None:
        r = secrets.randbelow(Q - 1) + 1
    c1 = pow(G, r, P)
    c2 = (pow(pk, r, P) * pow(G, vote, P)) % P
    return Ciphertext(c1, c2), r


def elgamal_decrypt(ct: Ciphertext, sk: int, max_tally: int = MAX_VOTERS) -> int:
    """
    Decrypt an ElGamal ciphertext using secret key sk.

    Recovers G^v from the ciphertext, then brute-forces v in [0, max_tally].
    Returns the plaintext integer or raises ValueError if not in range.
    """
    s = pow(ct.c1, sk, P)
    s_inv = _modinv(s, P)
    gv = (ct.c2 * s_inv) % P
    for v in range(max_tally + 1):
        if pow(G, v, P) == gv:
            return v
    raise ValueError(f"decrypted G^v not found in [0, {max_tally}]")


# ---------------------------------------------------------------------------
# Homomorphic tally
# ---------------------------------------------------------------------------

def homomorphic_tally(ciphertexts: List[Ciphertext]) -> Ciphertext:
    """
    Multiply all ciphertexts component-wise.

    Because Enc(v1) * Enc(v2) = Enc(v1 + v2) under ElGamal, the product
    is an encryption of the sum of votes.  Decrypting this single ciphertext
    reveals the tally without revealing any individual vote.
    """
    if not ciphertexts:
        raise ValueError("need at least one ciphertext")
    tc1 = 1
    tc2 = 1
    for ct in ciphertexts:
        tc1 = (tc1 * ct.c1) % P
        tc2 = (tc2 * ct.c2) % P
    return Ciphertext(tc1, tc2)


# ---------------------------------------------------------------------------
# Disjunctive Schnorr or-proof: vote in {0, 1}
# ---------------------------------------------------------------------------
# The prover shows that the ciphertext encrypts 0 OR 1 without revealing which.
#
# Proof structure (Chaum-Pedersen disjunctive, Cramer et al. 1994):
#   For vote=0: C2 = h^r                (i.e. C2 / G^0 = h^r)
#   For vote=1: C2 / G = h^r            (i.e. C2 / G^1 = h^r)
#
# We prove knowledge of r such that:
#   (C1 = G^r  AND  C2 = h^r)    -- branch for vote=0
# OR
#   (C1 = G^r  AND  C2/G = h^r)  -- branch for vote=1
#
# The proof is a sigma-protocol composed with the "or" trick (Cramer et al.):
#   - Simulate the false branch first (pick c_false, z_false at random)
#   - Compute the real commitment with a fresh nonce k
#   - Apply Fiat-Shamir: c_total = H(params, ct, A0, B0, A1, B1)
#   - Set c_real = c_total - c_false mod Q
#   - Respond: z_real = k + c_real * r mod Q
#
# Branches are always stored in canonical order (v=0 first, v=1 second)
# so the verifier is symmetric.
# ---------------------------------------------------------------------------

@dataclass
class OrProof:
    """
    Disjunctive (or) proof that a ciphertext encrypts 0 or 1.

    Fields use canonical ordering: branch 0 (vote=0) always first.
    """
    # Commitments
    a0: int   # G^k for branch 0
    b0: int   # h^k for branch 0
    a1: int   # G^k for branch 1
    b1: int   # h^k for branch 1
    # Challenges
    c0: int
    c1: int
    # Responses
    z0: int
    z1: int


def prove_vote(ct: Ciphertext, vote: int, r: int, pk: int) -> OrProof:
    """
    Construct a disjunctive or-proof that ct encrypts vote in {0, 1}.

    Parameters
    ----------
    ct   : Ciphertext  -- the ElGamal ciphertext
    vote : int         -- the actual vote (0 or 1); kept secret by the proof
    r    : int         -- the randomness used when encrypting
    pk   : int         -- the public key h = G^x
    """
    if vote not in (0, 1):
        raise ValueError("vote must be 0 or 1")

    # C2 adjusted for each branch:
    #   branch 0: target = C2 / G^0 = C2
    #   branch 1: target = C2 / G^1 = C2 * G^{-1}
    c2_b0 = ct.c2
    c2_b1 = (ct.c2 * _modinv(G, P)) % P

    # Simulated challenge and response for the false branch
    c_false = secrets.randbelow(Q)
    z_false = secrets.randbelow(Q)

    # Commitment for real branch (random nonce k)
    k = secrets.randbelow(Q - 1) + 1
    a_real = pow(G, k, P)
    b_real = pow(pk, k, P)

    # Simulated commitment for false branch (back-compute from c_false, z_false):
    #   a_false = G^z_false * C1^{-c_false}
    #   b_false = h^z_false * target^{-c_false}
    if vote == 0:
        # Real branch: v=0.  False branch: v=1.
        target_false = c2_b1
        a_false = (pow(G, z_false, P) * pow(ct.c1, Q - c_false, P)) % P
        b_false = (pow(pk, z_false, P) * pow(target_false, Q - c_false, P)) % P

        # Commitments in canonical order (v=0 real, v=1 simulated)
        a0, b0 = a_real, b_real
        a1, b1 = a_false, b_false
    else:
        # Real branch: v=1.  False branch: v=0.
        target_false = c2_b0
        a_false = (pow(G, z_false, P) * pow(ct.c1, Q - c_false, P)) % P
        b_false = (pow(pk, z_false, P) * pow(target_false, Q - c_false, P)) % P

        # Commitments in canonical order (v=0 simulated, v=1 real)
        a0, b0 = a_false, b_false
        a1, b1 = a_real, b_real

    # Fiat-Shamir: c_total = H(P, G, pk, C1, C2, a0, b0, a1, b1)
    c_total = _sha256_int(P, G, pk, ct.c1, ct.c2, a0, b0, a1, b1) % Q

    # Real challenge = c_total - c_false mod Q
    c_real = (c_total - c_false) % Q

    # Real response: z_real = k + c_real * r mod Q
    z_real = (k + c_real * r) % Q

    if vote == 0:
        return OrProof(a0=a0, b0=b0, a1=a1, b1=b1, c0=c_real, c1=c_false, z0=z_real, z1=z_false)
    else:
        return OrProof(a0=a0, b0=b0, a1=a1, b1=b1, c0=c_false, c1=c_real, z0=z_false, z1=z_real)


def verify_vote_proof(ct: Ciphertext, proof: OrProof, pk: int) -> bool:
    """
    Verify that ct encrypts either 0 or 1, given the or-proof.

    Returns True iff the proof is valid.
    """
    # Adjusted ciphertexts for each branch
    c2_b0 = ct.c2
    c2_b1 = (ct.c2 * _modinv(G, P)) % P

    # Recompute Fiat-Shamir challenge
    c_total = _sha256_int(P, G, pk, ct.c1, ct.c2, proof.a0, proof.b0, proof.a1, proof.b1) % Q

    # Challenge consistency: c0 + c1 = c_total mod Q
    if (proof.c0 + proof.c1) % Q != c_total % Q:
        return False

    # Branch 0 (vote=0): G^z0 = a0 * C1^c0   and   h^z0 = b0 * C2^c0
    lhs0_a = pow(G, proof.z0, P)
    rhs0_a = (proof.a0 * pow(ct.c1, proof.c0, P)) % P
    if lhs0_a != rhs0_a:
        return False

    lhs0_b = pow(pk, proof.z0, P)
    rhs0_b = (proof.b0 * pow(c2_b0, proof.c0, P)) % P
    if lhs0_b != rhs0_b:
        return False

    # Branch 1 (vote=1): G^z1 = a1 * C1^c1   and   h^z1 = b1 * (C2/G)^c1
    lhs1_a = pow(G, proof.z1, P)
    rhs1_a = (proof.a1 * pow(ct.c1, proof.c1, P)) % P
    if lhs1_a != rhs1_a:
        return False

    lhs1_b = pow(pk, proof.z1, P)
    rhs1_b = (proof.b1 * pow(c2_b1, proof.c1, P)) % P
    if lhs1_b != rhs1_b:
        return False

    return True


# ---------------------------------------------------------------------------
# Bulletin board
# ---------------------------------------------------------------------------

@dataclass
class BallotEntry:
    """One row on the public bulletin board."""
    voter_id: str
    ct: Ciphertext
    proof: OrProof


def submit_ballot(
    board: List[BallotEntry],
    voter_id: str,
    vote: int,
    pk: int,
) -> BallotEntry:
    """
    Encrypt vote and attach a validity proof, then append to the bulletin board.
    Returns the ballot entry (for inspection in demos).
    """
    ct, r = elgamal_encrypt(vote, pk)
    proof = prove_vote(ct, vote, r, pk)
    entry = BallotEntry(voter_id=voter_id, ct=ct, proof=proof)
    board.append(entry)
    return entry


def verify_board(board: List[BallotEntry], pk: int) -> bool:
    """Return True iff every ballot on the board has a valid or-proof."""
    return all(verify_vote_proof(entry.ct, entry.proof, pk) for entry in board)


# ---------------------------------------------------------------------------
# Main demo
# ---------------------------------------------------------------------------

def main() -> None:
    print("=== Step 1: Group setup ===")
    print(f"  p = {P}  (safe prime, p = 2*q + 1)")
    print(f"  q = {Q}  (prime subgroup order)")
    print(f"  g = {G}  (generator of order-q subgroup)")
    print(f"  Note: p is 10 bits — real systems use >=2048 bits")

    print("=== Step 2: Key generation ===")
    sk, pk = keygen()
    print(f"  private key x = {sk}")
    print(f"  public  key h = g^x mod p = {pk}")

    print("=== Step 3: Three voters cast ballots ===")
    # Votes: Alice=1, Bob=0, Carol=1 → expected tally = 2
    votes = [("Alice", 1), ("Bob", 0), ("Carol", 1)]
    board: List[BallotEntry] = []

    for voter_id, vote in votes:
        entry = submit_ballot(board, voter_id, vote, pk)
        print(f"  {voter_id} voted {vote}: C1={entry.ct.c1}, C2={entry.ct.c2}")

    print("=== Step 4: Verify all proofs on bulletin board ===")
    for entry in board:
        ok = verify_vote_proof(entry.ct, entry.proof, pk)
        print(f"  {entry.voter_id}: proof valid = {ok}")
    all_ok = verify_board(board, pk)
    print(f"  All proofs valid: {all_ok}")

    print("=== Step 5: Homomorphic tally ===")
    tally_ct = homomorphic_tally([e.ct for e in board])
    print(f"  Tally ciphertext: C1={tally_ct.c1}, C2={tally_ct.c2}")
    tally_result = elgamal_decrypt(tally_ct, sk, max_tally=len(board))
    print(f"  Tally = {tally_result}  (expected: 2 = 1+0+1)")

    print("=== Step 6: Reject a tampered ballot ===")
    # Construct a ciphertext for vote=2 directly (bypassing the vote-validity guard)
    bad_r = 3
    bad_c1 = pow(G, bad_r, P)
    bad_c2 = (pow(pk, bad_r, P) * pow(G, 2, P)) % P
    bad_ct = Ciphertext(bad_c1, bad_c2)
    # Build a valid proof for vote=0 with the same r (legit ciphertext differs from bad_ct)
    legit_ct, legit_r = elgamal_encrypt(0, pk, r=bad_r)
    legit_proof = prove_vote(legit_ct, 0, legit_r, pk)
    # Transplanting the legit proof onto bad_ct must fail
    forged_result = verify_vote_proof(bad_ct, legit_proof, pk)
    print(f"  Forged ballot (vote=2 with transplanted proof) accepted: {forged_result}  (expected: False)")


if __name__ == "__main__":
    main()
