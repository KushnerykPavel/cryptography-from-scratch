"""
Anonymous Credentials — BBS+ (educational toy over Z_p).

Implements a simplified BBS+ credential scheme that captures the algebraic
structure of the real protocol:

  P = 2^127 - 1  (Mersenne prime, prime-order group)
  G = 3           (generator of a multiplicative subgroup of Z_P*)

  Key generation:
    sk  = random scalar in Z_P
    pk  = G^sk mod P

  Sign (messages m_1 ... m_L, each an integer in Z_P):
    e, s = fixed/random scalars
    B    = G * H_0^s * H_1^m_1 * ... * H_L^m_L  (all mod P)
    A    = B^(1/(e+sk) mod (P-1))  mod P          (BBS+ "A" component)
    sig  = (A, e, s)

  Verify (with issuer sk, toy simplification — real BBS+ uses bilinear pairings):
    Recompute B from messages, check A^(e+sk) mod P == B

  Selective disclosure proof:
    Prover reveals a subset of messages.  For hidden messages the prover
    supplies their individual commitments (H_i^m_i mod P) so the verifier
    can reconstruct B without learning the hidden values.

NOTE: This is a TOY model. Production BBS+ uses bilinear pairings on BLS12-381
so that verification does NOT require the issuer secret key.  That property
(called "signer-independent verification") is the whole point of BBS+.
Here we explicitly note where the pairing would be used and verify with sk
so the algebraic relationships remain visible.

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib
import math


# ---------------------------------------------------------------------------
# Group parameters
# ---------------------------------------------------------------------------

P = (1 << 127) - 1   # Mersenne prime 2^127 - 1
G = 3                 # generator


# ---------------------------------------------------------------------------
# Arithmetic helpers
# ---------------------------------------------------------------------------

def _modinv(a: int, m: int) -> int:
    """Modular inverse of a mod m (m must be prime for Fermat's little theorem)."""
    return pow(a, m - 2, m)


def _generators(L: int) -> list[int]:
    """
    Return L+1 fixed generators [H_0, H_1, ..., H_L] in Z_P*.

    H_i = G^(i+1) mod P — deterministic and publicly known.
    H_0 is the blinding generator; H_1..H_L are the message generators.
    """
    return [pow(G, i + 1, P) for i in range(L + 1)]


def _compute_B(s: int, messages: list[int], hs: list[int]) -> int:
    """
    Compute the message commitment B:
      B = G * H_0^s * H_1^m_1 * ... * H_L^m_L  mod P
    """
    acc = G % P
    acc = acc * pow(hs[0], s, P) % P
    for i, m in enumerate(messages):
        acc = acc * pow(hs[i + 1], m, P) % P
    return acc


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def bbs_setup(num_attrs: int) -> dict:
    """
    Generate public parameters for a BBS+ credential with num_attrs attributes.

    Returns a dict with keys:
      P          — group prime
      G          — group generator
      generators — list of L+1 integers [H_0, H_1, ..., H_L]
      num_attrs  — L
    """
    hs = _generators(num_attrs)
    return {"P": P, "G": G, "generators": hs, "num_attrs": num_attrs}


def bbs_keygen() -> tuple[int, int]:
    """
    Generate a BBS+ issuer key pair.

    Returns (sk, pk) where pk = G^sk mod P.
    The secret key sk is fixed for deterministic test vectors.
    """
    sk = 0x1234567890abcdef1234567890abcdef % (P - 1)
    pk = pow(G, sk, P)
    return sk, pk


def bbs_sign(sk: int, messages: list[int]) -> tuple[int, int, int]:
    """
    Sign a vector of integer messages with the issuer secret key.

    Parameters
    ----------
    sk        : issuer secret key (integer in Z_P)
    messages  : list of L integer attribute values (each in Z_P)

    Returns (A, e, s) where:
      e, s are random-looking scalars (fixed here for determinism)
      B    = G * H_0^s * prod(H_i^m_i)  mod P
      A    = B^(1/(e+sk) mod (P-1))      mod P

    NOTE: In production the exponent inverse is taken modulo the group order.
    Here P is prime so |Z_P*| = P-1 and we invert modulo P-1.
    We require gcd(e+sk, P-1) == 1; the fixed constants below satisfy this
    (verified at module load time).
    """
    L = len(messages)
    hs = _generators(L)

    # Fixed scalars for determinism; in production these would be random.
    # e = 0xfedcba9876543212 chosen so gcd(e+sk, P-1)==1 for the demo sk.
    e = 0xfedcba9876543212 % (P - 1)
    s = 0x0123456789abcdef % (P - 1)

    B = _compute_B(s, messages, hs)

    # A = B^(1/(e+sk)) mod P  — requires gcd(e+sk, P-1) == 1
    exp_val = (e + sk) % (P - 1)
    assert math.gcd(exp_val, P - 1) == 1, (
        f"gcd(e+sk, P-1) = {math.gcd(exp_val, P-1)} != 1; "
        "cannot invert — choose different e or sk"
    )
    exp_inv = pow(exp_val, -1, P - 1)
    A = pow(B, exp_inv, P)
    return A, e, s


def bbs_verify(sk: int, messages: list[int], sig: tuple[int, int, int]) -> bool:
    """
    Verify a BBS+ signature against all messages.

    TOY SIMPLIFICATION: real BBS+ verification uses a bilinear pairing:
      e(A, W * G^e) == e(B, G)   where W = G^sk (the public key)
    Without an elliptic-curve pairing library we verify by checking:
      A^(e+sk) mod P == B
    This requires the issuer secret key and is here only to show the math.

    Returns True iff the signature is valid.
    """
    A, e, s = sig
    L = len(messages)
    hs = _generators(L)
    B = _compute_B(s, messages, hs)
    return pow(A, (e + sk) % (P - 1), P) == B


def bbs_create_proof(
    messages: list[int],
    sig: tuple[int, int, int],
    revealed: list[int],
) -> dict:
    """
    Create a selective-disclosure proof that reveals only the messages at
    `revealed` indices, hiding the rest.

    The prover:
    1. Passes through (A, e, s) unchanged (in real BBS+ these are randomised
       via a ZK proof of knowledge; here we keep them for clarity).
    2. For each hidden index i, computes the partial commitment C_i = H_{i+1}^m_i mod P.
    3. Provides revealed message values in plain.

    The verifier can reconstruct B = G * H_0^s * prod(revealed) * prod(hidden C_i)
    and check the signature without learning the hidden message values.

    Returns a proof dict.
    """
    A, e, s = sig
    L = len(messages)
    hs = _generators(L)

    hidden_commitments: dict[int, int] = {}
    for i in range(L):
        if i not in revealed:
            hidden_commitments[i] = pow(hs[i + 1], messages[i], P)

    revealed_messages: dict[int, int] = {i: messages[i] for i in revealed}

    return {
        "A": A,
        "e": e,
        "s": s,
        "revealed_messages": revealed_messages,
        "hidden_commitments": hidden_commitments,
        "num_attrs": L,
    }


def bbs_verify_proof(sk: int, proof: dict) -> bool:
    """
    Verify a selective-disclosure proof.

    Reconstructs B from the revealed messages and hidden commitments, then
    checks the signature equation A^(e+sk) == B.

    In production BBS+ the pairing check replaces the sk-dependent check here.
    """
    A = proof["A"]
    e = proof["e"]
    s = proof["s"]
    revealed: dict[int, int] = proof["revealed_messages"]
    hidden: dict[int, int] = proof["hidden_commitments"]
    L: int = proof["num_attrs"]
    hs = _generators(L)

    # Reconstruct B
    B = G % P
    B = B * pow(hs[0], s, P) % P
    # Revealed attributes: use message values directly
    for i, m in revealed.items():
        B = B * pow(hs[i + 1], m, P) % P
    # Hidden attributes: use pre-committed values
    for _, c in hidden.items():
        B = B * c % P

    return pow(A, (e + sk) % (P - 1), P) == B


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hx(n: int) -> str:
    return hex(n)


# ---------------------------------------------------------------------------
# main — demo walkthrough
# ---------------------------------------------------------------------------

def main() -> None:
    print("=== Step 1: BBS+ Setup — Group Parameters ===")
    num_attrs = 4
    params = bbs_setup(num_attrs)
    print(f"P (prime)  = {P}")
    print(f"G (gen)    = {G}")
    print(f"Generators = {params['generators']}")
    print()

    print("=== Step 2: Key Generation ===")
    sk, pk = bbs_keygen()
    print(f"sk = {_hx(sk)}")
    print(f"pk = G^sk mod P = {pk}")
    print()

    print("=== Step 3: Sign Credential (4 attributes) ===")
    messages = [42, 1337, 2024, 99]
    print(f"messages = {messages}  (e.g. age=42, id=1337, year=2024, score=99)")
    A, e, s = bbs_sign(sk, messages)
    sig = (A, e, s)
    print(f"A  = {_hx(A)}")
    print(f"e  = {_hx(e)}")
    print(f"s  = {_hx(s)}")
    print()

    print("=== Step 4: Verify Full Signature ===")
    valid = bbs_verify(sk, messages, sig)
    print(f"bbs_verify(sk, messages, sig) = {valid}")
    tampered = bbs_verify(sk, [42, 1337, 2024, 100], sig)
    print(f"tampered score=100 => verify = {tampered}")
    print()

    print("=== Step 5: Selective Disclosure Proof ===")
    # Reveal only age (0) and year (2); hide id (1) and score (3)
    revealed_indices = [0, 2]
    proof = bbs_create_proof(messages, sig, revealed_indices)
    print(f"Revealed indices: {revealed_indices}  (age={messages[0]}, year={messages[2]})")
    print(f"Hidden indices:   [1, 3]  (id and score not disclosed)")
    print(f"Hidden commitments: {proof['hidden_commitments']}")
    print()

    print("=== Step 6: Verify Selective Disclosure Proof ===")
    ok = bbs_verify_proof(sk, proof)
    print(f"bbs_verify_proof(sk, proof) = {ok}")

    # Tamper: change revealed age from 42 to 43
    bad_proof = dict(proof)
    bad_proof["revealed_messages"] = dict(proof["revealed_messages"])
    bad_proof["revealed_messages"][0] = 43
    bad_ok = bbs_verify_proof(sk, bad_proof)
    print(f"tampered age=43 in proof => verify = {bad_ok}")
    print()

    print("=== Step 7: Multi-message Credential Binding ===")
    # Show that signing different attribute sets produces different signatures
    msgs_a = [1, 2, 3]
    msgs_b = [1, 2, 4]
    sigA = bbs_sign(sk, msgs_a)
    sigB = bbs_sign(sk, msgs_b)
    print(f"sig for [1,2,3]: A={_hx(sigA[0])}")
    print(f"sig for [1,2,4]: A={_hx(sigB[0])}")
    print(f"Signatures differ: {sigA[0] != sigB[0]}")


if __name__ == "__main__":
    main()
