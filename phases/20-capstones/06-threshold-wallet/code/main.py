"""
Threshold wallet demo (educational).

Run:
  python3 code/main.py

This capstone builds a threshold (t-of-n) wallet from scratch:
1. Shamir secret sharing over Z_q
2. Distributed Key Generation (DKG): parties collaboratively generate a keypair
   where no single party holds the full private key
3. Threshold Schnorr signing: t parties sign a message without reconstructing the key
4. A 3-of-5 wallet demo signing a simulated transaction
"""

from __future__ import annotations

import hashlib
import json
import math
import random
import secrets
from dataclasses import dataclass, field
from typing import List, Tuple

# ---------------------------------------------------------------------------
# Group parameters
# p = 2063 is a safe prime: p = 2q + 1, q = 1031 (also prime)
# g = 4 = 2^((p-1)/q) mod p has order q in Z_p
# All cryptographic values live in Z_q; public keys/commitments live in Z_p
# ---------------------------------------------------------------------------
P = 2063   # safe prime
Q = 1031   # Sophie Germain prime: (P-1)//2
G = 4      # generator of order Q in Z_P


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def mod_inv(a: int, m: int) -> int:
    return pow(a, -1, m)


def hash_int(*parts: object) -> int:
    """Hash arbitrary integer/bytes/str parts to an integer mod Q."""
    h = hashlib.sha256()
    for part in parts:
        if isinstance(part, int):
            h.update(part.to_bytes(8, "big"))
        elif isinstance(part, bytes):
            h.update(part)
        elif isinstance(part, str):
            h.update(part.encode())
        else:
            raise TypeError(f"hash_int: unsupported type {type(part)}")
    return int(h.hexdigest(), 16) % Q


# ---------------------------------------------------------------------------
# Step 1: Shamir Secret Sharing
# ---------------------------------------------------------------------------

def _eval_poly(coeffs: List[int], x: int, q: int) -> int:
    """Evaluate polynomial with given coefficients at x, mod q (Horner's method)."""
    result = 0
    for c in reversed(coeffs):
        result = (result * x + c) % q
    return result


def share_secret(
    secret: int, t: int, n: int, rng_seed: int | None = None
) -> List[Tuple[int, int]]:
    """
    Split secret into n Shamir shares with threshold t.

    Returns list of (party_index, share_value) pairs for indices 1..n.
    The polynomial f has degree t-1 with f(0) = secret; any t shares reconstruct.
    """
    if not (1 <= t <= n):
        raise ValueError(f"need 1 <= t <= n, got t={t}, n={n}")
    if not (0 <= secret < Q):
        raise ValueError(f"secret must be in [0, Q); got {secret}")

    rng = random.Random(rng_seed)
    coeffs = [secret] + [rng.randrange(1, Q) for _ in range(t - 1)]
    return [(i, _eval_poly(coeffs, i, Q)) for i in range(1, n + 1)]


def lagrange_coeff(i: int, others: List[int], q: int) -> int:
    """Lagrange basis coefficient for index i given the set of all indices."""
    num, den = 1, 1
    for j in others:
        if j == i:
            continue
        num = (num * (-j)) % q
        den = (den * (i - j)) % q
    return (num * mod_inv(den, q)) % q


def reconstruct_secret(shares: List[Tuple[int, int]], q: int = Q) -> int:
    """
    Reconstruct the secret via Lagrange interpolation.

    shares: at least t (index, value) pairs.
    """
    if not shares:
        raise ValueError("need at least one share")
    indices = [s[0] for s in shares]
    result = 0
    for i, yi in shares:
        lam = lagrange_coeff(i, indices, q)
        result = (result + yi * lam) % q
    return result


# ---------------------------------------------------------------------------
# Step 2: Schnorr signatures (single-key)
# ---------------------------------------------------------------------------

def schnorr_sign(
    private_key: int, msg_bytes: bytes, k_seed: int | None = None
) -> Tuple[int, int]:
    """
    Sign msg_bytes with private_key using Schnorr over Z_p.

    Returns (R, s) where:
      R = g^k mod p
      e = H(R || msg_bytes)
      s = k - private_key * e mod q
    """
    if k_seed is not None:
        rng = random.Random(k_seed)
        k = rng.randrange(1, Q)
    else:
        k = secrets.randbelow(Q - 1) + 1
    R = pow(G, k, P)
    e = hash_int(R, msg_bytes)
    s = (k - private_key * e) % Q
    return (R, s)


def schnorr_verify(public_key: int, msg_bytes: bytes, R: int, s: int) -> bool:
    """
    Verify a Schnorr signature (R, s) against public_key.

    Check: g^s * X^e mod p == R, where e = H(R || msg_bytes).
    """
    e = hash_int(R, msg_bytes)
    lhs = pow(G, s, P) * pow(public_key, e, P) % P
    return lhs == R


# ---------------------------------------------------------------------------
# Step 3: Distributed Key Generation (DKG, simulated in-process)
# ---------------------------------------------------------------------------

@dataclass
class DKGResult:
    """Output of the DKG protocol."""
    party_pubkeys: List[int]                   # g^x_i for each party i
    aggregate_shares: List[Tuple[int, int]]    # share of aggregate secret per party
    aggregate_pubkey: int                      # product of party_pubkeys = g^(sum x_i)


def dkg_simulate(t: int, n: int, rng_seed: int | None = None) -> DKGResult:
    """
    Simulate a Pedersen-style DKG in a single process.

    Each of n parties:
      1. Generates a random secret x_i and commits X_i = g^x_i mod p.
      2. Distributes Shamir shares of x_i to all other parties.

    Each party j then holds: agg_share_j = sum_i f_i(j) mod q.
    The aggregate public key is X = product_i X_i = g^(sum_i x_i) mod p.

    No single party ever learns sum_i x_i (the aggregate private key).
    """
    if not (1 <= t <= n):
        raise ValueError(f"need 1 <= t <= n, got t={t}, n={n}")

    rng = random.Random(rng_seed)

    # Step 1: each party generates a secret and commits g^x_i
    party_secrets = [rng.randrange(1, Q) for _ in range(n)]
    party_pubkeys = [pow(G, xi, P) for xi in party_secrets]

    # Step 2: each party i distributes Shamir shares of x_i to all n parties
    all_shares_matrix: List[List[Tuple[int, int]]] = []
    for i, xi in enumerate(party_secrets):
        seed = (rng_seed * 100 + i) if rng_seed is not None else None
        shares = share_secret(xi, t, n, rng_seed=seed)
        all_shares_matrix.append(shares)

    # Step 3: each party j aggregates the shares it received from all other parties
    aggregate_shares: List[Tuple[int, int]] = []
    for j in range(1, n + 1):
        agg_val = sum(all_shares_matrix[i][j - 1][1] for i in range(n)) % Q
        aggregate_shares.append((j, agg_val))

    # Step 4: aggregate public key = product of individual public keys mod p
    aggregate_pubkey = 1
    for pk in party_pubkeys:
        aggregate_pubkey = aggregate_pubkey * pk % P

    return DKGResult(
        party_pubkeys=party_pubkeys,
        aggregate_shares=aggregate_shares,
        aggregate_pubkey=aggregate_pubkey,
    )


# ---------------------------------------------------------------------------
# Step 4: Threshold Schnorr Signing (simplified FROST-like)
# ---------------------------------------------------------------------------

def threshold_sign(
    msg_bytes: bytes,
    signer_indices: List[int],
    aggregate_shares: List[Tuple[int, int]],
    aggregate_pubkey: int,
    rng_seed: int | None = None,
) -> Tuple[int, int]:
    """
    Threshold Schnorr signing without key reconstruction.

    Protocol (simplified FROST):
      1. Each signer i picks nonce k_i, publishes R_i = g^k_i.
      2. Aggregate R = product of R_i mod p.
      3. Challenge e = H(R || msg).
      4. Each signer computes partial sig: s_i = k_i - x_i * e * lambda_i mod q.
      5. Aggregate s = sum s_i mod q.

    Correctness: g^s * X^e
      = g^(sum s_i) * (g^x)^e
      = product(g^(k_i - x_i*e*lambda_i)) * g^(x*e)
      = R * g^(-e * sum(x_i*lambda_i) + x*e)
      = R * g^0 = R   (by Lagrange: sum x_i*lambda_i = x)
    """
    if len(signer_indices) < 1:
        raise ValueError("need at least one signer")

    rng = random.Random(rng_seed)

    # Step 1: per-signer nonces
    nonces: dict[int, int] = {}
    R_vals: dict[int, int] = {}
    for idx in signer_indices:
        ki = rng.randrange(1, Q) if rng_seed is not None else secrets.randbelow(Q - 1) + 1
        nonces[idx] = ki
        R_vals[idx] = pow(G, ki, P)

    # Step 2: aggregate R
    R_agg = 1
    for ri in R_vals.values():
        R_agg = R_agg * ri % P

    # Step 3: challenge
    e = hash_int(R_agg, msg_bytes)

    # Step 4: partial signatures with Lagrange coefficients
    shares_dict = dict(aggregate_shares)
    partial_sigs: dict[int, int] = {}
    for idx in signer_indices:
        xi_share = shares_dict[idx]
        lam = lagrange_coeff(idx, signer_indices, Q)
        si = (nonces[idx] - xi_share * e * lam) % Q
        partial_sigs[idx] = si

    # Step 5: aggregate partial signatures
    s_agg = sum(partial_sigs.values()) % Q

    return (R_agg, s_agg)


# ---------------------------------------------------------------------------
# Main demo: 3-of-5 threshold wallet
# ---------------------------------------------------------------------------

def main() -> None:
    print("=== Step 1: Shamir Secret Sharing ===")
    secret = 42
    t, n = 3, 5
    shares = share_secret(secret, t, n, rng_seed=7)
    print(f"secret={secret}, t={t}, n={n}")
    print(f"shares: {shares}")

    rec_all = reconstruct_secret(shares[:3])
    print(f"reconstructed (shares 1,2,3): {rec_all}")
    assert rec_all == secret

    rec_alt = reconstruct_secret([shares[1], shares[3], shares[4]])
    print(f"reconstructed (shares 2,4,5): {rec_alt}")
    assert rec_alt == secret

    rec_bad = reconstruct_secret(shares[:2])
    print(f"reconstructed (only 2 shares): {rec_bad}  (wrong — need >= t)")
    assert rec_bad != secret

    print()
    print("=== Step 2: Schnorr Signature (single key) ===")
    x = 123
    X = pow(G, x, P)
    msg = b"transfer 10 ETH"
    R, s = schnorr_sign(x, msg, k_seed=42)
    ok = schnorr_verify(X, msg, R, s)
    print(f"private_key={x}, public_key={X}")
    print(f"signature: R={R}, s={s}")
    print(f"verify: {ok}")
    assert ok

    bad_ok = schnorr_verify(X, b"tampered message", R, s)
    print(f"verify tampered msg: {bad_ok}  (should be False)")
    assert not bad_ok

    print()
    print("=== Step 3: Distributed Key Generation (3-of-5 DKG) ===")
    t, n = 3, 5
    dkg = dkg_simulate(t, n, rng_seed=42)
    print(f"party public keys: {dkg.party_pubkeys}")
    print(f"aggregate public key: {dkg.aggregate_pubkey}")
    print(f"aggregate shares (per party): {dkg.aggregate_shares}")

    # Consistency check: reconstructing from t shares gives aggregate secret
    agg_secret_check = reconstruct_secret(dkg.aggregate_shares[:t])
    assert pow(G, agg_secret_check, P) == dkg.aggregate_pubkey
    print(f"DKG consistency check: g^(reconstructed_secret) == aggregate_pubkey: True")

    print()
    print("=== Step 4: Threshold Signing (3-of-5, signers 1,2,3) ===")
    tx_msg = b"send 1 BTC to Alice"
    signers = [1, 2, 3]
    R_t, s_t = threshold_sign(tx_msg, signers, dkg.aggregate_shares, dkg.aggregate_pubkey, rng_seed=77)
    ok_t = schnorr_verify(dkg.aggregate_pubkey, tx_msg, R_t, s_t)
    print(f"signers: {signers}")
    print(f"signature: R={R_t}, s={s_t}")
    print(f"verify against aggregate public key: {ok_t}")
    assert ok_t

    print()
    print("=== Step 5: Different quorum (signers 2,4,5) ===")
    signers2 = [2, 4, 5]
    R_t2, s_t2 = threshold_sign(tx_msg, signers2, dkg.aggregate_shares, dkg.aggregate_pubkey, rng_seed=88)
    ok_t2 = schnorr_verify(dkg.aggregate_pubkey, tx_msg, R_t2, s_t2)
    print(f"signers: {signers2}")
    print(f"signature: R={R_t2}, s={s_t2}")
    print(f"verify against aggregate public key: {ok_t2}")
    assert ok_t2

    print()
    print("=== All assertions passed ===")


if __name__ == "__main__":
    main()
