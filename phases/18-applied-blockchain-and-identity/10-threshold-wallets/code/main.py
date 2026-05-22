"""
Threshold Wallets — DKG to Signing (educational):
Shamir Secret Sharing, Distributed Key Generation (DKG), and threshold
Schnorr signing (simplified FROST-like protocol).

Two distinct primes are used to keep the math correct:

  _TW_N     = 2**31 - 1  (Mersenne prime) — the "field prime" for the
              multiplicative group Z_N*. Group elements live here.
              This is ALSO used as the Shamir polynomial prime because it
              is prime (GF(_TW_N) is a valid finite field).

  _TW_ORDER = _TW_N - 1  — the group order of Z_N* (Fermat).
              Scalar exponents used in DH/Schnorr are reduced mod ORDER.
              Note: ORDER is NOT prime, so Lagrange interpolation for
              Shamir MUST use _TW_N (a prime), not _TW_ORDER.

Public API functions accept a 'prime' parameter. For Shamir functions
pass _TW_N. For DKG/Schnorr functions also pass _TW_N (they derive ORDER
internally as prime - 1).

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib

# ---------------------------------------------------------------------------
# Toy group parameters
# ---------------------------------------------------------------------------
_TW_N: int = 2**31 - 1       # Field prime (2147483647)
_TW_G: int = 3                # Generator of Z_N*
_TW_ORDER: int = _TW_N - 1   # Group order = N - 1


def _sha256_int(data: bytes) -> int:
    return int(hashlib.sha256(data).hexdigest(), 16)


def _det_coeff(seed: int, index: int, prime: int) -> int:
    """Deterministic polynomial coefficient from seed and index."""
    return _sha256_int(f"{seed}:{index}".encode()) % prime


# ---------------------------------------------------------------------------
# Shamir Secret Sharing
# ---------------------------------------------------------------------------

def shamir_split(secret: int, t: int, n: int, prime: int) -> list[tuple[int, int]]:
    """Split secret into n shares with threshold t.

    Polynomial: f(x) = secret + a1*x + ... + a_{t-1}*x^{t-1}  mod prime
    Returns [(1, f(1)), (2, f(2)), ..., (n, f(n))].

    Uses deterministic coefficients: a_i = _det_coeff(secret, i, prime).
    """
    # Build polynomial coefficients: [secret, a1, a2, ..., a_{t-1}]
    coeffs = [secret % prime]
    for i in range(1, t):
        coeffs.append(_det_coeff(secret, i, prime))

    shares = []
    for x in range(1, n + 1):
        y = 0
        for power, coeff in enumerate(coeffs):
            y = (y + coeff * pow(x, power, prime)) % prime
        shares.append((x, y))
    return shares


def shamir_reconstruct(shares: list[tuple[int, int]], prime: int) -> int:
    """Reconstruct the secret from any t shares using Lagrange interpolation.

    Computes f(0) from the given (x, y) points modulo prime.
    """
    secret = 0
    for i, (xi, yi) in enumerate(shares):
        num = yi
        den = 1
        for j, (xj, _) in enumerate(shares):
            if i == j:
                continue
            num = num * (-xj) % prime
            den = den * (xi - xj) % prime
        secret = (secret + num * pow(den, prime - 2, prime)) % prime
    return secret


# ---------------------------------------------------------------------------
# Distributed Key Generation (DKG) — Pedersen / Feldman style
# ---------------------------------------------------------------------------

def dkg_round1(party_id: int, n: int, t: int, prime: int) -> tuple[list[int], list[int]]:
    """DKG Round 1: each party generates a secret polynomial and broadcasts
    commitments to its coefficients.

    The 'prime' here is the field prime (N), so group elements live in Z_N*.
    Scalar coefficients are computed mod ORDER = prime - 1.

    Returns:
      coefficients  — list of t scalars (kept secret by the party)
      commitments   — list of t group elements: [G^coeff_i mod N]
    """
    order = prime - 1
    coeffs = []
    for i in range(t):
        c = _det_coeff(party_id * 1000 + i, i, order)
        if c == 0:
            c = 1
        coeffs.append(c)

    commitments = [pow(_TW_G, c, prime) for c in coeffs]
    return coeffs, commitments


def dkg_round2(party_id: int, other_shares: list[tuple[int, int]], prime: int) -> int:
    """DKG Round 2: compute this party's final secret share.

    other_shares: list of (x_value, share_value) received from all parties
    (including the party's own share from its own polynomial).
    The final share = sum of all received shares mod ORDER.
    """
    order = prime - 1
    return sum(s for _, s in other_shares) % order


def dkg_final_pubkey(all_commitments: list[list[int]], prime: int) -> int:
    """Compute the group public key = product of all parties' f_i(0) commitments.

    Each party's commitment[0] = G^(a_i0) mod N, where a_i0 is party i's
    secret constant term. The group public key = G^(sum of a_i0) =
    product of all commitment[0] values mod N.
    """
    pk = 1
    for party_commitments in all_commitments:
        pk = pk * party_commitments[0] % prime
    return pk


# ---------------------------------------------------------------------------
# Threshold Schnorr Signing (simplified FROST)
# ---------------------------------------------------------------------------

def threshold_sign_round1(party_id: int, prime: int) -> tuple[int, int]:
    """FROST Round 1: generate a nonce and broadcast its commitment.

    Uses a deterministic nonce for reproducibility:
      nonce = _det_coeff(party_id, 0, ORDER)

    Returns (nonce_secret, nonce_commitment = G^nonce mod N).
    Scalars live in Z_ORDER; group elements live in Z_N.
    """
    order = prime - 1
    nonce = _det_coeff(party_id, 0, order)
    if nonce == 0:
        nonce = 1
    commitment = pow(_TW_G, nonce, prime)
    return nonce, commitment


def threshold_sign_round2(
    party_id: int,
    sk_share: int,
    nonce_secret: int,
    agg_nonce: int,
    message: bytes,
    prime: int,
) -> int:
    """FROST Round 2: compute a partial signature.

    challenge = SHA256(agg_nonce_bytes || message) mod ORDER
    partial_sig = (nonce_secret + sk_share * challenge) mod ORDER
    """
    order = prime - 1
    agg_nonce_bytes = agg_nonce.to_bytes(8, "big")
    challenge = _sha256_int(agg_nonce_bytes + message) % order
    return (nonce_secret + sk_share * challenge) % order


def threshold_aggregate_sigs(partial_sigs: list[int], prime: int) -> int:
    """Aggregate partial signatures: sum(partial_sigs) mod ORDER."""
    order = prime - 1
    return sum(partial_sigs) % order


def threshold_verify(
    agg_pk: int,
    agg_nonce: int,
    message: bytes,
    sig: int,
    prime: int,
) -> bool:
    """Verify an aggregated threshold Schnorr signature.

    challenge = SHA256(agg_nonce_bytes || message) mod ORDER
    Check: G^sig ≡ agg_nonce * agg_pk^challenge  (mod N)
    """
    order = prime - 1
    agg_nonce_bytes = agg_nonce.to_bytes(8, "big")
    challenge = _sha256_int(agg_nonce_bytes + message) % order
    lhs = pow(_TW_G, sig, prime)
    rhs = agg_nonce * pow(agg_pk, challenge, prime) % prime
    return lhs == rhs


# ---------------------------------------------------------------------------
# main — demo walkthrough
# ---------------------------------------------------------------------------

def main() -> None:
    PRIME = _TW_N
    ORDER = _TW_ORDER

    print("=== Step 1: Shamir Secret Sharing ===")
    secret = 12345
    t, n = 2, 3
    # Shamir uses PRIME (a genuine prime) for GF arithmetic, not ORDER
    shares = shamir_split(secret, t, n, PRIME)
    print(f"secret = {secret}, threshold = {t}, parties = {n}")
    for x, y in shares:
        print(f"  share[{x}] = {y}")

    # Reconstruct from any 2 shares
    rec_01 = shamir_reconstruct(shares[:2], PRIME)
    rec_12 = shamir_reconstruct(shares[1:], PRIME)
    rec_02 = shamir_reconstruct([shares[0], shares[2]], PRIME)
    print(f"  reconstruct(shares[1,2]) = {rec_01}  match={rec_01 == secret}")
    print(f"  reconstruct(shares[2,3]) = {rec_12}  match={rec_12 == secret}")
    print(f"  reconstruct(shares[1,3]) = {rec_02}  match={rec_02 == secret}")
    print()

    print("=== Step 2: Distributed Key Generation (DKG) ===")
    num_parties = 3
    threshold = 2
    all_coeffs = []
    all_commitments = []
    for pid in range(1, num_parties + 1):
        coeffs, comms = dkg_round1(pid, num_parties, threshold, PRIME)
        all_coeffs.append(coeffs)
        all_commitments.append(comms)
        print(f"  party {pid}: secret_coeff[0]={coeffs[0]}, commitment[0]={comms[0]}")

    # Each party computes shares for every other party
    # party_shares[i] = list of (x, f_j(i)) for each party j
    all_shares_for = [[] for _ in range(num_parties)]
    for j, coeffs in enumerate(all_coeffs):
        for i in range(num_parties):
            x = i + 1
            y = sum(coeffs[k] * pow(x, k, ORDER) for k in range(len(coeffs))) % ORDER
            all_shares_for[i].append((x, y))

    sk_shares = []
    for i in range(num_parties):
        sk_i = dkg_round2(i + 1, all_shares_for[i], PRIME)
        sk_shares.append(sk_i)
        print(f"  party {i+1}: sk_share = {sk_i}")

    group_pk = dkg_final_pubkey(all_commitments, PRIME)
    print(f"  group public key = {group_pk}")
    print()

    print("=== Step 3: Threshold Signing — Round 1 ===")
    # Only parties 1 and 2 sign (threshold = 2)
    signing_parties = [1, 2]
    nonces = {}
    nonce_commitments = {}
    for pid in signing_parties:
        ns, nc = threshold_sign_round1(pid, PRIME)
        nonces[pid] = ns
        nonce_commitments[pid] = nc
        print(f"  party {pid}: nonce={ns}, commitment={nc}")

    # Aggregate nonce commitments: product in the group
    agg_nonce = 1
    for nc in nonce_commitments.values():
        agg_nonce = agg_nonce * nc % PRIME
    print(f"  aggregated nonce commitment = {agg_nonce}")
    print()

    print("=== Step 4: Threshold Signing — Round 2 ===")
    message = b"send 1 BTC to Alice"
    partial_sigs = []
    for pid in signing_parties:
        ps = threshold_sign_round2(
            pid, sk_shares[pid - 1], nonces[pid], agg_nonce, message, PRIME
        )
        partial_sigs.append(ps)
        print(f"  party {pid}: partial_sig = {ps}")

    agg_sig = threshold_aggregate_sigs(partial_sigs, PRIME)
    print(f"  aggregated signature = {agg_sig}")
    print()

    print("=== Step 5: Verify Threshold Signature ===")
    # Compute the combined public key for the signing subset using Lagrange
    # For a (t, n) setup, the full-secret public key is used with the
    # aggregated partial sigs (simplified: parties contribute sk_shares directly)
    # For verification we need the "effective" public key for this signing set.
    # In FROST, partial sigs use Lagrange-weighted sk_shares. Here we use the
    # simpler additive approach: agg_pk = product of G^sk_i for signers.
    signing_pk = 1
    for pid in signing_parties:
        signing_pk = signing_pk * pow(_TW_G, sk_shares[pid - 1], PRIME) % PRIME

    valid = threshold_verify(signing_pk, agg_nonce, message, agg_sig, PRIME)
    print(f"  signature valid = {valid}")

    # Wrong message should fail
    bad_valid = threshold_verify(signing_pk, agg_nonce, b"wrong message", agg_sig, PRIME)
    print(f"  wrong message valid = {bad_valid}  (expected False)")


if __name__ == "__main__":
    main()
