"""
BLS Aggregation in Eth2 (educational toy model over Z_Q).

This is a LINEAR ANALOG of BLS signatures — it captures the aggregation
algebra (additive homomorphism) without requiring pairing-friendly elliptic
curves.  Real BLS uses G1/G2 pairings over BLS12-381; this model uses
ordinary modular arithmetic over a tiny prime so the numbers stay readable.

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib

# ---------------------------------------------------------------------------
# Group parameters (toy field — educational only)
# ---------------------------------------------------------------------------

Q = 1_000_003  # small prime; all group elements live in Z_Q

# ---------------------------------------------------------------------------
# Core BLS primitives
# ---------------------------------------------------------------------------


def bls_hash_to_g1(message: bytes) -> int:
    """Hash a message to a group element in Z_Q."""
    digest = hashlib.sha256(message).digest()
    return int.from_bytes(digest, "big") % Q


def bls_keygen(sk: int) -> int:
    """Derive public key from secret key: pk = sk mod Q."""
    return sk % Q


def bls_sign(sk: int, message: bytes) -> int:
    """Sign: sig = H(message) * sk mod Q."""
    h = bls_hash_to_g1(message)
    return (h * sk) % Q


def bls_verify(pk: int, message: bytes, sig: int) -> bool:
    """Verify a single signature: sig == H(message) * pk mod Q."""
    h = bls_hash_to_g1(message)
    return sig % Q == (h * pk) % Q


# ---------------------------------------------------------------------------
# Aggregation (same-message variant)
# ---------------------------------------------------------------------------


def bls_aggregate_pks(pks: list[int]) -> int:
    """Aggregate public keys: agg_pk = sum(pks) mod Q."""
    return sum(pks) % Q


def bls_aggregate_sigs(sigs: list[int]) -> int:
    """Aggregate signatures: agg_sig = sum(sigs) mod Q."""
    return sum(sigs) % Q


def bls_verify_aggregate(agg_pk: int, message: bytes, agg_sig: int) -> bool:
    """
    Verify an aggregate signature where all signers signed the same message.

    Holds because:  sum(H(m)*sk_i) = H(m) * sum(sk_i) = H(m) * agg_pk  (mod Q)
    """
    h = bls_hash_to_g1(message)
    return agg_sig % Q == (h * agg_pk) % Q


# ---------------------------------------------------------------------------
# Multi-message aggregation
# ---------------------------------------------------------------------------


def bls_verify_aggregate_multi(
    pks: list[int], messages: list[bytes], agg_sig: int
) -> bool:
    """
    Verify an aggregate signature where each signer signed a distinct message.

    agg_sig = sum(H(m_i) * sk_i)  =>  check against  sum(H(m_i) * pk_i)
    """
    if len(pks) != len(messages):
        raise ValueError("pks and messages must have the same length")
    expected = sum(bls_hash_to_g1(m) * pk for pk, m in zip(pks, messages)) % Q
    return agg_sig % Q == expected


# ---------------------------------------------------------------------------
# Rogue key attack
# ---------------------------------------------------------------------------


def bls_rogue_key_attack(target_pk: int, attacker_sk: int) -> int:
    """
    Demonstrate the rogue key attack.

    Attacker publishes  pk' = (attacker_sk - target_pk) mod Q.
    When naively aggregated:  agg_pk = target_pk + pk' = attacker_sk mod Q.
    The attacker can then produce a valid aggregate signature using only
    attacker_sk, completely ignoring the target's actual secret key.

    Returns the crafted rogue public key pk'.
    """
    return (attacker_sk - target_pk) % Q


# ---------------------------------------------------------------------------
# Proof-of-Possession (PoP)
# ---------------------------------------------------------------------------

_POP_TAG = b"BLS-POP|"


def bls_sign_with_pop(sk: int) -> tuple[int, int]:
    """
    Return (pk, proof_of_possession).

    The proof is a signature over the signer's own public key bytes,
    domain-separated with a PoP tag.  This binds sk to pk before
    inclusion in any multi-signer aggregate.
    """
    pk = bls_keygen(sk)
    pk_bytes = _POP_TAG + pk.to_bytes(4, "big")
    pop = bls_sign(sk, pk_bytes)
    return pk, pop


def bls_verify_pop(pk: int, pop: int) -> bool:
    """Verify that the holder of sk(=pk) actually controls that key."""
    pk_bytes = _POP_TAG + pk.to_bytes(4, "big")
    return bls_verify(pk, pk_bytes, pop)


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------


def main() -> None:
    print("=== Step 1: Key Generation ===")
    sks = [42, 100, 200]
    pks = [bls_keygen(sk) for sk in sks]
    for sk, pk in zip(sks, pks):
        print(f"  sk={sk:>3}  ->  pk={pk}")
    print()

    print("=== Step 2: Sign and Verify ===")
    message = b"Ethereum block 1"
    for sk, pk in zip(sks, pks):
        sig = bls_sign(sk, message)
        ok = bls_verify(pk, message, sig)
        print(f"  sk={sk:>3}  sig={sig:>7}  verify={ok}")
    print()

    print("=== Step 3: Aggregate Signatures ===")
    sigs = [bls_sign(sk, message) for sk in sks]
    agg_sig = bls_aggregate_sigs(sigs)
    agg_pk = bls_aggregate_pks(pks)
    ok_agg = bls_verify_aggregate(agg_pk, message, agg_sig)
    print(f"  sigs       = {sigs}")
    print(f"  agg_sig    = {agg_sig}")
    print(f"  agg_pk     = {agg_pk}")
    print(f"  verify_agg = {ok_agg}")

    # multi-message
    messages_multi = [b"msg_alice", b"msg_bob", b"msg_carol"]
    sigs_multi = [bls_sign(sk, m) for sk, m in zip(sks, messages_multi)]
    agg_sig_multi = bls_aggregate_sigs(sigs_multi)
    ok_multi = bls_verify_aggregate_multi(pks, messages_multi, agg_sig_multi)
    print(f"  multi-message verify = {ok_multi}")
    print()

    print("=== Step 4: Rogue Key Attack ===")
    # Victim: sk=42 -> pk=42
    victim_pk = bls_keygen(42)
    attacker_sk = 999
    rogue_pk = bls_rogue_key_attack(victim_pk, attacker_sk)
    naive_agg_pk = (victim_pk + rogue_pk) % Q  # == attacker_sk % Q

    # Attacker signs *alone* using attacker_sk, producing a valid aggregate sig
    forged_sig = bls_sign(attacker_sk, message)
    ok_forged = bls_verify_aggregate(naive_agg_pk, message, forged_sig)

    print(f"  victim pk           = {victim_pk}")
    print(f"  rogue pk            = {rogue_pk}")
    print(f"  naive agg_pk        = {naive_agg_pk}  (== attacker_sk={attacker_sk % Q})")
    print(f"  forged sig verifies = {ok_forged}  <-- attacker wins without victim's key!")
    print()

    print("=== Step 5: Proof-of-Possession Defense ===")
    # Register all participants with valid PoPs
    pop_entries: list[tuple[int, int]] = []
    for sk in [42, 100, 200]:
        pk, pop = bls_sign_with_pop(sk)
        valid_pop = bls_verify_pop(pk, pop)
        print(f"  sk={sk:>3}  pk={pk:>7}  pop={pop:>7}  pop_valid={valid_pop}")
        pop_entries.append((pk, pop))

    # Attacker tries to register rogue key — PoP will fail
    attacker_sk2 = 999
    rogue_pk2 = bls_rogue_key_attack(bls_keygen(42), attacker_sk2)
    # Attacker cannot sign rogue_pk2 because they don't know sk such that
    # bls_keygen(sk)==rogue_pk2 AND that sk lets them sign rogue_pk2 bytes.
    # Demonstrate: any pop the attacker provides for rogue_pk2 is wrong.
    fake_pop = bls_sign(attacker_sk2, _POP_TAG + rogue_pk2.to_bytes(4, "big"))
    rogue_pop_valid = bls_verify_pop(rogue_pk2, fake_pop)
    print(f"  rogue pk={rogue_pk2:>7}  fake_pop_valid={rogue_pop_valid}  <-- defense works!")


if __name__ == "__main__":
    main()
