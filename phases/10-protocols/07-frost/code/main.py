"""
Toy, educational implementation of a 2-round FROST threshold Schnorr signature.

This script:
- builds a tiny prime-order subgroup (mod p),
- splits a signing key with Shamir secret sharing,
- runs the two FROST rounds (commitments → signature shares),
- aggregates an (R, z) Schnorr signature and verifies it,
- demonstrates why nonce reuse destroys Schnorr-style signatures.

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Dict, Iterable, List, Sequence, Tuple


# Small safe prime parameters for a fast, human-auditable demo.
# p = 2q + 1 where q is prime; the subgroup of quadratic residues has order q.
P = 2039
Q = 1019


def _int_to_fixed_len_bytes(x: int, length: int) -> bytes:
    if x < 0:
        raise ValueError("negative integer")
    return x.to_bytes(length, byteorder="big")


def serialize_scalar(x: int, q: int = Q) -> bytes:
    length = (q.bit_length() + 7) // 8
    return _int_to_fixed_len_bytes(x % q, length)


def serialize_element(x: int, p: int = P) -> bytes:
    length = (p.bit_length() + 7) // 8
    return _int_to_fixed_len_bytes(x % p, length)


def hash_to_scalar(tag: bytes, data: bytes, q: int = Q) -> int:
    h = hashlib.sha256(tag + b"|" + data).digest()
    return int.from_bytes(h, byteorder="big") % q


class DeterministicRng:
    def __init__(self, seed: bytes):
        self._seed = seed
        self._counter = 0

    def scalar(self, label: bytes, q: int = Q) -> int:
        self._counter += 1
        data = self._seed + b"|" + label + b"|" + _int_to_fixed_len_bytes(self._counter, 4)
        x = hash_to_scalar(b"drbg", data, q=q)
        if x == 0:
            return 1
        return x


def modinv(a: int, m: int) -> int:
    a = a % m
    if a == 0:
        raise ValueError("inverse does not exist")
    t0, t1 = 0, 1
    r0, r1 = m, a
    while r1 != 0:
        q = r0 // r1
        r0, r1 = r1, r0 - q * r1
        t0, t1 = t1, t0 - q * t1
    if r0 != 1:
        raise ValueError("inverse does not exist")
    return t0 % m


def _is_prime(n: int) -> bool:
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    d = 3
    while d * d <= n:
        if n % d == 0:
            return False
        d += 2
    return True


def find_generator_of_order_q(p: int, q: int) -> int:
    if p != 2 * q + 1:
        raise ValueError("expected safe prime p=2q+1")
    for h in range(2, p - 1):
        g = pow(h, 2, p)
        if g != 1 and pow(g, q, p) == 1:
            return g
    raise ValueError("no generator found")


def group_mul(a: int, b: int, p: int = P) -> int:
    return (a * b) % p


def group_pow(base: int, exponent: int, p: int = P) -> int:
    return pow(base % p, exponent, p)


def prime_order_sign(msg: bytes, sk: int, g: int, p: int = P, q: int = Q, seed: bytes = b"") -> Tuple[int, int, int]:
    rng = DeterministicRng(seed or b"prime_order_sign")
    r = rng.scalar(b"nonce", q=q)
    R = group_pow(g, r, p)
    PK = group_pow(g, sk, p)
    c = hash_to_scalar(b"chal", serialize_element(R, p) + serialize_element(PK, p) + msg, q=q)
    z = (r + c * (sk % q)) % q
    return (R, z, c)


def prime_order_verify(msg: bytes, sig: Tuple[int, int], pk: int, g: int, p: int = P, q: int = Q) -> bool:
    R, z = sig
    c = hash_to_scalar(b"chal", serialize_element(R, p) + serialize_element(pk, p) + msg, q=q)
    left = group_pow(g, z, p)
    right = group_mul(R % p, group_pow(pk, c, p), p)
    return left == right


def recover_secret_from_reused_nonce(
    msg1: bytes,
    msg2: bytes,
    sig1: Tuple[int, int],
    sig2: Tuple[int, int],
    pk: int,
    q: int = Q,
    p: int = P,
) -> int:
    R1, z1 = sig1
    R2, z2 = sig2
    if R1 != R2:
        raise ValueError("expected reused nonce (same R)")
    c1 = hash_to_scalar(b"chal", serialize_element(R1, p) + serialize_element(pk, p) + msg1, q=q)
    c2 = hash_to_scalar(b"chal", serialize_element(R2, p) + serialize_element(pk, p) + msg2, q=q)
    denom = (c1 - c2) % q
    if denom == 0:
        raise ValueError("challenges are equal; choose different messages")
    x = ((z1 - z2) * modinv(denom, q)) % q
    return x


def eval_polynomial(coefficients: Sequence[int], x: int, q: int = Q) -> int:
    acc = 0
    for c in reversed(coefficients):
        acc = (acc * (x % q) + (c % q)) % q
    return acc


def shamir_split(secret: int, threshold: int, participant_ids: Sequence[int], rng: DeterministicRng, q: int = Q) -> Dict[int, int]:
    if threshold < 2:
        raise ValueError("threshold must be >= 2")
    if len(set(participant_ids)) != len(participant_ids):
        raise ValueError("duplicate participant id")
    if any(i % q == 0 for i in participant_ids):
        raise ValueError("participant ids must be non-zero mod q")
    coeffs = [secret % q] + [rng.scalar(b"poly_coeff", q=q) for _ in range(threshold - 1)]
    return {i: eval_polynomial(coeffs, i, q=q) for i in participant_ids}


def lagrange_coefficient_at_zero(identifier: int, participant_ids: Sequence[int], q: int = Q) -> int:
    if identifier not in participant_ids:
        raise ValueError("identifier not in participant set")
    num = 1
    den = 1
    for j in participant_ids:
        if j == identifier:
            continue
        num = (num * (j % q)) % q
        den = (den * ((j - identifier) % q)) % q
    return (num * modinv(den, q)) % q


def shamir_combine_at_zero(shares: Sequence[Tuple[int, int]], q: int = Q) -> int:
    ids = [i for (i, _) in shares]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate share id")
    secret = 0
    for i, y in shares:
        lam = lagrange_coefficient_at_zero(i, ids, q=q)
        secret = (secret + (y % q) * lam) % q
    return secret


@dataclass(frozen=True)
class ParticipantKeyShare:
    identifier: int
    sk_share: int
    pk_share: int


def trusted_dealer_keygen(
    *,
    secret: int,
    threshold: int,
    participant_ids: Sequence[int],
    g: int,
    p: int = P,
    q: int = Q,
    seed: bytes = b"dealer",
) -> Tuple[int, int, Dict[int, ParticipantKeyShare]]:
    rng = DeterministicRng(seed)
    shares = shamir_split(secret, threshold, participant_ids, rng, q=q)
    group_pk = group_pow(g, secret % q, p)
    key_shares: Dict[int, ParticipantKeyShare] = {}
    for i in participant_ids:
        sk_i = shares[i] % q
        pk_i = group_pow(g, sk_i, p)
        key_shares[i] = ParticipantKeyShare(identifier=i, sk_share=sk_i, pk_share=pk_i)
    return (secret % q, group_pk, key_shares)


@dataclass(frozen=True)
class NoncePair:
    hiding_nonce: int
    binding_nonce: int
    hiding_commitment: int
    binding_commitment: int


def nonce_generate(identifier: int, rng: DeterministicRng, g: int, p: int = P, q: int = Q) -> NoncePair:
    d = rng.scalar(b"nonce_d|" + serialize_scalar(identifier, q=q), q=q)
    e = rng.scalar(b"nonce_e|" + serialize_scalar(identifier, q=q), q=q)
    D = group_pow(g, d, p)
    E = group_pow(g, e, p)
    return NoncePair(hiding_nonce=d, binding_nonce=e, hiding_commitment=D, binding_commitment=E)


CommitmentList = List[Tuple[int, int, int]]  # (identifier, D_i, E_i)


def encode_group_commitment_list(commitment_list: CommitmentList, p: int = P, q: int = Q) -> bytes:
    out = b""
    for identifier, D_i, E_i in commitment_list:
        out += serialize_scalar(identifier, q=q) + serialize_element(D_i, p) + serialize_element(E_i, p)
    return out


def compute_binding_factors(group_pk: int, commitment_list: CommitmentList, msg: bytes, q: int = Q, p: int = P) -> Dict[int, int]:
    msg_hash = hashlib.sha256(msg).digest()
    commitment_hash = hashlib.sha256(encode_group_commitment_list(commitment_list, p=p, q=q)).digest()
    prefix = serialize_element(group_pk, p) + msg_hash + commitment_hash
    rhos: Dict[int, int] = {}
    for identifier, _, _ in commitment_list:
        rho_input = prefix + serialize_scalar(identifier, q=q)
        rho_i = hash_to_scalar(b"rho", rho_input, q=q)
        rhos[identifier] = rho_i
    return rhos


def commitment_share(identifier: int, commitment_list: CommitmentList, binding_factors: Dict[int, int], p: int = P) -> int:
    for i, D_i, E_i in commitment_list:
        if i == identifier:
            rho_i = binding_factors[i]
            return group_mul(D_i, group_pow(E_i, rho_i, p), p)
    raise ValueError("unknown identifier")


def compute_group_commitment(commitment_list: CommitmentList, binding_factors: Dict[int, int], p: int = P) -> int:
    R = 1
    for identifier, _, _ in commitment_list:
        R = group_mul(R, commitment_share(identifier, commitment_list, binding_factors, p), p)
    return R


def compute_challenge(group_commitment: int, group_pk: int, msg: bytes, q: int = Q, p: int = P) -> int:
    inp = serialize_element(group_commitment, p) + serialize_element(group_pk, p) + msg
    return hash_to_scalar(b"chal", inp, q=q)


def sign_signature_share(
    identifier: int,
    key_share: ParticipantKeyShare,
    nonce_pair: NoncePair,
    binding_factor: int,
    challenge: int,
    participant_ids: Sequence[int],
    q: int = Q,
) -> int:
    lam = lagrange_coefficient_at_zero(identifier, participant_ids, q=q)
    z_i = (
        nonce_pair.hiding_nonce
        + (binding_factor * nonce_pair.binding_nonce)
        + (challenge * lam * key_share.sk_share)
    ) % q
    return z_i


def verify_signature_share(
    identifier: int,
    sig_share: int,
    key_share: ParticipantKeyShare,
    commitment_list: CommitmentList,
    binding_factors: Dict[int, int],
    challenge: int,
    participant_ids: Sequence[int],
    g: int,
    p: int = P,
    q: int = Q,
) -> bool:
    lam = lagrange_coefficient_at_zero(identifier, participant_ids, q=q)
    comm = commitment_share(identifier, commitment_list, binding_factors, p=p)
    left = group_pow(g, sig_share % q, p)
    right = group_mul(comm, group_pow(key_share.pk_share, (challenge * lam) % q, p), p)
    return left == right


def aggregate_signature(sig_shares: Dict[int, int], group_commitment: int, q: int = Q) -> Tuple[int, int]:
    z = 0
    for z_i in sig_shares.values():
        z = (z + (z_i % q)) % q
    return (group_commitment, z)


def demo_frost_signing() -> None:
    if not (_is_prime(P) and _is_prime(Q) and P == 2 * Q + 1):
        raise RuntimeError("unexpected group parameters")
    g = find_generator_of_order_q(P, Q)

    print("=== Step 1: Prime-order Schnorr (toy group) ===")
    msg = b"hello frost"
    sk = 123 % Q
    pk = group_pow(g, sk, P)
    R, z, _ = prime_order_sign(msg, sk, g, seed=b"schnorr-demo")
    print(f"p={P}, q={Q}, g={g}")
    print(f"msg={msg!r}")
    print(f"pk={pk}")
    print(f"sig=(R={R}, z={z}) verify={prime_order_verify(msg, (R, z), pk, g)}")
    print()

    print("=== Step 2: Shamir shares + Lagrange coefficients ===")
    threshold = 3
    all_ids = [1, 2, 3, 4, 5]
    group_sk, group_pk, shares = trusted_dealer_keygen(
        secret=777,
        threshold=threshold,
        participant_ids=all_ids,
        g=g,
        seed=b"dealer-demo",
    )
    signers = [1, 2, 4]
    lams = {i: lagrange_coefficient_at_zero(i, signers, q=Q) for i in signers}
    reconstructed = shamir_combine_at_zero([(i, shares[i].sk_share) for i in signers], q=Q)
    print(f"threshold={threshold}, participants={all_ids}, signing_subset={signers}")
    print(f"group_pk={group_pk}")
    print(f"reconstructed_group_sk_from_subset={reconstructed} (matches={reconstructed == group_sk})")
    print(f"lambdas_at_zero={lams}")
    print()

    print("=== Step 3: Round 1 (commitments → binding factors → group commitment) ===")
    round1_rng = DeterministicRng(b"round1-demo")
    nonce_pairs: Dict[int, NoncePair] = {}
    commitment_list: CommitmentList = []
    for i in signers:
        nonce_pairs[i] = nonce_generate(i, round1_rng, g, p=P, q=Q)
        np = nonce_pairs[i]
        commitment_list.append((i, np.hiding_commitment, np.binding_commitment))
    commitment_list.sort(key=lambda t: t[0])
    rhos = compute_binding_factors(group_pk, commitment_list, msg, q=Q, p=P)
    R_group = compute_group_commitment(commitment_list, rhos, p=P)
    print(f"commitment_list={commitment_list}")
    print(f"binding_factors={rhos}")
    print(f"group_commitment_R={R_group}")
    print()

    print("=== Step 4: Round 2 (signature shares + share verification) ===")
    c = compute_challenge(R_group, group_pk, msg, q=Q, p=P)
    sig_shares: Dict[int, int] = {}
    for i in signers:
        z_i = sign_signature_share(
            i,
            shares[i],
            nonce_pairs[i],
            rhos[i],
            c,
            signers,
            q=Q,
        )
        sig_shares[i] = z_i
        ok = verify_signature_share(i, z_i, shares[i], commitment_list, rhos, c, signers, g, p=P, q=Q)
        print(f"participant={i} z_i={z_i} share_verify={ok}")
    print()

    print("=== Step 5: Aggregate signature + (nonce reuse) failure mode ===")
    sig = aggregate_signature(sig_shares, R_group, q=Q)
    ok = prime_order_verify(msg, sig, group_pk, g, p=P, q=Q)
    print(f"aggregate_sig=(R={sig[0]}, z={sig[1]}) verify={ok}")

    reuse_rng = DeterministicRng(b"nonce-reuse-demo")
    reused_r = reuse_rng.scalar(b"fixed_r", q=Q)
    reused_R = group_pow(g, reused_r, P)
    msg1 = b"m1"
    msg2 = b"m2"
    c1 = hash_to_scalar(b"chal", serialize_element(reused_R, P) + serialize_element(pk, P) + msg1, q=Q)
    c2 = hash_to_scalar(b"chal", serialize_element(reused_R, P) + serialize_element(pk, P) + msg2, q=Q)
    z1 = (reused_r + c1 * sk) % Q
    z2 = (reused_r + c2 * sk) % Q
    recovered = recover_secret_from_reused_nonce(msg1, msg2, (reused_R, z1), (reused_R, z2), pk, q=Q, p=P)
    print(f"nonce_reuse_demo: recovered_sk={recovered} (matches={recovered == sk})")


def main() -> None:
    demo_frost_signing()


if __name__ == "__main__":
    main()
