# Threshold Signatures — FROST

> Two rounds, one signature: many keys behave like one.

**Type:** Build
**Languages:** Python
**Prerequisites:** `phases/02-abstract-algebra/02-cyclic-groups`, `phases/01-number-theory/14-index-calculus-discrete-log`, Shamir secret sharing basics
**Time:** ~120 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- **Explain** what FROST signs and what it outputs (a normal Schnorr `(R, z)` signature).
- **Compute** Shamir secret shares and Lagrange coefficients for a signing subset.
- **Implement** binding factors, group commitment, and challenge computation.
- **Distinguish** aggregate-signature verification from per-share verification (how you identify a bad signer).
- **Apply** nonce-hygiene rules by demonstrating the nonce-reuse key-recovery attack.

## The Problem

You want a Bitcoin-style “single signature” that is valid only if *k out of n* devices cooperate. Example: a company treasury key where any 3 of 5 hardware wallets can authorize a transfer, so a single lost device doesn’t brick the funds — but a single stolen device can’t sign.

Naively, you could just collect `k` independent signatures. But that leaks who signed, costs bandwidth/verification time, and doesn’t give you the “looks like one signer” property many protocols assume. Threshold signatures solve this by producing **one** signature that verifies under **one** public key, while the private key never exists on any single machine.

FROST is a practical way to do this for Schnorr: it’s **two rounds** (commitments, then shares), and the final output is a standard Schnorr signature. That makes it usable anywhere Schnorr fits — if you implement the details correctly.

## The Concept

### What FROST produces

FROST produces a normal Schnorr signature `(R, z)` that verifies like:

```
g^z  ==  R * PK^c   (mod p)
```

where `c = H(R || PK || msg)` is a hash challenge, `PK` is the *group* public key, and `g` is a generator.

### Why “threshold” works

Instead of one secret key `s`, we split it into **Shamir shares** `s_i = f(i)` using a random polynomial `f` of degree `t-1` such that `f(0) = s`.

For any signing subset `S` of size `t`, there are **Lagrange coefficients** `λ_i` (computed from the identifiers in `S`) such that:

```
s  ==  Σ (λ_i * s_i)    over i in S
```

That’s the core trick: each signer contributes `λ_i * s_i` in the right place, and the aggregator adds everything up.

### Why FROST needs “binding factors”

In a threshold setting, the coordinator sees everyone’s nonce commitments first. If nonces were combined without care, a malicious coordinator (or signer) could bias or “mix and match” commitments across sessions.

FROST prevents that by computing a per-signer **binding factor** `ρ_i` from:
- the group public key,
- the message,
- and the *entire* (sorted) list of nonce commitments.

Then each signer’s “effective” commitment becomes `D_i * E_i^{ρ_i}`, which ties the final signature to a specific transcript.

## Build It

### Step 1: Prime-order Schnorr (toy group)

We’ll work in a tiny prime-order subgroup of `Z_p*` to keep everything fast and inspectable. We’ll implement basic serialization + hashing to scalars, a small modular inverse, and standard Schnorr sign/verify.

```python
import hashlib
from typing import Dict, Iterable, List, Sequence, Tuple


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
```

This gives us a working Schnorr signature in a prime-order subgroup. FROST will produce the same `(R, z)` format — just computed collaboratively.

### Step 2: Shamir shares + Lagrange coefficients

Now we split a group signing key `s` into shares `s_i` using a degree `t-1` polynomial, and we implement Lagrange coefficients `λ_i` that let a subset reconstruct `s` at `x=0`.

```python
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
```

In real systems, key shares typically come from a distributed key generation (DKG), not a “trusted dealer”. We use a trusted dealer here to keep the lesson self-contained and deterministic.

### Step 3: Round 1 (commitments → binding factors → group commitment)

Each signer creates two nonces: a hiding nonce `d_i` and a binding nonce `e_i`, and publishes commitments `D_i = g^{d_i}`, `E_i = g^{e_i}`. The coordinator computes binding factors `ρ_i` from the full commitment list and message, then computes the group commitment `R`.

```python
from dataclasses import dataclass


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
```

This is where many real-world bugs happen: the commitment list must be *sorted* and encoded consistently, or signers and coordinator will compute different `ρ_i`, making signatures fail (or worse, become malleable).

### Step 4: Round 2 (signature shares + share verification)

Given the group commitment `R`, we compute the challenge `c = H(R || PK || msg)`. Each signer computes a signature share `z_i`, and the coordinator can verify each share before aggregating.

```python
@dataclass(frozen=True)
class ParticipantKeyShare:
    identifier: int
    sk_share: int
    pk_share: int


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
```

The per-share verification step is what lets the coordinator identify a faulty/malicious participant *before* publishing an invalid aggregate signature.

### Step 5: Aggregate signature + (nonce reuse) failure mode

Finally, we verify the aggregate signature with standard Schnorr verification. Then we demonstrate the classic Schnorr pitfall: reusing the same nonce across two messages lets an attacker recover the secret key.

```python
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
```

Nonce reuse is catastrophic because Schnorr (and FROST) signatures are linear in both the nonce and the secret key. Always treat nonces as single-use secrets and delete them after signing.

Run it:
`python3 code/main.py`

## Use It

Production-ready FROST implementations live in audited libraries and use real prime-order groups (ristretto255, P-256, secp256k1, etc.), careful transcript/domain separation, and (typically) DKG instead of a trusted dealer.

- **RFC 9591** defines the protocol and helper functions (binding factors, group commitments, challenge, share verification).
- **Rust**: Zcash Foundation’s `frost` crates are a common reference implementation.
- **Protocol stacks**: ecosystems like Bitcoin Taproot (BIP340 Schnorr) often use threshold signing protocols at the wallet layer, not inside consensus.

## Pitfalls

- **Unsorted commitment list**: if `commitment_list` isn’t sorted identically by all parties, `ρ_i` differs and signatures fail (or become transcript-malleable).
- **Inconsistent encoding**: changing scalar/element byte lengths, endianness, or transcript layout breaks compatibility and can create subtle malleability.
- **Nonce reuse or nonce cache bugs**: reusing `(d_i, e_i)` across messages can leak signing shares or break security assumptions.
- **Skipping share verification**: without `verify_signature_share`, you can’t attribute faults; you only learn “aggregate signature is invalid.”
- **Identifier mistakes**: duplicate/zero identifiers or mixing sessions (commitments from one session + message from another) can create invalid or exploitable transcripts.

## Ship It

This lesson ships a coordinator/runbook checklist you can paste into a PR review when integrating threshold Schnorr signing:

- File: `outputs/frost-coordinator-runbook.md`
- Use it to audit: transcript binding, list sorting, encoding, share verification, nonce lifecycle, and error handling.

## Exercises

1. **Easy:** Run `python3 code/main.py`. Observe that the aggregate signature verifies like a normal Schnorr signature.
2. **Medium:** Change the signing subset (e.g., `[2, 4, 5]`) and re-run. Observe how `λ_i` values change and signatures still verify.
3. **Hard:** Pick a real ciphersuite (ristretto255 or secp256k1) and map this toy demo onto an existing FROST library’s API. Identify which parts become “library calls” and which transcript/serialization rules you must still enforce.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Threshold signature | “k-of-n signature” | A single signature that verifies under one public key, produced only if ≥k participants cooperate. |
| Shamir share | “a piece of the key” | A polynomial evaluation `f(i)` such that any `t` shares reconstruct `f(0)` but fewer give no info (in the information-theoretic model). |
| Lagrange coefficient `λ_i` | “reconstruction weight” | The scalar that maps share `s_i` into a contribution to the reconstructed secret at `x=0`. |
| Nonce commitments `(D_i, E_i)` | “public nonces” | Commitments to two per-signer nonces used to form the group commitment `R` without revealing nonce scalars. |
| Binding factor `ρ_i` | “ties nonces to the transcript” | A per-signer hash output derived from the full commitment list and message, preventing transcript mix-and-match. |

## Further Reading

- Connolly et al., *RFC 9591: FROST* (2024) — the protocol spec and helper functions.
- Shamir, *How to Share a Secret* (1979) — the polynomial secret sharing primitive.
- Zcash Foundation, *FROST Book* (ongoing) — practical implementation notes and pitfalls.
