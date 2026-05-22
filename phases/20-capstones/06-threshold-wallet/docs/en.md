# Build a Threshold Wallet

> No single party holds the key — and signing still works.

**Type:** Build
**Languages:** Python
**Prerequisites:** Shamir's secret sharing, ECDSA/Schnorr signatures, MPC protocols, elliptic curves
**Time:** ~90 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Implement Shamir secret sharing and Lagrange interpolation over a finite field
- Explain why distributed key generation (DKG) lets parties share a public key with no party knowing the private key
- Build a simplified threshold Schnorr signing protocol (FROST-style) where t parties sign without reconstructing the secret
- Verify that any t-of-n signer subset produces a valid aggregate signature
- Identify the gap between this toy construction and production MPC wallets (Fireblocks, ZenGo, GG20, FROST)

## The Problem

Every software wallet has a single point of failure: the private key. Steal the key file, drain the wallet. Compromise the signing device, forge every transaction. For individuals this is an inconvenience; for exchanges holding billions of dollars it is an existential risk — and history is full of exactly these failures.

The naive mitigation is to back up the key in multiple places, but that multiplies the attack surface. A threshold wallet takes a different approach: split the private key into n shares, require any t of them to sign. Now an attacker must compromise t separate parties simultaneously, and the security boundary is a set of machines rather than a single file.

The deeper insight — used in production systems like Fireblocks, ZenGo, and the FROST protocol — is that you never need to assemble the key at all. Through distributed key generation (DKG) and threshold signing, the aggregate public key is published and signatures are produced, but the aggregate private key exists only as a mathematical abstraction across the parties. It is never computed in any single place, not even temporarily.

## The Concept

**Shamir Secret Sharing (SSS)** splits a secret `s` into `n` shares using a polynomial `f` of degree `t-1` with `f(0) = s`. Any `t` evaluation points on the polynomial reconstruct `s` via Lagrange interpolation; any `t-1` or fewer reveal nothing (information-theoretically). Shares are points `(i, f(i))` in Z_q.

**Threshold Schnorr signatures** work because Schnorr is linear. In standard Schnorr: sign with nonce `k`, publish `R = g^k`, challenge `e = H(R || msg)`, response `s = k - x*e`. To threshold this:
- Each signer `i` picks nonce `k_i`, publishes `R_i = g^k_i`.
- Aggregate `R = product(R_i)`.
- Each signer computes `s_i = k_i - x_i * e * lambda_i` where `x_i` is their share of the private key and `lambda_i` is the Lagrange coefficient for their index.
- Aggregate `s = sum(s_i)`.

Correctness follows from Lagrange: `sum(x_i * lambda_i) = x`, so the partial responses cancel to a valid Schnorr signature under the aggregate key.

**Distributed Key Generation (DKG)** means parties collaboratively produce `(aggregate_pubkey, shares)` without any party learning the aggregate private key. The Pedersen DKG approach: each party `i` independently generates a secret `x_i`, publishes `X_i = g^x_i` (a commitment), and Shamir-shares `x_i` among all parties. The aggregate public key is `X = product(X_i) = g^(sum x_i)`. Party `j` holds `agg_share_j = sum_i f_i(j)` — a Shamir share of the aggregate secret — but can never see `sum x_i` directly.

## Build It

### Step 1: Shamir secret sharing

```python
P = 2063   # safe prime
Q = 1031   # Sophie Germain prime: (P-1)//2
G = 4      # generator of order Q in Z_P

def mod_inv(a: int, m: int) -> int:
    return pow(a, -1, m)

def _eval_poly(coeffs: List[int], x: int, q: int) -> int:
    result = 0
    for c in reversed(coeffs):
        result = (result * x + c) % q
    return result

def share_secret(
    secret: int, t: int, n: int, rng_seed: int | None = None
) -> List[Tuple[int, int]]:
    if not (1 <= t <= n):
        raise ValueError(f"need 1 <= t <= n, got t={t}, n={n}")
    if not (0 <= secret < Q):
        raise ValueError(f"secret must be in [0, Q); got {secret}")
    rng = random.Random(rng_seed)
    coeffs = [secret] + [rng.randrange(1, Q) for _ in range(t - 1)]
    return [(i, _eval_poly(coeffs, i, Q)) for i in range(1, n + 1)]

def lagrange_coeff(i: int, others: List[int], q: int) -> int:
    num, den = 1, 1
    for j in others:
        if j == i:
            continue
        num = (num * (-j)) % q
        den = (den * (i - j)) % q
    return (num * mod_inv(den, q)) % q

def reconstruct_secret(shares: List[Tuple[int, int]], q: int = Q) -> int:
    if not shares:
        raise ValueError("need at least one share")
    indices = [s[0] for s in shares]
    result = 0
    for i, yi in shares:
        lam = lagrange_coeff(i, indices, q)
        result = (result + yi * lam) % q
    return result
```

`share_secret` picks a random degree `t-1` polynomial over Z_q and evaluates it at `1..n`. `reconstruct_secret` applies Lagrange interpolation: each share contributes `y_i * lambda_i` where `lambda_i` is the basis polynomial for index `i` evaluated at 0. The modular inverse via `pow(a, -1, m)` (Python 3.8+) handles the denominator in Z_q.

### Step 2: Schnorr signatures (single key)

```python
def schnorr_sign(
    private_key: int, msg_bytes: bytes, k_seed: int | None = None
) -> Tuple[int, int]:
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
    e = hash_int(R, msg_bytes)
    lhs = pow(G, s, P) * pow(public_key, e, P) % P
    return lhs == R
```

Standard Schnorr over the group Z_p with generator g. Verification uses the identity `g^s * X^e = g^(k - x*e) * g^(x*e) = g^k = R`. The `hash_int` helper encodes integers as 8-byte big-endian before SHA-256, giving a deterministic, domain-separated hash.

### Step 3: Distributed Key Generation

```python
@dataclass
class DKGResult:
    party_pubkeys: List[int]
    aggregate_shares: List[Tuple[int, int]]
    aggregate_pubkey: int

def dkg_simulate(t: int, n: int, rng_seed: int | None = None) -> DKGResult:
    if not (1 <= t <= n):
        raise ValueError(f"need 1 <= t <= n, got t={t}, n={n}")
    rng = random.Random(rng_seed)
    party_secrets = [rng.randrange(1, Q) for _ in range(n)]
    party_pubkeys = [pow(G, xi, P) for xi in party_secrets]
    all_shares_matrix: List[List[Tuple[int, int]]] = []
    for i, xi in enumerate(party_secrets):
        seed = (rng_seed * 100 + i) if rng_seed is not None else None
        shares = share_secret(xi, t, n, rng_seed=seed)
        all_shares_matrix.append(shares)
    aggregate_shares: List[Tuple[int, int]] = []
    for j in range(1, n + 1):
        agg_val = sum(all_shares_matrix[i][j - 1][1] for i in range(n)) % Q
        aggregate_shares.append((j, agg_val))
    aggregate_pubkey = 1
    for pk in party_pubkeys:
        aggregate_pubkey = aggregate_pubkey * pk % P
    return DKGResult(
        party_pubkeys=party_pubkeys,
        aggregate_shares=aggregate_shares,
        aggregate_pubkey=aggregate_pubkey,
    )
```

Each party `i` independently contributes a random secret `x_i` and its commitment `X_i = g^x_i`. The aggregate public key `X = product(X_i) = g^(sum x_i)` is public. Party `j`'s aggregate share `sum_i f_i(j)` is a Shamir share of `sum x_i` — but no party ever computes that sum in the clear.

### Step 4: Threshold Schnorr signing

```python
def threshold_sign(
    msg_bytes: bytes,
    signer_indices: List[int],
    aggregate_shares: List[Tuple[int, int]],
    aggregate_pubkey: int,
    rng_seed: int | None = None,
) -> Tuple[int, int]:
    if len(signer_indices) < 1:
        raise ValueError("need at least one signer")
    rng = random.Random(rng_seed)
    nonces: dict[int, int] = {}
    R_vals: dict[int, int] = {}
    for idx in signer_indices:
        ki = rng.randrange(1, Q) if rng_seed is not None else secrets.randbelow(Q - 1) + 1
        nonces[idx] = ki
        R_vals[idx] = pow(G, ki, P)
    R_agg = 1
    for ri in R_vals.values():
        R_agg = R_agg * ri % P
    e = hash_int(R_agg, msg_bytes)
    shares_dict = dict(aggregate_shares)
    partial_sigs: dict[int, int] = {}
    for idx in signer_indices:
        xi_share = shares_dict[idx]
        lam = lagrange_coeff(idx, signer_indices, Q)
        si = (nonces[idx] - xi_share * e * lam) % Q
        partial_sigs[idx] = si
    s_agg = sum(partial_sigs.values()) % Q
    return (R_agg, s_agg)
```

Each signer contributes one nonce commitment `R_i = g^k_i` and one partial response `s_i`. The aggregate `(R, s)` is a standard Schnorr signature under the aggregate public key `X`. The Lagrange coefficients ensure `sum(x_i * lambda_i) = x` even though only a t-subset signs.

### Step 5: 3-of-5 wallet demo

```python
def main() -> None:
    # --- Shamir ---
    secret = 42
    t, n = 3, 5
    shares = share_secret(secret, t, n, rng_seed=7)
    assert reconstruct_secret(shares[:3]) == secret
    assert reconstruct_secret([shares[1], shares[3], shares[4]]) == secret
    assert reconstruct_secret(shares[:2]) != secret  # under-threshold

    # --- Single-key Schnorr ---
    x = 123
    X = pow(G, x, P)
    msg = b"transfer 10 ETH"
    R, s = schnorr_sign(x, msg, k_seed=42)
    assert schnorr_verify(X, msg, R, s)
    assert not schnorr_verify(X, b"tampered message", R, s)

    # --- DKG ---
    dkg = dkg_simulate(t=3, n=5, rng_seed=42)
    agg_secret_check = reconstruct_secret(dkg.aggregate_shares[:3])
    assert pow(G, agg_secret_check, P) == dkg.aggregate_pubkey

    # --- Threshold sign (two different quorums) ---
    tx_msg = b"send 1 BTC to Alice"
    R_t, s_t = threshold_sign(tx_msg, [1, 2, 3], dkg.aggregate_shares, dkg.aggregate_pubkey, rng_seed=77)
    assert schnorr_verify(dkg.aggregate_pubkey, tx_msg, R_t, s_t)

    R_t2, s_t2 = threshold_sign(tx_msg, [2, 4, 5], dkg.aggregate_shares, dkg.aggregate_pubkey, rng_seed=88)
    assert schnorr_verify(dkg.aggregate_pubkey, tx_msg, R_t2, s_t2)
```

Run it:
```
python3 code/main.py
```

## Use It

Production threshold wallets use this same mathematical skeleton but replace every piece with production-grade components:

- **Group**: secp256k1 or ed25519 instead of Z_p with a small prime.
- **DKG**: Pedersen DKG with VSS (verifiable secret sharing) — each party proves their polynomial commitments are consistent, preventing malicious parties from biasing the key.
- **Threshold signing**: FROST (Flexible Round-Optimized Schnorr Threshold) for Schnorr/ed25519; GG20/CGGMP21 for ECDSA (ECDSA is not linear, so threshold ECDSA requires MPC techniques not needed here).
- **Nonce safety**: FROST uses a pre-commitment round to bind nonces before the message is known, preventing rogue-key and nonce-reuse attacks.
- **Secure channels**: In real protocols, each party-to-party message travels over an authenticated encrypted channel.

Libraries: `frost-dalek` (Rust/FROST), `tss-lib` (Go/GG20, used by Binance), `threshold-bls` (JS), `multi-party-ecdsa` (Rust/CGGMP21).

## Pitfalls

- **Reusing nonces**: In threshold Schnorr, nonce reuse across two signing sessions leaks the secret share. Each session must generate fresh nonces.
- **Rushing attacks in DKG**: A malicious last party can abort after seeing others' public commitments and restart until the aggregate key is biased to their advantage. Pedersen DKG with commitment-then-reveal rounds mitigates this.
- **t-of-n confusion**: Threshold `t` means "at least t signers required." Using t=1 gives no threshold protection; using t=n means any single missing party blocks signing.
- **Lagrange over the wrong field**: Lagrange coefficients must be computed mod q (the group order), not mod p (the field prime) or as ordinary rationals.
- **No authentication of shares**: This demo trusts all shares. In production, each received share is verified against the sender's public commitment `g^(a_ij)` from the DKG broadcast.
- **Small group**: P=2063, Q=1031 are toy parameters. Real systems use 256-bit or larger groups.

## Ship It

Save a reusable threshold wallet architecture guide to `outputs/threshold-wallet-design-guide.md`. It covers t-of-n tradeoffs, DKG protocol selection, and security considerations for teams building MPC wallets.

## Exercises

1. **Easy.** Run `python3 code/main.py`. Confirm that `reconstruct_secret(shares[:2])` returns the wrong answer for a 3-of-5 scheme, and that both quorums `[1,2,3]` and `[2,4,5]` produce valid signatures.
2. **Medium.** Add a `verify_share` function that checks a received Shamir share `(j, f_i(j))` against the dealer's public commitment `C_i = g^(x_i) mod p` (use the commitment `g^(a_i0) * ... * g^(a_i(t-1))^(j^(t-1))` form). Test that a corrupted share is rejected.
3. **Hard.** Extend `dkg_simulate` to detect a cheating party: have one party submit an inconsistent share (wrong polynomial evaluation) and show that commitment verification catches it before the signing phase.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|------------------------|
| Shamir Secret Sharing | "Split the key into pieces" | A degree-(t-1) polynomial where f(0) = secret; any t points reconstruct, t-1 reveal nothing |
| DKG | "Nobody knows the private key" | A multi-round protocol where parties collaboratively commit to a shared public key without any party computing the aggregate private key |
| Threshold signature | "Multi-sig" (imprecise) | A single valid signature produced by t-of-n parties via partial signing and aggregation — distinct from on-chain multi-sig where n separate signatures are stored |
| Lagrange coefficient | "The interpolation weight" | The scalar lambda_i such that sum(f(i) * lambda_i) = f(0); computed mod the group order |
| FROST | "A threshold Schnorr scheme" | Flexible Round-Optimized Schnorr Threshold — a two-round protocol with provable security against adaptive adversaries |
| GG20 / CGGMP21 | "Threshold ECDSA" | MPC protocols for threshold ECDSA; more complex than threshold Schnorr because ECDSA uses a modular inverse that breaks linearity |
| Nonce reuse | "Using k twice" | Catastrophic in threshold Schnorr: two signatures with the same k and different messages leak the secret share algebraically |

## Further Reading

- Komlo & Goldberg, "FROST: Flexible Round-Optimized Schnorr Threshold Signatures" (2020) — the canonical threshold Schnorr scheme with security proof
- Gennaro & Goldfeder, "Fast Multiparty Threshold ECDSA with Fast Trustless Setup" (2020, GG20) — the protocol behind many production MPC wallets
- Pedersen, "Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing" (1991) — VSS and the DKG commitment scheme
- Nick, Ruffing & Seurin, "MuSig2: Simple Two-Round Schnorr Multi-Signatures" (2021) — a simpler t=n multi-sig variant worth comparing with FROST
