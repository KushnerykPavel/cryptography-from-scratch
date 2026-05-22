# VRFs — Verifiable Random Functions

> Randomness anyone can verify but no one can predict — the primitive that powers Cardano leader election, Chainlink VRF, and DNSSEC.

**Type:** Learn | Build
**Languages:** Python
**Prerequisites:** 01-bitcoin-stack (Schnorr signatures), modular arithmetic, discrete log assumption
**Time:** ~75 minutes

> Warning: Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain the three VRF properties: pseudorandomness, provability, and uniqueness
- Compute a VRF output and proof over a discrete-log MODP group
- Implement and verify the Schnorr-style dleq proof that binds gamma to pk
- Distinguish a VRF from a PRF, a hash function, and a commitment scheme
- Apply VRFs to leader election and unbiasable randomness beacon designs

## The Problem

Blockchains frequently need unpredictable randomness: which validator proposes the next block, which shard gets assigned which committee, what lottery ticket wins. Using an ordinary hash `H(seed)` fails because a malicious proposer can grind seeds until they get a favorable output. Using a random oracle that no one controls fails because you need someone to call it — and that someone can withhold the result.

The ideal primitive produces a value that is pseudorandom (no one can distinguish it from uniform random before it is revealed), unique (there is exactly one correct output for a given key and message), and verifiable (anyone can confirm the output is correct given a proof, without knowing the secret key). This combination is exactly what a Verifiable Random Function provides.

Cardano's Ouroboros Praos uses VRFs for slot leader election. Chainlink VRF uses them for on-chain randomness in smart contracts. IETF RFC 9381 standardizes ECVRF for DNSSEC. In each case the VRF holder commits to a deterministic output that no one else can predict or manipulate, but that everyone can verify after the fact.

## The Concept

### The construction at a glance

A DH-VRF over a multiplicative group works like a Schnorr signature where the "message" is hashed into the group itself:

```
pk   = g^sk mod p          (public key, same as DH)
H    = hash_to_group(m)    (message mapped to group element)
gamma = H^sk mod p          (VRF output seed — "the random value")
beta  = SHA-256(gamma)      (final pseudorandom bytes)
proof = (c, s)              (Schnorr dleq proof: same sk used for pk and gamma)
```

The proof certifies that `log_g(pk) == log_H(gamma)` — both equal `sk` — without revealing `sk`. This is a standard discrete-log equality (dleq) proof, the same structure used in Pedersen commitments and ElGamal rerandomization.

### Why the output is pseudorandom

Before `gamma` is revealed, it looks uniform because the discrete log problem is hard: given `H` and `pk`, computing `H^sk` without knowing `sk` is infeasible. Once revealed with a valid proof, the output is uniquely determined — there is exactly one `gamma` for a given `(sk, m)` pair.

### The proof structure

```
k   ← random nonce
U   = g^k mod p          (commitment on g)
V   = H^k mod p          (commitment on H)
c   = SHA-256(pk ‖ gamma ‖ U ‖ V) mod q    (Fiat-Shamir challenge)
s   = (k − sk·c) mod q   (response)
```

Verification recomputes:
```
U'  = g^s · pk^c mod p
V'  = H^s · gamma^c mod p
c'  = SHA-256(pk ‖ gamma ‖ U' ‖ V') mod q
accept iff c' == c
```

If `s = k − sk·c`, then `g^s · pk^c = g^(k − sk·c) · g^(sk·c) = g^k = U`. Similarly for V. The Fiat-Shamir transform makes this non-interactive.

### Group choice

This implementation uses RFC 2409 Oakley Group 2: a 1024-bit safe prime `p = 2q+1` with generator `g = 2`. For a safe prime, squaring any non-trivial element maps into the unique q-order subgroup, so `hash_to_group(m) = candidate^2 mod p` where `candidate = SHA-256(m) mod p`.

| Parameter | Value |
|-----------|-------|
| p | RFC 2409 1024-bit safe prime |
| g | 2 |
| q | (p−1)/2, 1023-bit prime |
| Hash | SHA-256 |
| Proof | Schnorr dleq (Fiat-Shamir) |

## Build It

### Step 1: Group Setup and Key Generation

```python
_P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF"
)
P: int = int(_P_HEX, 16)
G: int = 2
SUBGROUP_ORDER: int = (P - 1) // 2

def vrf_keygen(sk: int) -> int:
    return pow(G, sk, P)
```

The public key is a standard DH key. The security rests on the computational Diffie-Hellman assumption in this group: given `g^sk`, recovering `sk` is infeasible.

### Step 2: Hash to Group

```python
def vrf_hash_to_group(m: bytes) -> int:
    counter = 0
    while True:
        candidate = _sha256_int(m + struct.pack(">I", counter)) % P
        h = pow(candidate, 2, P)
        if h not in (0, 1, P - 1):
            return h
        counter += 1
```

Hashing to the group must be deterministic and collision-resistant. For a safe prime `p = 2q+1`, every quadratic residue is an element of the q-order subgroup. Squaring a random element maps into that subgroup with probability ~1/2; the while loop retries on the rare degenerate cases (the loop terminates in an expected 2 iterations).

### Step 3: VRF Evaluate

```python
def vrf_evaluate(sk: int, m: bytes, k: int) -> tuple[int, int, int]:
    pk = vrf_keygen(sk)
    h = vrf_hash_to_group(m)
    gamma = pow(h, sk, P)

    u = pow(G, k, P)
    v = pow(h, k, P)

    c_data = (
        _encode_fixed(pk) + _encode_fixed(gamma) +
        _encode_fixed(u) + _encode_fixed(v)
    )
    c = _sha256_int(c_data) % SUBGROUP_ORDER
    s = (k - sk * c) % SUBGROUP_ORDER

    return gamma, c, s
```

`gamma = H^sk` is the VRF's core output — pseudorandom because computing it requires `sk`, and unique because there is exactly one value for a given `(sk, m)`. The proof `(c, s)` certifies the same `sk` was used without revealing it.

### Step 4: VRF Verify

```python
def vrf_verify(pk: int, m: bytes, gamma: int, c: int, s: int) -> bool:
    h = vrf_hash_to_group(m)

    u_prime = pow(G, s, P) * pow(pk, c, P) % P
    v_prime = pow(h, s, P) * pow(gamma, c, P) % P

    c_data = (
        _encode_fixed(pk) + _encode_fixed(gamma) +
        _encode_fixed(u_prime) + _encode_fixed(v_prime)
    )
    c_check = _sha256_int(c_data) % SUBGROUP_ORDER
    return c_check == c
```

Verification recomputes `U'` and `V'` from `(s, c)` and checks the Fiat-Shamir challenge. A valid proof guarantees that the prover used the same secret key for both `pk` and `gamma`.

### Step 5: Proof to Hash

```python
def vrf_proof_to_hash(gamma: int) -> bytes:
    return hashlib.sha256(_encode_fixed(gamma)).digest()
```

The final VRF output `beta` is a hash of `gamma` rather than `gamma` itself. This ensures the output is a fixed-length uniform byte string regardless of group representation, and prevents any algebraic structure of `gamma` from leaking into `beta`.

Run it:
```
python3 code/main.py
```

## Use It

| Task | Production library / standard |
|------|-------------------------------|
| ECVRF (RFC 9381) | `vrf-py` (Algorand), `fastecdsa` with custom ECVRF |
| Cardano slot election | `cardano-crypto` — VRF over curve25519 |
| Chainlink VRF | Solidity `VRF.sol` + off-chain coordinator |
| DNSSEC NSEC5 | `nsec5` library (NSEC5 RFC draft) |
| Go implementation | `r2ishiguro/vrf` (go), `nicholasgasior/gvrf` |

RFC 9381 (ECVRF) is the current IETF standard. It uses `ECVRF-EDWARDS25519-SHA512-ELL2` as the recommended suite, which requires the `cryptography` or `PyNaCl` library. The structure is identical to this lesson's construction, substituting Edwards25519 group operations for MODP exponentiation.

## Pitfalls

1. **Reusing the nonce k.** If `k` is reused across two evaluations with the same `sk`, an attacker can recover `sk` by solving a linear equation from the two `(c, s)` pairs — identical to the Schnorr nonce-reuse attack. In production, `k` must be derived deterministically from `(sk, m, randomness)` as in RFC 9381 §5.4.2.

2. **Variable-length encoding in the challenge hash.** If the inputs to the challenge hash `H(pk ‖ gamma ‖ U ‖ V)` are encoded with variable length (no leading zeros), two different value combinations can produce the same byte string. This lesson uses fixed 128-byte encodings. RFC 9381 uses fixed-length point encodings on the elliptic curve.

3. **Not checking that gamma is in the correct subgroup.** A malicious prover could submit a `gamma` outside the q-order subgroup. For a safe prime, this check is `pow(gamma, q, p) == 1`. Skipping this check may allow forgeries in degenerate cases.

4. **Treating beta as a commitment before the proof is published.** A VRF output is pseudorandom only before the proof is revealed. Once `gamma` and `(c, s)` are published, the output is fully determined and public. Do not use beta as a secret after revealing the proof.

5. **Using 1024-bit MODP in new systems.** A 1024-bit MODP group provides roughly 80 bits of security — below modern recommendations (128 bits). Use RFC 9381 ECVRF over curve25519 for any real deployment.

## Ship It

This lesson produces `outputs/vrf-audit-checklist.md` — a reviewer checklist for VRF implementations covering proof structure, nonce safety, group membership checks, and output handling.

## Exercises

1. Easy. Run `python3 code/main.py`. In Step 4, observe that `verify with tampered gamma = False`. Manually change one bit of `gamma` in the source and confirm verification still fails.
2. Medium. Implement a simple randomness beacon: given a sequence of 10 messages `b"slot-0"` through `b"slot-9"`, evaluate the VRF on each with the same key and a deterministic nonce `k = H(sk ‖ message)`. Print the first 4 bytes of each `beta` as a "winning lottery number." Verify all proofs.
3. Hard. Implement a threshold VRF: split `sk` using (2-of-3) Shamir secret sharing, have each shard holder produce a partial `gamma_i = H^sk_i mod p`, and reconstruct the full `gamma` using Lagrange interpolation in the exponent. Verify the reconstructed output against `pk = g^sk`.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|------------------------|
| VRF | "verifiable random" | A function that maps (sk, m) to a pseudorandom output with a non-interactive proof of correctness |
| gamma | "VRF output" | The group element `H^sk`; seeds the final byte output after hashing |
| beta | "VRF output bytes" | SHA-256(gamma) — the actual pseudorandom output consumed by applications |
| dleq proof | "discrete log equality proof" | A Schnorr-style ZK proof that two group elements share the same discrete log |
| hash_to_group | "map to curve/group" | Deterministic injective function from byte strings to group elements; must be collision-resistant |
| Fiat-Shamir | "non-interactive proof" | Heuristic that replaces an interactive verifier challenge with a hash of the transcript |

## Further Reading

- Silvio Micali, Michael Rabin, Salil Vadhan, "Verifiable Random Functions" (FOCS 1999) — original VRF definition and construction
- RFC 9381: Verifiable Random Functions (VRFs), Goldberg et al. (2023) — current IETF standard with ECVRF suites and test vectors
- Algorand technical report, "Algorand: Scaling Byzantine Agreements for Cryptocurrencies" (2017) — describes VRF-based leader election in a production blockchain
- Adam Langley, "DNSSEC and VRFs" (imperialviolet.org, 2015) — accessible motivation for VRFs in DNS authenticated denial of existence
