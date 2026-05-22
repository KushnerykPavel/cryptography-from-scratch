# BLS Aggregation in Eth2

> One signature for 500,000 validators — BLS aggregation is why Ethereum's beacon chain is practical.

**Type:** Learn | Build
**Languages:** Python
**Prerequisites:** 01-bitcoin-stack (Schnorr signatures), basic modular arithmetic
**Time:** ~70 minutes

> Warning: Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain why naively summing public keys is insecure (rogue key attack)
- Compute a BLS signature, aggregate signature, and aggregate public key over a toy prime field
- Implement proof-of-possession and describe why it defeats the rogue key attack
- Distinguish same-message aggregation from multi-message aggregation
- Apply the toy model's aggregation algebra to explain how Ethereum 2 compresses validator signatures

## The Problem

Ethereum's beacon chain finalizes blocks with attestations from up to 512,000 active validators. If each validator broadcast a separate 96-byte BLS12-381 signature, the network would drown in ~49 MB of signature data per slot, every 12 seconds. Verification would require hundreds of thousands of individual pairing operations, well beyond any realistic hardware budget.

BLS signatures solve this by being algebraically homomorphic: the sum of individual signatures is a valid signature under the sum of the corresponding public keys. A committee of 512 validators produces exactly one 96-byte aggregate signature and one aggregate public key. A single pairing check verifies all 512 attestations simultaneously. This is the engineering miracle that makes Ethereum's proof-of-stake consensus tractable.

The catch is subtle but dangerous: naive aggregation is insecure. An attacker can craft a "rogue key" that, when added to a victim's key, makes the aggregate equal to a key the attacker controls alone. The defense — proof-of-possession — requires each validator to sign their own public key before joining any aggregate. This lesson builds the complete story from scratch.

## The Concept

### The toy model

Real BLS operates over a pairing-friendly elliptic curve (BLS12-381). Pairings are expensive to implement from scratch and obscure the core idea. This lesson uses a linear analog over Z_Q (integers mod a prime Q = 1,000,003):

| Real BLS (BLS12-381) | Toy model (Z_Q) |
|----------------------|-----------------|
| sk in Z_r, pk = sk * G1 | sk integer, pk = sk mod Q |
| H(m) in G1 via hash-to-curve | H(m) = SHA-256(m) mod Q |
| sig = sk * H(m) in G1 | sig = sk * H(m) mod Q |
| Pairing verification: e(sig, G2) == e(H(m), pk) | Check: sig == H(m) * pk mod Q |
| Aggregation: sum in G1 | Aggregation: sum mod Q |

The aggregation algebra is identical. What is missing is the bilinear pairing, which in production BLS allows verification of `sum(sigs)` against `sum(pks)` without knowing individual components. In the toy model we verify the same algebraic identity directly.

### Why aggregation works

If signer i has key `sk_i` and signs message `m`:
```
sig_i = H(m) * sk_i  (mod Q)
```

Sum of signatures:
```
agg_sig = sum(sig_i) = H(m) * sum(sk_i) = H(m) * agg_pk  (mod Q)
```

The verification equation `agg_sig == H(m) * agg_pk` holds because multiplication distributes over addition in a field. This is the same identity that makes real BLS work.

### The rogue key attack

Suppose victim has `pk_v = sk_v mod Q`. Attacker picks `attacker_sk` and publishes:
```
pk_attacker = (attacker_sk - pk_v) mod Q
```

Now:
```
naive_agg_pk = pk_v + pk_attacker = pk_v + attacker_sk - pk_v = attacker_sk  (mod Q)
```

The attacker can sign `m` with `attacker_sk` alone and produce a "valid" aggregate signature — without ever knowing `sk_v`. The victim's key is effectively erased.

### Proof-of-Possession defense

Before entering any aggregate, each signer proves they know the secret key behind their public key. They sign a domain-tagged representation of their own pk:

```
pop = sign(sk, "BLS-POP|" + pk_bytes)
```

A rogue key `pk' = attacker_sk - pk_v` is computable, but the attacker cannot produce a valid PoP for `pk'` because there is no secret key `x` such that `bls_keygen(x) == pk'` AND `bls_sign(x, "BLS-POP|" + pk'_bytes)` verifies — unless the attacker happens to know a preimage of `pk'`, which requires solving the discrete log.

## Build It

### Step 1: Key Generation and Hashing

```python
Q = 1_000_003

def bls_hash_to_g1(message: bytes) -> int:
    digest = hashlib.sha256(message).digest()
    return int.from_bytes(digest, "big") % Q

def bls_keygen(sk: int) -> int:
    return sk % Q
```

`bls_hash_to_g1` maps an arbitrary message to a group element by hashing it with SHA-256 and reducing mod Q. `bls_keygen` derives the public key — in Z_Q arithmetic, scalar multiplication by the generator is just the identity, so `pk = sk mod Q`.

### Step 2: Sign and Verify

```python
def bls_sign(sk: int, message: bytes) -> int:
    h = bls_hash_to_g1(message)
    return (h * sk) % Q

def bls_verify(pk: int, message: bytes, sig: int) -> bool:
    h = bls_hash_to_g1(message)
    return sig % Q == (h * pk) % Q
```

The signature is the product of the message hash and the secret key. Verification checks the same product using the public key. This mirrors the real BLS verification equation, which uses pairings to check `e(sig, G2) == e(H(m), pk)`.

### Step 3: Aggregation

```python
def bls_aggregate_pks(pks: list[int]) -> int:
    return sum(pks) % Q

def bls_aggregate_sigs(sigs: list[int]) -> int:
    return sum(sigs) % Q

def bls_verify_aggregate(agg_pk: int, message: bytes, agg_sig: int) -> bool:
    h = bls_hash_to_g1(message)
    return agg_sig % Q == (h * agg_pk) % Q

def bls_verify_aggregate_multi(
    pks: list[int], messages: list[bytes], agg_sig: int
) -> bool:
    expected = sum(bls_hash_to_g1(m) * pk for pk, m in zip(pks, messages)) % Q
    return agg_sig % Q == expected
```

Aggregation is pointwise addition mod Q. For same-message aggregation, verification uses the summed public key and the single message. For multi-message aggregation, verification recomputes the full sum `sum(H(m_i) * pk_i)` — this requires knowing each individual pk and message, but saves bandwidth when signatures were already batched.

### Step 4: Rogue Key Attack

```python
def bls_rogue_key_attack(target_pk: int, attacker_sk: int) -> int:
    return (attacker_sk - target_pk) % Q
```

The attacker returns a rogue public key. When the victim's pk and the rogue pk are summed naively, the result equals `attacker_sk % Q`. The attacker can then sign any message with `attacker_sk` and have it verify against the "aggregate".

### Step 5: Proof-of-Possession Defense

```python
_POP_TAG = b"BLS-POP|"

def bls_sign_with_pop(sk: int) -> tuple[int, int]:
    pk = bls_keygen(sk)
    pk_bytes = _POP_TAG + pk.to_bytes(4, "big")
    pop = bls_sign(sk, pk_bytes)
    return pk, pop

def bls_verify_pop(pk: int, pop: int) -> bool:
    pk_bytes = _POP_TAG + pk.to_bytes(4, "big")
    return bls_verify(pk, pk_bytes, pop)
```

Every legitimate participant generates a proof-of-possession before their key is accepted into any aggregate. The PoP domain tag `"BLS-POP|"` prevents cross-protocol attacks where a normal message signature is mistaken for a PoP.

Run it:
```
python3 code/main.py
```

## Use It

| Task | Production library |
|------|--------------------|
| BLS12-381 signatures | `py_ecc` (Ethereum Foundation), `blspy` (Chia Network) |
| Ethereum validator signing | `eth2-py` / `py-ssz` with `py_ecc.bls` |
| BLS in Go | `kilic/bls12-381`, used in go-ethereum |
| BLS in Rust | `blst` (supranational) — fastest production library |
| Standard spec | IETF draft-irtf-cfrg-bls-signature-05 |

In production Ethereum code, `py_ecc.bls.G2ProofOfPossession.Sign(sk, msg)` produces a G2 point signature, and `Aggregate(sigs)` sums G2 points. The PoP scheme is mandatory in the Ethereum consensus spec (EIP-2335, BLS Key Management).

## Pitfalls

1. **Skipping PoP registration.** Some early BLS libraries allowed aggregation without verifying proofs-of-possession. An attacker registering a rogue key could forge signatures over any message signed by other participants. Always check PoP before adding a key to any aggregate set.

2. **Aggregating across different messages without batching.** Same-message aggregation (`verify_aggregate`) is fast but only works when all signers signed the same message. Multi-message aggregation requires knowing every (pk, message) pair — if a verifier loses track of which signer signed what, verification becomes impossible.

3. **sk = 0 or pk = 1 (group identity).** A zero secret key makes all signatures trivially forgeable. A pk that is the group identity will verify any signature for any message. Always validate that `1 <= sk < Q` and `pk != 0` and `pk != 1`.

4. **Reusing the toy model in production.** The Z_Q toy uses ordinary integers and has no hardness guarantee — discrete log in Z_Q is trivial. Never use this code outside of educational contexts.

5. **Not domain-separating PoP from message signatures.** Without the `"BLS-POP|"` tag, a normal message signature could be repurposed as a PoP. If the application signs messages that happen to be encoded public keys, the PoP check provides no security.

## Ship It

This lesson produces `outputs/bls-aggregation-audit-checklist.md` — a reviewer checklist for BLS implementations in production systems. Use it when auditing validator clients, threshold signing protocols, or any codebase that aggregates BLS signatures.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that the rogue key attack produces `forged sig verifies = True` in Step 4, then that `fake_pop_valid = False` in Step 5. Trace through the math to confirm each output.
2. Medium. Extend the implementation: add a `bls_batch_verify(entries: list[tuple[int, bytes, int]]) -> bool` function that verifies multiple independent (pk, message, sig) triples with a single check by computing `sum(r_i * sig_i) == sum(r_i * H(m_i) * pk_i)` for random scalars `r_i`. Benchmark it against calling `bls_verify` in a loop.
3. Hard. Implement a simplified threshold BLS: distribute the secret key among N participants using Shamir secret sharing (t-of-N), have each signer produce a partial signature, and combine t partial signatures into a full aggregate. Verify the result with `bls_verify`.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|------------------------|
| BLS | "a signature scheme" | Boneh-Lynn-Shacham — uses bilinear pairings to make signatures additively homomorphic |
| Aggregation | "combining signatures" | Summing group elements; valid because pairing is bilinear |
| Rogue key attack | "public key substitution" | Attacker chooses pk such that pk + victim_pk equals a key the attacker controls |
| Proof-of-Possession | "PoP" | A signature over one's own public key, proving knowledge of the secret key |
| G1 / G2 | "the two groups" | Distinct prime-order groups on BLS12-381 used for keys vs. signatures or vice versa |
| agg_pk | "aggregate public key" | Sum of participating public keys; valid only if all PoPs checked first |

## Further Reading

- Dan Boneh, Ben Lynn, Hovav Shacham, "Short Signatures from the Weil Pairing" (2001) — original BLS paper; section 4 covers aggregation
- Ethereum consensus spec, `bls.py` (github.com/ethereum/consensus-specs) — reference implementation of PoP-secured aggregation used in the beacon chain
- IETF draft-irtf-cfrg-bls-signature-05 — protocol standard covering PopProve, PopVerify, and AggregateVerify
- Justin Drake, "BLS12-381 for the Rest of Us" (HackMD, 2019) — accessible explanation of why BLS12-381 was chosen and how pairings work
