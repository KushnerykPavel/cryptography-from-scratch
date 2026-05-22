# Anonymous Credentials — BBS+

> Sign once, disclose selectively — without revealing what you kept hidden.

**Type:** Build
**Languages:** Python
**Prerequisites:** 01-bitcoin-stack (elliptic curve basics), 03-bls-aggregation-eth2 (pairing concepts)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.
> Real BBS+ requires bilinear pairings on BLS12-381. This toy works over Z_p
> and verifies with the issuer secret key for clarity; see "Use It" for production libraries.

## The Problem

Your digital identity contains dozens of attributes: name, birthdate, nationality,
address, employer, income range, health status.  Every time you authenticate, you
hand over all of them — even when the relying party only needs one.

Traditional digital certificates (X.509, JWT) work like a photocopied passport: the
verifier sees every field even if they only asked to check your age.  Worse, every
presentation is linkable — the signature is the same each time, so different verifiers
can collude to track you.

What you need is a credential scheme where:

1. An issuer signs all your attributes at once.
2. You can later present any subset of attributes with a proof that they came from the
   issuer's signature — without revealing the rest.
3. Each presentation is unlinkable to previous ones (in the full ZK version).

**BBS+ signatures** (Boneh-Boyen-Shacham, extended) solve all three requirements
using bilinear pairings on elliptic curves.  They underpin W3C Verifiable Credentials,
the EU Digital Identity Wallet (EUDI), and the IETF BBS draft standard.

## The Concept

### Message commitment B

The signer combines all messages into a single group element called B:

```
B = G * H_0^s * H_1^m_1 * H_2^m_2 * ... * H_L^m_L  (mod P)
```

- `G, H_0, H_1, ..., H_L` are public generators (random-looking group elements).
- `s` is a random blinding factor that hides B from the issuer.
- `m_1 ... m_L` are the credential attributes (integers in Z_p).

Each generator `H_i` is "dedicated" to one attribute slot, so changing any message
changes B completely.

### BBS+ signature A

The issuer holds secret key `sk` and computes:

```
A = B^(1/(e + sk))  (exponent inverse mod group order)
```

The signature is the triple `(A, e, s)`.

**Verification** (toy version — real BBS+ uses a pairing):

```
A^(e + sk)  ==  B
```

In production the verifier does NOT have `sk`. Instead they use the pairing equation:

```
e(A, W · G^e) == e(B, G)   where W = G^sk is the public key
```

This is the key property: the issuer's identity is bound into the check without
revealing `sk`.

### Selective disclosure

To disclose only attributes `i ∈ R` (revealed set), the prover:

1. Passes `(A, e, s)` to the verifier.
2. For each hidden attribute `j ∉ R`, sends the partial commitment `C_j = H_{j+1}^{m_j}`.
3. Reveals the plain values for `i ∈ R`.

The verifier reconstructs:

```
B = G * H_0^s * prod(H_{i+1}^{m_i} for i in R) * prod(C_j for j not in R)
```

and checks the signature.  The hidden values `m_j` never appear — only their
group-element commitments do.

```
Issuer                     Holder                    Verifier
------                     ------                    --------
keygen() -> sk, pk         receive credential        know pk
sign(sk, [m1..mL])         sig = (A, e, s)
  -> (A, e, s)             create_proof(sig,         verify_proof(pk, proof)
                             reveal=[0,2])
                             -> proof with
                                revealed: {0:m0, 2:m2}
                                hidden: {C_1, C_3}
```

### Unlinkability (full ZK — not in this toy)

In the full BBS+ protocol, the holder randomises `(A, e, s)` before each presentation
by computing `A' = A * r1` for a fresh random `r1`, then provides a zero-knowledge
proof of knowledge of `(A, e, s, r1)` relative to `A'`.  Different presentations
of the same credential look completely different to the verifier.  This toy omits
randomisation for clarity.

## Build It

### Step 1: Group Parameters and Generators

```python
P = (1 << 127) - 1   # Mersenne prime — toy group order
G = 3                 # generator

def _generators(L):
    return [pow(G, i + 1, P) for i in range(L + 1)]
    # H_0 = G^1, H_1 = G^2, ..., H_L = G^(L+1)
```

### Step 2: Key Generation

```python
def bbs_keygen():
    sk = <random scalar in Z_P>
    pk = pow(G, sk, P)
    return sk, pk
```

### Step 3: Sign

```python
def bbs_sign(sk, messages):
    hs = _generators(len(messages))
    e, s = <random scalars>
    B = G * pow(hs[0], s) * prod(pow(hs[i+1], m) for i, m in enumerate(messages))
    exp_inv = pow((e + sk) % (P-1), -1, P-1)   # invert mod group order
    A = pow(B, exp_inv, P)
    return A, e, s
```

### Step 4: Verify (toy — uses sk)

```python
def bbs_verify(sk, messages, sig):
    A, e, s = sig
    B = recompute_B(s, messages)
    return pow(A, (e + sk) % (P-1), P) == B
```

### Step 5: Selective Disclosure Proof

```python
def bbs_create_proof(messages, sig, revealed):
    A, e, s = sig
    hidden_commitments = {
        i: pow(H[i+1], messages[i], P)
        for i in range(L) if i not in revealed
    }
    return {
        "A": A, "e": e, "s": s,
        "revealed_messages": {i: messages[i] for i in revealed},
        "hidden_commitments": hidden_commitments,
    }

def bbs_verify_proof(sk, proof):
    # reconstruct B from revealed values + hidden commitments
    B = G * H0^s * prod(revealed) * prod(hidden_commitments)
    return pow(A, (e + sk) % (P-1), P) == B
```

## Use It

Production BBS+ libraries and standards:

| Library / Standard | Language | Curve | Notes |
|--------------------|----------|-------|-------|
| [mattrglobal/bbs-signatures](https://github.com/mattrglobal/bbs-signatures) | TypeScript/Rust | BLS12-381 | W3C VC compatible |
| [hyperledger/ursa](https://github.com/hyperledger/ursa) | Rust | BLS12-381 | Used in Hyperledger Indy |
| [IETF BBS draft](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html) | Spec | BLS12-381 | Standardisation in progress |
| [zkryptium](https://github.com/Cybersecurity-LINKS/zkryptium) | Rust | BLS12-381 | EUDI wallet implementation |

Key differences from this toy:

- Curve: BLS12-381 with a Type-3 pairing `e: G1 × G2 → GT`
- Verification uses `e(A, W · G2^e) == e(B, G2)` — no secret key needed
- Proof of knowledge randomises `A` for unlinkability across presentations
- Challenge derived via Fiat-Shamir (hash of proof transcript)

## Attack It

### Forge a hidden commitment

In this toy, a malicious holder could replace a hidden commitment `C_j = H_j^{m_j}`
with `H_j^{m_j'}` for a different value `m_j'`, and the verifier cannot detect it
(they only see the commitment).  **Real BBS+** prevents this by requiring a
zero-knowledge proof of knowledge of the discrete log of each hidden commitment
relative to the corresponding generator.

### Linkability via A

In this toy `(A, e, s)` is identical across every presentation of the same credential.
Any two verifiers who compare notes can link them trivially.  **Full BBS+** fixes this
with holder-side randomisation before each presentation.

### Weak group order

With `P = 2^127 - 1` (127 bits), the discrete logarithm is hard but the group is not
the standard BLS12-381 curve used in production.  The toy generators `H_i = G^i` are
particularly weak — in production generators are hash-to-curve outputs with unknown
discrete logs relative to each other.

## Ship It

The reusable artifact for this lesson is a selective disclosure protocol guide.
See `outputs/bbs-selective-disclosure-guide.md`.

## Exercises

1. **Easy**: Add a fifth attribute (e.g., `email_hash`) to the demo credential and
   create a proof that reveals only `age` and `email_hash`.
2. **Medium**: Implement a `bbs_blind_sign` function where the holder commits to one
   attribute before the issuer signs, so the issuer never learns that attribute.
3. **Hard**: Research BLS12-381 pairing arithmetic and sketch (in pseudocode) how
   `bbs_verify` would look without using `sk` — using `e(A, pk · G^e) == e(B, G)`.

## Key Terms

| Term | What people say | What it actually means |
|------|-----------------|------------------------|
| BBS+ signature | "pairing-based multi-message sig" | A signature scheme where one sig covers many messages and supports selective disclosure |
| Selective disclosure | "showing only some fields" | Revealing a subset of signed attributes with a proof that the signature covers all of them |
| Bilinear pairing | "e(P, Q)" | A map e: G1 × G2 → GT with the property e(aP, bQ) = e(P,Q)^(ab) |
| Unlinkability | "different each time" | Each credential presentation is computationally indistinguishable from presentations of other credentials |
| Generator H_i | "attribute slot" | A public group element dedicated to one message slot; H_i^{m_i} is a hiding commitment to m_i |
| Holder | "credential owner" | The entity that receives a credential and later presents proofs from it |

## Test Vectors

Derived from `code/main.py` using `P = 2^127 - 1`, `G = 3`, fixed demo `sk`.

| messages | A (hex prefix) | verify |
|----------|----------------|--------|
| [42, 1337, 2024, 99] | 0x798b1ea9... | True |
| [1, 2, 3] | 0x43dc961f... | True |
| [100, 200, 300] | 0x... | True |

See `tests/vectors.json` for full values and proof verification vectors.

## Further Reading

- [Boneh, Boyen, Shacham 2004](https://eprint.iacr.org/2004/174.pdf) — Short Group Signatures (original BBS)
- [Camenisch, Lysyanskaya 2004](https://eprint.iacr.org/2002/164.pdf) — Signature Schemes and Anonymous Credentials
- [IETF BBS Draft](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html) — BBS Signature Scheme (RFC draft)
- [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model/) — The VC data model that BBS+ powers
- [Mattr BBS explainer](https://mattr.global/blog/bbs-signatures-explainer) — Accessible walkthrough of the full scheme
