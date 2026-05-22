---
name: bbs-selective-disclosure-guide
description: A design guide and checklist for integrating BBS+ selective-disclosure credentials into protocols — covering credential issuance, proof creation, verification, and common pitfalls.
phase: 18-applied-blockchain-and-identity
lesson: 06-bbs-plus
---

# BBS+ Selective Disclosure Protocol Design Guide

Use this guide when you need a credential scheme where a holder can prove
possession of issuer-signed attributes without revealing all of them, and
where presentations are unlinkable across verifiers.

---

## 1) Define your credential schema

Before any crypto, answer:

- How many attribute slots do you need?  (BBS+ handles L messages per credential)
- Are attributes integers, strings, or structured data?  (Hash strings to integers before signing)
- Which attributes are always revealed?  (e.g., credential type, expiry date)
- Which attributes must be hideable?  (PII: name, address, income, health data)
- Do you need holder-binding?  (Bind a public key so only the legitimate holder can present)

```
Example: Driver's licence credential
  Slot 0:  credential_type  = H("driving_licence")  -- always revealed
  Slot 1:  country          = H("DE")               -- usually revealed
  Slot 2:  birthdate_epoch  = 19850315              -- sometimes revealed (age check)
  Slot 3:  name_hash        = H("Alice Smith")      -- rarely revealed
  Slot 4:  address_hash     = H("123 Main St")      -- rarely revealed
  Slot 5:  holder_pk        = holder_public_key     -- always revealed (binding)
```

---

## 2) Issuance flow

```
Holder                              Issuer
------                              ------
1. Commit to private attrs          2. Receive commitment + public attrs
   (blind sign request)                Verify holder commitment
                                    3. bbs_sign(sk, all_attributes)
                                       -> (A, e, s)
4. Receive (A, e, s) credential
   Store securely
```

For the simplest (non-blind) issuance:

```python
# Issuer
credential = bbs_sign(issuer_sk, [attr_0, attr_1, ..., attr_L])
send_to_holder(credential)
```

For blind issuance (holder keeps one attribute private from issuer):

```python
# Holder: commit to private_attr
blinding = random_scalar()
commitment = pow(H_secret_slot, private_attr, P) * pow(G, blinding, P) % P
send_to_issuer(commitment, other_attrs)

# Issuer: sign commitment + other attrs (blind sign)
# Holder: unblind to get final credential
```

---

## 3) Proof creation

```python
# Holder chooses what to reveal
revealed_indices = [0, 2]   # reveal credential_type and birthdate only

proof = bbs_create_proof(
    messages=credential_attrs,
    sig=credential_sig,
    revealed=revealed_indices,
)

# Send to verifier:
# proof["revealed_messages"]    -- plaintext values for revealed slots
# proof["hidden_commitments"]   -- H_i^{m_i} for each hidden slot
# proof["A"], proof["e"], proof["s"]  -- signature components
```

In production (full BBS+ with unlinkability):

```python
# Randomise before presentation
r1, r2 = random_scalars()
A_prime = pow(A, r1, P)
# ... (full ZK proof of knowledge of witness)
```

---

## 4) Verification

```python
# Verifier reconstructs B and checks signature
ok = bbs_verify_proof(issuer_pk, proof)

# Verifier also checks:
# - credential_type in proof["revealed_messages"][0] matches expected
# - expiry in proof["revealed_messages"][X] is in the future
# - the proof["num_attrs"] matches the expected schema
```

Checklist for verifiers:

- [ ] Issuer public key is fetched from a trusted registry (not from the credential itself)
- [ ] `num_attrs` matches the expected schema for this credential type
- [ ] Required attributes (type, expiry) are present in `revealed_messages`
- [ ] Attribute values pass domain validation (e.g., birthdate is a valid date)
- [ ] Presentation is fresh (add a nonce / timestamp to prevent replay)

---

## 5) Unlinkability requirements

| Property | Toy (this lesson) | Full BBS+ |
|----------|------------------|-----------|
| Selective disclosure | Yes | Yes |
| Same A across presentations | Yes (linkable) | No (randomised per presentation) |
| Verifier cannot link two proofs | No | Yes |
| Requires ZK proof of knowledge | No | Yes |
| Requires bilinear pairing | No (uses sk) | Yes (BLS12-381) |

For production unlinkability, the holder must randomise `(A, e, s)` before
each presentation using the full BBS+ proof-of-knowledge protocol.

---

## 6) Common failure modes

| Failure | Cause | Mitigation |
|---------|-------|------------|
| Linkable presentations | Using same (A, e, s) each time | Holder randomises A per presentation |
| Issuer forges attributes | Issuer knows all m_i | Blind issuance for sensitive slots |
| Verifier collusion tracking | Same proof sent to multiple verifiers | Unlinkability requires randomised A |
| Hidden commitment forgery | Prover substitutes H_i^{m'} undetected | Full BBS+ requires ZK proof of opening |
| Replay attack | Old proof replayed to same verifier | Bind presentation to a verifier-supplied nonce |
| Weak generators | H_i = G^i leaks discrete log relations | Use hash-to-curve generators with unknown DL |
| Small group | 127-bit P is not BLS12-381 | Use standard library on BLS12-381 |

---

## 7) Production libraries

```python
# Python — use the IETF draft implementation
# pip install bbs  (or use the Rust bindings via cffi)

from bbs import BbsSigner, BbsVerifier

signer = BbsSigner.from_key_pair(secret_key, public_key)
credential = signer.sign(messages=[b"attr1", b"attr2", b"attr3"])

verifier = BbsVerifier(public_key)
proof = credential.create_proof(nonce=b"verifier-nonce", revealed=[0, 2])
assert verifier.verify_proof(proof, revealed={0: b"attr1", 2: b"attr3"})
```

Key differences from this toy:
- Messages are byte strings, not integers (hashed internally to BLS12-381 scalars)
- Verification uses pairing — no secret key needed at verification time
- Proofs include a ZK PoK component for unlinkability
- Nonce from verifier binds each proof to prevent replay

---

## 8) Pre-deployment checklist

- [ ] Using a production library on BLS12-381 (not a toy Z_p group)
- [ ] Issuer key securely generated and stored (HSM recommended)
- [ ] Credential schema versioned and published in a public registry
- [ ] Holder randomises A for each presentation (unlinkability)
- [ ] Verifier supplies a fresh nonce bound to each proof request
- [ ] All hidden-attribute ZK proofs are verified (not just the signature)
- [ ] Attribute encoding is canonical (same value always hashes to same integer)
- [ ] Credential expiry slot is always revealed and checked by verifier
- [ ] Revocation mechanism defined (e.g., accumulator or status list)
