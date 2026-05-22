# VC Issuance Flow — Design Template

Use this template to design a Verifiable Credential issuance system for any
credential type. Fill in every section before writing code.

---

## 1. Credential Metadata

| Field | Your Value |
|-------|-----------|
| Credential name | e.g. "University Degree Credential" |
| `@context` URLs | `https://www.w3.org/2018/credentials/v1` + any domain context |
| `type` array | `["VerifiableCredential", "YourCredentialType"]` |
| Expiry policy | none / 1 year / on revocation |

---

## 2. Parties

| Role | DID method | Key type |
|------|-----------|---------|
| Issuer | `did:web`, `did:ethr`, … | Ed25519 / secp256k1 |
| Holder | `did:key`, `did:web`, … | Ed25519 / secp256k1 |
| Verifier | resolves issuer DID | needs issuer public key |

---

## 3. Credential Subject Fields

List every claim the credential makes about the subject.

| Field name | Type | Required | Notes |
|-----------|------|----------|-------|
| `id` | DID string | yes | subject DID |
| `name` | string | | legal name |
| `degree` | string | | e.g. "BSc Computer Science" |
| … | … | … | … |

---

## 4. Issuance Flow

```
1. Issuer authenticates the holder (out-of-band or via OpenID4VCI)
2. Issuer calls vc_create(issuer_did, holder_did, claims)
3. Issuer calls vc_sign(vc, issuer_sk)           # adds "proof" field
4. Issuer delivers signed VC to holder (HTTPS, QR code, wallet protocol)
5. Holder stores VC in wallet
```

---

## 5. Presentation Flow

```
1. Verifier sends presentation request (list of required credential types)
2. Holder selects matching VCs from wallet
3. Holder optionally strips unneeded claims: vc_selective_fields(vc, fields)
4. Holder calls vp_create(holder_did, [vc1, vc2, …])
5. Holder calls vp_sign(vp, holder_sk)
6. Holder sends signed VP to verifier
7. Verifier:
   a. Calls vp_verify(vp, holder_pk)
   b. Resolves issuer DID → DID Document → issuer public key
   c. Calls vc_verify(vc, issuer_pk) for each VC inside the VP
   d. Calls vc_check_expiry(vc) for each VC
   e. Checks required claims are present
```

---

## 6. Revocation Strategy

| Approach | How it works | Trade-off |
|----------|-------------|-----------|
| Expiry only | Short-lived VCs (hours/days) | Simple; fine for access tokens |
| Status List 2021 | Issuer publishes bitfield; verifier checks index | Privacy leak — issuer sees who verified |
| Accumulator / ZK revocation | ZK proof of non-revocation | Private but complex |

**Your choice:** _______________

---

## 7. Proof Mechanism Checklist

- [ ] Replace HMAC with Ed25519 JWS (or secp256k1)
- [ ] Use `JsonWebSignature2020` or `DataIntegrityProof` proof type
- [ ] Store only public key in DID Document
- [ ] Sign with private key; verify with public key
- [ ] Never reuse nonces if using randomised schemes

---

## 8. Security Checklist

- [ ] `sort_keys=True` (or equivalent) in canonical serialisation
- [ ] Proof excludes the `"proof"` field itself
- [ ] Expiry validated at every presentation check
- [ ] Holder authenticates before wallet releases VP
- [ ] Credential type matches expected type before checking claims
- [ ] Issuer DID resolved fresh (not cached stale doc)

---

## 9. Production Library

Fill in once you move off the educational implementation:

| Component | Library |
|-----------|---------|
| VC issuance / verification | |
| DID resolution | |
| Wallet / storage | |
| Transport (OpenID4VCI) | |
