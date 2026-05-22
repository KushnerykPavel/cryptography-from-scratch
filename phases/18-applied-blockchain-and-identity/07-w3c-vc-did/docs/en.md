# W3C Verifiable Credentials & DIDs
> A credential you can prove, a DID you control — no central registry required.

**Type:** Learn
**Languages:** Python
**Prerequisites:** Phase 09 · 01 (Hash Commitments), Phase 18 · 01 (Bitcoin Stack — signing concepts)
**Time:** ~50 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain what a Decentralized Identifier (DID) is and why it replaces centralised identity.
- Compute and parse the three-part `did:<method>:<identifier>` format.
- Implement a minimal DID Document with a verification method.
- Distinguish an unsigned VC from a signed one and a Verifiable Presentation (VP).
- Apply HMAC-SHA256 as a stand-in for real JWS proofs and verify them.

## The Problem

Every time you log in somewhere you hand control of your identity to that platform. If it goes down, changes its API, or decides to ban you, your identity disappears with it. The same problem hits professional credentials, government IDs, and access passes: the issuer controls the source of truth, not you.

Decentralized Identifiers (DIDs) and Verifiable Credentials (VCs) are the W3C answer. A DID is a self-describing, globally unique string that resolves to a document *you* control, hosted wherever you like — a blockchain, a personal server, or even a plain DNS record. A VC is a tamper-evident claim ("Alice is over 18") signed by an issuer and held by the subject. No one can revoke Alice's copy without her knowing.

Without understanding the data model you cannot audit VC libraries, build compliant issuers, or debug verification failures. This lesson builds every piece from scratch so the structure becomes second nature: DID string → DID Document → unsigned VC → signed VC → VP → verification.

## The Concept

### DIDs in one diagram

```
did : example : alice123
 │       │          │
 │    method     identifier
 │  (how to      (unique within
"DID"  resolve)    that method)
```

A **DID Document** ties the DID to cryptographic material:

```json
{
  "id": "did:example:alice",
  "verificationMethod": [{
    "id": "did:example:alice#keys-1",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:example:alice",
    "publicKeyHex": "..."
  }],
  "authentication": ["did:example:alice#keys-1"]
}
```

### VC lifecycle

```
Issuer signs VC  →  Holder stores VC  →  Holder builds VP  →  Verifier checks VP
```

A signed VC looks like this:

```json
{
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  "type": ["VerifiableCredential"],
  "id": "urn:uuid:...",
  "issuer": "did:example:issuer",
  "issuanceDate": "2024-01-01T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:holder",
    "name": "Alice",
    "age": 30
  },
  "proof": {
    "type": "Hmac2024",
    "proofValue": "<hex>"
  }
}
```

The **proof** is computed over the canonical form of all other fields. Change any field — even `issuanceDate` by one second — and the proof no longer matches.

### Signing shortcut used here

Real VCs use Ed25519 or secp256k1 JWS with a detached payload. Here we use HMAC-SHA256 so the math is one line and the focus stays on structure:

```
proofValue = HMAC-SHA256(sk, sort_keys_JSON(vc_without_proof))
```

This is **symmetric** — the same key signs and verifies — which is fine for learning but wrong for production (where a private key signs and a public key verifies).

### Selective disclosure

A holder may not want to share all claims. `vc_selective_fields` strips fields from `credentialSubject` before placing the VC in a VP. In production this is done with BBS+ signatures or SD-JWT (both covered in Phase 18 · 06).

## Build It

### Step 1: DID format

```python
def did_generate(method: str, identifier: str) -> str:
    if not method or not identifier:
        raise ValueError("method and identifier must be non-empty")
    return f"did:{method}:{identifier}"
```

The DID is just a string with exactly three colon-delimited parts. Validation rejects empty components — a common mistake when building identifier pipelines.

### Step 2: DID Document

```python
def did_document_create(did: str, public_key_bytes: bytes) -> dict:
    key_id = f"{did}#keys-1"
    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        ],
        "id": did,
        "verificationMethod": [{
            "id": key_id,
            "type": "Ed25519VerificationKey2020",
            "controller": did,
            "publicKeyHex": public_key_bytes.hex(),
        }],
        "authentication": [key_id],
        "assertionMethod": [key_id],
    }
```

The `authentication` list tells verifiers which key to use for authentication challenges. `assertionMethod` is used for signing credentials. Both point to the same key here; production documents separate them.

### Step 3: Create an unsigned VC

```python
def vc_create(issuer_did: str, subject_did: str, claims: dict) -> dict:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    credential_subject = {"id": subject_did}
    credential_subject.update(claims)
    return {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential"],
        "id": f"urn:uuid:{uuid.uuid4()}",
        "issuer": issuer_did,
        "issuanceDate": now,
        "credentialSubject": credential_subject,
    }
```

A UUID `id` makes every credential unique even if the claims are identical. The `@context` URL is the W3C VC 1.1 context — required for JSON-LD conformance.

### Step 4: Sign and verify

```python
def _vc_canonical(vc: dict) -> bytes:
    unsigned = {k: v for k, v in vc.items() if k != "proof"}
    return json.dumps(unsigned, sort_keys=True).encode()

def vc_sign(vc: dict, issuer_sk: bytes) -> dict:
    proof_value = hmac.new(issuer_sk, _vc_canonical(vc), hashlib.sha256).hexdigest()
    signed = dict(vc)
    signed["proof"] = {"type": "Hmac2024", "proofValue": proof_value}
    return signed

def vc_verify(vc: dict, issuer_pk: bytes) -> bool:
    if "proof" not in vc:
        return False
    expected = hmac.new(issuer_pk, _vc_canonical(vc), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, vc["proof"].get("proofValue", ""))
```

The canonical form excludes the `proof` field itself (otherwise the proof would cover itself — a circular dependency). `sort_keys=True` ensures the JSON serialisation is deterministic across Python versions and dict orderings.

### Step 5: Verifiable Presentation

```python
def vp_create(holder_did: str, credentials: list[dict]) -> dict:
    return {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiablePresentation"],
        "id": f"urn:uuid:{uuid.uuid4()}",
        "holder": holder_did,
        "verifiableCredential": credentials,
    }
```

A VP wraps one or more signed VCs with a holder proof. The holder signs the VP with their own key. The verifier then checks: (a) the VP holder proof, and (b) each VC issuer proof inside.

### Step 6: Expiry and selective disclosure

```python
def vc_check_expiry(vc: dict) -> bool:
    expiry_str = vc.get("expirationDate")
    if expiry_str is None:
        return True
    expiry = datetime.fromisoformat(expiry_str.replace("Z", "+00:00"))
    return datetime.now(timezone.utc) <= expiry

def vc_selective_fields(vc: dict, fields: list[str]) -> dict:
    original = vc.get("credentialSubject", {})
    filtered = {"id": original.get("id", "")}
    for field in fields:
        if field in original:
            filtered[field] = original[field]
    result = dict(vc)
    result["credentialSubject"] = filtered
    return result
```

Expiry is a simple datetime comparison. Selective disclosure here is naive — it strips fields before signing, which means the issuer's proof no longer covers the full claim set. Production systems use BBS+ or SD-JWT to prove that the disclosed fields are a subset of the original without re-signing.

Run it:
```
python3 code/main.py
```

Expected output:
```
=== Step 1: Generate DIDs ===
Issuer DID: did:example:issuer
Holder DID: did:example:holder

=== Step 2: Create DID Document ===
DID Document id: did:example:issuer
Verification method: did:example:issuer#keys-1

=== Step 3: Issue Verifiable Credential ===
...

=== Step 4: Verify Credential ===
Valid signature:         True
Tampered VC rejects:     True
Not expired (no expiry): True

=== Step 5: Create and Verify Presentation ===
VP signature valid: True
```

## Use It

| Task | Library | Notes |
|------|---------|-------|
| Issue/verify VCs (Python) | `pyvclib`, `vc-py` | Full JSON-LD with Ed25519 and BBS+ |
| DID resolution | `did-resolver` (JS/Python bindings) | Resolves `did:web`, `did:key`, `did:ethr` |
| SD-JWT credentials | `sd-jwt-python` | Selective disclosure without BBS+ |
| Full W3C VC suite | `veramo` (Node.js) | Production-grade DID + VC stack |
| Government eID | `eudi-lib-jvm-openid4vci` | EU Digital Identity Wallet spec |

## Pitfalls

1. **Signing the proof field itself.** If you include `"proof"` in the payload before computing the HMAC you get a circular dependency. Always exclude it.
2. **Non-deterministic JSON serialisation.** Python dicts are insertion-ordered but `json.dumps` without `sort_keys=True` gives different bytes across versions. Always sort keys for the canonical form.
3. **Symmetric vs asymmetric proofs.** HMAC requires the verifier to hold the secret key — fine for toy code, catastrophic in production where anyone who can verify can also forge.
4. **Missing `@context`.** JSON-LD libraries reject VCs whose `@context` doesn't include the W3C base URL. Omitting it produces documents that look valid in Python dicts but fail compliance checks.
5. **Selective disclosure breaks the original proof.** Stripping fields from `credentialSubject` after signing invalidates the issuer's signature. Use SD-JWT or BBS+ for production selective disclosure.

## Ship It

This lesson produces `outputs/vc-did-issuance-template.md` — a template for designing a VC issuance flow for any credential type (degree, health record, access pass). Fill in the blanks to get a shareable design document.

## Exercises

1. **Easy.** Run `python3 code/main.py`. Observe that `Tampered VC rejects: True`. Change the `age` in `vc4_unsigned` (in tests) and confirm the proof value changes.
2. **Medium.** Add an `expirationDate` field to `vc_create` (optional parameter). Issue a credential that expires in 1 minute, wait, then call `vc_check_expiry` and confirm it returns `False`.
3. **Hard.** Replace HMAC-SHA256 with real Ed25519 signing using Python's `cryptography` library. Rewrite `vc_sign` and `vc_verify` to use `Ed25519PrivateKey.sign()` and `Ed25519PublicKey.verify()` with the same canonical JSON payload.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|------------------------|
| DID | "decentralised ID" | A URI (`did:method:id`) that resolves to a DID Document you control |
| DID Document | "DID doc" | A JSON-LD document linking a DID to public keys and service endpoints |
| VC | "verifiable credential" | A tamper-evident, signed claim from an issuer about a subject |
| VP | "presentation" | A holder-signed envelope wrapping one or more VCs for a specific verifier |
| Credential Subject | "the subject" | The entity the VC makes claims about (identified by their DID) |
| Proof | "signature" | The cryptographic proof field that makes the credential tamper-evident |
| Selective Disclosure | "SD" | Revealing only a subset of credential claims without re-issuing |
| JSON-LD | "linked data JSON" | JSON with `@context` for semantic interoperability across systems |

## Further Reading

- W3C, *Verifiable Credentials Data Model 1.1* (2022) — the normative specification
- W3C, *Decentralized Identifiers (DIDs) v1.0* (2022) — DID syntax, resolution, and document format
- Sporny et al., *Verifiable Credentials Use Cases* (2019) — concrete scenarios from education to supply chain
- Lodder & Waite, *Self-Sovereign Identity* (2021, Manning) — broad overview including DID methods and wallet architecture
- OpenID Foundation, *OpenID for Verifiable Credential Issuance* (2023) — the protocol layering VCs on top of OAuth 2.0
