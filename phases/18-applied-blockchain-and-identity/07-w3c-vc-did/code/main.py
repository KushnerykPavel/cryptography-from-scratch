"""
W3C Verifiable Credentials & DIDs (educational).

Implements the W3C VC/DID data model with HMAC-SHA256 as a simplified proof
primitive.  Real implementations use Ed25519 or secp256k1 JWS; the educational
focus here is on the DATA STRUCTURES and PROTOCOL FLOW.

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# DID helpers
# ---------------------------------------------------------------------------

def did_generate(method: str, identifier: str) -> str:
    """Generate a DID string: did:<method>:<identifier>"""
    if not method or not identifier:
        raise ValueError("method and identifier must be non-empty")
    return f"did:{method}:{identifier}"


def did_document_create(did: str, public_key_bytes: bytes) -> dict:
    """Create a minimal DID document with verification method."""
    key_id = f"{did}#keys-1"
    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        ],
        "id": did,
        "verificationMethod": [
            {
                "id": key_id,
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyHex": public_key_bytes.hex(),
            }
        ],
        "authentication": [key_id],
        "assertionMethod": [key_id],
    }


# ---------------------------------------------------------------------------
# Verifiable Credential
# ---------------------------------------------------------------------------

def vc_create(issuer_did: str, subject_did: str, claims: dict) -> dict:
    """Create an unsigned VC (W3C format)."""
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


def _vc_canonical(vc: dict) -> bytes:
    """Canonical JSON bytes for signing (exclude 'proof' field)."""
    unsigned = {k: v for k, v in vc.items() if k != "proof"}
    return json.dumps(unsigned, sort_keys=True).encode()


def vc_sign(vc: dict, issuer_sk: bytes) -> dict:
    """Sign a VC: adds 'proof' field with HMAC-SHA256 over canonical JSON."""
    proof_value = hmac.new(issuer_sk, _vc_canonical(vc), hashlib.sha256).hexdigest()
    signed = dict(vc)
    signed["proof"] = {
        "type": "Hmac2024",
        "proofValue": proof_value,
    }
    return signed


def vc_verify(vc: dict, issuer_pk: bytes) -> bool:
    """Verify VC proof using HMAC-SHA256."""
    if "proof" not in vc:
        return False
    expected = hmac.new(issuer_pk, _vc_canonical(vc), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, vc["proof"].get("proofValue", ""))


# ---------------------------------------------------------------------------
# Verifiable Presentation
# ---------------------------------------------------------------------------

def vp_create(holder_did: str, credentials: list[dict]) -> dict:
    """Create an unsigned VP containing one or more VCs."""
    return {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiablePresentation"],
        "id": f"urn:uuid:{uuid.uuid4()}",
        "holder": holder_did,
        "verifiableCredential": credentials,
    }


def _vp_canonical(vp: dict) -> bytes:
    """Canonical JSON bytes for signing (exclude 'proof' field)."""
    unsigned = {k: v for k, v in vp.items() if k != "proof"}
    return json.dumps(unsigned, sort_keys=True).encode()


def vp_sign(vp: dict, holder_sk: bytes) -> dict:
    """Sign a VP."""
    proof_value = hmac.new(holder_sk, _vp_canonical(vp), hashlib.sha256).hexdigest()
    signed = dict(vp)
    signed["proof"] = {
        "type": "Hmac2024",
        "proofValue": proof_value,
    }
    return signed


def vp_verify(vp: dict, holder_pk: bytes) -> bool:
    """Verify VP signature."""
    if "proof" not in vp:
        return False
    expected = hmac.new(holder_pk, _vp_canonical(vp), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, vp["proof"].get("proofValue", ""))


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def vc_check_expiry(vc: dict) -> bool:
    """Check that VC is not expired (compare expirationDate to now).

    Returns True if the credential is still valid (not expired or no expiry).
    Returns False if it has expired.
    """
    expiry_str = vc.get("expirationDate")
    if expiry_str is None:
        return True  # no expiration set — still valid
    expiry = datetime.fromisoformat(expiry_str.replace("Z", "+00:00"))
    now = datetime.now(timezone.utc)
    return now <= expiry


def vc_selective_fields(vc: dict, fields: list[str]) -> dict:
    """Return VC with only the specified credential subject fields (for presentation).

    The 'id' field of credentialSubject is always preserved.
    """
    original_subject = vc.get("credentialSubject", {})
    filtered_subject = {"id": original_subject.get("id", "")}
    for field in fields:
        if field in original_subject:
            filtered_subject[field] = original_subject[field]
    result = dict(vc)
    result["credentialSubject"] = filtered_subject
    return result


# ---------------------------------------------------------------------------
# main demo
# ---------------------------------------------------------------------------

def main():
    issuer_sk = b"\x01" * 32
    holder_sk = b"\x02" * 32

    print("=== Step 1: Generate DIDs ===")
    issuer_did = did_generate("example", "issuer")
    holder_did = did_generate("example", "holder")
    print(f"Issuer DID: {issuer_did}")
    print(f"Holder DID: {holder_did}")
    print()

    print("=== Step 2: Create DID Document ===")
    issuer_doc = did_document_create(issuer_did, issuer_sk)
    print(f"DID Document id: {issuer_doc['id']}")
    print(f"Verification method: {issuer_doc['verificationMethod'][0]['id']}")
    print()

    print("=== Step 3: Issue Verifiable Credential ===")
    vc = vc_create(issuer_did, holder_did, {"name": "Alice", "age": 30})
    vc_signed = vc_sign(vc, issuer_sk)
    print(f"VC id:       {vc_signed['id']}")
    print(f"Issuer:      {vc_signed['issuer']}")
    print(f"Subject id:  {vc_signed['credentialSubject']['id']}")
    print(f"Claims:      name={vc_signed['credentialSubject']['name']!r}, "
          f"age={vc_signed['credentialSubject']['age']}")
    print(f"Proof value: {vc_signed['proof']['proofValue'][:32]}...")
    print()

    print("=== Step 4: Verify Credential ===")
    ok = vc_verify(vc_signed, issuer_sk)
    print(f"Valid signature:         {ok}")
    tampered = dict(vc_signed)
    tampered["credentialSubject"] = dict(tampered["credentialSubject"])
    tampered["credentialSubject"]["age"] = 99
    print(f"Tampered VC rejects:     {not vc_verify(tampered, issuer_sk)}")
    not_expired = vc_check_expiry(vc_signed)
    print(f"Not expired (no expiry): {not_expired}")
    print()

    print("=== Step 5: Create and Verify Presentation ===")
    selective = vc_selective_fields(vc_signed, ["name"])
    vp = vp_create(holder_did, [selective])
    vp_signed = vp_sign(vp, holder_sk)
    vp_ok = vp_verify(vp_signed, holder_sk)
    print(f"VP id:              {vp_signed['id']}")
    print(f"Holder:             {vp_signed['holder']}")
    print(f"Selective fields:   {list(vp_signed['verifiableCredential'][0]['credentialSubject'].keys())}")
    print(f"VP signature valid: {vp_ok}")


if __name__ == "__main__":
    main()
