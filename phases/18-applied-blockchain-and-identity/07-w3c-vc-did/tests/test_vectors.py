import json
import sys
from pathlib import Path

LESSON = Path(__file__).resolve().parents[1]
VECTORS_PATH = LESSON / "tests" / "vectors.json"

sys.path.insert(0, str(LESSON / "code"))
import main as vc  # noqa: E402


def _b(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


def call(vector):
    op = vector["op"]

    if op == "did_generate":
        return vc.did_generate(vector["method"], vector["identifier"])

    if op == "did_document_create_id":
        doc = vc.did_document_create(vector["did"], _b(vector["public_key_hex"]))
        return doc["id"]

    if op == "did_document_create_pubkey":
        doc = vc.did_document_create(vector["did"], _b(vector["public_key_hex"]))
        return doc["verificationMethod"][0]["publicKeyHex"]

    if op == "vc_sign_proof":
        signed = vc.vc_sign(vector["vc"], _b(vector["issuer_sk_hex"]))
        return signed["proof"]["proofValue"]

    if op == "vc_verify":
        return vc.vc_verify(vector["vc"], _b(vector["pk_hex"]))

    if op == "vp_sign_proof":
        signed = vc.vp_sign(vector["vp"], _b(vector["holder_sk_hex"]))
        return signed["proof"]["proofValue"]

    if op == "vc_check_expiry":
        stub_vc = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential"],
            "id": "urn:uuid:test",
            "issuer": "did:example:issuer",
            "issuanceDate": "2024-01-01T00:00:00Z",
            "credentialSubject": {"id": "did:example:holder"},
            "expirationDate": vector["expiration_date"],
        }
        return vc.vc_check_expiry(stub_vc)

    if op == "vc_check_expiry_none":
        stub_vc = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential"],
            "id": "urn:uuid:test",
            "issuer": "did:example:issuer",
            "issuanceDate": "2024-01-01T00:00:00Z",
            "credentialSubject": {"id": "did:example:holder"},
        }
        return vc.vc_check_expiry(stub_vc)

    if op == "vc_selective_fields":
        result = vc.vc_selective_fields(vector["vc"], vector["fields"])
        subject = result["credentialSubject"]
        keys_match = sorted(subject.keys()) == sorted(vector["expected_subject_keys"])
        age_present = "age" in subject
        return keys_match and (age_present == vector["age_present"])

    raise AssertionError(f"unknown op: {op}")


def test_vectors():
    vectors = json.loads(VECTORS_PATH.read_text())["vectors"]
    for vector in vectors:
        result = call(vector)
        if "expected" in vector:
            assert result == vector["expected"], (
                f"FAIL [{vector['description']}]: got {result!r}, "
                f"expected {vector['expected']!r}"
            )
        elif "expected_subject_keys" in vector:
            # vc_selective_fields returns a bool from call()
            assert result is True, f"FAIL [{vector['description']}]"


def test_did_generate_error():
    try:
        vc.did_generate("", "identifier")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for empty method")

    try:
        vc.did_generate("example", "")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for empty identifier")


def test_vc_roundtrip():
    sk = b"\x03" * 32
    issuer_did = vc.did_generate("test", "issuer")
    holder_did = vc.did_generate("test", "holder")
    unsigned = vc.vc_create(issuer_did, holder_did, {"role": "admin"})
    signed = vc.vc_sign(unsigned, sk)
    assert vc.vc_verify(signed, sk)
    # tamper the VC
    tampered = dict(signed)
    tampered["credentialSubject"] = dict(tampered["credentialSubject"])
    tampered["credentialSubject"]["role"] = "superadmin"
    assert not vc.vc_verify(tampered, sk)


def test_vp_roundtrip():
    issuer_sk = b"\x04" * 32
    holder_sk = b"\x05" * 32
    issuer_did = vc.did_generate("test", "issuer2")
    holder_did = vc.did_generate("test", "holder2")
    unsigned_vc = vc.vc_create(issuer_did, holder_did, {"score": 42})
    signed_vc = vc.vc_sign(unsigned_vc, issuer_sk)
    vp = vc.vp_create(holder_did, [signed_vc])
    signed_vp = vc.vp_sign(vp, holder_sk)
    assert vc.vp_verify(signed_vp, holder_sk)
    assert not vc.vp_verify(signed_vp, issuer_sk)


def test_selective_fields():
    issuer_sk = b"\x06" * 32
    issuer_did = vc.did_generate("test", "issuer3")
    holder_did = vc.did_generate("test", "holder3")
    unsigned = vc.vc_create(issuer_did, holder_did, {"name": "Bob", "age": 25, "email": "bob@example.com"})
    signed = vc.vc_sign(unsigned, issuer_sk)
    result = vc.vc_selective_fields(signed, ["name"])
    subj = result["credentialSubject"]
    assert "id" in subj
    assert "name" in subj
    assert "age" not in subj
    assert "email" not in subj


def test_check_expiry():
    base = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential"],
        "id": "urn:uuid:expiry-test",
        "issuer": "did:example:issuer",
        "issuanceDate": "2024-01-01T00:00:00Z",
        "credentialSubject": {"id": "did:example:holder"},
    }
    # No expiry
    assert vc.vc_check_expiry(base) is True
    # Future expiry
    future = dict(base, expirationDate="2099-06-15T12:00:00Z")
    assert vc.vc_check_expiry(future) is True
    # Past expiry
    past = dict(base, expirationDate="2000-06-15T12:00:00Z")
    assert vc.vc_check_expiry(past) is False


if __name__ == "__main__":
    test_vectors()
    test_did_generate_error()
    test_vc_roundtrip()
    test_vp_roundtrip()
    test_selective_fields()
    test_check_expiry()
    print("all tests pass")
