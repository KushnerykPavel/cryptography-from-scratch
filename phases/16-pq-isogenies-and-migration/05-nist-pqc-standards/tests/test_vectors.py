import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (  # noqa: E402
    SystemProfile,
    build_migration_plan,
    classify_component,
    hndl_priority,
    normalize_algorithm_name,
    pqc_standards_catalog,
    recommend_pqc_suite,
    render_checklist_markdown,
    security_category_to_bits,
    toy_kem_decaps,
    toy_kem_encaps,
    toy_kem_keygen,
)


def _bytes(v: dict, key: str) -> bytes:
    if f"{key}_ascii" in v:
        return v[f"{key}_ascii"].encode("utf-8")
    if f"{key}_hex" in v:
        return bytes.fromhex(v[f"{key}_hex"])
    raise AssertionError(f"vector must include {key}_ascii or {key}_hex")


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]
        if op == "normalize_algorithm_name":
            got = normalize_algorithm_name(v["name"])
            assert got == v["expected"]
        elif op == "security_category_to_bits":
            got = security_category_to_bits(int(v["category"]))
            assert got == v["expected"]
        elif op == "toy_kem_keygen":
            pk, sk = toy_kem_keygen(_bytes(v, "seed"))
            assert pk.hex() == v["expected_public_key_hex"]
            assert sk.hex() == v["expected_secret_key_hex"]
        elif op == "toy_kem_encaps":
            pk = _bytes(v, "public_key")
            ct, ss = toy_kem_encaps(pk, _bytes(v, "seed"))
            assert ct.hex() == v["expected_ciphertext_hex"]
            assert ss.hex() == v["expected_shared_secret_hex"]
        elif op == "toy_kem_decaps":
            sk = _bytes(v, "secret_key")
            ct = _bytes(v, "ciphertext")
            ss = toy_kem_decaps(sk, ct)
            assert ss.hex() == v["expected_shared_secret_hex"]
        elif op == "recommend_pqc_suite":
            p = v["profile"]
            profile = SystemProfile(
                use_case=p["use_case"],
                target_security_category=int(p["target_security_category"]),
                conservative_signatures=bool(p["conservative_signatures"]),
                hybrid_during_migration=bool(p["hybrid_during_migration"]),
            )
            rec = recommend_pqc_suite(profile)
            got = {"kem": rec.kem, "signature": rec.signature, "notes": list(rec.notes)}
            assert got == v["expected"]
        elif op == "hndl_priority":
            got = hndl_priority(
                years_confidentiality_needed=int(v["years_confidentiality_needed"]),
                years_until_q_ready=int(v["years_until_q_ready"]),
            )
            assert got == v["expected"]
        elif op == "classify_component":
            finding = classify_component(v["component"])
            got = {
                "component": finding.component,
                "primitive": finding.primitive,
                "algorithm": finding.algorithm,
                "pqc_relevant": finding.pqc_relevant,
            }
            assert got == v["expected"]
        elif op == "render_checklist_markdown":
            got = render_checklist_markdown(v["title"], v["items"])
            assert got == v["expected"]
        else:
            raise AssertionError(f"unknown op {op}")


def test_catalog_is_stable_and_complete():
    cat = pqc_standards_catalog()
    assert set(cat.keys()) == {"ML-KEM", "ML-DSA", "SLH-DSA"}
    assert cat["ML-KEM"].primitive == "KEM"
    assert cat["ML-DSA"].primitive == "Signature"
    assert cat["SLH-DSA"].basis == "hash-based"


def test_toy_kem_roundtrip():
    pk, sk = toy_kem_keygen(b"seed-seed-seed-seed-0000")
    ct, ss1 = toy_kem_encaps(pk, b"encaps-encaps-encaps-0000")
    ss2 = toy_kem_decaps(sk, ct)
    assert ss1 == ss2


def test_hndl_priority_rejects_negative_years():
    for a, b in [(-1, 0), (0, -1), (-3, -2)]:
        try:
            hndl_priority(a, b)
        except ValueError:
            pass
        else:
            raise AssertionError("expected ValueError")


def test_classify_component_rejects_missing_fields():
    try:
        classify_component({"component": "X", "primitive": "signature"})
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


def test_build_migration_plan_emits_key_tasks():
    findings = [
        classify_component({"component": "TLS", "primitive": "key-establishment", "algorithm": "ECDH"}),
        classify_component({"component": "JWT", "primitive": "signature", "algorithm": "ES256"}),
    ]
    tasks = build_migration_plan(findings)
    joined = "\n".join(tasks).lower()
    assert "inventory" in joined
    assert "ml-kem" in joined
    assert "ml-dsa" in joined or "slh-dsa" in joined
    assert "agility" in joined


if __name__ == "__main__":
    test_vectors()
    test_catalog_is_stable_and_complete()
    test_toy_kem_roundtrip()
    test_hndl_priority_rejects_negative_years()
    test_classify_component_rejects_missing_fields()
    test_build_migration_plan_emits_key_tasks()
    print("all tests pass")

