"""
NIST PQC Standards Tour (FIPS 203/204/205) — a practical, code-driven overview.

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Iterable, Literal, cast

Primitive = Literal["KEM", "Signature"]


@dataclass(frozen=True)
class PqcStandard:
    family: str
    fips: str
    primitive: Primitive
    basis: str
    standardized_on: str


def pqc_standards_catalog() -> dict[str, PqcStandard]:
    standards = [
        PqcStandard(
            family="ML-KEM",
            fips="FIPS 203",
            primitive="KEM",
            basis="module-lattice",
            standardized_on="2024-08-13",
        ),
        PqcStandard(
            family="ML-DSA",
            fips="FIPS 204",
            primitive="Signature",
            basis="module-lattice",
            standardized_on="2024-08-13",
        ),
        PqcStandard(
            family="SLH-DSA",
            fips="FIPS 205",
            primitive="Signature",
            basis="hash-based",
            standardized_on="2024-08-13",
        ),
    ]
    return {s.family: s for s in standards}


def normalize_algorithm_name(name: str) -> str:
    n = name.strip().lower()
    if not n:
        raise ValueError("empty algorithm name")

    aliases = {
        "crystals-kyber": "ML-KEM",
        "kyber": "ML-KEM",
        "ml-kem": "ML-KEM",
        "crystals-dilithium": "ML-DSA",
        "dilithium": "ML-DSA",
        "ml-dsa": "ML-DSA",
        "sphincs+": "SLH-DSA",
        "sphincs": "SLH-DSA",
        "sphincsplus": "SLH-DSA",
        "slh-dsa": "SLH-DSA",
    }
    n = n.replace("_", "-").replace(" ", "")
    if n in aliases:
        return aliases[n]
    raise ValueError(f"unknown/unsupported algorithm name: {name!r}")


def security_category_to_bits(category: int) -> int:
    if category == 1:
        return 128
    if category == 3:
        return 192
    if category == 5:
        return 256
    raise ValueError("category must be one of {1, 3, 5}")


def _kdf(label: bytes, data: bytes, out_len: int) -> bytes:
    return hashlib.shake_256(label + b"\x00" + data).digest(out_len)


def toy_kem_keygen(seed: bytes) -> tuple[bytes, bytes]:
    if len(seed) < 16:
        raise ValueError("seed too short")
    secret_key = _kdf(b"toy-kem/sk", seed, 32)
    public_key = _kdf(b"toy-kem/pk", secret_key, 32)
    return public_key, secret_key


def toy_kem_encaps(public_key: bytes, seed: bytes) -> tuple[bytes, bytes]:
    if len(public_key) != 32:
        raise ValueError("public_key must be 32 bytes")
    if len(seed) < 16:
        raise ValueError("seed too short")
    ciphertext = _kdf(b"toy-kem/ct", seed, 32)
    shared_secret = _kdf(b"toy-kem/ss", public_key + ciphertext, 32)
    return ciphertext, shared_secret


def toy_kem_decaps(secret_key: bytes, ciphertext: bytes) -> bytes:
    if len(secret_key) != 32:
        raise ValueError("secret_key must be 32 bytes")
    if len(ciphertext) != 32:
        raise ValueError("ciphertext must be 32 bytes")
    public_key = _kdf(b"toy-kem/pk", secret_key, 32)
    return _kdf(b"toy-kem/ss", public_key + ciphertext, 32)


@dataclass(frozen=True)
class SystemProfile:
    use_case: Literal["tls", "certificates", "code-signing", "messaging"]
    target_security_category: Literal[1, 3, 5]
    conservative_signatures: bool
    hybrid_during_migration: bool


@dataclass(frozen=True)
class SuiteRecommendation:
    kem: str
    signature: str
    notes: tuple[str, ...]


def recommend_pqc_suite(profile: SystemProfile) -> SuiteRecommendation:
    cat_bits = security_category_to_bits(int(profile.target_security_category))
    notes: list[str] = [f"Target security category {profile.target_security_category} (~{cat_bits}-bit)."]

    kem = "ML-KEM"
    signature = "ML-DSA"
    if profile.conservative_signatures:
        signature = "SLH-DSA"
        notes.append("Chose SLH-DSA for conservative, hash-based signatures (larger signatures).")
    else:
        notes.append("Chose ML-DSA for mainstream PQ signatures (smaller, faster in many environments).")

    if profile.use_case in {"certificates", "code-signing"} and profile.conservative_signatures:
        notes.append("Conservative choice often fits better for long-lived roots / high-assurance signing.")

    if profile.hybrid_during_migration:
        notes.append("Use hybrid (classical + PQC) during migration to handle compatibility and reduce single-family risk.")

    return SuiteRecommendation(kem=kem, signature=signature, notes=tuple(notes))


def hndl_priority(years_confidentiality_needed: int, years_until_q_ready: int) -> str:
    if years_confidentiality_needed < 0 or years_until_q_ready < 0:
        raise ValueError("years must be non-negative")
    if years_confidentiality_needed >= years_until_q_ready:
        return "urgent"
    if years_confidentiality_needed + 5 >= years_until_q_ready:
        return "high"
    return "moderate"


@dataclass(frozen=True)
class CryptoFinding:
    component: str
    primitive: "CryptoPrimitive"
    algorithm: str
    pqc_relevant: bool


CryptoPrimitive = Literal["key-establishment", "signature", "hash", "symmetric", "unknown"]


def classify_component(component: dict) -> CryptoFinding:
    required = {"component", "primitive", "algorithm"}
    missing = required - set(component.keys())
    if missing:
        raise ValueError(f"missing fields: {sorted(missing)}")

    primitive = str(component["primitive"]).strip().lower()
    algorithm = str(component["algorithm"]).strip()
    if primitive not in {"key-establishment", "signature", "hash", "symmetric"}:
        primitive_out: CryptoPrimitive = "unknown"
    else:
        primitive_out = cast(CryptoPrimitive, primitive)

    pqc_relevant = primitive_out in {"key-establishment", "signature"}
    return CryptoFinding(
        component=str(component["component"]),
        primitive=primitive_out,
        algorithm=algorithm,
        pqc_relevant=pqc_relevant,
    )


def build_migration_plan(findings: Iterable[CryptoFinding]) -> list[str]:
    relevant = [f for f in findings if f.pqc_relevant]
    tasks: list[str] = [
        "Inventory all public-key cryptography (key establishment + signatures) in software, devices, and protocols.",
        "Prioritize by data lifetime (HNDL exposure) and by upgrade difficulty (embedded/firmware/third-party dependencies).",
    ]
    if any(f.primitive == "key-establishment" for f in relevant):
        tasks.append("Plan for ML-KEM-based key establishment (often via hybrid handshakes during migration).")
    if any(f.primitive == "signature" for f in relevant):
        tasks.append("Plan for ML-DSA and/or SLH-DSA in certificates, code-signing, and application-layer signatures.")
    tasks.append("Add crypto agility: negotiation, versioning, and a way to rotate algorithms without redeploying everything.")
    tasks.append("Integrate testing/validation: known-answer tests, negative tests, and interoperability tests across endpoints.")
    return tasks


def render_checklist_markdown(title: str, items: Iterable[str]) -> str:
    lines = [f"# {title}", ""]
    for item in items:
        lines.append(f"- [ ] {item}")
    lines.append("")
    return "\n".join(lines)


def _hex(b: bytes) -> str:
    return b.hex()


def main():
    print("=== Step 1: Identify what’s standardized ===")
    cat = pqc_standards_catalog()
    for family in sorted(cat.keys()):
        s = cat[family]
        print(f"{s.family}: {s.fips} ({s.primitive}, {s.basis}), standardized {s.standardized_on}")
    print()
    print("Normalize names:")
    for raw in ["Kyber", "CRYSTALS-Dilithium", "SPHINCS+"]:
        print(f"  {raw!r} -> {normalize_algorithm_name(raw)}")

    print("\n=== Step 2: Understand KEM vs signatures (toy demo) ===")
    seed = b"demo-seed-00000000000000000000"
    pk, sk = toy_kem_keygen(seed)
    ct, ss1 = toy_kem_encaps(pk, b"encaps-seed-000000000000000")
    ss2 = toy_kem_decaps(sk, ct)
    print(f"toy KEM public_key = {_hex(pk)[:16]}…")
    print(f"toy KEM ciphertext = {_hex(ct)[:16]}…")
    print(f"toy KEM shared_secret(encaps) = {_hex(ss1)[:16]}…")
    print(f"toy KEM shared_secret(decaps) = {_hex(ss2)[:16]}…")
    print(f"shared secrets match: {ss1 == ss2}")

    profile = SystemProfile(
        use_case="tls",
        target_security_category=1,
        conservative_signatures=False,
        hybrid_during_migration=True,
    )
    rec = recommend_pqc_suite(profile)
    print("\nExample recommendation (TLS):")
    print(json.dumps({"kem": rec.kem, "signature": rec.signature, "notes": rec.notes}, indent=2))

    print("\n=== Step 3: Prioritize by HNDL (timeline thinking) ===")
    for years_data in [1, 7, 15]:
        prio = hndl_priority(years_confidentiality_needed=years_data, years_until_q_ready=10)
        print(f"Confidentiality needed {years_data}y, quantum in 10y -> priority: {prio}")

    print("\n=== Step 4: Turn inventory into a migration plan ===")
    inventory = [
        {"component": "TLS termination", "primitive": "key-establishment", "algorithm": "ECDH P-256"},
        {"component": "JWT signing", "primitive": "signature", "algorithm": "ES256"},
        {"component": "Database at rest", "primitive": "symmetric", "algorithm": "AES-256-GCM"},
    ]
    findings = [classify_component(x) for x in inventory]
    for f in findings:
        tag = "PQC-relevant" if f.pqc_relevant else "not PQC-relevant"
        print(f"- {f.component}: {f.primitive} / {f.algorithm} -> {tag}")

    plan = build_migration_plan(findings)
    md = render_checklist_markdown("PQC Migration Checklist (Starter)", plan)
    print("\nGenerated checklist:\n")
    print(md)


if __name__ == "__main__":
    main()
