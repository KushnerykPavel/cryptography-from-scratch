# NIST PQC Standards (FIPS 203/204/205)

> Standards are interfaces: names, roles, and constraints you migrate against.

**Type:** Learn
**Languages:** Python
**Prerequisites:** 16-pq-isogenies-and-migration/02-sidh-broken, 16-pq-isogenies-and-migration/08-harvest-now-decrypt-later
**Time:** ~45 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain what FIPS 203/204/205 standardize and what they don’t
- Distinguish KEMs from signatures and map them to real system boundaries
- Implement a small “standards catalog + decision helper” in pure stdlib Python
- Compute a simple HNDL-driven prioritization for migrations
- Apply a repeatable checklist to review PQC-related PRs and designs

## The Problem

Teams keep asking: “which post-quantum algorithm should we use?” and then try to answer it as if it were a library choice. That fails because the hard part isn’t the math — it’s understanding where the standards fit into protocols, certificates, devices, compliance, and rollouts.

If you don’t internalize what NIST actually standardized, you’ll ship mistakes like: treating ML-KEM as “encryption”, swapping signatures without updating certificate/tooling assumptions, or migrating the wrong thing first (e.g., focusing on AES while your key exchange is exposed to harvest-now-decrypt-later).

## The Concept

NIST’s first post-quantum cryptography standards are Federal Information Processing Standards (FIPS) that specify *interfaces* for:

- **Key establishment** (via a **KEM**) — used to derive shared secrets for symmetric encryption.
- **Digital signatures** — used for identity, authenticity, and integrity (certificates, code signing, messages).

The key idea: *a KEM is not “public-key encryption”*. A KEM gives you a shared secret you feed into symmetric encryption (AEAD). A signature gives you authenticity but does not create secrecy.

Here’s the “tour map” (families, not parameter sets):

| Standard | Standardized family name | Primitive | What you replace in systems |
|---|---|---|---|
| FIPS 203 | ML-KEM (ex-Kyber) | KEM | RSA key transport, (EC)DH key exchange |
| FIPS 204 | ML-DSA (ex-Dilithium) | Signature | RSA/ECDSA/EdDSA signatures |
| FIPS 205 | SLH-DSA (ex-SPHINCS+) | Signature | High-assurance signatures when you accept larger sizes |

This lesson builds a tiny helper that:
1) normalizes naming, 2) demonstrates KEM vs signature semantics, 3) ties migration priority to **data lifetime**, and 4) turns an inventory into a migration checklist.

## Build It

### Step 1: Identify what’s standardized
We model the three standardized families (FIPS 203/204/205), plus a strict name normalizer so you stop mixing “Kyber/Dilithium/SPHINCS+” with “ML-KEM/ML-DSA/SLH-DSA”.

```python
from dataclasses import dataclass
from typing import Literal

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
```

### Step 2: Understand KEM vs signatures (toy demo)
To keep this lesson stdlib-only, we implement a deterministic “toy KEM” that demonstrates the *shape* of a KEM API: keygen → encapsulate (ciphertext + shared secret) → decapsulate (shared secret). This is not secure cryptography — it’s a semantic model you can map to ML-KEM in real systems.

```python
import hashlib


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
```

### Step 3: Prioritize by HNDL (timeline thinking)
Migration priority isn’t “how fancy is the crypto”. It’s mostly: **how long the data must stay confidential** vs **when you think quantum becomes practical** for breaking key establishment. This step encodes that logic and produces a recommendation skeleton.

```python
from dataclasses import dataclass
from typing import Literal


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
```

### Step 4: Turn inventory into a migration plan
Real migrations start with an inventory. This step classifies components, filters what’s PQC-relevant, and turns that into a concrete checklist you can hand to a team.

```python
from dataclasses import dataclass
from typing import Iterable, Literal, cast


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
```

Run it:

```bash
python3 code/main.py
```

## Use It

In production, you don’t implement ML-KEM/ML-DSA/SLH-DSA yourself. You pick an audited implementation and integrate it via protocols and certificate tooling.

- **TLS / protocols:** use a TLS stack that supports PQC (often **hybrid** key exchange during migration).
- **Library implementations:** Open Quantum Safe (`liboqs`) and integrations (e.g., OpenSSL provider) are commonly used for experimentation and pilots.
- **Validation/compliance:** for regulated environments, you care about algorithm profiles, test vectors, and validation pipelines (e.g., known-answer tests and interoperability suites), not just “it compiles”.

## Pitfalls

- Treating **ML-KEM as encryption** instead of key establishment (you still need AEAD for data).
- Migrating **symmetric crypto first** (AES/SHA) while leaving key exchange/signatures quantum-vulnerable (the actual weak link for PQC transition).
- Forgetting that **signatures touch tooling**: CAs, certificate profiles, firmware signing, HSMs, update pipelines, and verification libraries.
- Shipping a “PQC upgrade” with **no crypto agility** (no negotiation/versioning → impossible to rotate again).
- Ignoring **message sizes/latency**: some PQ signatures are much larger than classical ones; protocols and storage need budgets.

## Ship It

Save and reuse the artifact in `outputs/pqc-migration-pr-review-checklist.md`:

- Use it as a PR review checklist for any “PQC”, “hybrid TLS”, “certificate”, or “crypto-agility” change.
- Paste it into an LLM when reviewing a migration plan and answer the questions with project-specific details.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe the KEM roundtrip and how the inventory becomes a checklist.
2. Medium. Extend the sample `inventory` in `code/main.py` with 5 more components (e.g., mTLS, OAuth tokens, update signing, database backups, S/MIME). Ensure the printed classification makes sense.
3. Hard. Take a real service boundary (e.g., “browser ↔ API gateway ↔ backend”) and write a short migration plan that specifies (a) where ML-KEM fits, (b) which signatures you need, and (c) how you’ll run hybrid + negotiate + roll back safely.

## Key Terms

| Term | What people say | What it actually means |
|---|---|---|
| FIPS | “a standard” | A specific NIST publication specifying an algorithm interface + requirements |
| KEM | “PQC encryption” | A mechanism to establish a shared secret; you still encrypt with symmetric AEAD |
| ML-KEM | “Kyber” | NIST-standardized KEM family (FIPS 203) |
| ML-DSA | “Dilithium” | NIST-standardized signature family (FIPS 204) |
| SLH-DSA | “SPHINCS+” | NIST-standardized stateless hash-based signatures (FIPS 205) |
| Hybrid | “use two algorithms” | Combine classical + PQC during migration to reduce risk and improve interoperability |
| HNDL | “future problem” | Harvest-now-decrypt-later: captured traffic can be decrypted later if key establishment breaks |
| Crypto agility | “support algorithms” | Ability to negotiate, rotate, and recover without redesigning the whole system |

## Further Reading

- NIST, “NIST Releases First 3 Finalized Post-Quantum Encryption Standards” (2024) — announcement and high-level positioning of FIPS 203/204/205.
- NIST CSRC, FIPS 203 / FIPS 204 / FIPS 205 (final, 2024-08-13) — the normative standards for ML-KEM, ML-DSA, SLH-DSA.
- NIST CSRC, Post-Quantum Cryptography project page — status and pointers to transition guidance.
- NIST IR 8547 (draft), “Transition to Post-Quantum Cryptography Standards” (2024) — migration framing and timelines.
