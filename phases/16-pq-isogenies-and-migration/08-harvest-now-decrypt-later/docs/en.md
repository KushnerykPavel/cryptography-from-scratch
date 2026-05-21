# Harvest-Now, Decrypt Later (HNDL) — Threat & Timeline
> Quantum turns “someday” into “already”: if the data must stay secret past Q‑Day, recording it today is enough.

**Type:** Learn
**Languages:** Python
**Prerequisites:** Phase 16 Lessons 05–07 (`05-nist-pqc-standards`, `06-hybrid-tls`, `07-crypto-agility`)
**Time:** ~45 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain what “harvest now, decrypt later” means in operational terms (record now, decrypt when CRQC arrives)
- Compute the HNDL exposure window given data lifetime and estimated “years to CRQC”
- Implement Mosca’s X/Y/Z margin check to justify “start migration now” decisions
- Distinguish Shor’s impact on public-key crypto from Grover’s impact on symmetric crypto
- Apply a simple risk scoring model to prioritize a crypto inventory for PQ migration work

## The Problem

You ship TLS, VPNs, encrypted backups, and signed updates today. Most of it is “secure” against *current* attackers. But a well-resourced adversary can still record your ciphertext at scale (internet backbone, data center taps, compromised edge devices), store it cheaply, and wait.

When a cryptographically relevant quantum computer (CRQC) arrives, Shor’s algorithm breaks the public-key math that underpins most key establishment (RSA, (EC)DH). That means recorded traffic can be decrypted *retroactively*. The painful part: you cannot patch “yesterday’s ciphertext”. If the data needed to stay secret for 10–20 years, it’s already a present-day risk.

This lesson gives you a timeline-first mental model and a small, testable script to turn “quantum is coming” into: “Which systems do we migrate first, and why?”

## The Concept

Think of HNDL as a *time mismatch* problem:

1) You send ciphertext today.
2) The attacker records it today.
3) Years later, the attacker gains a new capability (CRQC).
4) If your data is still sensitive at that point, the attacker decrypts it.

The timeline can be summarized by Mosca’s X/Y/Z model:

- **X** = data security life (how many years must it remain secret)
- **Y** = migration time (how many years to deploy PQ/hybrid everywhere it matters)
- **Z** = years until CRQC (your best estimate, plus uncertainty)

Rule of thumb:
- If **X + Y > Z**, you must treat this as urgent: your migration won’t finish before your secrets expire.

Why “PFS” isn’t a free pass:
- Forward secrecy protects you against *key compromise later*.
- HNDL is about *algorithm collapse later*: if key establishment is Shor-vulnerable, recorded handshakes can be retroactively solved.

Why “AES-256” alone isn’t enough:
- Even if symmetric crypto only loses a square-root factor under Grover, the session key still has to be established.
- If key establishment is broken, the symmetric strength becomes irrelevant: the attacker recovers the session key directly.

## Build It

### Step 1: Model the timeline (X, Y, Z)
This step implements two tiny timeline calculators:
- `hndl_exposure_years(X, Z)` tells you how many years of data remain sensitive after CRQC arrives.
- `mosca_margin_years(X, Y, Z)` turns Mosca’s rule into a single “margin” number (positive means urgent).

```python
def _require_int(name: str, value: int) -> int:
    if not isinstance(value, int):
        raise TypeError(f"{name} must be int, got {type(value).__name__}")
    return value


def _require_non_negative(name: str, value: int) -> int:
    _require_int(name, value)
    if value < 0:
        raise ValueError(f"{name} must be >= 0, got {value}")
    return value


def _require_str(name: str, value: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be str, got {type(value).__name__}")
    return value


def clamp_int(value: int, lo: int, hi: int) -> int:
    _require_int("value", value)
    _require_int("lo", lo)
    _require_int("hi", hi)
    if lo > hi:
        raise ValueError("lo must be <= hi")
    if value < lo:
        return lo
    if value > hi:
        return hi
    return value


def hndl_exposure_years(data_security_life_years: int, years_to_crqc: int) -> int:
    """
    How many years of *still-sensitive* ciphertext exist *after* a CRQC arrives?

    If an attacker records ciphertext today and can decrypt it in `years_to_crqc` years,
    then any data that must remain secret longer than that is exposed.
    """
    _require_non_negative("data_security_life_years", data_security_life_years)
    _require_non_negative("years_to_crqc", years_to_crqc)
    return max(0, data_security_life_years - years_to_crqc)


def mosca_margin_years(
    data_security_life_years: int, migration_years: int, years_to_crqc: int
) -> int:
    """
    Mosca's XYZ model as a single number (margin in years).

    - X: how long the data must remain secure (data_security_life_years)
    - Y: how long migration takes (migration_years)
    - Z: years until a cryptographically relevant quantum computer (years_to_crqc)

    If X + Y > Z, the margin is positive and you should treat it as "start now".
    """
    _require_non_negative("data_security_life_years", data_security_life_years)
    _require_non_negative("migration_years", migration_years)
    _require_non_negative("years_to_crqc", years_to_crqc)
    return (data_security_life_years + migration_years) - years_to_crqc
```

### Step 2: Distinguish Shor vs Grover impact
This step adds the two “back of the napkin” checks you’ll see in real PQ planning:
- Grover’s generic speedup suggests doubling symmetric key sizes (rule-of-thumb).
- HNDL risk is dominated by whether key establishment is still Shor-vulnerable vs hybrid/PQ.

```python
def grover_effective_security_bits(symmetric_key_bits: int) -> int:
    """
    Tiny rule-of-thumb: Grover turns 2^n key search into ~2^(n/2).

    This is *not* a concrete cost model. It's just the mental arithmetic that:
    - AES-128 (128-bit) -> ~64-bit against ideal Grover
    - AES-256 (256-bit) -> ~128-bit against ideal Grover
    """
    _require_non_negative("symmetric_key_bits", symmetric_key_bits)
    return symmetric_key_bits // 2


def is_hybrid_or_pq(mode: str) -> bool:
    _require_str("mode", mode)
    normalized = mode.strip().lower()
    return normalized in {"hybrid", "pqc", "pq"}


def is_classical(mode: str) -> bool:
    _require_str("mode", mode)
    normalized = mode.strip().lower()
    return normalized in {"classical", "classic", "rsa", "ecdh", "ecdhe", "dh"}
```

### Step 3: Score a crypto inventory for HNDL risk
This step defines a tiny “crypto inventory row” (`CryptoUse`) and a deterministic `hndl_risk_score(...)` (0–100). It’s not “security math”; it’s a prioritization aid to make the timeline explicit.

```python
from dataclasses import dataclass
from typing import Iterable, List, Tuple


@dataclass(frozen=True)
class CryptoUse:
    name: str
    kind: str
    key_establishment_mode: str
    data_security_life_years: int
    migration_years: int
    blast_radius: int

    def validate(self) -> None:
        if not self.name:
            raise ValueError("name must be non-empty")
        if self.kind not in {"in_transit", "at_rest", "signing"}:
            raise ValueError("kind must be one of: in_transit, at_rest, signing")
        if not (is_classical(self.key_establishment_mode) or is_hybrid_or_pq(self.key_establishment_mode)):
            raise ValueError(
                "key_establishment_mode must be 'classical', 'hybrid', or 'pqc' (or a classical alias)"
            )
        _require_non_negative("data_security_life_years", self.data_security_life_years)
        _require_non_negative("migration_years", self.migration_years)
        if self.blast_radius not in {1, 2, 3}:
            raise ValueError("blast_radius must be 1, 2, or 3")


def hndl_risk_score(use: CryptoUse, years_to_crqc: int) -> int:
    """
    Deterministic 0..100 score for prioritization.

    - If key establishment is hybrid/PQ: treat HNDL confidentiality risk as 0.
    - Otherwise: risk increases if the data remains sensitive past CRQC arrival,
      and if migration cannot finish before CRQC.
    """
    use.validate()
    _require_non_negative("years_to_crqc", years_to_crqc)

    if is_hybrid_or_pq(use.key_establishment_mode):
        return 0

    exposure = hndl_exposure_years(use.data_security_life_years, years_to_crqc)
    if exposure == 0:
        return 0

    time_component = (exposure * 100) // max(1, use.data_security_life_years)
    behind_component = 25 if use.migration_years > years_to_crqc else 0
    mosca_component = 25 if mosca_margin_years(use.data_security_life_years, use.migration_years, years_to_crqc) > 0 else 0
    blast_component = (use.blast_radius - 1) * 15

    return clamp_int(time_component + behind_component + mosca_component + blast_component, 0, 100)


def prioritize(uses: Iterable[CryptoUse], years_to_crqc: int) -> List[Tuple[CryptoUse, int]]:
    scored = [(use, hndl_risk_score(use, years_to_crqc)) for use in uses]
    scored.sort(key=lambda pair: (pair[1], pair[0].name), reverse=True)
    return scored
```

### Step 4: Turn scores into a migration order
This step is the “so what”: print a migration order that includes the same X/Y/Z you used to justify it. In real life, you’d export this to a tracker or a CBOM-like inventory, but the shape is the same.

```python
def _print_step(step: int, name: str) -> None:
    print(f"=== Step {step}: {name} ===")


def main() -> None:
    years_to_crqc = 10

    _print_step(1, "Model the timeline (X, Y, Z)")
    x = 15
    y = 4
    z = years_to_crqc
    print(f"Example: X={x}y data life, Y={y}y migration, Z={z}y to CRQC")
    print(f"Mosca margin (X+Y-Z): {mosca_margin_years(x, y, z)} years")
    print(f"HNDL exposure (max(0, X-Z)): {hndl_exposure_years(x, z)} years")
    print()

    _print_step(2, "Distinguish Shor vs Grover impact")
    print(f"Grover effective bits: AES-128 -> {grover_effective_security_bits(128)} bits")
    print(f"Grover effective bits: AES-256 -> {grover_effective_security_bits(256)} bits")
    print("Takeaway: for HNDL, public-key key establishment dominates the risk.")
    print()

    _print_step(3, "Score a crypto inventory for HNDL risk")
    uses = [
        CryptoUse(
            name="External API TLS",
            kind="in_transit",
            key_establishment_mode="classical",
            data_security_life_years=12,
            migration_years=3,
            blast_radius=3,
        ),
        CryptoUse(
            name="Internal service mesh",
            kind="in_transit",
            key_establishment_mode="hybrid",
            data_security_life_years=7,
            migration_years=2,
            blast_radius=3,
        ),
        CryptoUse(
            name="Long-term backups (envelope keys)",
            kind="at_rest",
            key_establishment_mode="classical",
            data_security_life_years=20,
            migration_years=5,
            blast_radius=2,
        ),
        CryptoUse(
            name="Code signing pipeline",
            kind="signing",
            key_establishment_mode="classical",
            data_security_life_years=8,
            migration_years=4,
            blast_radius=2,
        ),
    ]
    for use, score in prioritize(uses, years_to_crqc):
        print(f"{score:>3}  {use.name}")
    print()

    _print_step(4, "Turn scores into a migration order")
    prioritized = prioritize(uses, years_to_crqc)
    for idx, (use, score) in enumerate(prioritized, start=1):
        if score == 0:
            continue
        margin = mosca_margin_years(use.data_security_life_years, use.migration_years, years_to_crqc)
        print(
            f"{idx}. {use.name}: score={score}, kind={use.kind}, mode={use.key_establishment_mode}, "
            f"X={use.data_security_life_years}, Y={use.migration_years}, Z={years_to_crqc}, margin={margin}"
        )
```

Run it:
`python3 code/main.py`

## Use It

Real-world equivalents (you don’t “implement HNDL defense”; you migrate the cryptography):

- **TLS / QUIC key establishment:** adopt a TLS 1.3 stack that supports **hybrid key exchange** (classical + PQ) during transition (e.g., X25519 + ML‑KEM), then move toward pure PQ when your ecosystem supports it.
- **SSH / remote access:** prefer implementations that offer hybrid/PQ KEX options and can be centrally enforced.
- **Certificates & signatures:** plan for PQ signatures for long-lived trust anchors and software update ecosystems (new roots, intermediate strategy, signing infrastructure updates).
- **Discovery & inventory:** follow a cryptographic discovery + inventory process (often described as a CBOM-like asset register) so you can answer: “where are RSA/ECDH used?”

## Pitfalls

- Treating “quantum” as a future-only risk and delaying migration planning until “we see Q‑Day coming”.
- Assuming “TLS 1.3 + PFS” eliminates HNDL risk without checking whether key establishment is Shor-vulnerable.
- Upgrading **only** symmetric primitives (e.g., switching to AES‑256) while leaving RSA/ECDH key establishment unchanged.
- Focusing only on the internet edge and ignoring **internal** traffic, backups, logs, telemetry, and cross-region replication.
- Building migration plans without a real inventory: you can’t prioritize what you can’t find.

## Ship It

Reusable artifact: `outputs/hndl-decision-guide.md`.

Use it as a paste-ready checklist to:
- open a PQ readiness issue
- review a TLS/VPN/backup change in a PR
- drive a crypto inventory meeting (“what’s our X, Y, Z for this system?”)

## Exercises

1. Easy: Run `python3 code/main.py`. Observe which `CryptoUse` entries get a non-zero score and why.
2. Medium: Edit the `uses = [...]` list in `code/main.py` to model your own environment (TLS edge, service mesh, backups, code signing). Change `years_to_crqc` and see how the priority order changes.
3. Hard: Create a “crypto inventory” file for a small system you control (even a single service). For each connection/storage/signing workflow, record: X (data lifetime), Y (migration time), and whether key establishment is classical vs hybrid/PQ. Then compare your manual ordering to the script’s ordering and explain discrepancies.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| HNDL | “Decrypt later with quantum” | Record ciphertext today; decrypt later if/when key establishment collapses |
| CRQC | “A big quantum computer” | A quantum computer capable of breaking widely deployed public-key cryptography at practical cost |
| Mosca X/Y/Z | “A theorem” | A timeline model: data lifetime + migration time vs years until collapse |
| Hybrid key exchange | “Best of both worlds” | Combine classical + PQ components so either one surviving protects the session (if done correctly) |
| Crypto inventory / CBOM | “List the algorithms” | A system-level map of where cryptography is used in practice (protocols, keys, certs, libraries, configs) |
| Crypto-agility | “Swapping algorithms” | The engineering capability to change crypto without rewriting everything (APIs, config, rollout, rollback) |

## Further Reading

- NIST, *What Is Post-Quantum Cryptography?* (2024) — concise overview, includes “harvest now, decrypt later”.
- NIST, *IR 8547 (IPD): Transition to Post-Quantum Cryptography Standards* (2024) — migration considerations and Mosca timeline framing.
- NIST NCCoE, *SP 1800-38: Migration to Post-Quantum Cryptography (Practice Guide)* (preliminary draft) — practical discovery/inventory and migration architecture.
- IETF, *Hybrid key exchange in TLS 1.3* (draft-ietf-tls-hybrid-design) — how hybrid KEX is negotiated in TLS 1.3 during the transition.
