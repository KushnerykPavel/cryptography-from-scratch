# Crypto-Agility — Designing for Migration

> Crypto changes are inevitable; make them safe, measurable, and boring.

**Type:** Build
**Languages:** Python
**Prerequisites:** `phases/16-pq-isogenies-and-migration/05-nist-pqc-standards`, `phases/16-pq-isogenies-and-migration/06-hybrid-tls`
**Time:** ~60 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- **Explain** why “supporting many algorithms” is not crypto-agility unless selection is constrained by policy
- **Compute** an acceptable algorithm set from a registry + policy (allowlist/denylist, security level, deprecation date)
- **Implement** deterministic suite negotiation: client capabilities ∩ server preferences ∩ policy
- **Distinguish** “compatibility fallback” (dangerous) from “controlled migration” (feature-flagged, logged, measurable)
- **Apply** a migration scan to detect deprecated/unknown algorithm IDs in configs before they ship

## The Problem

Post-quantum migration is not a one-time switch. Real systems carry *years* of compatibility pressure: older clients, embedded devices, vendor stacks, and “temporary” flags that become permanent. When an algorithm is broken or deprecated (e.g., an isogeny-based candidate like SIKE/SIDH), the worst failures come from “we supported the replacement” but the system *still negotiated the bad thing* in some edge case.

Crypto breaks at the seams: a new algorithm lands, negotiation logic is patched in, a fallback path stays enabled, and suddenly you have silent downgrade risk, split-brain deployments, or “unknown algorithm ID” strings that different components interpret differently. Without an explicit agility design, you don’t have a migration plan — you have a hope.

This lesson makes crypto-agility concrete: model algorithms as data, enforce a policy, negotiate suites deterministically, and scan configs for deprecated IDs. The goal is not a TLS implementation; it’s the engineering pattern that keeps migrations safe.

## The Concept

Crypto-agility is *not* “support lots of algorithms”. It’s a discipline for safely changing algorithms over time.

Think in layers:

| Layer | What it is | Failure mode if you skip it |
|------|------------|-----------------------------|
| Algorithm registry | “What algorithms exist here, with metadata?” | Hard-coded strings, inconsistent names, shadow support |
| Policy | “What’s allowed today, and why?” | Accidental negotiation of deprecated/broken/weak choices |
| Negotiation | “Given client/server capability, pick one allowed suite.” | Downgrades, split-brain, “first match wins” surprises |
| Telemetry + rollout | “Measure negotiated IDs and gate via flags.” | You can’t prove migration progress (or detect regressions) |
| Kill switch | “Rapidly deny an algorithm everywhere.” | Emergency response becomes a multi-week redeploy |

Two mental models help:

1) **Treat algorithm IDs as an API.** If IDs aren’t canonicalized and validated, you don’t have interoperability; you have stringly-typed chaos.

2) **Separate capability from policy.** A component might *support* an algorithm (capability), but policy decides whether it is *allowed* to be used in production at a given time.

We’ll build a tiny framework that embodies those ideas.

## Build It

### Step 1: Model algorithms and ids

Create a small algorithm registry. Each algorithm has a stable ID plus metadata we can reason about (family, security level, PQ-ness, protocol version, and an optional deprecation date). We also canonicalize IDs to avoid “Ed25519” vs “ed_25519” drift.

```python
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Iterable, Mapping, Sequence


class PolicyError(ValueError):
    pass


class NegotiationError(ValueError):
    pass


def canonicalize_alg_id(name: str) -> str:
    s = name.strip().lower()
    s = s.replace("_", "-").replace(" ", "-")
    out = []
    prev_dash = False
    for ch in s:
        ok = ("a" <= ch <= "z") or ("0" <= ch <= "9")
        if ok:
            out.append(ch)
            prev_dash = False
            continue
        if ch == "-":
            if not prev_dash:
                out.append("-")
            prev_dash = True
            continue
    normalized = "".join(out).strip("-")
    if not normalized:
        raise ValueError("empty/invalid algorithm id")
    return normalized


@dataclass(frozen=True)
class Algorithm:
    alg_id: str
    family: str  # "sig" | "kem"
    security_level: int  # NIST-ish 1..5
    pq: bool
    min_protocol_version: int = 1
    not_after: date | None = None
    notes: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "alg_id", canonicalize_alg_id(self.alg_id))
        family = self.family.strip().lower()
        object.__setattr__(self, "family", family)
        if family not in {"sig", "kem"}:
            raise ValueError(f"unknown family: {self.family}")
        if not (1 <= self.security_level <= 5):
            raise ValueError("security_level must be in 1..5")
        if self.min_protocol_version < 1:
            raise ValueError("min_protocol_version must be >= 1")
```

This registry is the “source of truth” for what algorithm IDs mean. It’s also where you attach migration hooks like `not_after` (a hard cutoff date) and `min_protocol_version` (to prevent old protocol versions from selecting new algorithms by accident).

### Step 2: Enforce a policy and pick defaults

Define a policy that maps “what we want in production today” into a filter over the registry. Then add deterministic selection logic to pick a default signature and KEM.

```python
@dataclass(frozen=True)
class CryptoPolicy:
    protocol_version: int
    now: date
    min_security_level: int = 1
    require_pq: bool = False
    allow_classical_fallback: bool = True
    allowed_algs: frozenset[str] | None = None
    denied_algs: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if self.protocol_version < 1:
            raise PolicyError("protocol_version must be >= 1")
        if not (1 <= self.min_security_level <= 5):
            raise PolicyError("min_security_level must be in 1..5")
        if self.allowed_algs is not None:
            canon = frozenset(canonicalize_alg_id(a) for a in self.allowed_algs)
            object.__setattr__(self, "allowed_algs", canon)
        object.__setattr__(
            self, "denied_algs", frozenset(canonicalize_alg_id(a) for a in self.denied_algs)
        )


def filter_algorithms(
    algorithms: Sequence[Algorithm], policy: CryptoPolicy, family: str | None = None
) -> list[Algorithm]:
    fam = family.strip().lower() if family is not None else None
    if fam is not None and fam not in {"sig", "kem"}:
        raise PolicyError(f"unknown family: {family}")

    out: list[Algorithm] = []
    for alg in algorithms:
        if fam is not None and alg.family != fam:
            continue
        if alg.min_protocol_version > policy.protocol_version:
            continue
        if alg.security_level < policy.min_security_level:
            continue
        if policy.allowed_algs is not None and alg.alg_id not in policy.allowed_algs:
            continue
        if alg.alg_id in policy.denied_algs:
            continue
        if alg.not_after is not None and policy.now > alg.not_after:
            continue
        if policy.require_pq and not alg.pq:
            continue
        out.append(alg)

    if out:
        return out
    if policy.require_pq and policy.allow_classical_fallback:
        relaxed = CryptoPolicy(
            protocol_version=policy.protocol_version,
            now=policy.now,
            min_security_level=policy.min_security_level,
            require_pq=False,
            allow_classical_fallback=policy.allow_classical_fallback,
            allowed_algs=policy.allowed_algs,
            denied_algs=policy.denied_algs,
        )
        return filter_algorithms(algorithms=algorithms, policy=relaxed, family=family)
    return []


def algorithm_rank_key(alg: Algorithm, policy: CryptoPolicy) -> tuple[int, int, str]:
    pq_bonus = 1 if alg.pq else 0
    return (pq_bonus, alg.security_level, alg.alg_id)


def pick_algorithm(
    algorithms: Sequence[Algorithm], policy: CryptoPolicy, family: str
) -> Algorithm:
    candidates = filter_algorithms(algorithms=algorithms, policy=policy, family=family)
    if not candidates:
        raise NegotiationError(f"no acceptable algorithms for family={family!r}")
    return max(candidates, key=lambda a: algorithm_rank_key(a, policy))
```

This is the core of crypto-agility: policy expresses constraints, and every selection path goes through that policy (not through ad-hoc `if` statements scattered across the codebase).

### Step 3: Negotiate a suite safely

Negotiation should be deterministic and auditable: pick from `client ∩ server` but only if both algorithms pass the policy. We’ll represent a “suite” as `(signature, KEM)`.

```python
@dataclass(frozen=True)
class CryptoSuite:
    sig_alg: str
    kem_alg: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "sig_alg", canonicalize_alg_id(self.sig_alg))
        object.__setattr__(self, "kem_alg", canonicalize_alg_id(self.kem_alg))

    def suite_id(self) -> str:
        return f"sig={self.sig_alg};kem={self.kem_alg}"


def negotiate_suite(
    client_suites: Sequence[CryptoSuite],
    server_suites: Sequence[CryptoSuite],
    algorithms: Sequence[Algorithm],
    policy: CryptoPolicy,
) -> CryptoSuite:
    allowed_sig = {a.alg_id for a in filter_algorithms(algorithms, policy, family="sig")}
    allowed_kem = {a.alg_id for a in filter_algorithms(algorithms, policy, family="kem")}

    client_set = {(s.sig_alg, s.kem_alg) for s in client_suites}
    for suite in server_suites:
        if (suite.sig_alg, suite.kem_alg) not in client_set:
            continue
        if suite.sig_alg not in allowed_sig:
            continue
        if suite.kem_alg not in allowed_kem:
            continue
        return suite
    raise NegotiationError("no mutually supported suite passes policy")
```

The important detail is where the “order” comes from: in this implementation, the server’s preference order is explicit (the `server_suites` list order), but the server cannot “prefer” anything the policy disallows.

### Step 4: Scan configs and build a migration plan

Agility fails when deprecated algorithms are still present in configs, even if the “happy path” code uses something else. We’ll scan a config object for unknown/deprecated IDs, then build a rollout target plan for the next deployment.

```python
@dataclass(frozen=True)
class MigrationFinding:
    alg_id: str
    reason: str
    action: str


def scan_config_for_deprecated_algorithms(
    config: Mapping[str, object], algorithms: Sequence[Algorithm], on: date
) -> list[MigrationFinding]:
    alg_index = {a.alg_id: a for a in algorithms}

    used: set[str] = set()
    for key in ("sig_alg", "kem_alg", "allowed_algs", "denied_algs"):
        value = config.get(key)
        if value is None:
            continue
        if isinstance(value, str):
            used.add(canonicalize_alg_id(value))
            continue
        if isinstance(value, (list, tuple, set)):
            for item in value:
                if isinstance(item, str):
                    used.add(canonicalize_alg_id(item))

    findings: list[MigrationFinding] = []
    for alg_id in sorted(used):
        alg = alg_index.get(alg_id)
        if alg is None:
            findings.append(
                MigrationFinding(
                    alg_id=alg_id,
                    reason="unknown algorithm id in config",
                    action="delete or map to a known id; block unknown negotiation",
                )
            )
            continue
        if alg.not_after is not None and on > alg.not_after:
            findings.append(
                MigrationFinding(
                    alg_id=alg_id,
                    reason=f"deprecated after {alg.not_after.isoformat()}",
                    action="remove from allowlist/negotiation and rotate any long-lived keys",
                )
            )
    return findings


def build_migration_plan(
    algorithms: Sequence[Algorithm],
    policy: CryptoPolicy,
    preferred_sig_order: Sequence[str],
    preferred_kem_order: Sequence[str],
) -> dict[str, str]:
    candidates_sig = {a.alg_id for a in filter_algorithms(algorithms, policy, family="sig")}
    candidates_kem = {a.alg_id for a in filter_algorithms(algorithms, policy, family="kem")}

    def pick(preferred: Sequence[str], candidates: set[str]) -> str:
        for alg_id in (canonicalize_alg_id(x) for x in preferred):
            if alg_id in candidates:
                return alg_id
        if candidates:
            return sorted(candidates)[-1]
        raise NegotiationError("no candidates for migration plan")

    chosen_sig = pick(preferred_sig_order, candidates_sig)
    chosen_kem = pick(preferred_kem_order, candidates_kem)
    return {
        "rollout_target_suite": CryptoSuite(sig_alg=chosen_sig, kem_alg=chosen_kem).suite_id(),
        "policy_protocol_version": str(policy.protocol_version),
        "policy_min_security_level": str(policy.min_security_level),
        "policy_require_pq": str(policy.require_pq),
        "advice": "roll out behind a feature flag; log negotiated ids; add denylist kill-switch",
    }
```

This is the migration loop: inventory -> detect drift -> choose a target -> roll out with measurement and a kill switch.

Run it:

`python3 code/main.py`

## Use It

Crypto-agility in production is usually enforced across multiple layers:

- **TLS**: cipher suite / group selection + policy (OpenSSL, BoringSSL, NSS, rustls).
- **Policy/config**: explicit allowlists/denylists with fast rollout (feature flags, config pushes).
- **Post-quantum**: hybrid modes and PQ KEMs/signatures via standardized identifiers (e.g., ML-KEM, ML-DSA) and vendor toolchains (OpenSSL providers, liboqs integrations).

Practical “equivalents” of what we built:

- Algorithm registry: internal “crypto catalog” + shared constants (no ad-hoc strings).
- Policy: config schema + CI checks + centralized evaluation (denylist kill switch).
- Negotiation: deterministic selection with telemetry; tests that forbid disallowed suites.

## Pitfalls

1) **Leaving compatibility fallbacks enabled forever.** “Temporary” classical fallback becomes a silent downgrade path.
2) **Allowing unknown algorithm IDs.** If parsing fails open (“unknown means allow”), attackers get a new bypass.
3) **Negotiation logic scattered across services.** Two components disagree on what “ml-kem-768” means, and you get split-brain security.
4) **No telemetry of negotiated IDs.** If you don’t log the chosen suite IDs, you can’t prove migration progress or detect regressions.
5) **No emergency denylist path.** When an algorithm is deprecated, you need a single switch to disable it everywhere quickly.

## Ship It

Save and reuse the artifact at `outputs/crypto-agility-migration-checklist.md` as a paste-ready PR review checklist + prompt. Use it when:

- you’re introducing PQ algorithms (or hybrid suites),
- you’re deprecating a broken primitive (e.g., SIKE/SIDH-era code paths),
- or you’re reviewing negotiation/policy changes that could introduce downgrade risk.

Concrete workflow:

1) Paste the checklist into your PR description or security review doc.
2) Use the “Must-have tests” section to add CI guardrails before rollout.
3) Keep the “Kill switch” section up to date so emergencies are boring.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe how policy blocks deprecated/denied algorithms even if client/server both “support” them.
2. Medium. Extend `code/main.py` to add a `protocol_version=1` client and show that PQ-only algorithms (`min_protocol_version=2`) can’t be negotiated.
3. Hard. Integrate this pattern into a real service config: define a schema for `allowed_algs/denied_algs`, enforce it in CI, and add metrics that count negotiated `(sig, kem)` IDs by version.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Crypto-agility | “Support many algorithms” | Ability to change algorithms safely via registry + policy + negotiation + telemetry |
| Allowlist / denylist | “Config list” | Enforced constraints that gate all selection paths (including fallback paths) |
| Deprecation date | “We don’t like this algo” | A hard time-based cutoff that selection logic must respect |
| Downgrade | “Client chose weaker suite” | Attacker forces negotiation into an allowed-but-weak or unintended choice |
| Suite | “Cipher suite” | A compatible set of algorithms selected together (here: signature + KEM) |

## Further Reading

- Eric Rescorla, *The Transport Layer Security (TLS) Protocol Version 1.3* (2018) — Understand negotiation, downgrade protections, and why policy matters.
- NIST, *Post-Quantum Cryptography Standardization* (project + FIPS 203/204/205) — The “what” of PQ primitives that migrations target.
- CISA, *Post-Quantum Cryptography Initiative* (living guidance) — Practical migration planning, inventory, and risk framing for real systems.
