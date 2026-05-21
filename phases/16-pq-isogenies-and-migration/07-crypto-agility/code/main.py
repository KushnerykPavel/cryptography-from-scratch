"""
Crypto-agility demo: model algorithms, enforce policy, negotiate suites, and plan
safe migrations.

Run:
  python3 code/main.py
"""

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


def _demo_algorithms() -> list[Algorithm]:
    return [
        Algorithm("ecdsa-p256", family="sig", security_level=1, pq=False, notes="classical"),
        Algorithm("ed25519", family="sig", security_level=1, pq=False, notes="classical"),
        Algorithm("ml-dsa-44", family="sig", security_level=2, pq=True, min_protocol_version=2),
        Algorithm("ml-dsa-65", family="sig", security_level=3, pq=True, min_protocol_version=2),
        Algorithm(
            "rsa-2048",
            family="sig",
            security_level=1,
            pq=False,
            not_after=date(2030, 1, 1),
            notes="legacy",
        ),
        Algorithm("x25519", family="kem", security_level=1, pq=False, notes="classical ECDH"),
        Algorithm("p256-ecdh", family="kem", security_level=1, pq=False, notes="classical ECDH"),
        Algorithm("ml-kem-512", family="kem", security_level=1, pq=True, min_protocol_version=2),
        Algorithm("ml-kem-768", family="kem", security_level=3, pq=True, min_protocol_version=2),
        Algorithm(
            "sike-p434",
            family="kem",
            security_level=1,
            pq=True,
            not_after=date(2022, 8, 1),
            notes="broken; keep only to demonstrate deprecation",
        ),
    ]


def _print_table(rows: Sequence[Sequence[str]]) -> None:
    widths = [0] * max(len(r) for r in rows)
    for r in rows:
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], len(cell))
    for r in rows:
        parts = []
        for i, cell in enumerate(r):
            parts.append(cell.ljust(widths[i]))
        print("  ".join(parts).rstrip())


def main() -> None:
    algorithms = _demo_algorithms()

    print("=== Step 1: Model algorithms and ids ===")
    print("Canonical ids:")
    for raw in [" ML-KEM_768 ", "Ed25519", "RSA 2048", "sike_p434"]:
        print(f"- {raw!r} -> {canonicalize_alg_id(raw)!r}")
    print()

    print("=== Step 2: Enforce a policy and pick defaults ===")
    policy = CryptoPolicy(
        protocol_version=2,
        now=date(2026, 5, 21),
        min_security_level=2,
        require_pq=True,
        allow_classical_fallback=False,
        denied_algs=frozenset({"sike-p434"}),
    )
    picked_sig = pick_algorithm(algorithms, policy, family="sig")
    picked_kem = pick_algorithm(algorithms, policy, family="kem")
    print(f"Picked signature: {picked_sig.alg_id} (L{picked_sig.security_level}, pq={picked_sig.pq})")
    print(f"Picked KEM      : {picked_kem.alg_id} (L{picked_kem.security_level}, pq={picked_kem.pq})")
    print()

    print("=== Step 3: Negotiate a suite safely ===")
    client = [
        CryptoSuite("ed25519", "x25519"),
        CryptoSuite("ml-dsa-44", "ml-kem-512"),
        CryptoSuite("ml-dsa-65", "ml-kem-768"),
    ]
    server = [
        CryptoSuite("ml-dsa-65", "ml-kem-768"),
        CryptoSuite("ml-dsa-44", "ml-kem-512"),
        CryptoSuite("ed25519", "x25519"),
    ]
    chosen = negotiate_suite(client, server, algorithms, policy)
    print(f"Negotiated: {chosen.suite_id()}")
    print()

    print("=== Step 4: Scan config and build a migration plan ===")
    sample_config: dict[str, object] = {
        "protocol_version": 2,
        "sig_alg": "RSA 2048",
        "kem_alg": "SIKE_P434",
        "allowed_algs": ["rsa-2048", "ml-dsa-44", "ml-dsa-65", "sike-p434", "ml-kem-768"],
    }
    findings = scan_config_for_deprecated_algorithms(sample_config, algorithms, on=policy.now)
    if not findings:
        print("No deprecations detected.")
    else:
        _print_table(
            [
                ("alg_id", "reason", "action"),
                *[(f.alg_id, f.reason, f.action) for f in findings],
            ]
        )
    plan = build_migration_plan(
        algorithms=algorithms,
        policy=policy,
        preferred_sig_order=["ml-dsa-65", "ml-dsa-44"],
        preferred_kem_order=["ml-kem-768", "ml-kem-512"],
    )
    print()
    _print_table([("key", "value"), *sorted(plan.items())])


if __name__ == "__main__":
    main()
