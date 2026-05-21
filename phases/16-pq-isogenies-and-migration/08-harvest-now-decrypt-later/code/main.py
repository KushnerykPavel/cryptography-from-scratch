"""
Harvest-now, decrypt-later (HNDL) threat modeling mini-lab.

Run:
  python3 code/main.py

This is an educational, from-scratch model of the *timeline logic* behind HNDL:
- "If an attacker records ciphertext today, can they decrypt it later?"
- Mosca's XYZ rule-of-thumb: if X (data lifetime) + Y (migration time) > Z (years to CRQC),
  you're already late.

The code intentionally stays small and deterministic so it can be tested with
`tests/vectors.json` using stdlib-only Python.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Tuple


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


if __name__ == "__main__":
    main()
