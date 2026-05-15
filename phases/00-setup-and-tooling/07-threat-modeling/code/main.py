from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Asset:
    name: str
    why: str
    impact: str


@dataclass(frozen=True)
class TrustBoundary:
    src: str
    dst: str
    data: str


@dataclass(frozen=True)
class Adversary:
    name: str
    capabilities: tuple[str, ...]


@dataclass(frozen=True)
class ThreatModelSpec:
    system_name: str
    system_description: str
    assets: tuple[Asset, ...]
    trust_boundaries: tuple[TrustBoundary, ...]
    adversaries: tuple[Adversary, ...]
    security_goals: tuple[str, ...]
    out_of_scope: tuple[str, ...]
    assumptions: tuple[str, ...]
    notes: tuple[str, ...]


def _require_str(obj: dict, key: str) -> str:
    if key not in obj:
        raise ValueError(f"missing required field: {key}")
    v = obj[key]
    if not isinstance(v, str) or not v.strip():
        raise ValueError(f"field must be a non-empty string: {key}")
    return v.strip()


def _optional_str(obj: dict, key: str) -> str | None:
    v = obj.get(key)
    if v is None:
        return None
    if not isinstance(v, str) or not v.strip():
        raise ValueError(f"field must be a non-empty string when present: {key}")
    return v.strip()


def _optional_list_of_str(obj: dict, key: str) -> tuple[str, ...]:
    v = obj.get(key, [])
    if v is None:
        return ()
    if not isinstance(v, list):
        raise ValueError(f"field must be a list: {key}")
    out: list[str] = []
    for i, item in enumerate(v):
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"{key}[{i}] must be a non-empty string")
        out.append(item.strip())
    return tuple(out)


def _optional_list(obj: dict, key: str) -> list:
    v = obj.get(key, [])
    if v is None:
        return []
    if not isinstance(v, list):
        raise ValueError(f"field must be a list: {key}")
    return v


def parse_threat_model_spec(raw: dict) -> ThreatModelSpec:
    if not isinstance(raw, dict):
        raise ValueError("spec must be a JSON object")

    system = raw.get("system")
    if not isinstance(system, dict):
        raise ValueError("missing required field: system")

    system_name = _require_str(system, "name")
    system_description = _require_str(system, "description")

    assets_raw = _optional_list(raw, "assets")
    assets: list[Asset] = []
    for i, a in enumerate(assets_raw):
        if not isinstance(a, dict):
            raise ValueError(f"assets[{i}] must be an object")
        name = _require_str(a, "name")
        why = _require_str(a, "why")
        impact = _require_str(a, "impact")
        assets.append(Asset(name=name, why=why, impact=impact))

    tb_raw = _optional_list(raw, "trust_boundaries")
    trust_boundaries: list[TrustBoundary] = []
    for i, tb in enumerate(tb_raw):
        if not isinstance(tb, dict):
            raise ValueError(f"trust_boundaries[{i}] must be an object")
        src = _require_str(tb, "from")
        dst = _require_str(tb, "to")
        data = _require_str(tb, "data")
        trust_boundaries.append(TrustBoundary(src=src, dst=dst, data=data))

    adv_raw = _optional_list(raw, "adversaries")
    adversaries: list[Adversary] = []
    for i, adv in enumerate(adv_raw):
        if not isinstance(adv, dict):
            raise ValueError(f"adversaries[{i}] must be an object")
        name = _require_str(adv, "name")
        caps_list = _optional_list_of_str(adv, "capabilities")
        adversaries.append(Adversary(name=name, capabilities=caps_list))

    return ThreatModelSpec(
        system_name=system_name,
        system_description=system_description,
        assets=tuple(assets),
        trust_boundaries=tuple(trust_boundaries),
        adversaries=tuple(adversaries),
        security_goals=_optional_list_of_str(raw, "security_goals"),
        out_of_scope=_optional_list_of_str(raw, "out_of_scope"),
        assumptions=_optional_list_of_str(raw, "assumptions"),
        notes=_optional_list_of_str(raw, "notes"),
    )


def _md_table(rows: list[list[str]]) -> str:
    if not rows:
        return ""
    widths = [0] * len(rows[0])
    for r in rows:
        if len(r) != len(widths):
            raise ValueError("table row width mismatch")
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], len(cell))

    def fmt_row(r: list[str]) -> str:
        padded = [r[i].ljust(widths[i]) for i in range(len(widths))]
        return "| " + " | ".join(padded) + " |"

    out = [fmt_row(rows[0])]
    out.append("|" + "|".join("-" * (w + 2) for w in widths) + "|")
    for r in rows[1:]:
        out.append(fmt_row(r))
    return "\n".join(out)


def render_threat_model_markdown(spec: ThreatModelSpec) -> str:
    lines: list[str] = []
    lines.append(f"# Threat Model — {spec.system_name}")
    lines.append("")
    lines.append("## System")
    lines.append(spec.system_description)

    if spec.assets:
        lines.append("")
        lines.append("## Assets")
        rows = [["Asset", "Why it matters", "Impact"]]
        for a in spec.assets:
            rows.append([a.name, a.why, a.impact])
        lines.append(_md_table(rows))

    if spec.trust_boundaries:
        lines.append("")
        lines.append("## Trust Boundaries")
        rows = [["From", "To", "Data that crosses"]]
        for tb in spec.trust_boundaries:
            rows.append([tb.src, tb.dst, tb.data])
        lines.append(_md_table(rows))

    if spec.adversaries:
        lines.append("")
        lines.append("## Adversaries")
        for adv in spec.adversaries:
            if adv.capabilities:
                caps = ", ".join(adv.capabilities)
                lines.append(f"- **{adv.name}** ({caps})")
            else:
                lines.append(f"- **{adv.name}**")

    if spec.security_goals:
        lines.append("")
        lines.append("## Security Goals")
        for g in spec.security_goals:
            lines.append(f"- {g}")

    if spec.assumptions:
        lines.append("")
        lines.append("## Assumptions")
        for a in spec.assumptions:
            lines.append(f"- {a}")

    if spec.out_of_scope:
        lines.append("")
        lines.append("## Out of Scope")
        for o in spec.out_of_scope:
            lines.append(f"- {o}")

    if spec.notes:
        lines.append("")
        lines.append("## Notes")
        for n in spec.notes:
            lines.append(f"- {n}")

    lines.append("")
    lines.append("## Review Checklist")
    checklist = [
        "Is the primary adversary named in one sentence?",
        "Are trust boundaries explicit?",
        "Do the goals mention integrity/authentication (not just encryption)?",
        "Is replay/freshness addressed where relevant?",
        "Is key management specified (generation, storage, rotation, revocation)?",
        "Are out-of-scope items explicit (and acceptable)?",
    ]
    for item in checklist:
        lines.append(f"- [ ] {item}")

    lines.append("")
    return "\n".join(lines)


def example_spec() -> dict:
    return {
        "system": {"name": "Encrypted Notes (toy)", "description": "A single-user notes app that syncs to a server."},
        "assets": [
            {"name": "note contents", "why": "privacy", "impact": "high"},
            {"name": "encryption keys", "why": "all notes depend on them", "impact": "critical"},
        ],
        "trust_boundaries": [{"from": "device", "to": "sync server", "data": "ciphertext + metadata"}],
        "adversaries": [
            {"name": "passive network observer", "capabilities": ["eavesdrop"]},
            {"name": "server compromise", "capabilities": ["read stored ciphertext", "tamper with stored blobs"]},
        ],
        "security_goals": ["confidentiality", "integrity", "replay resistance"],
        "out_of_scope": ["device compromise (this toy app assumes the OS is not malware)"],
        "notes": ["Use an audited AEAD library; never roll your own."],
    }


def _load_json(path: Path) -> dict:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ValueError(f"input file not found: {path}")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON: {exc.msg} at line {exc.lineno} column {exc.colno}")
    if not isinstance(data, dict):
        raise ValueError("top-level JSON value must be an object")
    return data


def main() -> None:
    p = argparse.ArgumentParser(description="Generate a one-page threat model in Markdown.")
    p.add_argument("--in", dest="in_path", metavar="PATH", help="Input JSON threat model spec.")
    p.add_argument("--example", action="store_true", help="Print an example threat model.")
    args = p.parse_args()

    if bool(args.in_path) == bool(args.example):
        raise SystemExit("pass exactly one of: --in PATH, --example")

    raw = example_spec() if args.example else _load_json(Path(args.in_path))
    spec = parse_threat_model_spec(raw)
    print(render_threat_model_markdown(spec))


if __name__ == "__main__":
    main()
