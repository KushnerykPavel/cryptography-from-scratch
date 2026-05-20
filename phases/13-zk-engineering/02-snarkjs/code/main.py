"""
snarkjs (Groth16) artifact sanity checks + reproducible hashing (stdlib-only).

What this file does:
- Implements a tiny "linter" for common snarkjs Groth16 JSON artifacts:
  - verification_key.json
  - public.json (public signals)
  - proof.json
- Runs structural + consistency checks (protocol/curve match, IC length, nPublic).
- Produces deterministic SHA-256 hashes for the artifacts using canonical JSON.

How to run:
  python3 code/main.py

Important:
- This is an educational implementation. Not constant-time. Not production-safe.
- This does NOT cryptographically verify Groth16 proofs (pairings are out of scope for stdlib-only Python).
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Dict, List, Mapping, Tuple


def canonical_json_dumps(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_json(obj: Any) -> str:
    return sha256_hex(canonical_json_dumps(obj).encode("utf-8"))


def parse_nonneg_decimal_str(value: Any, *, field: str) -> int:
    if not isinstance(value, str):
        raise TypeError(f"{field}: expected str, got {type(value).__name__}")
    if value == "":
        raise ValueError(f"{field}: empty string")
    if value.startswith("-"):
        raise ValueError(f"{field}: expected non-negative decimal string, got {value!r}")
    if not value.isdigit():
        raise ValueError(f"{field}: expected decimal string, got {value!r}")
    return int(value)


def normalize_g1_point(value: Any, *, field: str) -> Tuple[str, str]:
    if not isinstance(value, (list, tuple)):
        raise TypeError(f"{field}: expected list/tuple, got {type(value).__name__}")
    if len(value) not in (2, 3):
        raise ValueError(f"{field}: expected length 2 or 3, got {len(value)}")
    x = value[0]
    y = value[1]
    parse_nonneg_decimal_str(x, field=f"{field}[0]")
    parse_nonneg_decimal_str(y, field=f"{field}[1]")
    return (x, y)


def normalize_g2_point(value: Any, *, field: str) -> Tuple[Tuple[str, str], Tuple[str, str]]:
    if not isinstance(value, (list, tuple)):
        raise TypeError(f"{field}: expected list/tuple, got {type(value).__name__}")
    if len(value) not in (2, 3):
        raise ValueError(f"{field}: expected 2 or 3 rows, got {len(value)}")

    row0 = value[0]
    row1 = value[1]
    if not isinstance(row0, (list, tuple)) or not isinstance(row1, (list, tuple)):
        raise TypeError(f"{field}: expected row lists")
    if len(row0) != 2 or len(row1) != 2:
        raise ValueError(f"{field}: expected each row length=2")

    x0, x1 = row0[0], row0[1]
    y0, y1 = row1[0], row1[1]
    parse_nonneg_decimal_str(x0, field=f"{field}[0][0]")
    parse_nonneg_decimal_str(x1, field=f"{field}[0][1]")
    parse_nonneg_decimal_str(y0, field=f"{field}[1][0]")
    parse_nonneg_decimal_str(y1, field=f"{field}[1][1]")
    return ((x0, x1), (y0, y1))


def validate_public_signals(value: Any) -> List[str]:
    if not isinstance(value, list):
        raise TypeError(f"public_signals: expected list, got {type(value).__name__}")
    out: List[str] = []
    for i, s in enumerate(value):
        parse_nonneg_decimal_str(s, field=f"public_signals[{i}]")
        out.append(s)
    return out


@dataclass(frozen=True)
class ProofJson:
    protocol: str
    curve: str
    pi_a: Tuple[str, str]
    pi_b: Tuple[Tuple[str, str], Tuple[str, str]]
    pi_c: Tuple[str, str]

    def as_jsonable(self) -> Dict[str, Any]:
        return {
            "protocol": self.protocol,
            "curve": self.curve,
            "pi_a": [self.pi_a[0], self.pi_a[1], "1"],
            "pi_b": [[self.pi_b[0][0], self.pi_b[0][1]], [self.pi_b[1][0], self.pi_b[1][1]], ["1", "0"]],
            "pi_c": [self.pi_c[0], self.pi_c[1], "1"],
        }


def validate_proof_json(value: Any) -> ProofJson:
    if not isinstance(value, Mapping):
        raise TypeError(f"proof: expected object, got {type(value).__name__}")

    protocol = value.get("protocol")
    curve = value.get("curve")
    if not isinstance(protocol, str) or protocol == "":
        raise ValueError("proof.protocol: expected non-empty string")
    if not isinstance(curve, str) or curve == "":
        raise ValueError("proof.curve: expected non-empty string")

    pi_a = normalize_g1_point(value.get("pi_a"), field="proof.pi_a")
    pi_b = normalize_g2_point(value.get("pi_b"), field="proof.pi_b")
    pi_c = normalize_g1_point(value.get("pi_c"), field="proof.pi_c")

    return ProofJson(protocol=protocol, curve=curve, pi_a=pi_a, pi_b=pi_b, pi_c=pi_c)


@dataclass(frozen=True)
class VerificationKeyJson:
    protocol: str
    curve: str
    n_public: int
    vk_alpha_1: Tuple[str, str]
    vk_beta_2: Tuple[Tuple[str, str], Tuple[str, str]]
    vk_gamma_2: Tuple[Tuple[str, str], Tuple[str, str]]
    vk_delta_2: Tuple[Tuple[str, str], Tuple[str, str]]
    ic: List[Tuple[str, str]]

    def as_jsonable(self) -> Dict[str, Any]:
        return {
            "protocol": self.protocol,
            "curve": self.curve,
            "nPublic": self.n_public,
            "vk_alpha_1": [self.vk_alpha_1[0], self.vk_alpha_1[1]],
            "vk_beta_2": [[self.vk_beta_2[0][0], self.vk_beta_2[0][1]], [self.vk_beta_2[1][0], self.vk_beta_2[1][1]]],
            "vk_gamma_2": [[self.vk_gamma_2[0][0], self.vk_gamma_2[0][1]], [self.vk_gamma_2[1][0], self.vk_gamma_2[1][1]]],
            "vk_delta_2": [[self.vk_delta_2[0][0], self.vk_delta_2[0][1]], [self.vk_delta_2[1][0], self.vk_delta_2[1][1]]],
            "IC": [[x, y] for (x, y) in self.ic],
        }


def validate_verification_key_json(value: Any) -> VerificationKeyJson:
    if not isinstance(value, Mapping):
        raise TypeError(f"verification_key: expected object, got {type(value).__name__}")

    protocol = value.get("protocol")
    curve = value.get("curve")
    if not isinstance(protocol, str) or protocol == "":
        raise ValueError("verification_key.protocol: expected non-empty string")
    if not isinstance(curve, str) or curve == "":
        raise ValueError("verification_key.curve: expected non-empty string")

    n_public_raw = None
    if "nPublic" in value:
        n_public_raw = value.get("nPublic")
    elif "n_public" in value:
        n_public_raw = value.get("n_public")
    elif "n_public_inputs" in value:
        n_public_raw = value.get("n_public_inputs")
    elif "nPublicInputs" in value:
        n_public_raw = value.get("nPublicInputs")

    if not isinstance(n_public_raw, int) or n_public_raw < 0:
        raise ValueError("verification_key.nPublic: expected non-negative int")
    n_public = n_public_raw

    alpha_1 = normalize_g1_point(value.get("vk_alpha_1"), field="verification_key.vk_alpha_1")
    beta_2 = normalize_g2_point(value.get("vk_beta_2"), field="verification_key.vk_beta_2")
    gamma_2 = normalize_g2_point(value.get("vk_gamma_2"), field="verification_key.vk_gamma_2")
    delta_2 = normalize_g2_point(value.get("vk_delta_2"), field="verification_key.vk_delta_2")

    ic_raw = value.get("IC")
    if not isinstance(ic_raw, list):
        raise TypeError(f"verification_key.IC: expected list, got {type(ic_raw).__name__}")
    ic: List[Tuple[str, str]] = []
    for i, p in enumerate(ic_raw):
        ic.append(normalize_g1_point(p, field=f"verification_key.IC[{i}]"))

    return VerificationKeyJson(
        protocol=protocol,
        curve=curve,
        n_public=n_public,
        vk_alpha_1=alpha_1,
        vk_beta_2=beta_2,
        vk_gamma_2=gamma_2,
        vk_delta_2=delta_2,
        ic=ic,
    )


@dataclass(frozen=True)
class Groth16Bundle:
    verification_key: VerificationKeyJson
    public_signals: List[str]
    proof: ProofJson


def validate_groth16_bundle(*, verification_key: Any, public_signals: Any, proof: Any) -> Groth16Bundle:
    vk = validate_verification_key_json(verification_key)
    pub = validate_public_signals(public_signals)
    prf = validate_proof_json(proof)

    if vk.protocol != "groth16":
        raise ValueError(f"verification_key.protocol: expected 'groth16', got {vk.protocol!r}")
    if prf.protocol != "groth16":
        raise ValueError(f"proof.protocol: expected 'groth16', got {prf.protocol!r}")
    if vk.curve != prf.curve:
        raise ValueError(f"curve mismatch: vk.curve={vk.curve!r} proof.curve={prf.curve!r}")

    if vk.n_public != len(pub):
        raise ValueError(f"nPublic mismatch: vk.nPublic={vk.n_public} public_signals={len(pub)}")
    if len(vk.ic) != len(pub) + 1:
        raise ValueError(f"IC length mismatch: len(IC)={len(vk.ic)} expected={len(pub) + 1}")

    return Groth16Bundle(verification_key=vk, public_signals=pub, proof=prf)


def build_bundle_manifest(bundle: Groth16Bundle) -> Dict[str, Any]:
    vk_json = bundle.verification_key.as_jsonable()
    proof_json = bundle.proof.as_jsonable()
    public_json = list(bundle.public_signals)

    return {
        "kind": "snarkjs.groth16.bundle",
        "version": 1,
        "protocol": bundle.verification_key.protocol,
        "curve": bundle.verification_key.curve,
        "n_public": bundle.verification_key.n_public,
        "checks": {
            "ic_len_ok": len(bundle.verification_key.ic) == len(bundle.public_signals) + 1,
            "protocol_ok": bundle.verification_key.protocol == "groth16" and bundle.proof.protocol == "groth16",
            "curve_match": bundle.verification_key.curve == bundle.proof.curve,
        },
        "sha256": {
            "verification_key_json": sha256_json(vk_json),
            "proof_json": sha256_json(proof_json),
            "public_json": sha256_json(public_json),
        },
    }


def _print_step(title: str) -> None:
    print(f"=== {title} ===")


def main() -> None:
    demo_vk = {
        "protocol": "groth16",
        "curve": "bn128",
        "nPublic": 2,
        "vk_alpha_1": ["1", "2"],
        "vk_beta_2": [["3", "4"], ["5", "6"]],
        "vk_gamma_2": [["7", "8"], ["9", "10"]],
        "vk_delta_2": [["11", "12"], ["13", "14"]],
        "IC": [["15", "16"], ["17", "18"], ["19", "20"]],
    }
    demo_public = ["42", "1337"]
    demo_proof = {
        "protocol": "groth16",
        "curve": "bn128",
        "pi_a": ["21", "22", "1"],
        "pi_b": [["23", "24"], ["25", "26"], ["1", "0"]],
        "pi_c": ["27", "28", "1"],
    }

    _print_step("Step 1: Canonical JSON + SHA-256")
    print("sha256(verification_key.json) =", sha256_json(demo_vk))
    print("sha256(public.json)          =", sha256_json(demo_public))
    print("sha256(proof.json)           =", sha256_json(demo_proof))
    print()

    _print_step("Step 2: Validate artifact schemas")
    bundle = validate_groth16_bundle(verification_key=demo_vk, public_signals=demo_public, proof=demo_proof)
    print("protocol =", bundle.verification_key.protocol)
    print("curve    =", bundle.verification_key.curve)
    print("nPublic  =", bundle.verification_key.n_public)
    print("IC len   =", len(bundle.verification_key.ic))
    print()

    _print_step("Step 3: Consistency checks (IC vs public signals)")
    try:
        bad_public = ["42"]
        validate_groth16_bundle(verification_key=demo_vk, public_signals=bad_public, proof=demo_proof)
        print("unexpected: mismatch should have failed")
    except (TypeError, ValueError) as e:
        print("expected failure:", str(e))
    print()

    _print_step("Step 4: Build a bundle manifest (attestation)")
    manifest = build_bundle_manifest(bundle)
    print(json.dumps(manifest, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
