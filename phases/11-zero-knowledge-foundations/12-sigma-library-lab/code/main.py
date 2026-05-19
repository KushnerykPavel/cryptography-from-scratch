"""Sigma protocol library lab (toy, from scratch).

Run:
  python3 code/main.py

This lesson builds a tiny "Σ-protocol library" for prime-order subgroups of Z_p*.
It includes:
  - A transcript type shared by protocols
  - Two protocol instances: Schnorr (discrete log) and Chaum–Pedersen (DLEQ)
  - A special HVZK simulator and a nonce-reuse extractor for each
  - A Fiat–Shamir wrapper (interactive Σ -> non-interactive proof)

Educational implementation. Not constant-time. Not production-safe.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import secrets
from typing import Any


def egcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return (abs(a), 1 if a >= 0 else -1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def mod_inv(a: int, mod: int) -> int:
    a = a % mod
    if a == 0:
        raise ValueError("0 has no inverse modulo mod")
    g, x, _y = egcd(a, mod)
    if g != 1:
        raise ValueError("a and mod are not coprime")
    return x % mod


def mod_mul(a: int, b: int, mod: int) -> int:
    return (a % mod) * (b % mod) % mod


def mod_pow(base: int, exp: int, mod: int) -> int:
    return pow(base % mod, exp, mod)


def hash_to_int_sha256(data: bytes, mod: int) -> int:
    if mod <= 0:
        raise ValueError("mod must be positive")
    digest = hashlib.sha256(data).digest()
    return int.from_bytes(digest, "big") % mod


def encode_fs_context(domain_sep: str, items: list[tuple[str, int]]) -> bytes:
    if domain_sep == "":
        raise ValueError("domain_sep must be non-empty")
    msg = domain_sep
    for k, v in items:
        msg += f"|{k}={v}"
    return msg.encode("utf-8")


class DeterministicRNG:
    def __init__(self, seed: bytes):
        if seed == b"":
            raise ValueError("seed must be non-empty")
        self._seed = seed
        self._counter = 0

    def randbelow(self, n: int) -> int:
        if n <= 0:
            raise ValueError("n must be positive")
        h = hashlib.sha256(self._seed + self._counter.to_bytes(4, "big")).digest()
        self._counter += 1
        return int.from_bytes(h, "big") % n


def rand_zq(q: int, rng: DeterministicRNG | None = None) -> int:
    if q <= 1:
        raise ValueError("q must be > 1")
    if rng is None:
        return secrets.randbelow(q)
    return rng.randbelow(q)


@dataclass(frozen=True)
class SchnorrParams:
    """Toy subgroup parameters for Schnorr-style protocols."""

    p: int
    q: int
    g: int


def schnorr_params_toy() -> SchnorrParams:
    return SchnorrParams(p=23, q=11, g=2)


def assert_prime_order_subgroup(params: SchnorrParams, *, elements: list[int]) -> None:
    if params.p <= 2 or params.q <= 1:
        raise ValueError("bad group parameters")
    if (params.p - 1) % params.q != 0:
        raise ValueError("q must divide p-1")
    if not (1 < params.g < params.p):
        raise ValueError("g must satisfy 1 < g < p")
    if mod_pow(params.g, params.q, params.p) != 1:
        raise ValueError("g does not have order q")

    for el in elements:
        if not (1 <= el < params.p):
            raise ValueError("element out of range")
        if mod_pow(el, params.q, params.p) != 1:
            raise ValueError("element not in subgroup of order q")


@dataclass(frozen=True)
class SigmaTranscript:
    """A Σ-protocol transcript: (commitment, challenge, response)."""

    commitment: Any
    challenge: int
    response: int


def fiat_shamir_challenge(q: int, *, domain_sep: str, items: list[tuple[str, int]]) -> int:
    return hash_to_int_sha256(encode_fs_context(domain_sep, items), q)


def schnorr_public_key(params: SchnorrParams, x: int) -> int:
    x = x % params.q
    return mod_pow(params.g, x, params.p)


def schnorr_commit(params: SchnorrParams, r: int) -> int:
    r = r % params.q
    return mod_pow(params.g, r, params.p)


def schnorr_respond(q: int, r: int, c: int, x: int) -> int:
    return (r + (c % q) * (x % q)) % q


def schnorr_prove(params: SchnorrParams, x: int, *, c: int, rng: DeterministicRNG | None = None) -> SigmaTranscript:
    r = rand_zq(params.q, rng=rng)
    a = schnorr_commit(params, r)
    s = schnorr_respond(params.q, r, c, x)
    return SigmaTranscript(commitment=a, challenge=c % params.q, response=s)


def schnorr_verify(params: SchnorrParams, y: int, a: int, c: int, s: int) -> bool:
    if not (0 <= c < params.q):
        return False
    if not (0 <= s < params.q):
        return False
    if not (0 <= a < params.p):
        return False
    left = mod_pow(params.g, s, params.p)
    right = mod_mul(a, mod_pow(y, c, params.p), params.p)
    return left == right


def schnorr_simulate_hvz(params: SchnorrParams, y: int, c: int, s: int) -> SigmaTranscript:
    c = c % params.q
    s = s % params.q
    y_to_c = mod_pow(y, c, params.p)
    a = mod_mul(mod_pow(params.g, s, params.p), mod_inv(y_to_c, params.p), params.p)
    return SigmaTranscript(commitment=a, challenge=c, response=s)


def schnorr_extract_witness(q: int, c1: int, s1: int, c2: int, s2: int) -> int:
    c1 = c1 % q
    c2 = c2 % q
    s1 = s1 % q
    s2 = s2 % q
    if c1 == c2:
        raise ValueError("need two different challenges to extract")
    num = (s1 - s2) % q
    den = (c1 - c2) % q
    return (num * mod_inv(den, q)) % q


def schnorr_prove_fs(
    params: SchnorrParams,
    x: int,
    *,
    statement_y: int,
    domain_sep: str,
    rng: DeterministicRNG | None = None,
) -> SigmaTranscript:
    r = rand_zq(params.q, rng=rng)
    a = schnorr_commit(params, r)
    c = fiat_shamir_challenge(params.q, domain_sep=domain_sep, items=[("y", statement_y), ("a", a)])
    s = schnorr_respond(params.q, r, c, x)
    return SigmaTranscript(commitment=a, challenge=c, response=s)


def schnorr_verify_fs(
    params: SchnorrParams,
    y: int,
    proof: SigmaTranscript,
    *,
    domain_sep: str,
) -> bool:
    if not isinstance(proof.commitment, int):
        return False
    a = proof.commitment
    expected_c = fiat_shamir_challenge(params.q, domain_sep=domain_sep, items=[("y", y), ("a", a)])
    if proof.challenge % params.q != expected_c:
        return False
    return schnorr_verify(params, y, a, expected_c, proof.response)


@dataclass(frozen=True)
class DLEQStatement:
    """Chaum–Pedersen statement: y1 = g1^x and y2 = g2^x in the same group."""

    params: SchnorrParams
    g1: int
    g2: int
    y1: int
    y2: int


def dleq_commit(stmt: DLEQStatement, r: int) -> tuple[int, int]:
    r = r % stmt.params.q
    a1 = mod_pow(stmt.g1, r, stmt.params.p)
    a2 = mod_pow(stmt.g2, r, stmt.params.p)
    return (a1, a2)


def dleq_respond(q: int, r: int, c: int, x: int) -> int:
    return (r + (c % q) * (x % q)) % q


def dleq_verify(stmt: DLEQStatement, a: tuple[int, int], c: int, s: int) -> bool:
    if not (0 <= c < stmt.params.q):
        return False
    if not (0 <= s < stmt.params.q):
        return False
    a1, a2 = a
    if not (0 <= a1 < stmt.params.p) or not (0 <= a2 < stmt.params.p):
        return False

    left1 = mod_pow(stmt.g1, s, stmt.params.p)
    right1 = mod_mul(a1, mod_pow(stmt.y1, c, stmt.params.p), stmt.params.p)
    left2 = mod_pow(stmt.g2, s, stmt.params.p)
    right2 = mod_mul(a2, mod_pow(stmt.y2, c, stmt.params.p), stmt.params.p)
    return left1 == right1 and left2 == right2


def dleq_simulate_hvz(stmt: DLEQStatement, c: int, s: int) -> SigmaTranscript:
    c = c % stmt.params.q
    s = s % stmt.params.q
    y1_to_c = mod_pow(stmt.y1, c, stmt.params.p)
    y2_to_c = mod_pow(stmt.y2, c, stmt.params.p)
    a1 = mod_mul(mod_pow(stmt.g1, s, stmt.params.p), mod_inv(y1_to_c, stmt.params.p), stmt.params.p)
    a2 = mod_mul(mod_pow(stmt.g2, s, stmt.params.p), mod_inv(y2_to_c, stmt.params.p), stmt.params.p)
    return SigmaTranscript(commitment=(a1, a2), challenge=c, response=s)


def dleq_extract_witness(q: int, c1: int, s1: int, c2: int, s2: int) -> int:
    return schnorr_extract_witness(q, c1, s1, c2, s2)


def dleq_prove(
    stmt: DLEQStatement, x: int, *, c: int, rng: DeterministicRNG | None = None
) -> SigmaTranscript:
    r = rand_zq(stmt.params.q, rng=rng)
    a1, a2 = dleq_commit(stmt, r)
    s = dleq_respond(stmt.params.q, r, c, x)
    return SigmaTranscript(commitment=(a1, a2), challenge=c % stmt.params.q, response=s)


def dleq_prove_fs(
    stmt: DLEQStatement,
    x: int,
    *,
    domain_sep: str,
    rng: DeterministicRNG | None = None,
) -> SigmaTranscript:
    r = rand_zq(stmt.params.q, rng=rng)
    a1, a2 = dleq_commit(stmt, r)
    c = fiat_shamir_challenge(
        stmt.params.q,
        domain_sep=domain_sep,
        items=[("g1", stmt.g1), ("g2", stmt.g2), ("y1", stmt.y1), ("y2", stmt.y2), ("a1", a1), ("a2", a2)],
    )
    s = dleq_respond(stmt.params.q, r, c, x)
    return SigmaTranscript(commitment=(a1, a2), challenge=c, response=s)


def dleq_verify_fs(stmt: DLEQStatement, proof: SigmaTranscript, *, domain_sep: str) -> bool:
    if not (isinstance(proof.commitment, tuple) and len(proof.commitment) == 2):
        return False
    a1, a2 = proof.commitment
    if not (isinstance(a1, int) and isinstance(a2, int)):
        return False
    expected_c = fiat_shamir_challenge(
        stmt.params.q,
        domain_sep=domain_sep,
        items=[("g1", stmt.g1), ("g2", stmt.g2), ("y1", stmt.y1), ("y2", stmt.y2), ("a1", a1), ("a2", a2)],
    )
    if proof.challenge % stmt.params.q != expected_c:
        return False
    return dleq_verify(stmt, (a1, a2), expected_c, proof.response)


def fmt_tr(tr: SigmaTranscript) -> str:
    return f"(commitment={tr.commitment}, c={tr.challenge}, s={tr.response})"


def step_1_transcript_and_group() -> tuple[SchnorrParams, int, int]:
    print("=== Step 1: Shared types + toy group ===")
    params = schnorr_params_toy()
    x = 7
    y = schnorr_public_key(params, x)
    assert_prime_order_subgroup(params, elements=[y])
    print(f"params: p={params.p}, q={params.q}, g={params.g}")
    print(f"statement: y = g^x mod p = {y}")
    return (params, x, y)


def step_2_schnorr_protocol(params: SchnorrParams, x: int, y: int) -> SigmaTranscript:
    print("=== Step 2: Schnorr Σ-protocol (prove/verify) ===")
    rng = DeterministicRNG(b"lesson-seed")
    c = 5
    proof = schnorr_prove(params, x, c=c, rng=rng)
    ok = schnorr_verify(params, y, proof.commitment, proof.challenge, proof.response)
    print(f"challenge c = {c}")
    print(f"proof = {fmt_tr(proof)}")
    print(f"verify => {ok}")
    return proof


def step_3_simulate_and_extract(params: SchnorrParams, x: int, y: int) -> None:
    print("=== Step 3: Simulate (HVZK) + extract (nonce reuse) ===")
    c = 5
    s = 5
    sim = schnorr_simulate_hvz(params, y, c, s)
    print(f"simulated = {fmt_tr(sim)}")
    print(f"verify(simulated) => {schnorr_verify(params, y, sim.commitment, sim.challenge, sim.response)}")

    r = 3
    a = schnorr_commit(params, r)
    c1, c2 = 5, 2
    s1 = schnorr_respond(params.q, r, c1, x)
    s2 = schnorr_respond(params.q, r, c2, x)
    extracted = schnorr_extract_witness(params.q, c1, s1, c2, s2)
    print(f"reused commitment a = {a} with (c1,s1)=({c1},{s1}) and (c2,s2)=({c2},{s2})")
    print(f"extracted x = {extracted}")


def step_4_dleq_and_fiat_shamir(params: SchnorrParams) -> None:
    print("=== Step 4: DLEQ (Chaum–Pedersen) + Fiat–Shamir proofs ===")
    g1 = params.g
    g2 = 6
    x = 7
    y1 = mod_pow(g1, x, params.p)
    y2 = mod_pow(g2, x, params.p)
    stmt = DLEQStatement(params=params, g1=g1, g2=g2, y1=y1, y2=y2)
    assert_prime_order_subgroup(params, elements=[g2, y1, y2])

    rng = DeterministicRNG(b"lesson-seed")
    proof = dleq_prove(stmt, x, c=5, rng=rng)
    print(f"interactive transcript = {fmt_tr(proof)}")
    print(f"verify(interactive) => {dleq_verify(stmt, proof.commitment, proof.challenge, proof.response)}")

    domain_sep = "sigma-library-lab-v1"
    fs_proof = dleq_prove_fs(stmt, x, domain_sep=domain_sep, rng=DeterministicRNG(b"lesson-seed"))
    print(f"fiat-shamir proof = {fmt_tr(fs_proof)}")
    print(f"verify(fs) => {dleq_verify_fs(stmt, fs_proof, domain_sep=domain_sep)}")


def load_vectors_file(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def main() -> None:
    params, x, y = step_1_transcript_and_group()
    step_2_schnorr_protocol(params, x, y)
    step_3_simulate_and_extract(params, x, y)
    step_4_dleq_and_fiat_shamir(params)


if __name__ == "__main__":
    main()
