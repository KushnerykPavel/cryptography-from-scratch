"""Chaum–Pedersen DLEQ proof from scratch (toy equality of discrete logs).

Run:
  python3 code/main.py

This lesson builds the Chaum–Pedersen Σ-protocol for proving equality of two
discrete logarithms:

  y1 = g^x (mod p) and y2 = h^x (mod p)

without revealing x. It also demonstrates the two core Σ-protocol properties
you rely on when engineering ZK protocols:
  - Special HVZK: simulate accepting transcripts without the witness.
  - Special soundness: reuse the same nonce once and the witness is extractable.

Educational implementation. Not constant-time. Not production-safe.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256


def egcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended GCD: returns (g, x, y) such that a*x + b*y = g = gcd(a, b)."""
    if b == 0:
        return (abs(a), 1 if a >= 0 else -1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def mod_inv(a: int, mod: int) -> int:
    """Multiplicative inverse of a modulo mod. Raises ValueError if none."""
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


def _hash_to_scalar(domain: str, ints: list[int], q: int) -> int:
    """Hash domain-separated integers into Z_q (toy Fiat–Shamir helper)."""
    h = sha256()
    h.update(domain.encode("utf-8"))
    h.update(b"\x00")
    for v in ints:
        if v < 0:
            raise ValueError("hash inputs must be non-negative integers")
        b = v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
        h.update(len(b).to_bytes(4, "big"))
        h.update(b)
    return int.from_bytes(h.digest(), "big") % q


@dataclass(frozen=True)
class ChaumPedersenParams:
    """Toy subgroup parameters for Chaum–Pedersen (DLEQ) proofs.

    Work in a subgroup of Z_p* of prime order q. Both g and h generate that
    same subgroup.
    """

    p: int
    q: int
    g: int
    h: int


@dataclass(frozen=True)
class ChaumPedersenTranscript:
    """A Chaum–Pedersen Σ-protocol transcript: (a1, a2, c, s)."""

    commitment_g: int
    commitment_h: int
    challenge: int
    response: int


def assert_chaum_pedersen_params(params: ChaumPedersenParams, y1: int, y2: int) -> None:
    if params.p <= 2 or params.q <= 1:
        raise ValueError("bad group parameters")
    if (params.p - 1) % params.q != 0:
        raise ValueError("q must divide p-1")
    if not (1 < params.g < params.p):
        raise ValueError("g must satisfy 1 < g < p")
    if not (1 < params.h < params.p):
        raise ValueError("h must satisfy 1 < h < p")
    if mod_pow(params.g, params.q, params.p) != 1:
        raise ValueError("g does not have order q")
    if mod_pow(params.h, params.q, params.p) != 1:
        raise ValueError("h does not have order q")
    if mod_pow(y1, params.q, params.p) != 1:
        raise ValueError("y1 is not in the subgroup of order q")
    if mod_pow(y2, params.q, params.p) != 1:
        raise ValueError("y2 is not in the subgroup of order q")


def chaum_pedersen_publics(params: ChaumPedersenParams, x: int) -> tuple[int, int]:
    x = x % params.q
    return (mod_pow(params.g, x, params.p), mod_pow(params.h, x, params.p))


def chaum_pedersen_commit(params: ChaumPedersenParams, r: int) -> tuple[int, int]:
    r = r % params.q
    return (mod_pow(params.g, r, params.p), mod_pow(params.h, r, params.p))


def chaum_pedersen_response(q: int, r: int, c: int, x: int) -> int:
    return (r + c * x) % q


def chaum_pedersen_verify(
    params: ChaumPedersenParams,
    y1: int,
    y2: int,
    a1: int,
    a2: int,
    c: int,
    s: int,
) -> bool:
    if not (0 <= c < params.q):
        return False
    if not (0 <= s < params.q):
        return False
    if not (0 <= a1 < params.p) or not (0 <= a2 < params.p):
        return False

    left1 = mod_pow(params.g, s, params.p)
    right1 = mod_mul(a1, mod_pow(y1, c, params.p), params.p)
    if left1 != right1:
        return False

    left2 = mod_pow(params.h, s, params.p)
    right2 = mod_mul(a2, mod_pow(y2, c, params.p), params.p)
    return left2 == right2


def chaum_pedersen_prove(
    params: ChaumPedersenParams, x: int, r: int, c: int
) -> tuple[int, int, ChaumPedersenTranscript]:
    y1, y2 = chaum_pedersen_publics(params, x)
    a1, a2 = chaum_pedersen_commit(params, r)
    s = chaum_pedersen_response(params.q, r, c, x)
    t = ChaumPedersenTranscript(
        commitment_g=a1, commitment_h=a2, challenge=c % params.q, response=s
    )
    return (y1, y2, t)


def chaum_pedersen_simulate_hvz(
    params: ChaumPedersenParams, y1: int, y2: int, c: int, s: int
) -> ChaumPedersenTranscript:
    """Special HVZK simulator for Chaum–Pedersen transcripts.

    Pick (c, s) and compute (a1, a2) so that both verification equations hold:

      g^s = a1 * y1^c  =>  a1 = g^s * (y1^c)^(-1)  (mod p)
      h^s = a2 * y2^c  =>  a2 = h^s * (y2^c)^(-1)  (mod p)
    """
    c = c % params.q
    s = s % params.q

    a1 = mod_mul(
        mod_pow(params.g, s, params.p),
        mod_inv(mod_pow(y1, c, params.p), params.p),
        params.p,
    )
    a2 = mod_mul(
        mod_pow(params.h, s, params.p),
        mod_inv(mod_pow(y2, c, params.p), params.p),
        params.p,
    )
    return ChaumPedersenTranscript(
        commitment_g=a1, commitment_h=a2, challenge=c, response=s
    )


def chaum_pedersen_extract_witness(q: int, c1: int, s1: int, c2: int, s2: int) -> int:
    """Extract x from two accepting transcripts with same commitments and c1 != c2."""
    if c1 == c2:
        raise ValueError("need two different challenges to extract")
    num = (s1 - s2) % q
    den = (c1 - c2) % q
    return (num * mod_inv(den, q)) % q


def chaum_pedersen_fiat_shamir_challenge(
    params: ChaumPedersenParams, y1: int, y2: int, a1: int, a2: int, domain: str
) -> int:
    return _hash_to_scalar(domain, [params.p, params.q, params.g, params.h, y1, y2, a1, a2], params.q)


def chaum_pedersen_prove_fiat_shamir(
    params: ChaumPedersenParams, x: int, r: int, domain: str
) -> tuple[int, int, ChaumPedersenTranscript]:
    y1, y2 = chaum_pedersen_publics(params, x)
    a1, a2 = chaum_pedersen_commit(params, r)
    c = chaum_pedersen_fiat_shamir_challenge(params, y1, y2, a1, a2, domain)
    s = chaum_pedersen_response(params.q, r, c, x)
    t = ChaumPedersenTranscript(
        commitment_g=a1, commitment_h=a2, challenge=c, response=s
    )
    return (y1, y2, t)


def chaum_pedersen_verify_fiat_shamir(
    params: ChaumPedersenParams,
    y1: int,
    y2: int,
    a1: int,
    a2: int,
    s: int,
    domain: str,
) -> bool:
    c = chaum_pedersen_fiat_shamir_challenge(params, y1, y2, a1, a2, domain)
    return chaum_pedersen_verify(params, y1, y2, a1, a2, c, s)


def fmt_transcript(t: ChaumPedersenTranscript) -> str:
    return f"(a1={t.commitment_g}, a2={t.commitment_h}, c={t.challenge}, s={t.response})"


def step_1_statement_and_transcript(params: ChaumPedersenParams) -> tuple[int, int, int]:
    print("=== Step 1: The DLEQ statement and transcript ===")
    x = 7
    y1, y2 = chaum_pedersen_publics(params, x)
    assert_chaum_pedersen_params(params, y1, y2)
    print(f"params: p={params.p}, q={params.q}, g={params.g}, h={params.h}")
    print(f"witness: x = {x}")
    print(f"statement: y1=g^x mod p = {y1}, y2=h^x mod p = {y2}")
    t = ChaumPedersenTranscript(commitment_g=16, commitment_h=8, challenge=3, response=3)
    print(f"transcript shape: {fmt_transcript(t)}")
    return (x, y1, y2)


def step_2_prove_and_verify(params: ChaumPedersenParams, x: int, y1: int, y2: int) -> ChaumPedersenTranscript:
    print("=== Step 2: Prove and verify (interactive) ===")
    r = 4
    c = 3
    _y1, _y2, t = chaum_pedersen_prove(params, x, r, c)
    ok = chaum_pedersen_verify(
        params,
        y1,
        y2,
        t.commitment_g,
        t.commitment_h,
        t.challenge,
        t.response,
    )
    print(f"nonce r = {r}, challenge c = {c}")
    print(f"proof: {fmt_transcript(t)}")
    print(f"verifier accepts: {ok}")
    return t


def step_3_hvz_simulation(params: ChaumPedersenParams, y1: int, y2: int) -> ChaumPedersenTranscript:
    print("=== Step 3: Special HVZK simulation (no witness) ===")
    c = 2
    s = 7
    t = chaum_pedersen_simulate_hvz(params, y1, y2, c, s)
    ok = chaum_pedersen_verify(
        params, y1, y2, t.commitment_g, t.commitment_h, t.challenge, t.response
    )
    print(f"simulated proof: {fmt_transcript(t)}")
    print(f"verifier accepts: {ok}")
    return t


def step_4_special_soundness(params: ChaumPedersenParams) -> None:
    print("=== Step 4: Special soundness (nonce reuse => witness extraction) ===")
    x = 5
    y1, y2 = chaum_pedersen_publics(params, x)
    assert_chaum_pedersen_params(params, y1, y2)

    r = 4
    a1, a2 = chaum_pedersen_commit(params, r)
    c1, c2 = 1, 9
    s1 = chaum_pedersen_response(params.q, r, c1, x)
    s2 = chaum_pedersen_response(params.q, r, c2, x)

    ok1 = chaum_pedersen_verify(params, y1, y2, a1, a2, c1, s1)
    ok2 = chaum_pedersen_verify(params, y1, y2, a1, a2, c2, s2)
    extracted = chaum_pedersen_extract_witness(params.q, c1, s1, c2, s2)

    print(f"same commitments (a1,a2)=({a1},{a2}) (same r)")
    print(f"t1 = (c={c1}, s={s1}) -> accepts={ok1}")
    print(f"t2 = (c={c2}, s={s2}) -> accepts={ok2}")
    print(f"extract(c1,s1,c2,s2) -> x = {extracted} (matches: {extracted == (x % params.q)})")


def step_5_fiat_shamir(params: ChaumPedersenParams) -> None:
    print("=== Step 5: Fiat–Shamir (make it non-interactive) ===")
    domain = "CPv1"
    x = 7
    r = 4
    y1, y2, t = chaum_pedersen_prove_fiat_shamir(params, x, r, domain)
    assert_chaum_pedersen_params(params, y1, y2)
    ok = chaum_pedersen_verify_fiat_shamir(
        params, y1, y2, t.commitment_g, t.commitment_h, t.response, domain
    )
    print(f"domain = {domain}")
    print(f"statement: (y1,y2)=({y1},{y2})")
    print(f"proof contains: (a1,a2,s)=({t.commitment_g},{t.commitment_h},{t.response})")
    print(f"derived challenge c = H(domain || statement || commitments) mod q = {t.challenge}")
    print(f"verifier accepts: {ok}")


def main() -> None:
    params = ChaumPedersenParams(p=23, q=11, g=2, h=6)

    x, y1, y2 = step_1_statement_and_transcript(params)
    _real = step_2_prove_and_verify(params, x, y1, y2)
    _sim = step_3_hvz_simulation(params, y1, y2)
    step_4_special_soundness(params)
    step_5_fiat_shamir(params)


if __name__ == "__main__":
    main()
