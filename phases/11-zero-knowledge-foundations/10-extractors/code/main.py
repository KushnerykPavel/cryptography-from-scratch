"""
Knowledge soundness: extractors (toy Schnorr + OR composition).

This script demonstrates how "proof of knowledge" is formalized via an
*extractor*: an algorithm that can recover the hidden witness if a prover can
convince the verifier often enough.

We use a toy Schnorr sigma protocol (discrete-log relation) and show:
- Special soundness: two accepting transcripts with the same commitment but
  different challenges reveal the witness.
- A rewinding extractor: obtain those two transcripts by rewinding a prover
  after the commitment.
- OR composition: an OR proof remains extractable; from two accepting OR
  transcripts we can extract *one* witness.

Run:
  python3 code/main.py
"""

from __future__ import annotations

import random
from dataclasses import dataclass


def inv_mod(a: int, m: int) -> int:
    a %= m
    if a == 0:
        raise ValueError("0 has no inverse modulo m")

    t0, t1 = 0, 1
    r0, r1 = m, a
    while r1 != 0:
        q = r0 // r1
        t0, t1 = t1, t0 - q * t1
        r0, r1 = r1, r0 - q * r1

    if r0 != 1:
        raise ValueError("a is not invertible modulo m")
    return t0 % m


def toy_group() -> tuple[int, int, int]:
    p = 467
    q = 233
    g = 3
    if pow(g, q, p) != 1 or g % p in (0, 1):
        raise ValueError("bad toy group parameters")
    return p, q, g


@dataclass(frozen=True)
class SchnorrTranscript:
    t: int
    c: int
    s: int


def schnorr_commit(*, p: int, g: int, r: int) -> int:
    return pow(g, r, p)


def schnorr_respond(*, q: int, r: int, x: int, c: int) -> int:
    return (r + c * x) % q


def schnorr_verify(*, p: int, q: int, g: int, y: int, transcript: SchnorrTranscript) -> bool:
    if not (0 <= transcript.c < q and 0 <= transcript.s < q):
        return False
    left = pow(g, transcript.s, p)
    right = (transcript.t * pow(y, transcript.c, p)) % p
    return left == right


def schnorr_simulate_commitment(*, p: int, g: int, y: int, c: int, s: int) -> int:
    y_inv = inv_mod(y, p)
    return (pow(g, s, p) * pow(y_inv, c, p)) % p


def schnorr_simulate_transcript(*, p: int, q: int, g: int, y: int, c: int, s: int) -> SchnorrTranscript:
    t = schnorr_simulate_commitment(p=p, g=g, y=y, c=c, s=s)
    return SchnorrTranscript(t=t, c=c % q, s=s % q)


def schnorr_extract_witness(*, q: int, transcript1: SchnorrTranscript, transcript2: SchnorrTranscript) -> int:
    if transcript1.t != transcript2.t:
        raise ValueError("extractor requires the same commitment t in both transcripts")
    if transcript1.c == transcript2.c:
        raise ValueError("extractor requires two different challenges")

    num = (transcript1.s - transcript2.s) % q
    den = (transcript1.c - transcript2.c) % q
    return (num * inv_mod(den, q)) % q


@dataclass(frozen=True)
class OrCommitment:
    t1: int
    t2: int


@dataclass(frozen=True)
class OrResponse:
    c1: int
    c2: int
    s1: int
    s2: int


def or_verify(
    *,
    p: int,
    q: int,
    g: int,
    y1: int,
    y2: int,
    commitment: OrCommitment,
    challenge: int,
    response: OrResponse,
) -> bool:
    if (response.c1 + response.c2) % q != (challenge % q):
        return False
    ok1 = schnorr_verify(p=p, q=q, g=g, y=y1, transcript=SchnorrTranscript(commitment.t1, response.c1 % q, response.s1 % q))
    ok2 = schnorr_verify(p=p, q=q, g=g, y=y2, transcript=SchnorrTranscript(commitment.t2, response.c2 % q, response.s2 % q))
    return ok1 and ok2


class OrProver:
    def __init__(
        self,
        *,
        p: int,
        q: int,
        g: int,
        y1: int,
        y2: int,
        x1: int | None,
        x2: int | None,
        rng: random.Random,
    ) -> None:
        if (x1 is None) == (x2 is None):
            raise ValueError("provide exactly one witness (x1 or x2)")
        self._p = p
        self._q = q
        self._g = g
        self._y1 = y1
        self._y2 = y2
        self._x1 = x1
        self._x2 = x2
        self._rng = rng

        self._r_real: int | None = None
        self._c_sim: int | None = None
        self._s_sim: int | None = None
        self._commitment: OrCommitment | None = None

    def commit(self) -> OrCommitment:
        q = self._q
        p = self._p
        g = self._g

        self._c_sim = self._rng.randrange(0, q)
        self._s_sim = self._rng.randrange(0, q)

        if self._x1 is not None:
            t2 = schnorr_simulate_commitment(p=p, g=g, y=self._y2, c=self._c_sim, s=self._s_sim)
            self._r_real = self._rng.randrange(0, q)
            t1 = pow(g, self._r_real, p)
            self._commitment = OrCommitment(t1=t1, t2=t2)
            return self._commitment

        t1 = schnorr_simulate_commitment(p=p, g=g, y=self._y1, c=self._c_sim, s=self._s_sim)
        self._r_real = self._rng.randrange(0, q)
        t2 = pow(g, self._r_real, p)
        self._commitment = OrCommitment(t1=t1, t2=t2)
        return self._commitment

    def respond(self, challenge: int) -> OrResponse:
        if self._commitment is None or self._r_real is None or self._c_sim is None or self._s_sim is None:
            raise ValueError("must call commit() before respond()")

        p = self._p
        q = self._q
        g = self._g
        c = challenge % q

        if self._x1 is not None:
            c2 = self._c_sim
            s2 = self._s_sim
            c1 = (c - c2) % q
            s1 = (self._r_real + c1 * self._x1) % q
            out = OrResponse(c1=c1, c2=c2, s1=s1, s2=s2)
            if not or_verify(p=p, q=q, g=g, y1=self._y1, y2=self._y2, commitment=self._commitment, challenge=c, response=out):
                raise AssertionError("constructed OR response did not verify")
            return out

        c1 = self._c_sim
        s1 = self._s_sim
        c2 = (c - c1) % q
        s2 = (self._r_real + c2 * self._x2) % q
        out = OrResponse(c1=c1, c2=c2, s1=s1, s2=s2)
        if not or_verify(p=p, q=q, g=g, y1=self._y1, y2=self._y2, commitment=self._commitment, challenge=c, response=out):
            raise AssertionError("constructed OR response did not verify")
        return out


def or_extract_witness_from_two_transcripts(
    *,
    p: int,
    q: int,
    g: int,
    y1: int,
    y2: int,
    commitment: OrCommitment,
    challenge1: int,
    response1: OrResponse,
    challenge2: int,
    response2: OrResponse,
) -> tuple[int, int]:
    if not or_verify(p=p, q=q, g=g, y1=y1, y2=y2, commitment=commitment, challenge=challenge1, response=response1):
        raise ValueError("first transcript is not accepting")
    if not or_verify(p=p, q=q, g=g, y1=y1, y2=y2, commitment=commitment, challenge=challenge2, response=response2):
        raise ValueError("second transcript is not accepting")
    if (challenge1 % q) == (challenge2 % q):
        raise ValueError("extractor requires different global challenges")

    if (response1.c1 % q) != (response2.c1 % q):
        x1 = schnorr_extract_witness(
            q=q,
            transcript1=SchnorrTranscript(commitment.t1, response1.c1 % q, response1.s1 % q),
            transcript2=SchnorrTranscript(commitment.t1, response2.c1 % q, response2.s1 % q),
        )
        if pow(g, x1, p) != (y1 % p):
            raise ValueError("extracted witness does not match statement y1")
        return 1, x1

    if (response1.c2 % q) != (response2.c2 % q):
        x2 = schnorr_extract_witness(
            q=q,
            transcript1=SchnorrTranscript(commitment.t2, response1.c2 % q, response1.s2 % q),
            transcript2=SchnorrTranscript(commitment.t2, response2.c2 % q, response2.s2 % q),
        )
        if pow(g, x2, p) != (y2 % p):
            raise ValueError("extracted witness does not match statement y2")
        return 2, x2

    raise ValueError("no branch had two different challenges (unexpected for different global challenges)")


def main() -> None:
    p, q, g = toy_group()
    rng = random.Random(0)

    x = 42
    y = pow(g, x, p)

    print("=== Step 1: Implement Schnorr transcripts + a simulator ===")
    r = 17
    c = 123
    t = schnorr_commit(p=p, g=g, r=r)
    s = schnorr_respond(q=q, r=r, x=x, c=c)
    tr = SchnorrTranscript(t=t, c=c % q, s=s)
    print(f"statement: y=g^x mod p = {y}")
    print("real transcript:", tr)
    print("verify:", schnorr_verify(p=p, q=q, g=g, y=y, transcript=tr))
    sim = schnorr_simulate_transcript(p=p, q=q, g=g, y=y, c=77, s=202)
    print("simulated transcript:", sim)
    print("verify:", schnorr_verify(p=p, q=q, g=g, y=y, transcript=sim))

    print("\n=== Step 2: Implement the special-soundness extractor ===")
    c1 = 10
    c2 = 200
    t = schnorr_commit(p=p, g=g, r=r)
    s1 = schnorr_respond(q=q, r=r, x=x, c=c1)
    s2 = schnorr_respond(q=q, r=r, x=x, c=c2)
    tr1 = SchnorrTranscript(t=t, c=c1, s=s1)
    tr2 = SchnorrTranscript(t=t, c=c2, s=s2)
    x_hat = schnorr_extract_witness(q=q, transcript1=tr1, transcript2=tr2)
    print("transcript 1:", tr1)
    print("transcript 2:", tr2)
    print("extracted x:", x_hat)
    print("check g^x == y:", pow(g, x_hat, p) == y)

    print("\n=== Step 3: Rewinding = force two challenges for one commitment ===")
    r_secret = rng.randrange(0, q)
    t = schnorr_commit(p=p, g=g, r=r_secret)
    c1 = rng.randrange(0, q)
    s1 = schnorr_respond(q=q, r=r_secret, x=x, c=c1)
    c2 = (c1 + 1) % q
    s2 = schnorr_respond(q=q, r=r_secret, x=x, c=c2)
    x_hat = schnorr_extract_witness(q=q, transcript1=SchnorrTranscript(t, c1, s1), transcript2=SchnorrTranscript(t, c2, s2))
    print(f"commitment t={t} (fixed across rewinds)")
    print(f"challenges: c1={c1}, c2={c2}")
    print("extracted x:", x_hat)

    print("\n=== Step 4: OR proof extraction (extract one witness) ===")
    x1 = 42
    x2 = 99
    y1 = pow(g, x1, p)
    y2 = pow(g, x2, p)
    prover = OrProver(p=p, q=q, g=g, y1=y1, y2=y2, x1=x1, x2=None, rng=random.Random(0))
    com = prover.commit()
    e1 = 7
    e2 = 8
    resp1 = prover.respond(e1)
    resp2 = prover.respond(e2)
    print("commitment:", com)
    print("challenge 1 / response 1:", e1, resp1)
    print("challenge 2 / response 2:", e2, resp2)
    branch, witness = or_extract_witness_from_two_transcripts(
        p=p,
        q=q,
        g=g,
        y1=y1,
        y2=y2,
        commitment=com,
        challenge1=e1,
        response1=resp1,
        challenge2=e2,
        response2=resp2,
    )
    print(f"extracted branch={branch} witness={witness}")


if __name__ == "__main__":
    main()
