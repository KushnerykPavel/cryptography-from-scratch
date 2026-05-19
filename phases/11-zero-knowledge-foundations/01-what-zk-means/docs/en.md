# What ZK Means — Completeness, Soundness, Zero-Knowledge
> A proof is “zero-knowledge” when the verifier could have faked the transcript by itself.

**Type:** Learn
**Languages:** Python
**Prerequisites:** Phase 8 · 04 (Diffie-Hellman & Discrete Log), Phase 8 · 08 (Schnorr Signatures)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain completeness, soundness, and zero-knowledge in one paragraph each
- Distinguish “validity proof” from “privacy (ZK) proof” and “proof” from “argument”
- Apply the simulator mental model to decide what a transcript can leak
- Compute a Schnorr transcript check by hand in a tiny group
- Implement an HVZK simulator and a witness extractor for a 3-move protocol

## The Problem

“ZK” is overloaded in modern engineering. Teams say “we use ZK” when they mean “we use a succinct validity proof,” or “the prover hides inputs,” or “the verifier learns nothing,” or just “it’s a SNARK.” Those are different claims with different threat models. If you mix them up, you can ship something that verifies correctly but leaks secrets, or something that hides secrets but can be forged.

Concretely: a rollup proof can be **sound** (it prevents invalid state transitions) without being **zero-knowledge** (it might reveal private user data if you put that data into the public statement). Conversely, a protocol can feel “private” while still being unsound if the verifier is checking the wrong statement, or if the randomness/challenge design is flawed.

This lesson gives you a crisp definition you can use in design reviews: what it means for a protocol to be complete, sound, and zero-knowledge, and how the “simulator” connects the words to an implementation.

## The Concept

A (probabilistic) interactive protocol between a **prover** `P` and a **verifier** `V` has three core properties:

| Property | Informal meaning | Engineering check |
|---|---|---|
| Completeness | If the statement is true and `P` is honest, `V` accepts (with high probability). | “Honest runs pass.” |
| Soundness | If the statement is false, no cheating prover convinces `V` except with small probability `ε`. | “Cheating fails except rarely.” |
| Zero-knowledge | The verifier learns nothing beyond “the statement is true.” | “There exists a simulator for the transcript.” |

The key mental model for **zero-knowledge** is the simulator:

- The verifier’s “knowledge” after a run is captured by what it sees: the **transcript** (all messages) plus its own randomness.
- A protocol is zero-knowledge if for *any* verifier strategy there exists an efficient algorithm `S` (the simulator) that can generate a transcript with the **same distribution** as a real run, *without* knowing the secret witness.

If a verifier can generate an indistinguishable transcript by itself, then (intuitively) it didn’t “learn” anything new by interacting with the prover.

In practice we often start with **Σ-protocols** (3-move protocols): `commit -> challenge -> response`. Many have:

- **Special soundness**: from two accepting transcripts with the same commit and different challenges, you can extract the witness.
- **Honest-verifier zero-knowledge (HVZK)**: there is a simulator that works when the verifier chooses challenges honestly at random.

This lesson demonstrates those ideas with the classic Schnorr protocol in a tiny group where you can see every number.

## Build It

### Step 1: Modular arithmetic (inverse)
```python
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
```
The Schnorr protocol lives in a multiplicative group modulo `p`. You need just enough number theory to do that safely: fast modular exponentiation (`pow(…, mod)`) and modular inversion (`a^{-1} mod p`). The inverse is the first “gotcha” in ZK implementations: if your group/modulus choices are wrong, the inverse may not exist and your protocol quietly breaks.

### Step 2: Completeness (real Schnorr transcript)
```python
@dataclass(frozen=True)
class SchnorrParams:
    p: int
    q: int
    g: int


def schnorr_public_key(params: SchnorrParams, x: int) -> int:
    x = x % params.q
    return mod_pow(params.g, x, params.p)


def schnorr_commit(params: SchnorrParams, r: int) -> int:
    r = r % params.q
    return mod_pow(params.g, r, params.p)


def schnorr_response(q: int, r: int, e: int, x: int) -> int:
    return (r + e * x) % q


def schnorr_verify(
    params: SchnorrParams, y: int, a: int, e: int, z: int
) -> bool:
    if not (0 <= e < params.q):
        return False
    if not (0 <= z < params.q):
        return False
    left = mod_pow(params.g, z, params.p)
    right = mod_mul(a, mod_pow(y, e, params.p), params.p)
    return left == right


def assert_schnorr_params(params: SchnorrParams, y: int) -> None:
    if params.p <= 2 or params.q <= 1:
        raise ValueError("bad group parameters")
    if mod_pow(params.g, params.q, params.p) != 1:
        raise ValueError("g does not have order q")
    if mod_pow(y, params.q, params.p) != 1:
        raise ValueError("y is not in the subgroup of order q")
```
This is the “honest run” of a 3-move Σ-protocol. The prover knows a witness `x` such that `y = g^x (mod p)`. It commits with `a = g^r`, receives a random challenge `e`, and responds with `z = r + e·x (mod q)`. Completeness is the simplest property to test: if both parties follow the rules, verification should accept.

### Step 3: Zero-knowledge (HVZK simulator)
```python
def schnorr_simulate_hvz(
    params: SchnorrParams, y: int, e: int, z: int
) -> tuple[int, int, int]:
    """Honest-verifier ZK simulator for Schnorr transcripts.

    Picks (e, z) uniformly and computes a so that verification passes:
      g^z = a * y^e   =>   a = g^z * (y^e)^(-1)  (mod p)
    """
    e = e % params.q
    z = z % params.q
    y_to_e = mod_pow(y, e, params.p)
    a = mod_mul(mod_pow(params.g, z, params.p), mod_inv(y_to_e, params.p), params.p)
    return (a, e, z)
```
The simulator is the heart of the definition. Instead of “prove knowledge of `x`,” it manufactures a transcript that passes verification *without using `x` at all*. It chooses a challenge/response pair `(e, z)` and then solves for the commit `a` that makes `g^z = a·y^e`. If the verifier only sees the transcript, it can’t tell whether it came from a real prover or a simulator (this is HVZK for Schnorr).

### Step 4: Soundness intuition (extracting the witness)
```python
def schnorr_extract_witness(
    q: int, e1: int, z1: int, e2: int, z2: int
) -> int:
    """Extract x from two accepting transcripts with same commit and e1 != e2."""
    if e1 == e2:
        raise ValueError("need two different challenges to extract")
    num = (z1 - z2) % q
    den = (e1 - e2) % q
    return (num * mod_inv(den, q)) % q
```
Soundness is often proved by showing an *extractor*: if a prover can answer two different challenges for the same commit, it must “contain” the witness. Algebraically, two accepting transcripts give you two equations in the unknown `x`, and you solve for `x` by dividing by `(e1 - e2)`. This is exactly why reusing the prover’s randomness `r` is catastrophic: it enables extraction.

Run it:
`python3 code/main.py`

## Use It

When you need real ZK proofs, do not roll your own protocol. Use audited libraries and frameworks:

- **Proof systems:** `halo2` (Rust), `arkworks` (Rust), `circom` + `snarkjs` (TS), `gnark` (Go)
- **Discrete-log groups / curves:** `libsecp256k1` (C) for secp256k1, `ristretto255` (via libsodium) for modern prime-order groups
- **ZK primitives and gadgets:** commitment schemes, transcript hashing (Fiat–Shamir), and domain separation are typically provided by the framework’s APIs

The role of this lesson’s code is to make the words *complete / sound / zero-knowledge* mechanically real, so you can read a ZK library’s documentation and know what it is actually promising.

## Pitfalls

- Treating “we used a SNARK” as automatically **zero-knowledge**; ZK is an extra property that can be turned off or broken by how you encode the statement.
- Confusing **HVZK** with full ZK; a malicious verifier can deviate from “honest random challenge” and potentially learn information unless the protocol proves ZK against arbitrary verifiers.
- Reusing prover randomness (or biasing it); for Σ-protocols, nonce reuse turns soundness into witness leakage (the extractor demo is the attack).
- Forgetting domain separation / context binding when you later apply Fiat–Shamir; transcripts must be tied to the statement, prover identity, and session.
- Proving the wrong statement; if your “public input” includes something derived from the witness, you may leak exactly what you meant to hide.

## Ship It

This lesson ships a reusable checklist prompt: `outputs/prompt-zk-meaning-review-checklist.md`. Use it to review PRs, specs, or vendor claims that say “this is ZK.” Paste it into your LLM (or use it as a human checklist) to force clarity about: statement vs witness, what zero-knowledge actually guarantees, whether the claim is HVZK vs ZK, and how soundness is argued (error bounds, extractors, assumptions).

## Exercises

1. Easy: Run `python3 code/main.py`. Observe that simulated transcripts verify even though the simulator never uses `x`.
2. Medium: Extend `code/main.py` with a “cheating prover” that guesses the challenge `e` in advance, then measure (with a fixed RNG seed) the fraction of runs that verify as you change `q`.
3. Hard: Pick one ZK product you’ve heard of (a rollup, identity protocol, or private voting system). Write down the statement and witness explicitly, then use the shipped checklist to decide whether it needs the zero-knowledge property or only soundness.

## Key Terms

| Term | What people say | What it actually means |
|---|---|---|
| Completeness | “If it’s true, it verifies” | Honest `P` convinces honest `V` on true statements (probability close to 1) |
| Soundness | “It can’t be faked” | Cheating provers succeed with probability at most `ε` on false statements |
| Zero-knowledge | “It reveals nothing” | There exists a simulator producing transcripts indistinguishable from real runs |
| Transcript | “The proof” | The full message sequence (plus verifier randomness) produced by the protocol |
| HVZK | “It’s zero-knowledge” | Zero-knowledge only against an honest verifier who samples challenges correctly |
| Σ-protocol | “A 3-move proof” | Commit–challenge–response protocol with special soundness and HVZK properties |
| Witness | “The secret” | The private value whose existence makes the statement true (e.g., `x` in `y=g^x`) |
| Extractor | “A soundness proof” | An algorithm that recovers the witness from a prover that convinces too often |

## Further Reading

- Goldwasser, Micali, Rackoff, The Knowledge Complexity of Interactive Proof Systems (1985) — original definition of zero-knowledge via simulation.
- Schnorr, Efficient Signature Generation by Smart Cards (1991) — the Schnorr identification/sigma protocol family.
- Goldreich, Randomness, Interactive Proofs, and Zero-Knowledge (1988) — a classic survey that builds the simulator intuition carefully.
- Thaler, Proofs, Arguments, and Zero-Knowledge (lecture notes) — modern, practitioner-friendly framing of proofs vs arguments and ZK definitions.
