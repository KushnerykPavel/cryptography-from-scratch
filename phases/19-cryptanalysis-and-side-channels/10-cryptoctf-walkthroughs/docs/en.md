# Crypto CTF Walkthroughs — A Practical Triage Loop (Toy)

> Start with what’s cheap: formats, XORs, and GCDs.

**Type:** Build
**Languages:** Python
**Prerequisites:** Bytes/hex/base64; XOR; basic RSA modular arithmetic
**Time:** ~90 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain a repeatable “CTF crypto triage” workflow
- Compute quick encoding checks (hex vs base64)
- Implement a simple single-byte XOR breaker with scoring
- Distinguish RSA “math hardness” from implementation/configuration mistakes (shared primes)
- Apply GCD-based triage to detect and exploit shared RSA factors

## The Problem

In crypto CTFs (and in real incident response), you often face messy artifacts: ciphertexts, keys, and hints with unknown formats and unknown “what went wrong”. The fastest path is not “try advanced attacks first”; it’s a triage loop that tries cheap, high-yield checks.

Many challenges fall to simple mistakes: wrong encoding assumptions, XOR misuse, or misgenerated RSA keys (shared primes). Being systematic is a multiplier: you solve more problems faster and avoid rabbit holes.

This lesson provides a minimal, runnable workflow that you can reuse as a checklist and a starting template for new challenges.

## The Concept

A practical triage loop:

1. **Decode layers:** determine whether strings are hex/base64 and decode.
2. **Test cheap ciphers:** XOR, Caesar, single-byte XOR, repeating-key XOR.
3. **Run number theory sanity checks:** GCDs, shared factors, small exponents, modular inverses.
4. **Only then** escalate to deeper attacks (lattices, side channels, protocol breaks).

## Build It

### Step 1: Decode layers (hex vs base64)
```python
def decode_hex_or_base64(s: str) -> bytes:
    if looks_like_hex(s):
        return bytes.fromhex(s)
    return base64.b64decode(s, validate=True)
```
You save huge time by quickly validating encodings instead of guessing and corrupting data.

### Step 2: Crack single-byte XOR with scoring
```python
def break_single_byte_xor(ciphertext: bytes) -> Tuple[int, bytes]:
    best_k = 0
    best_pt = b""
    best_score = -1e18
    for k in range(256):
        pt = xor_with_byte(ciphertext, k)
        s = score_english(pt)
        if s > best_score:
            best_score = s
            best_k = k
            best_pt = pt
    return best_k, best_pt
```
Single-byte XOR is common in beginner challenges. A crude scoring function is often enough to pick the right plaintext.

### Step 3: RSA shared-prime detection (GCD)
```python
def find_shared_prime(n1: int, n2: int) -> Optional[int]:
    g = gcd(n1, n2)
    if g == 1 or g == n1 or g == n2:
        return None
    return g
```
If two RSA moduli share a prime (bad keygen), `gcd(n1, n2)` reveals it instantly. Once you factor `n`, you can decrypt.

Run it:
python3 code/main.py

## Use It

- Build a personal “crypto triage script” that includes:
  - decode layers, XOR breakers, gcd checks, small-exponent checks
- Keep it deterministic and testable: unit tests and known vectors save time.
- For real systems: shared-prime RSA is a catastrophic keygen failure; rotate keys immediately.

## Pitfalls

- Treating “base64-looking” strings as base64 without validation.
- Forgetting endianness and integer/byte conversions in RSA tasks.
- Overfitting scoring functions (false positives).
- Skipping GCD checks on RSA moduli lists.
- Falling into “advanced attack first” mode.

## Ship It

Save a copy-pastable triage prompt and checklist: `outputs/ctf-crypto-triage-prompt.md`.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe the decoded strings, XOR recovery, and shared-prime RSA recovery.
2. Medium. Add repeating-key XOR breaking (guess key size, score candidates).
3. Hard. Extend RSA triage with checks for small public exponent misuse and textbook RSA.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Triage | “quick checks” | Fast, high-yield tests before deeper attacks |
| XOR cipher | “simple masking” | Encryption by XOR; often breakable when misused |
| Scoring | “English detector” | A heuristic to rank plausible plaintexts |
| Shared prime | “RSA keygen bug” | Two moduli share a factor; GCD reveals it immediately |

## Further Reading

- CTF field guides on encoding/XOR/RSA sanity checks — practical playbooks
- Heninger et al., “Mining Your Ps and Qs” — real-world RSA key generation failures and shared factors
