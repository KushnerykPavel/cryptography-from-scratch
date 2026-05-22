# Timing Attacks — Early Exit vs Constant Time

> If your code returns early, your attacker learns early.

**Type:** Build
**Languages:** Python
**Prerequisites:** Basic bytes/encoding hygiene; threat modeling basics
**Time:** ~60 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain why early-exit code paths leak information via timing
- Compute a simple “timing trace” from step counts as a time proxy
- Implement an insecure byte-by-byte comparison that leaks prefix length
- Distinguish constant-time comparison from “same average time”
- Apply a simulated timing oracle to recover a secret token byte-by-byte

## The Problem

You build an API that checks `Authorization: Bearer <token>`. You never log the token and you never return it. But your server compares the provided token to the secret token byte-by-byte and returns as soon as a mismatch is found.

Attackers can exploit tiny timing differences: guesses that match more prefix bytes run slightly longer. With enough requests, they can recover the token one byte at a time.

This shows up in real systems as “MAC compare bugs”, “JWT signature compare bugs”, and “API key compare bugs”. Even if the difference is microseconds, attackers can average noise away with repeated queries.

## The Concept

Timing attacks need two ingredients:

1. A secret-dependent branch (early return, data-dependent loop count, cache-dependent table lookup, etc.).
2. An observable timing signal (response time, CPU cycles, network time averaged over many requests).

An early-exit compare leaks prefix length. If you can measure how long it runs, you get a side channel that correlates with “how many bytes matched”.

The fix is *constant-time* comparison: do the same amount of work regardless of where the first mismatch occurs.

## Build It

### Step 1: Early-exit comparisons leak prefix length
```python
def insecure_prefix_compare(a: bytes, b: bytes) -> Tuple[bool, int]:
    n = min(len(a), len(b))
    steps = 0
    for i in range(n):
        steps += 1
        if a[i] != b[i]:
            return False, steps
    steps += 1
    return len(a) == len(b), steps
```
This returns early on the first mismatch. The `steps` counter is a stand-in for “time”: more matching prefix bytes means more loop iterations.

### Step 2: Constant-time comparisons remove the signal
```python
def constant_time_compare(a: bytes, b: bytes) -> Tuple[bool, int]:
    steps = 0
    if len(a) != len(b):
        n = max(len(a), len(b))
        aa = a.ljust(n, b"\x00")
        bb = b.ljust(n, b"\x00")
    else:
        aa, bb = a, b
    diff = 0
    for x, y in zip(aa, bb):
        steps += 1
        diff |= x ^ y
    return diff == 0 and (len(a) == len(b)), steps
```
This always loops over the full length and accumulates differences. It doesn’t “stop early”, so the timing signal no longer correlates with prefix length.

### Step 3: Recover a secret with a timing oracle (simulated)
```python
def recover_secret_from_timing_oracle(
    oracle: Callable[[bytes], int], length: int, alphabet: Iterable[int]
) -> bytes:
    guess = bytearray(b"\x00" * length)
    for i in range(length):
        best_b = None
        best_score = -1
        for b in alphabet:
            guess[i] = b
            score = oracle(bytes(guess))
            if score > best_score:
                best_score = score
                best_b = b
        if best_b is None:
            raise RuntimeError("no candidate byte found")
        guess[i] = best_b
    return bytes(guess)
```
Given an oracle that returns “time”, pick the byte that maximizes the score at each position. Real attacks repeat measurements per candidate to average noise; the demo is noise-free.

Run it:
python3 code/main.py

## Use It

- Use constant-time primitives for comparisons:
  - Python: `hmac.compare_digest(a, b)` for MACs/tokens
  - Libraries: use vetted constant-time routines, not hand-rolled comparisons
- Avoid secret-dependent early returns in parsing and verification paths.
- Rate limit and add monitoring, but treat those as defense-in-depth, not fixes.

## Pitfalls

- Thinking “it’s only a few microseconds” means “it’s safe”.
- Comparing hex strings (variable-time normalization) instead of raw bytes.
- Early return on decode/parse before verification completes.
- Logging differences that correlate with failure stage.
- “Random sleep” mitigations that are still statistically distinguishable.

## Ship It

Save a constant-time review checklist for PR review: `outputs/constant-time-review-checklist.md`.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that the insecure compare leaks more `steps` for a better prefix.
2. Medium. Add noise to the oracle (random +/- jitter) and update the attack to average multiple samples per guess.
3. Hard. Replace the token with an HMAC tag and audit a verification path to use `hmac.compare_digest`.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Timing side channel | “It runs a bit slower” | Runtime correlates with secret-dependent branches |
| Early exit | “Return on mismatch” | Stops work at the first differing byte, leaking prefix length |
| Constant-time | “Same code path” | Work does not depend on secret values (no data-dependent branches) |
| Oracle | “A helper endpoint” | Any interface that leaks one bit of information per query |

## Further Reading

- Kocher, “Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems” (1996) — classic timing attacks paper
- Python docs: `hmac.compare_digest` — constant-time comparison for authentication data
