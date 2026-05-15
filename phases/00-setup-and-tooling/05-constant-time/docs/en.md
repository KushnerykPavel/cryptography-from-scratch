# Constant-Time Thinking & Side-Channel Hygiene

> Assume the attacker can measure time. Don’t let secrets change control flow.

**Type:** Learn
**Languages:** Python
**Prerequisites:** Phase 00 · 02 (Bytes, Hex, Base64)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Spot secret-dependent early exits (`return` on mismatch) and understand what they leak
- Write a compare routine that does not short-circuit on content differences
- Know when to use `hmac.compare_digest` / `secrets.compare_digest` instead of `==`
- Build a mental checklist for side-channel hygiene (timing + cache + error messages)

## The Problem

Cryptography doesn’t fail only because the math is wrong.

It also fails because *your code* leaks information via side channels:

- the time it takes to reject a request,
- which error message you return,
- how much work you do before aborting,
- which memory locations you touch (cache timing),
- which branches you take (branch predictor effects).

The classic “tiny” mistake is comparing secrets with `==` (or implementing your own comparison) in a way that returns early on the first mismatch. When the attacker can measure response times (even noisily), they can often learn *how many prefix bytes were correct* and then brute-force the next byte, one at a time.

This shows up everywhere:

- verifying an HMAC tag from an API request,
- checking an auth token / session cookie,
- comparing password hashes,
- verifying a signature blob that includes a MAC.

## The Concept

### “Constant-time” in security code

In crypto engineering, “constant-time” usually means:

> runtime should not depend on secret data

It’s allowed to depend on *public* things like the algorithm choice, and usually also on *length* (because you must read the input). The goal is to avoid data-dependent early exits, branches, or secret-dependent memory access patterns.

### The vulnerability pattern

Here’s the most common foot-gun:

```
for i in range(n):
    if expected[i] != provided[i]:
        return False   # leaks where the first mismatch happened
return True
```

If the first byte mismatches, you exit quickly. If 15 bytes match before the first mismatch, you do more work. Time becomes a signal.

### “The attacker can measure time” is a reasonable assumption

- Remote timing is noisy, but attackers can average many requests.
- Side channels often amplify themselves: small per-byte differences become detectable with repetition.
- Even if a timing attack is hard today, it might not be hard under different infrastructure conditions.

The rule is simple: **if you’re comparing secrets, don’t use short-circuiting comparisons**.

## Build It

All code for this lesson lives in `code/main.py`.

### Step 1: Implement a deliberately leaky comparison (for learning)

```python
def leaky_prefix_match_len(expected: bytes, provided: bytes) -> int:
    n = min(len(expected), len(provided))
    for i in range(n):
        if expected[i] != provided[i]:
            return i
    return n
```

This function is “what time leaks”: it returns how many prefix bytes matched before the first mismatch.

### Step 2: Implement a compare that doesn’t short-circuit on content

The standard trick is:

- XOR each byte pair
- OR the results into an accumulator
- only decide “equal vs not equal” at the end

```python
def ct_eq_bytes(a: bytes, b: bytes) -> bool:
    la = len(a)
    lb = len(b)
    max_len = la if la >= lb else lb

    diff = la ^ lb
    for i in range(max_len):
        ai = a[i] if i < la else 0
        bi = b[i] if i < lb else 0
        diff |= ai ^ bi
    return diff == 0
```

This is a *constant-time style* compare:

- it does not stop on the first mismatch,
- it still depends on input lengths (because it must iterate),
- in Python, you should not treat this as a production-quality constant-time guarantee.

### Step 3: Use the standard library for real comparisons

In Python, prefer:

- `hmac.compare_digest(a, b)` for bytes/ASCII strings
- `secrets.compare_digest(a, b)` for the same purpose (it delegates to the same underlying primitive in CPython)

These are designed to avoid content-based short-circuiting and are the right default for comparing MACs/tags/signatures.

## Use It

### Verifying a tag (pattern)

If you compute a tag/server-side value and compare it to attacker-controlled input, use `compare_digest`:

```python
import hmac

def verify_tag(expected_tag: bytes, provided_tag: bytes) -> bool:
    return hmac.compare_digest(expected_tag, provided_tag)
```

Also: compare *bytes*, not presentation strings. Decode hex/base64 at the boundary (Phase 00 · 02), then compare bytes.

## Attack It

### Timing attack (conceptual) → prefix oracle (deterministic)

Real timing attacks are statistical. For learning (and testing), we can replace “time” with a deterministic leak: “how many prefix bytes matched”.

If your server rejects after comparing a prefix, you’ve handed the attacker exactly the information they need to recover the secret one byte at a time.

`code/main.py` includes a demo attacker (`recover_secret_from_prefix_oracle`) that recovers an 8-byte secret from a prefix-leaking oracle.

## Ship It

This lesson ships a reusable constant-time review prompt:

- `outputs/prompt-constant-time-review-checklist.md`

Use it whenever you’re reviewing code that compares tags/tokens/password hashes, or when you’re writing a verifier.

## Exercises

1. **Easy:** Find 3 places in your codebase where a secret might be compared with `==`. Replace with `hmac.compare_digest`.
2. **Medium:** Write a tiny “MAC verifier” function that accepts base64 input, decodes strictly, and compares with `compare_digest` (use Phase 00 · 02 helpers).
3. **Hard:** Modify the leaky oracle demo to recover a longer secret and measure how many oracle calls it needs on average.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| side channel | “not a direct break” | an unintended signal (time, cache, power, errors) correlated with secrets |
| timing attack | “attack based on time” | exploiting runtime differences to learn secret-dependent information |
| constant-time | “same speed” | runtime not dependent on secret data (usually still depends on length) |
| short-circuiting | “early exit” | aborting as soon as you know the answer, often leaking where mismatch occurs |
| compare-digest | “safe equals” | a comparison routine designed to avoid content-based early exits |

## Test Vectors

This lesson uses project-internal behavioral vectors in `tests/vectors.json` to validate:

- equality results for leaky vs constant-time-style compares
- the prefix-leak function behavior

## Further Reading

- Python: `hmac.compare_digest` / `secrets.compare_digest`
- Nate Lawson: “Timing attack in Google Keyczar library” (classic compare pitfall)
- `cryptography` library: constant-time helpers and guidance (use audited libs for production)
