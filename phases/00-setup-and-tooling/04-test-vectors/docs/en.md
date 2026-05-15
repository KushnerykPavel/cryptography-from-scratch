# Test Vectors — RFC / NIST CAVP Workflow

> If your code can’t match the spec’s vectors, it doesn’t implement the spec.

**Type:** Learn
**Languages:** Python
**Prerequisites:** Phase 00, Lesson 02 (Bytes/Hex/Base64), Lesson 03 (Big Integers)
**Time:** ~60 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## The Problem

Cryptography code lives or dies on **interoperability**: your SHA-256 must hash the same bytes as everyone else, your AES must encrypt the same blocks, your signature verifier must reject the same malformed encodings.

Without test vectors, you can write code that “works on my machine” but is wrong in one of the worst ways:

- wrong encoding boundary (hashing text instead of bytes, or hex strings instead of decoded bytes)
- wrong endianness (little-endian integers where the RFC expects big-endian)
- non-canonical parsing (accepting multiple encodings for the same value)
- missing failure-path behavior (never testing that invalid inputs are rejected)

This lesson gives you a boring superpower: every time you implement a primitive later in the course, you will know how to ground it in an external source (RFC / NIST CAVP) and encode it as `tests/vectors.json` + a small harness.

## The Concept

Think of test vectors as a contract:

```
spec text  →  (inputs, outputs, rejection rules)  →  vectors.json  →  your tests
```

There are two different kinds of “correctness” you need:

1) **Known-answer tests (KATs)** — given input `x`, the output must be exactly `y`.
2) **Negative tests** — given malformed input `x_bad`, your code must reject it (and reject it consistently).

Most beginners do only KATs. Crypto breaks in the gaps:

- parsers that accept extra whitespace / alternative encodings
- implementations that “mostly work” but get edge cases wrong (empty message, all-zero key, max counter, etc.)
- code that matches a toy example but not the standard’s byte-level definition

### How this repo encodes vectors

Every lesson keeps vectors local and human-reviewable:

- `tests/vectors.json`: a cited source + a list of JSON objects
- `tests/test_vectors.py`: a tiny loop that loads vectors and checks behavior

The format is intentionally simple:

```json
{
  "source": "RFC / NIST / academic citation",
  "vectors": [
    {"op": "sha256", "msg_ascii": "abc", "expected": "<hex digest>"},
    {"op": "sha256", "msg_hex": "00", "expected": "<hex digest>"},
    {"op": "sha256", "expected_error": "vector must include msg_ascii or msg_hex"}
  ]
}
```

Each vector has:

- `op`: which operation you’re testing (so one file can cover multiple helpers)
- inputs: fields like `msg_ascii`, `msg_hex`, `key_hex`, `nonce_hex`, …
- exactly one of `expected` or `expected_error`

## Build It

This is a tooling lesson: the “build” is a reusable pattern you’ll apply everywhere.

### Step 1: Choose a single, explicit encoding for bytes

In specs, bytes are bytes. In JSON, bytes need an encoding.

In this repo:

- **bytes**: hex string fields like `*_hex`
- **text**: UTF-8 fields like `*_ascii` (only when the spec defines the message as text)

If an algorithm signs/verifies/hashes anything, do not let the test harness accept ambiguous encodings.

### Step 2: Validate the vector file before running vectors

Your harness should fail fast if the file is malformed.

```python
def validate_vectors_file(data: object) -> None:
    ...
```

This prevents a subtle failure mode: silently skipping vectors because a key was misspelled.

### Step 3: Dispatch by `op` and compare against `expected`

A minimal pattern looks like:

```python
def dispatch(vector: dict):
    op = vector["op"]
    if op == "...":
        return ...
    raise ValueError(f"unknown op: {op}")
```

Then your runner can be uniform:

- if `expected_error` exists: ensure the call raises
- otherwise: ensure `dispatch(vector) == expected`

### Step 4: Add negative tests on purpose

Make your vector set hostile. Add vectors that a naive-but-wrong implementation would accept:

- odd-length hex
- non-hex characters
- missing required fields
- ambiguous encodings (both `*_ascii` and `*_hex` present)

If a spec has “MUST reject” language, encode that as vectors.

## Use It

In real projects, you often consume large vector suites:

- **NIST CAVP**: official KATs for hashes, AES, HMAC, KDFs, etc.
- **Wycheproof**: adversarial vectors designed to catch “almost correct” crypto code

You still want a tiny local format like `tests/vectors.json` because it is:

- easy to review in a PR
- fast to run in CI
- stable over time (you can pin a subset of vectors that matter for your implementation)

Later in the course, you’ll see both:

1) a small RFC/NIST-based `vectors.json` you can read
2) a larger external suite you can optionally run as a deeper check

## Attack It

The “attack” in a tooling lesson is a false sense of security.

Here are two common ways vectors fail to protect you:

1) **Vectors that don’t match the spec’s bytes**
   - Example: hashing `"616263"` (three characters) instead of hashing `0x61 0x62 0x63` (three bytes).
   - Fix: store bytes as `msg_hex` and decode before hashing.

2) **Vectors that only test the happy path**
   - Example: a parser that accepts multiple encodings (leading zeros, non-canonical padding, whitespace) will still pass.
   - Fix: add negative vectors that explicitly assert rejection.

When you implement a primitive, assume a reviewer will ask: “What broken implementation would still pass these vectors?” Then add the vectors that would catch it.

## Ship It

Use `outputs/prompt-test-vectors-workflow.md` as a checklist when adding `tests/vectors.json` and writing harnesses in later lessons.

## Exercises

1. Easy: Add 2 SHA-256 vectors using `msg_hex` (including one with leading zero bytes) and confirm your harness still passes.
2. Medium: Extend the harness pattern to a new `op` (e.g. `hmac_sha256`) and add at least one negative vector (wrong key length, malformed hex).
3. Hard: For a later primitive lesson you already completed, add at least 3 negative vectors that would catch an “almost correct” implementation (endianness mixup, non-canonical encoding acceptance, wrong length handling).

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| Test vector | “Example input/output” | A deterministic contract between spec and implementation. |
| Known-answer test (KAT) | “A unit test” | A vector where the exact output is fixed and published. |
| Negative test | “Bad inputs” | A vector that asserts rejection (errors are part of the spec). |
| Canonical encoding | “The right format” | Rules that make an encoding unique (prevents alternative spellings). |
| Interoperability | “Works with others” | Multiple implementations accept/reject the same bytes. |

## Test Vectors

Source: NIST FIPS 180-4 (Secure Hash Standard) SHA-256 examples (plus a few project-internal negative tests for vector hygiene). Code must pass `tests/vectors.json`.

## Further Reading

- [NIST FIPS 180-4: Secure Hash Standard](https://csrc.nist.gov/publications/detail/fips/180/4/final) — the SHA family definitions and example digests.
- [Google Wycheproof](https://github.com/google/wycheproof) — adversarial crypto test vectors that catch subtle parsing and validation bugs.
