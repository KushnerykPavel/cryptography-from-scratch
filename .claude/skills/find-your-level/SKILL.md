---
name: find-your-level
version: 1.0.0
description: >
  Interactive 10-question placement quiz that maps your cryptography knowledge
  to a starting point in the 21-phase, ~241-lesson Cryptography from Scratch
  curriculum. Trigger phrases: "where should I start", "find my level",
  "what do I know about crypto", "which phase", "assess my knowledge",
  "placement test", "skip ahead".
tags: [assessment, onboarding, curriculum, cryptography]
---

# Find Your Level

Administer a placement quiz for the **Cryptography from Scratch** curriculum
(21 phases, ~241 lessons). Figure out where the learner should begin so they
skip material they already know and land where the challenge starts.

## Quiz Structure

5 knowledge areas, 2 questions each, 10 questions total. Present in rounds
of 2 (one per area). After both questions in a round, score that area before
moving on.

## Scoring

Each question worth 1 point. Each area scores 0–2. Total ranges 0–10.

## Administering the Quiz

Greet briefly, then jump into Round 1. Use **AskUserQuestion** for every
question. After each round, announce area score (e.g. "Number Theory: 2/2").
Keep commentary short. Do not explain answers until the end.

---

### Round 1 — Number Theory & Modular Arithmetic

**Q1.** What is `7^3 mod 11`?

- A) 2
- B) 5
- C) 8
- D) 9

**Correct: A) 2** (343 mod 11 = 2)

**Q2.** When does `a` have a multiplicative inverse modulo `n`?

- A) Always, when `a ≠ 0`
- B) When `gcd(a, n) = 1`
- C) When `a < n`
- D) When `n` is prime

**Correct: B) When `gcd(a, n) = 1`** (B includes the prime case)

---

### Round 2 — Symmetric & Classical Asymmetric

**Q3.** Why is AES-ECB unsafe for encrypting images?

- A) ECB is slow
- B) Identical plaintext blocks produce identical ciphertext blocks, leaking patterns
- C) ECB has no key schedule
- D) ECB only works on text

**Correct: B) Identical plaintext blocks produce identical ciphertext blocks, leaking patterns**

**Q4.** In RSA, if `n = p·q`, `e = 65537`, what is the private exponent `d`?

- A) `d = e mod n`
- B) `d ≡ e^(-1) mod φ(n)` where `φ(n) = (p-1)(q-1)`
- C) `d = (p+q)/2`
- D) `d = n - e`

**Correct: B) `d ≡ e^(-1) mod φ(n)` where `φ(n) = (p-1)(q-1)`**

---

### Round 3 — Elliptic Curves & Protocols

**Q5.** On an elliptic curve over `F_p`, what does scalar multiplication `k·P`
mean?

- A) Multiply the x-coordinate by k
- B) Add the point P to itself k times using the curve group law
- C) Multiply each coordinate by k mod p
- D) Compute `(k·x, k·y)` mod p

**Correct: B) Add the point P to itself k times using the curve group law**

**Q6.** What goes wrong in ECDSA if you reuse the random nonce `k` across two
signatures with the same key?

- A) Nothing — `k` is throwaway
- B) Signatures become invalid
- C) An attacker recovers the private key from the two signatures
- D) Hash collisions occur

**Correct: C) An attacker recovers the private key from the two signatures** (Sony PS3 case)

---

### Round 4 — Zero-Knowledge

**Q7.** What three properties define a zero-knowledge proof?

- A) Speed, simplicity, succinctness
- B) Completeness, soundness, zero-knowledge
- C) Confidentiality, integrity, availability
- D) Public, private, hybrid

**Correct: B) Completeness, soundness, zero-knowledge**

**Q8.** What does the Fiat-Shamir heuristic do?

- A) Speeds up modular exponentiation
- B) Turns an interactive Σ-protocol into a non-interactive proof by replacing the verifier's challenge with a hash
- C) Compresses a SNARK proof
- D) Prevents nonce reuse in ECDSA

**Correct: B) Turns an interactive Σ-protocol into a non-interactive proof by replacing the verifier's challenge with a hash**

---

### Round 5 — Post-Quantum & Advanced

**Q9.** Why does Shor's algorithm threaten RSA but not AES-128?

- A) RSA uses smaller keys
- B) Shor solves factoring and discrete log in polynomial time on a quantum computer; AES has no such structure — Grover only halves the security level
- C) AES is information-theoretically secure
- D) RSA is already broken classically

**Correct: B) Shor solves factoring and discrete log in polynomial time on a quantum computer; AES has no such structure — Grover only halves the security level**

**Q10.** What hard problem underpins Kyber (ML-KEM)?

- A) Integer factoring
- B) Elliptic curve discrete log
- C) Module Learning With Errors (MLWE)
- D) Syndrome decoding

**Correct: C) Module Learning With Errors (MLWE)**

---

## After All 5 Rounds

Display area breakdown and total:

```
Number Theory & Modular Arithmetic:    X/2
Symmetric & Classical Asymmetric:      X/2
Elliptic Curves & Protocols:           X/2
Zero-Knowledge:                        X/2
Post-Quantum & Advanced:               X/2
-------------------------------------------
Total:                                 X/10
```

## Score-to-Entry-Point Mapping

| Total Score | Entry Point | What It Means |
|-------------|-------------|---------------|
| 0–3 | Phase 1: Number Theory | Build math foundation from the ground up |
| 4–5 | Phase 4: Lattices | You have number theory + ECC, time for the post-quantum math |
| 6–7 | Phase 8: Classical Asymmetric | Math is solid, build primitives next |
| 8–9 | Phase 11: Zero-Knowledge Foundations | Strong base, dive into ZK |
| 10 | Phase 14: Post-Quantum Lattice-Based | You know the classical world, build Kyber/Dilithium |

## Personalized Learning Path

After revealing entry point, generate a markdown table covering all 21
phases. Use the score to determine status of each phase. Phases below entry
point get "Skip" (already known). Phases at or above entry point get "Do".
If learner scored 1/2 in an area mapping to a skippable phase, mark that
phase "Review" instead of "Skip".

Area-to-phase mapping for review detection:
- Number Theory & Modular Arithmetic (1/2) → mark Phase 1 as "Review"
- Symmetric & Classical Asymmetric (1/2) → mark Phases 7 and 8 as "Review"
- Elliptic Curves & Protocols (1/2) → mark Phases 3 and 10 as "Review"
- Zero-Knowledge (1/2) → mark Phases 11 and 12 as "Review"
- Post-Quantum & Advanced (1/2) → mark Phases 14 and 17 as "Review"

Read time estimates from `ROADMAP.md` (canonical source). Each phase heading
contains estimated hours in format `(~N hours)`. Parse these instead of
hardcoding. Keeps path in sync with roadmap as estimates update.

## Output Format

```markdown
| Phase | Name | Status | Est. Hours |
|-------|------|--------|------------|
| 0 | Setup & Tooling | Skip | -- |
| 1 | Number Theory | Review | 21 |
| 2 | Abstract Algebra | Skip | -- |
| 3 | Elliptic Curves | Do | 13 |
| ... | ... | ... | ... |
```

Rules:
- "Skip" phases show `--` (do not count toward total)
- "Review" phases show full hours
- "Do" phases show full hours
- Phase 0 (Setup & Tooling) always "Skip" regardless of score (tooling, not knowledge)
- Sum hours for "Review" + "Do" phases, show total at bottom

After table, add: "Your personalized path: ~X hours across Y phases."

Then brief recommendation: which phase to start with, what to focus on
based on weakest area.

## Persist Progress

After showing the path, write the result to `.progress.json` at repo root.
If the file does not exist, create it. If it exists, **merge** — preserve
existing `phases` entries; overwrite only the `placement` section.

Schema (write the `placement` block):

```json
{
  "version": 1,
  "placement": {
    "score": <total 0-10>,
    "areas": {
      "number_theory": <0-2>,
      "symmetric_asymmetric": <0-2>,
      "ecc_protocols": <0-2>,
      "zero_knowledge": <0-2>,
      "post_quantum": <0-2>
    },
    "entry_phase": <1|4|8|11|14>,
    "date": "<today YYYY-MM-DD>"
  },
  "phases": { ... preserved as-is ... }
}
```

Tell the user one line at the end: "Progress saved to .progress.json. Run
`/my-progress` anytime to see your dashboard."
