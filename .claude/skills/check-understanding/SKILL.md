---
name: check-understanding
version: 1.0.0
description: Phase quiz for Cryptography from Scratch. Trigger with "quiz me", "test phase", "check my understanding", "do I know phase 4", or `/check-understanding <phase>`.
---

# Check Understanding

Test knowledge of a completed phase from the Cryptography from Scratch course.

## Activation

Triggers when user says:
- `/check-understanding 4` or `/check-understanding lattices`
- "quiz me on phase 11"
- "test phase 8"
- "check my understanding of zero-knowledge"
- "do I know phase 14"
- "am I ready for the next phase"

## Input

Accepts a phase number (0–20) or a phase name as argument. If no argument,
ask the user which phase to test by listing all 21.

## Phase Map

Map argument to correct directory under `phases/`:

| Input | Directory | Phase Name |
|-------|-----------|------------|
| 0, setup, tooling | `00-setup-and-tooling` | Setup & Tooling |
| 1, number-theory, numbers | `01-number-theory` | Number Theory |
| 2, algebra, abstract-algebra | `02-abstract-algebra` | Abstract Algebra |
| 3, ecc, elliptic-curves | `03-elliptic-curves` | Elliptic Curves |
| 4, lattices | `04-lattices` | Lattices |
| 5, probability, info, information | `05-probability-and-information` | Probability & Information |
| 6, coding, codes | `06-coding-theory` | Coding Theory |
| 7, symmetric, aes | `07-symmetric-crypto` | Symmetric Cryptography |
| 8, asymmetric, rsa, classical | `08-classical-asymmetric` | Classical Asymmetric |
| 9, hashes, commitments, accumulators | `09-hashes-commitments-accumulators` | Hashes, Commitments, Accumulators |
| 10, protocols, tls, signal | `10-protocols` | Protocols |
| 11, zk, zero-knowledge, zk-foundations | `11-zero-knowledge-foundations` | Zero-Knowledge Foundations |
| 12, snarks, starks, zk-systems | `12-zk-proof-systems` | ZK Proof Systems |
| 13, zk-eng, zk-engineering, circom, halo2 | `13-zk-engineering` | ZK Engineering |
| 14, pq-lattice, kyber, dilithium | `14-pq-lattice` | Post-Quantum Lattice-Based |
| 15, pq-code, pq-hash, sphincs, mceliece | `15-pq-code-hash-multivariate` | Post-Quantum Code/Hash/Multivariate |
| 16, isogenies, csidh, pq-migration | `16-pq-isogenies-and-migration` | Post-Quantum Isogenies & Migration |
| 17, fhe, mpc, ckks, tfhe | `17-fhe-and-mpc` | FHE & MPC |
| 18, blockchain, identity, applied | `18-applied-blockchain-and-identity` | Applied — Blockchain & Identity |
| 19, cryptanalysis, side-channels, attacks | `19-cryptanalysis-and-side-channels` | Cryptanalysis & Side Channels |
| 20, capstones, capstone | `20-capstones` | Capstones |

## Procedure

### Step 1: Resolve the Phase

Parse argument. If number, validate 0–20 inclusive. Out of range: tell user
"Phase [N] does not exist. Valid phases are 0-20." and show full list. If
keyword, look up in Phase Map. No match: tell user "Unknown phase
'[keyword]'. Pick from the list below:" and show all 21. No argument: ask
user to pick from full list.

### Step 2: Read the Phase Content

Use Glob to find all lesson directories under `phases/<phase-dir>/`. For each
lesson, read `docs/en.md`. These contain the teaching material to draw from.

If a phase has many lessons (12+), prioritize a representative spread: first
few, middle, last few.

### Step 3: Generate 8 Questions

Create exactly 8 multiple-choice questions from the lesson content:

**Questions 1–4: Conceptual (What/Why)**
- "What is the purpose of X?"
- "Why does Y happen when Z?"
- "Which statement best describes the relationship between A and B?"
- "What hard problem does X reduce to?"

**Questions 5–8: Practical (How/Build/Attack)**
- "How would you implement X?"
- "Which approach correctly solves Y?"
- "What is the correct order of steps to build Z?"
- "Given attack scenario X, what is the vulnerability?"

For primitive lessons, at least one of Q5–Q8 must be an **Attack** question
(textbook-RSA pitfall, ECDSA nonce reuse, padding oracle, length extension,
biased Gaussian sampler, etc). Crypto without attacks is not crypto.

Each question has 3 or 4 options labeled A, B, C (and optionally D).
Exactly one correct. Wrong options plausible but clearly incorrect to a
reader who studied the material.

Tag each question with the lesson it draws from (e.g. "Lesson 03: Modular
Inverse & Fast Exponentiation").

### Step 4: Present Questions One at a Time

Use AskUserQuestion. Format:

```
Question 1/8 (Conceptual) — from Lesson 02: GCD, Bezout, Extended Euclidean

What does the Extended Euclidean Algorithm compute?

A) gcd(a, b) only
B) gcd(a, b) and integers s, t such that sa + tb = gcd(a, b)
C) The least common multiple
D) The modular exponentiation a^b mod n
```

Wait for answer before moving on.

### Step 5: Track and Score

Running tally:
- Total correct out of 8
- For each wrong: question number, user's answer, correct answer, source lesson

### Step 6: Show Results

After 8 questions, display score and grade:

**7–8 correct: Mastered**
If phase is 20 (Capstones): "You have mastered the final phase.
Congratulations, you have completed the entire curriculum."
Otherwise: "You have a strong grasp of Phase N. Ready for Phase N+1: [next
phase name]."

**5–6 correct: Almost**
"Solid foundation. Review these specific areas before moving on:"
List lessons tied to missed questions.

**3–4 correct: Developing**
"You are building understanding but need to revisit some lessons:"
List each missed question with lesson to re-read.

**0–2 correct: Start Over**
"This phase needs more time. Work through lessons again from the beginning,
focusing on:"
List all missed topics.

### Step 7: Wrong Answer Breakdown

For each wrong question:

```
Question N: [question text, abbreviated]
Your answer: B
Correct answer: C — [correct option text]
Why: [1-2 sentence explanation]
Review: Lesson NN — [lesson name] (phases/<phase-dir>/NN-<lesson-slug>/docs/en.md)
```

For Attack questions specifically, also append a one-liner: "This is the
real-world attack that broke <real system, e.g. Sony PS3, ROCA, FREAK>."
when applicable.

### Step 8: What Next?

Offer three choices:

1. **Retake this quiz** — fresh 8 questions from same phase
2. **Try another phase** — pick a different phase
3. **Explain a topic** — ask about any concept from missed questions

Wait for user choice and act.

### Step 9: Persist Progress

After scoring (before Step 8), append the result to `.progress.json` at repo
root. Create the file if missing. **Merge** — preserve `placement` and other
`phases` entries.

Update / create `phases.<N>`:

```json
{
  "version": 1,
  "placement": { ... preserved ... },
  "phases": {
    "<N>": {
      "last_score": <0-8>,
      "best_score": <max(previous best, this score)>,
      "attempts": <previous attempts + 1>,
      "lessons_completed": <preserved>,
      "last_attempt_date": "<today YYYY-MM-DD>"
    }
  }
}
```

Mention one line after the breakdown: "Progress saved. `/my-progress` shows
your full dashboard."

## Rules

- Avoid repeating questions on retakes until pool exhausted. Once exhausted,
  reshuffle or rephrase.
- Questions must be directly grounded in lesson docs, not general knowledge.
- Do not show correct answer until after user responds.
- Keep question text concise. One or two sentences max.
- Wrong options must be plausible. No joke answers.
- For primitive lessons, prefer pulling from the **Attack It** section over
  the **Build It** section — attacks are where understanding is tested.
- If phase has no lesson docs (`docs/en.md` is the placeholder template),
  tell user: "Phase N does not have lesson content yet. Pick a completed
  phase to quiz on."
