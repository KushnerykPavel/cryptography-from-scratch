# Lesson Template

Copy this folder structure for every new lesson. Fill in content per the format below.

## Folder Structure

```
NN-lesson-name/
├── code/
│   ├── main.py            (primary implementation)
│   ├── main.rs            (Rust version, if applicable)
│   ├── main.ts            (TypeScript version, if applicable)
│   └── main_galois.py     (galois / sympy / fpylll for finite-field & lattice work)
├── tests/
│   └── vectors.json       (RFC / NIST test vectors — mandatory for primitives)
├── notebook/
│   └── lesson.ipynb       (Jupyter for experimentation)
├── docs/
│   └── en.md              (lesson documentation)
├── quiz.json              (pre/post lesson quiz — schema below)
└── outputs/
    ├── prompt-*.md
    ├── skill-*.md
    └── tool-*/             (MCP server or CLI source)
```

## Documentation Format (`docs/en.md`)

```markdown
# [Lesson Title]

> [One-line motto — the core idea that sticks]

**Type:** Build | Learn
**Languages:** Python, Rust, TypeScript (list what's used)
**Prerequisites:** [List prior lessons needed]
**Time:** ~[estimated time] minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## The Problem

[2-3 paragraphs. What can't you do without this? Why should you care?
Show a concrete scenario where not knowing this hurts.]

## The Concept

[Explain with diagrams and intuition. No code yet.
Use ASCII diagrams, tables, or links to visuals in the web app.
Build mental models before implementation.]

## Build It

[Step-by-step from scratch. Start with the simplest version, then add
complexity. Every code block runnable on its own.]

### Step 1: [Name]

[Explanation]

    [code block]

### Step 2: [Name]

[Explanation]

    [code block]

## Use It

[Now show how a real library does the same thing. Compare your
from-scratch version. This proves the concept and introduces
practical tools (PyCryptodome, libsodium, arkworks, liboqs, etc).]

## Attack It

[For primitives: show the textbook attack. RSA without padding,
ECDSA with reused nonce, AES-ECB pattern leakage, etc. This is what
makes "build from scratch" actually educational.]

## Ship It

[Reusable artifact this lesson produces — prompt, skill, MCP server,
or CLI tool. Save in `outputs/`.]

## Exercises

1. [Easy — reinforce the core concept]
2. [Medium — apply to a different problem]
3. [Hard — extend, attack, or combine with prior lessons]

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| [term] | [common misconception] | [actual definition] |

## Test Vectors

[Source: RFC XXXX / NIST CAVP / project-internal.
Code must pass all vectors in `tests/vectors.json`.]

## Further Reading

- [Resource 1](url) — [why it's worth reading]
- [Resource 2](url) — [why it's worth reading]
```

## Quiz Format (`quiz.json`)

**Schema is locked.** Matches the parent project (AI Engineering from
Scratch) so cross-project tooling stays compatible. Do not introduce new
fields. Do not rename existing fields.

```json
{
  "questions": [
    {
      "stage": "pre",
      "question": "Question text (one or two sentences).",
      "options": [
        "Option A text",
        "Option B text",
        "Option C text",
        "Option D text"
      ],
      "correct": 1,
      "explanation": "Why the correct answer is correct, 1–2 sentences. Shown only after the learner answers."
    }
  ]
}
```

Field rules:

- `stage` — `"pre"` (before reading the lesson) or `"post"` (after). Pre
  questions test prior knowledge / setup; post questions test the lesson
  content.
- `question` — string. The prompt. No markdown headers.
- `options` — array of 3 or 4 strings. **Length parity required:** all
  options within ~25% character count of each other. Distractors must look
  legitimate. Never single out the correct option by length or phrasing.
- `correct` — integer index into `options` (0-based). Not a letter.
- `explanation` — 1–2 sentences. Revealed only after the user answers.

Question count per lesson:

- **Build lessons:** 2 pre + 6 post = 8 total. Of the 6 post, ≥1 must be
  an attack-themed question (textbook RSA pitfall, ECDSA nonce reuse,
  AES-ECB pattern leak, biased Gaussian sampler, etc).
- **Learn lessons:** 2 pre + 6 post = 8 total. No attack requirement.

Validation before writing `quiz.json`:

1. JSON parses.
2. Every question has all six fields.
3. `correct` is integer in `[0, len(options))`.
4. `len(options)` ∈ {3, 4}.
5. Option-length parity holds (max length ≤ 1.25 × min length).
6. No option string contains the substring `"(correct)"`, `"correct"`,
   or any hint phrasing referencing the answer.

If any check fails, do not write the file. Surface the failures and ask
the user to confirm before relaxing a rule.

## Code File Guidelines

- Code must run without errors.
- No comments unless the *why* is non-obvious. Code should be self-explanatory.
- Pick the language that fits best. Math-heavy → Python with `galois` / `sympy` / `fpylll` / `py_ecc`. Performance/memory → Rust. Web demos → TypeScript.
- Include `requirements.txt` / `Cargo.toml` / `package.json` per lesson if dependencies needed.
- Start simple, build up.
- Every primitive lesson must include test vectors from RFC / NIST / academic source.

## Output File Format

### Prompts

```markdown
---
name: prompt-name
description: What this prompt does
phase: [phase number]
lesson: [lesson number]
---

[Prompt content]
```

### Skills

```markdown
---
name: skill-name
description: What this skill teaches
version: 1.0.0
phase: [phase number]
lesson: [lesson number]
tags: [crypto, zk, pqc, ...]
---

[Skill content]
```
