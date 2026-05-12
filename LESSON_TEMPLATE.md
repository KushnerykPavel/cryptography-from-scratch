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
