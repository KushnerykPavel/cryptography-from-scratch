# Cryptography from Scratch — Agent Instructions

This file is read by AI coding agents (OpenCode, Claude Code via fallback, and others compatible with the AGENTS.md convention) to understand project context and conventions.

## What this repo is

A self-paced cryptography curriculum: 21 phases, ~241 lessons, ~300 hours. Phases cover number theory, abstract algebra, elliptic curves, lattices, probability/information, coding theory, symmetric crypto, classical asymmetric, hashes/commitments, protocols, zero-knowledge (foundations + proof systems + engineering), post-quantum (lattice / code-hash-multivariate / isogenies + migration), FHE & MPC, applied blockchain & identity, cryptanalysis & side channels, capstones.

See [`ROADMAP.md`](ROADMAP.md) for the full lesson list and time estimates.

## Repo layout

```
cryptography-from-scratch/
├── phases/<NN-phase>/<NN-lesson>/
│   ├── code/           # main.py (default), optional main.rs, main.ts
│   ├── tests/          # vectors.json (RFC / NIST), test_*.py
│   ├── docs/en.md      # lesson body — Problem → Concept → Build → Use → Attack → Ship → Exercises
│   ├── notebook/       # optional .ipynb
│   ├── outputs/        # prompts, skills, MCP servers, CLI tools shipped by the lesson
│   └── quiz.json       # multiple-choice quiz consumed by /check-understanding
├── glossary/           # terms.md, myths.md
├── scripts/            # scaffold-lesson.sh
├── .claude/skills/     # find-your-level, check-understanding
├── .opencode/commands/ # find-your-level, check-understanding (OpenCode)
└── ROADMAP.md          # canonical phase + lesson + hours table
```

## Lesson conventions

Every lesson `docs/en.md` follows the same arc. Do not skip steps. See [`LESSON_TEMPLATE.md`](LESSON_TEMPLATE.md) for the canonical structure:

1. **The Problem** — concrete scenario where missing this hurts.
2. **The Concept** — intuition + diagrams. No code yet.
3. **Build It** — implement from scratch in Python (default) or Rust where appropriate.
4. **Use It** — same primitive in a real audited library (PyCryptodome, libsodium, arkworks, liboqs, RustCrypto, halo2, snarkjs, OpenFHE, ...).
5. **Attack It** (primitive lessons only) — textbook attack on the naive version. This is where understanding is tested.
6. **Ship It** — reusable artifact saved in `outputs/`: prompt, skill, MCP server, or CLI tool.
7. **Exercises** — easy / medium / hard.
8. **Test Vectors** — RFC / NIST CAVP / academic source. Code must pass `tests/vectors.json`.

## Code rules

- Python is the default implementation language. For math-heavy work prefer pure-Python libraries: `galois` (finite fields, polynomial rings, NTT), `fpylll` (lattice algorithms), `sympy.ntheory` + `gmpy2` (number theory + bigint), `py_ecc` (curves, BLS12-381). Use Rust only for performance-critical phases (`13-zk-engineering`, `14-pq-lattice`).
- Code must run without errors. CI runs every `code/main.*` per lesson.
- No comments unless the *why* is non-obvious. Code should be self-explanatory.
- **Educational warning** at the top of every lesson doc: "Educational implementation. Not constant-time. Not production-safe."
- Test vectors are mandatory for any lesson that implements a primitive. Cite the RFC / NIST / academic source in `tests/vectors.json`.
- Avoid dependencies on niche / unmaintained libraries. Prefer stdlib or the curated list in `requirements.txt`.

## Security & ethics

- This repo is an educational resource. From-scratch primitives are NOT production-safe.
- Never recommend that a learner deploy code from this course. Always point to an audited library in the **Use It** section.
- Always show **Attack It** for primitive lessons. Crypto without attacks is not crypto.
- Do not write a comment / commit / PR description that suggests course code is suitable for production use.

## Slash commands

Two commands are available in both `.claude/skills/` (Claude Code) and `.opencode/commands/` (OpenCode):

- `/find-your-level` — 10-question placement quiz, maps score to starting phase + builds personalized path with hours parsed from `ROADMAP.md`.
- `/check-understanding <phase>` — 8 questions per phase (4 conceptual + 4 practical), grounded in lesson docs, with at least one Attack question per primitive phase.

Implementation lives in `.claude/skills/<name>/SKILL.md`. The `.opencode/commands/<name>.md` files reference those for the actual procedure.

## Adding a new lesson

```bash
scripts/scaffold-lesson.sh <phase-dir> <NN-lesson-slug> "Title"
```

Creates `code/`, `tests/`, `docs/en.md` skeleton, `notebook/`, `outputs/`, and `quiz.json`. Add a row to `ROADMAP.md` under the right phase. One lesson per commit / PR.

## Style

- Lesson docs: clear, direct, no hedging. Cite sources.
- No emoji in code or commits. Emoji OK in glossary / README headers if the AI Engineering from Scratch parent style is followed.
- Markdown tables for Key Terms and any comparison.
- Prefer ASCII diagrams in docs over images (cleaner diff, renders in TUI).

## License

MIT — see [LICENSE](LICENSE). Curriculum structure inspired by [AI Engineering from Scratch](https://github.com/rohitg00/ai-engineering-from-scratch) (also MIT). Course content is original.
