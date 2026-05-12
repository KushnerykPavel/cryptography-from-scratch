# Cryptography from Scratch

> *From modular arithmetic to post-quantum and zero-knowledge. Build every primitive yourself, then ship reusable tools.*

![status](https://img.shields.io/badge/status-v0.1.0--skeleton-yellow) ![license](https://img.shields.io/badge/license-MIT-blue) ![phases](https://img.shields.io/badge/phases-21-green) ![lessons](https://img.shields.io/badge/lessons-241-green) ![hours](https://img.shields.io/badge/hours-~300-green)

**241 lessons. 21 phases. ~300 hours.**

You don't just read about RSA, Kyber, or Groth16. You implement them. From scratch. Then you compare against real libraries (arkworks, liboqs, RustCrypto, libsodium) and ship usable artifacts: prompts, skills, MCP servers, and CLI tools.

> ⚠️ **v0.1.0 — Curriculum skeleton.** All 21 phases and 241 lesson dirs are scaffolded. One lesson (`phases/01-number-theory/01-modular-arithmetic`) is fully fleshed out as the reference template — runnable code, passing test vectors, shipped skill. The remaining lessons are placeholders with the template structure. Contributions welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md).

> ⚠️ **Educational use only.** Code is written for clarity, not for production. Real cryptography requires constant-time implementations, audited libraries, and threat modeling beyond the scope of any course. Never deploy from-scratch primitives without expert review.

## Why this course

Most crypto material splits into two camps:

- **Theory-heavy textbooks** (Boneh-Shoup, Katz-Lindell) — rigorous but no code.
- **Library tutorials** (`from cryptography.hazmat import...`) — code but no understanding.

This course closes the gap. Build the primitive in 200 LOC, then use the audited library, then learn what attacks the real version defends against.

## Course shape

| Phase block | Phases | Hours |
|-------------|--------|-------|
| Math foundations (number theory → lattices → coding) | 01–06 | ~75 |
| Symmetric & classical asymmetric | 07–10 | ~50 |
| Zero-knowledge | 11–13 | ~55 |
| Post-quantum | 14–16 | ~40 |
| Advanced (FHE, MPC, applied) | 17–18 | ~30 |
| Cryptanalysis & capstones | 19–20 | ~20 |

See **[ROADMAP.md](ROADMAP.md)** for full lesson list.

## Languages

- **Python** — primary teaching language. Math-heavy lessons use pure-Python libraries: `galois` (finite fields, polynomial rings, NTT), `fpylll` (LLL / BKZ / Babai), `sympy.ntheory` + `gmpy2` (number theory + fast bigint), `py_ecc` (BLS12-381, BN254, secp256k1). No SageMath dependency — install is `pip install -r requirements.txt`.
- **Rust** — primary implementation language. Crates: `arkworks`, `dalek`, `RustCrypto`, `liboqs-rust`, `halo2`, `noir`.
- **TypeScript** — protocol demos, web wallets, `noble-curves`, `snarkjs`.
- **Circom + Halo2 DSL** — ZK circuit phases.
- **C** — only for FFI demos with libsodium / OpenSSL.

## Lesson structure

Every lesson follows the same arc:

1. **The Problem** — what can't you do without this?
2. **The Concept** — intuition first, no code.
3. **Build It** — implement from scratch.
4. **Use It** — same thing in a real library.
5. **Ship It** — reusable artifact saved in `outputs/`.
6. **Exercises** — easy, medium, hard.

See **[LESSON_TEMPLATE.md](LESSON_TEMPLATE.md)**.

## Reusable artifacts

Every lesson ships at least one of:

- **Prompts** — `outputs/prompt-*.md`
- **Skills** — `outputs/skill-*.md` (Claude Code skills)
- **MCP servers** — e.g. `curve-arithmetic-server`, `lwe-parameter-checker`
- **CLI tools** — e.g. `pq-bench`, `circom-lint`, `kdf-audit`

By the end of the course you have a personal cryptography toolkit, not just notes.

## Quick start

```bash
git clone <repo>
cd cryptography-from-scratch
pip install -r requirements.txt
# pick a lesson
cd phases/01-number-theory/01-modular-arithmetic
python code/main.py
```

## Built-in agent commands

Three slash commands ship with the repo and work in both **Claude Code** and **OpenCode**:

| Command | What it does |
|---------|--------------|
| `/find-your-level` | 🧭 10-question quiz that maps your knowledge to a starting phase and builds a personalized path with hour estimates |
| `/check-understanding <phase>` | 📝 Per-phase quiz (8 questions) with feedback and specific lessons to review |
| `/lesson <phase> <lesson>` | 🎓 **OpenCode tutor mode** — walks you through a single lesson (Problem → Concept → Build → Use → Attack → Ship → 8-Q quiz). You write the code; the tutor hints, runs tests, and quizzes you. Never auto-fills `NotImplementedError` stubs |
| `/my-progress` | 📊 Personal dashboard — phases mastered, hours done / remaining, pace estimate, next step |

Progress is persisted to `.progress.json` (git-ignored, personal). For manual tracking see [`PROGRESS.md`](PROGRESS.md).

Examples:

```
/find-your-level
/lesson 1 2          # Phase 1, Lesson 2 (GCD + Extended Euclidean) in tutor mode
/check-understanding 4
/check-understanding zero-knowledge
/my-progress
```

| Agent | Source |
|-------|--------|
| Claude Code | [`.claude/skills/`](.claude/skills/) |
| OpenCode | [`.opencode/commands/`](.opencode/commands/) (slash commands) + [`.opencode/agent/crypto-tutor.md`](.opencode/agent/crypto-tutor.md) (tutor agent) |

Project-wide agent context lives in [`AGENTS.md`](AGENTS.md), which OpenCode reads natively and Claude Code picks up via fallback. The **Teaching mode** section in `AGENTS.md` is mandatory reading for any agent — it forbids auto-implementing lessons and defines the tutor loop. OpenCode users get a dedicated `crypto-tutor` agent (with `edit: ask` / `write: ask` permission gates) so stub-filling cannot happen silently.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). PRs adding new languages, test vectors, or attack demos are welcome.

## Acknowledgments

Curriculum structure, lesson arc (Problem → Concept → Build → Use → Ship → Exercises), and the `find-your-level` / `check-understanding` skill design are inspired by [AI Engineering from Scratch](https://github.com/rohitg00/ai-engineering-from-scratch) by Rohit Ghumare (MIT licensed). Course content (phases, lessons, glossary, attacks, ZK + PQ material) is original to this repository.

## License

MIT — see [LICENSE](LICENSE).
