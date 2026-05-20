# Changelog

## [0.11.0] — 2026-05-20

Phases 12 (ZK Proof Systems) and 13 (ZK Engineering) complete. 170/241 lessons implemented.

### Added (Phase 12 — ZK Proof Systems)
- All 16 lessons implemented: Arithmetic Circuits, R1CS, QAP, Pinocchio, Groth16, PLONK Overview, PLONK Implement, Lookup Arguments, PLONKish Arithmetization, Halo2, STARKs, FRI, DEEP-FRI, Recursive Proofs, Folding Schemes, SNARK/STARK Comparison Lab.
- Each lesson: runnable `code/main.py`, `tests/vectors.json`, `tests/test_vectors.py`, `quiz.json`, `docs/en.md`.

### Added (Phase 13 — ZK Engineering)
- All 12 lessons implemented: Circom, snarkjs, Halo2 Rust, arkworks, Noir, RISC0 zkVM, SP1 & Jolt, On-Chain Verifiers, Proof Aggregation & Recursion, ZK Mixers, Semaphore, ZK App End-to-End Lab.
- Each lesson: runnable `code/main.py`, `tests/vectors.json`, `tests/test_vectors.py`, `quiz.json`, `docs/en.md`.

## [0.2.0] — 2026-05-13

Phase 1 (Number Theory) complete; Phase 2 (Abstract Algebra) lessons 01–05 complete.

### Added (Phase 2 progress)
- Lesson 02/01 Groups, 02/02 Cyclic Groups, 02/03 Subgroups/Cosets/Lagrange, 02/04 Homomorphisms, 02/05 Rings/Ideals/Quotients fleshed out with runnable `code/main.py`, `tests/vectors.json` + `tests/test_vectors.py`, `quiz.json`, and shipped skill in `outputs/`.
- 02/05 Rings: `is_ring`, `principal_ideal`, `is_ideal`, `quotient_coset_reps`, `quotient_is_ring`, `units`, `zero_divisors`, `ring_report`, `ideal_report`. Vectors cover Z/12Z, Z/8Z, Z/6Z, Z/5Z (field), and a non-ideal failure case. Ships `skill-ring-ideal-review.md`.
- ROADMAP.md: Phase 2 → 🚧, lessons 01–05 → ✅.

### Phase 1

### Added
- All 18 Phase 1 lessons fleshed out: runnable `code/main.py`, JSON test vectors, `tests/test_vectors.py` runners, per-lesson quizzes (`quiz.json`), and shipped artifact in `outputs/` (skill or prompt).
- Lessons 02–18 cover GCD/Bezout/EEA, modular inverse + fast exp, Fermat/Euler, CRT, totient/Carmichael, quadratic residues + Tonelli-Shanks, Legendre/Jacobi, prime generation, Miller-Rabin, AKS, Pollard rho + p-1, quadratic sieve, index calculus, BSGS + rho DLP, smooth numbers + hidden subgroup, continued fractions, and the `numth` library lab.
- ROADMAP.md: Phase 1 status flipped to ✅.

## [0.1.0] — 2026-05-12

Initial public release. Curriculum skeleton + 1 reference lesson.

### Added
- Course skeleton: 21 phases, 241 lesson directories.
- ROADMAP.md with full phase + lesson breakdown and hour estimates.
- LESSON_TEMPLATE.md with Problem → Concept → Build → Use → Attack → Ship → Exercises arc.
- Reference lesson: `phases/01-number-theory/01-modular-arithmetic` — runnable code, 8 passing test vectors, shipped Claude Code skill.
- Scaffolding script `scripts/scaffold-lesson.sh`.
- Glossary (terms.md + myths.md).
- Pure-Python crypto stack — no SageMath dependency. `galois`, `fpylll`, `sympy`, `gmpy2`, `py_ecc`.
- Three slash commands × two agents:
  - `/find-your-level` — placement quiz, writes `.progress.json`.
  - `/check-understanding <phase>` — per-phase quiz, writes `.progress.json`.
  - `/my-progress` — read-only dashboard over `.progress.json` + ROADMAP.md.
- Claude Code skills in `.claude/skills/`; OpenCode commands in `.opencode/commands/` (delegate to the same SKILL.md procedures).
- `AGENTS.md` — project rules consumed by OpenCode natively and Claude Code via fallback.
- `PROGRESS.md` — manual checkbox tracker (all 241 lessons listed).
- Acknowledgments to [AI Engineering from Scratch](https://github.com/rohitg00/ai-engineering-from-scratch) — curriculum structure inspiration (MIT).
