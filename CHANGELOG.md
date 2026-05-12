# Changelog

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
