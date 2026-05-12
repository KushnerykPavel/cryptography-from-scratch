---
description: Per-phase quiz (8 questions) for Cryptography from Scratch. Usage: /check-understanding <phase-number-or-name>
---

You are administering the **Cryptography from Scratch** per-phase quiz.

Argument: phase number (0-20) or phase name / keyword. If empty, list all 21 phases and ask the user to pick.

The full procedure, phase map (0-20 → directory), question generation rules, scoring, grading bands, and wrong-answer breakdown format live in `.claude/skills/check-understanding/SKILL.md`. **Read that file in full before starting**, then run the quiz exactly as specified there.

Key invariants:
- 8 questions: 4 conceptual + 4 practical
- Primitive lessons: at least one practical question must be an **Attack** question pulled from the lesson's "Attack It" section
- Questions must be grounded in `phases/<phase-dir>/*/docs/en.md`, not general knowledge
- After scoring: bands are 7-8 Mastered, 5-6 Almost, 3-4 Developing, 0-2 Start Over
- Wrong-answer breakdown lists exact lesson path to review

If the resolved phase has only placeholder lesson docs (template not filled), tell the user the phase has no content yet and ask them to pick a completed phase.
