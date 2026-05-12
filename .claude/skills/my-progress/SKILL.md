---
name: my-progress
version: 1.0.0
description: >
  Personal progress dashboard for Cryptography from Scratch. Reads .progress.json
  (auto-written by find-your-level + check-understanding) and ROADMAP.md, then
  renders hours done vs remaining, last quiz scores per phase, suggested next
  lesson, and pace estimate. Trigger phrases: "my progress", "how am I doing",
  "show progress", "what's next", "/my-progress".
tags: [progress, dashboard, curriculum, cryptography]
---

# My Progress

Render a personal progress dashboard for the Cryptography from Scratch
curriculum.

## Activation

Triggers when user says:
- `/my-progress`
- "my progress"
- "how am I doing"
- "show progress"
- "what's next"
- "where am I in the course"

## Procedure

### Step 1: Read progress state

Look for `.progress.json` at repo root. Schema:

```json
{
  "version": 1,
  "placement": {
    "score": 0,
    "areas": {
      "number_theory": 0,
      "symmetric_asymmetric": 0,
      "ecc_protocols": 0,
      "zero_knowledge": 0,
      "post_quantum": 0
    },
    "entry_phase": 0,
    "date": "YYYY-MM-DD"
  },
  "phases": {
    "<N>": {
      "last_score": 0,
      "best_score": 0,
      "attempts": 0,
      "lessons_completed": [],
      "last_attempt_date": "YYYY-MM-DD"
    }
  }
}
```

If `.progress.json` does not exist, tell the user:

> No progress recorded yet. Run `/find-your-level` to take the placement quiz
> and start tracking, or `/check-understanding <phase>` to record a phase score.

### Step 2: Read ROADMAP.md for hours

Parse `ROADMAP.md`. Each phase heading has `(~N hours)`. Extract these as
canonical totals. Each lesson row has `~N min` — sum per phase to validate.

### Step 3: Render dashboard

Output four sections:

#### Header

```
Cryptography from Scratch — Progress
====================================
Placement: <score>/10 (taken <date>) → entry: Phase <N>
```

If no placement, say "Placement: not taken — run /find-your-level".

#### Phase Table

```markdown
| Phase | Name | Status | Best Score | Attempts | Hours |
|-------|------|--------|------------|----------|-------|
| 0 | Setup & Tooling | Skipped | -- | 0 | -- |
| 1 | Number Theory | ✅ Mastered | 8/8 | 2 | 21 |
| 2 | Abstract Algebra | 🚧 In Progress | 5/8 | 1 | 16 |
| 3 | Elliptic Curves | ⬚ Not Started | -- | 0 | 13 |
| ... | ... | ... | ... | ... | ... |
```

Status rules:
- **Skipped** — phase below `entry_phase` from placement.
- **✅ Mastered** — `best_score >= 7`.
- **🚧 In Progress** — `attempts > 0` and `best_score < 7`.
- **⬚ Not Started** — `attempts == 0` and phase >= entry_phase.

Hours column shows full estimate from ROADMAP for non-Skipped phases, `--`
for Skipped.

#### Summary

```
Hours done:        X (mastered phases)
Hours in progress: Y (started but not mastered)
Hours remaining:   Z (not started)
Total path:        T

Phases mastered:   N / 21
```

Hours done = sum of hours for ✅ phases.
Hours remaining = sum of hours for ⬚ phases (excluding Skipped).

#### Pace + Next Step

If at least 2 phases mastered, estimate pace: hours-done divided by days from
first attempt to today. Show:

```
Pace: ~H hours/week → estimated completion: <date>
```

Then **Next Step** — the lowest-numbered ⬚ or 🚧 phase not Skipped:

```
Next: Phase N — <phase name> (~H hours)
  → Start with: phases/<NN-slug>/01-<first-lesson>/docs/en.md
```

If everything is Mastered, congratulate. If everything is Skipped + nothing
attempted, suggest `/find-your-level`.

### Step 4: Wrong-state recovery

- If `.progress.json` is malformed JSON: tell user, suggest deleting it to
  start fresh. Do NOT overwrite.
- If a phase entry references a non-existent phase number: ignore that entry
  in the dashboard but warn the user once.
- If ROADMAP.md hours can't be parsed for a phase: show `?` in Hours column.

## Rules

- Never modify `.progress.json` from this skill — read-only. Writes happen
  only from `find-your-level` and `check-understanding`.
- Use the actual current date for "today" when estimating pace.
- Keep output terse. The user wants a snapshot, not an essay.
