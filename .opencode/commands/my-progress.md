---
description: Personal progress dashboard — reads .progress.json + ROADMAP.md, shows phases mastered, hours done, next step, pace estimate
---

You are rendering the **Cryptography from Scratch** personal progress dashboard.

Read `.progress.json` (written by `/find-your-level` and `/check-understanding`)
and `ROADMAP.md`. Render the dashboard exactly as specified in
`.claude/skills/my-progress/SKILL.md` — **read that file in full before
starting**.

Key invariants:
- This skill is read-only. Never modify `.progress.json`.
- If `.progress.json` is missing, tell the user to run `/find-your-level` first.
- Parse `(~N hours)` from ROADMAP.md headings for canonical phase hours.
- Status: Skipped (below entry phase) / ✅ Mastered (best ≥ 7) / 🚧 In Progress (attempts > 0, best < 7) / ⬚ Not Started.
- Show: header, phase table, summary (hours done/in-progress/remaining/total, phases mastered), pace + next step.
- Output terse. Snapshot, not essay.
