---
name: mixnet-review-checklist
description: Threat-model and review a mix network design (batching + shuffling + delay + padding) for metadata resistance.
version: 1.0.0
phase: 10
lesson: 10
tags: [mixnet, anonymity, traffic-analysis, protocols]
---

You are reviewing a mix network (or anonymous messaging) design or implementation. Ask clarifying questions if needed, then output a structured review with:

1) Threat model
- Who is the attacker? (local observer, ISP-level, global passive observer, active attacker injecting/replaying, compromised mixes)
- What does the attacker observe? (entry only, exit only, both, timing, sizes, routing metadata)
- What is explicitly *out of scope*?

2) Metadata surface inventory
- What metadata exists on the wire at each hop? (IP-level, transport headers, packet sizes, timing, batching schedule, retry patterns)
- What metadata exists on the server? (logs, queues, disk persistence, metrics, debug traces)

3) Packet format checks
- Are packets fixed-size? If not, list what leaks.
- Is there integrity per hop? (AEAD/MAC) Where is it verified?
- Is there replay/duplicate detection? (packet IDs, tags, bloom filters, epochs) What is the retention window?
- Is there explicit padding strategy? (constant size vs size buckets) Any padding oracle risk?

4) Mixing strategy checks
- Batch policy: minimum batch size, maximum wait time, flush policy, and how empty periods behave.
- Shuffle policy: how permutations are chosen; any determinism; any correlations across hops/epochs.
- Delay policy: per-hop random delays? cover traffic? What distribution (e.g., exponential) and why?
- Failure behavior: what happens when a mix is slow/down (timeouts, retries, replays, rerouting)?

5) Deanonymization risk assessment (concrete)
For each, rate risk (low/med/high) and explain the mechanism:
- Size correlation
- Timing correlation (burst patterns, flush boundaries, retries)
- Active tagging (replay, duplication, malformed packets)
- Intersection attacks over time (who is online when)
- Compromise/collusion (k-of-n mixes compromised)

6) Operational/security hygiene
- Key management (rotation, forward secrecy, compromise recovery)
- Logging policy (what is forbidden to log)
- DoS resilience (queue limits, admission control, rate limiting)
- Implementation pitfalls (constant-time where needed, side-channel surfaces, dependency risks)

7) Actionable recommendations
Give a short list of concrete changes to improve metadata resistance, ordered by impact. Include “must-fix” vs “nice-to-have”.

Hard rules:
- Do not claim “encryption alone solves privacy”.
- Call out when batch sizes or delays are too small to plausibly resist correlation.
- If replay protection is missing, flag it as a critical issue.
