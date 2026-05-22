---
name: "GMW Protocol Architecture Checklist"
description: "A practical checklist for designing and reviewing GMW-style boolean MPC systems."
phase: 17
lesson: 7
---

# GMW Protocol Architecture Checklist

Use this during design reviews and PR reviews for systems that claim “we use GMW (boolean MPC)”.

## 1) Threat model
- [ ] **Semi-honest vs malicious:** Is the system explicitly semi-honest, or does it defend against active deviation?
- [ ] **Abort behavior:** If a party aborts mid-protocol, does anything sensitive leak (e.g., selective failure or early reveals)?
- [ ] **Output policy:** Who learns the output (both parties, one party, or external aggregator), and is this enforced by the protocol?

## 2) Circuit and cost model
- [ ] **Gate accounting:** Do you track the number of AND gates separately from XOR/NOT gates?
- [ ] **Communication budget:** Is bandwidth/latency sized for `OT_cost × (#AND)` (online), plus preprocessing if used?
- [ ] **Circuit compilation:** Is the function compiled to a boolean circuit in a way that avoids accidental AND blowups?

## 3) OT layer
- [ ] **Do not roll your own OT:** Is OT coming from a vetted library (emp-ot, libOTe, MP-SPDZ stack, etc.)?
- [ ] **OT extension:** For non-trivial circuits, is OT extension used (base OTs + fast symmetric expansion)?
- [ ] **Group/curve choices:** Are you using standard curves/groups and constant-time implementations?

## 4) Sharing and conversions
- [ ] **Share type correctness:** Are you consistently using XOR shares for boolean wires?
- [ ] **Mixing protocols:** If you convert between boolean and arithmetic sharing, is the conversion implemented as a protocol (not a cast)?
- [ ] **Randomness lifecycle:** Are shares and masks fresh per execution (no reuse across runs)?

## 5) Malicious security (if required)
- [ ] **Input consistency:** Are there mechanisms preventing a party from changing inputs mid-computation?
- [ ] **Correctness checks:** Are there MACs/commitments/zero-knowledge checks (depending on the framework) to prevent cheating?
- [ ] **Transcript integrity:** Are messages authenticated (session keys, channel binding), not just encrypted?

## 6) Side channels and engineering
- [ ] **Constant-time primitives:** Are crypto and bit operations implemented in constant time where required?
- [ ] **Traffic analysis:** If network observers exist, do message sizes/timing leak sensitive structure?
- [ ] **Test strategy:** Do you have deterministic test vectors (functional correctness) and randomized property tests (robustness)?

