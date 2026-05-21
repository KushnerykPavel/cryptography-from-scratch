---
name: decision-guide-fhe-vs-mpc
description: Practical decision guide and review checklist for choosing FHE (BFV/BGV, CKKS, TFHE) vs MPC vs TEEs for a privacy-preserving compute feature
version: 1.0.0
phase: 17
lesson: 1
tags: [fhe, mpc, secure-computation, privacy, threat-modeling, systems]
---

# Decision Guide: FHE vs MPC (and When to Use TFHE vs CKKS vs BFV/BGV)

Use this when you’re designing or reviewing a “compute on private data” feature.

## Step 0: Write the requirement as a contract

Fill this in before picking any tool:

- **Who holds the input?** (user / client / data owner)
- **Who runs the compute?** (cloud service / multiple parties / hardware enclave)
- **Who learns the output?** (user only / service / both / auditors)
- **What is the function?** (boolean logic, integer arithmetic, linear algebra, ML inference)
- **Latency target:** p50/p95 (interactive vs batch)
- **Throughput target:** QPS / batch size
- **Data volume:** bytes per request; rows/columns; feature vector size
- **Security constraints:** regulatory boundaries, data residency, auditability

If you can’t write the contract, you’re not ready to choose FHE vs MPC.

## Step 1: Choose the *security model*

### Use FHE when…

- There is **one data owner** who can hold the secret key.
- The server should learn **nothing** about inputs (and ideally nothing beyond the output shape).
- You can express the computation as a circuit with manageable depth, or you can afford bootstrapping.
- You can tolerate large ciphertext sizes and heavier compute.

### Use MPC when…

- Inputs are **split across multiple parties** (each party has its own private input).
- You want a joint result without any party revealing inputs to the others.
- You can manage interactive protocols and coordination (online/offline phases, networking).

### Use TEEs when…

- You can accept hardware trust assumptions and side-channel risk management.
- You need high performance with near-native code and minimal algorithm rewriting.
- You have an ops plan for attestation, patching, and enclave lifecycle.

## Step 2: If you chose FHE, pick the scheme family

Pick based on the *shape* of your compute:

- **BFV/BGV:** exact integer arithmetic mod `t` (great for counts, sums, exact modular logic, packed SIMD).
- **CKKS:** approximate reals (great for dot products, matrix ops, ML inference where approximation is acceptable).
- **TFHE / FHEW:** fast bootstrapped boolean / LUT computations (great for comparisons, thresholds, argmax-like logic, bit-level exactness).

Rule of thumb:

- If you need `>`, `max`, `argmax`, branching-heavy logic: plan for TFHE-style or scheme switching.
- If you need linear algebra on floats: start with CKKS.
- If you need exactness: start with BFV/BGV.

## Step 3: Checklist for an FHE design review

### Function/Circuit

- [ ] Computation is written as a circuit (or a library IR) with a stated **multiplicative depth**
- [ ] Any non-polynomial ops (comparisons, division, branching) are explicitly handled (LUTs / approximations / scheme switch)
- [ ] Inputs/outputs are bounded (range limits) and tested at boundaries

### Parameters & correctness

- [ ] Parameter selection is tied to depth, precision, and target security level
- [ ] There is an explicit **noise/precision budget** (even if the library automates it)
- [ ] Correctness tests exist for worst-case inputs (not only random cases)

### Performance & ops

- [ ] Key generation, evaluation key generation, and key distribution are accounted for (size + time)
- [ ] Ciphertext expansion is measured and budgeted (bandwidth + storage)
- [ ] End-to-end latency is measured for realistic batch sizes (not just microbenchmarks)

### Threat model

- [ ] Adversary model is written (honest-but-curious vs malicious; what leaks are acceptable)
- [ ] Side channels are addressed at the system level (timing, memory, cache, logging)
- [ ] Output leakage is considered (even perfect FHE can leak through outputs)

## Step 4: Quick “gotchas” that usually break projects

- “We’ll just do `if` statements on ciphertexts.” (You won’t; you’ll do LUTs or approximations.)
- “We can keep bootstrapping out of it.” (Maybe — but only if depth is tiny.)
- “Keys are small.” (Evaluation keys can dwarf everything.)
- “It’s like running normal ML, just encrypted.” (Model must be adapted; operators must be FHE-friendly.)

## Template: one-paragraph decision justification

Paste this into a design doc:

> We chose **{FHE/MPC/TEE}** because {who holds inputs} needs {privacy property} while the compute is {function shape}. Our primary constraint is {latency/throughput/cost}. The main risk is {noise budget / interaction overhead / enclave trust}. We mitigate it by {bootstrapping plan / batching / offline preprocessing / attestation and monitoring}. Success is measured by {correctness tests + perf benchmarks}.

