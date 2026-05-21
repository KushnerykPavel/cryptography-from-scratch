---
name: "TFHE Scheme Evaluation Guide"
description: "A decision matrix and checklist for when to choose TFHE over other FHE schemes."
phase: 17
lesson: 4
---

# TFHE Evaluation Guide

Use this guide when architecting a Fully Homomorphic Encryption (FHE) solution to decide if TFHE is the right choice for your workload.

## 1. Workload Fit: Boolean vs. Arithmetic

TFHE is optimized for **Boolean circuits**. It represents data at the bit level and evaluates logic gates (NAND, AND, XOR).
- **Use TFHE when:** Your computation requires deep comparison operations (e.g., sorting, finding maximums, decision trees, string matching).
- **Avoid TFHE when:** Your computation is primarily heavy polynomial arithmetic, linear algebra, or machine learning model inference (use BGV/BFV or CKKS instead).

## 2. Bootstrapping Strategy

TFHE embraces **per-gate bootstrapping**. 
- **The Advantage:** You don't need to track multiplicative depth or parameterize your scheme for the deepest possible circuit. The parameters stay small and fast.
- **The Trade-off:** Every single gate requires a bootstrapping operation (blind rotation). While TFHE bootstrapping is very fast (milliseconds), evaluating a circuit with 1,000,000 gates will still be slow without hardware acceleration.

## 3. Programmable Bootstrapping (PBS)

PBS is TFHE's superpower. It allows you to evaluate any univariate function (like a Look-Up Table) *for free* while refreshing the noise.
- Can you represent your non-linear activation functions (like ReLU or Sigmoid) as a Look-Up Table? If yes, TFHE's PBS can compute it smoothly.

## 4. Integer Representation

If you need integers, libraries like Zama's Concrete build on TFHE to provide exact integer types (e.g., `uint8`, `int16`). Under the hood, they use PBS to perform operations on these integers.
- Keep data types as small as possible. A `uint4` operation is significantly faster than a `uint16` operation in TFHE.

## Architectural Checklist
- [ ] Are we doing comparisons, branching, or logic operations? *(Yes -> TFHE)*
- [ ] Are we doing mostly floating-point approximations? *(Yes -> CKKS)*
- [ ] Are we evaluating very deep circuits where tracking noise is too complex? *(Yes -> TFHE)*
- [ ] Can we aggressively quantize our data into small integers? *(Yes -> TFHE)*
