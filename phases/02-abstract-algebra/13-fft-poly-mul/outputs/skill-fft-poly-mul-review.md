---
name: skill-fft-poly-mul-review
description: Review an FFT-based integer polynomial multiplication implementation for correctness and common failure modes.
version: 1.0.0
phase: 02
lesson: 13
tags: [cryptography, fft, polynomial-multiplication, convolution, numerical, review]
---

# FFT Polynomial Multiplication Review

Use this when you see code that multiplies integer polynomials via a complex FFT (often for toy demos, big integer multiplication, or non-cryptographic compute kernels).

## Checklist

1. Verify it computes linear convolution (not circular).
   - Confirm padding length `N >= len(a) + len(b) - 1`.
   - Confirm both inputs are zero-padded to exactly `N`.
   - Red flag: `N` chosen from `max(len(a), len(b))` (wrap-around bug).

2. Verify transform-length constraints.
   - If the implementation assumes Cooley–Tukey power-of-two, confirm `N` is a power of two.

3. Verify the twiddle factors per stage.
   - For stage size `len`, verify `wlen = exp(±2πi/len)`.
   - Verify the sign convention is consistent between forward and inverse.

4. Verify bit-reversal / permutation logic.
   - Iterative FFT usually needs a bit-reversal permutation before the butterfly stages.
   - If no permutation is present, confirm the implementation uses a different (valid) schedule.

5. Verify inverse scaling.
   - Inverse must scale by `1/N` (or distribute that factor equivalently).
   - Quick property: `ifft(fft(x)) ≈ x` on multiple nontrivial inputs.

6. Verify coefficient recovery.
   - For integer inputs, outputs should be rounded to the nearest integer.
   - Red flag: `int(x.real)` truncation without rounding.

7. Verify numerical safety claims.
   - Complex FFT-based integer convolution can fail for large magnitudes (rounding errors).
   - If inputs can be adversarial or require exactness, recommend an NTT or a proven split-coefficient technique instead.

## Common Findings

| Finding | What it breaks |
|---------|----------------|
| Forgot zero padding | Computes circular convolution (mod `x^N - 1`) |
| Wrong twiddle base | Output is scrambled / wrong interpolation |
| Missing `1/N` scale | All coefficients are off by a factor of `N` |
| Used truncation instead of rounding | Systematic off-by-one errors |
| Large coefficients without safeguards | Silent rounding failures |

## Review Prompt

Review this FFT polynomial multiplication code. Confirm it pads to `N >= len(a)+len(b)-1`, uses a power-of-two `N` if required, uses `wlen = exp(±2πi/len)` per stage, performs the correct inverse (opposite sign + `1/N` scaling), and rounds recovered coefficients. Identify whether it computes linear convolution or circular convolution. If the use case needs exactness under adversarial inputs (crypto/ZK), recommend an NTT-based approach instead.
