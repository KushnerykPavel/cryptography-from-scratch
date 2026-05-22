# Differential Power Analysis (DPA) — CPA in Miniature

> If power correlates with intermediate values, traces can reveal keys.

**Type:** Build
**Languages:** Python
**Prerequisites:** XOR and bytes; basic statistics intuition (correlation)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain the leakage model idea (“power correlates with intermediate bits”)
- Compute Hamming weight as a simple leakage predictor
- Implement a trace simulator for a 1-byte S-box intermediate
- Distinguish DPA/CPA from brute force (why correlation works)
- Apply correlation power analysis to recover a 1-byte key in a toy setting

## The Problem

Even if a cryptographic algorithm is mathematically secure, implementations run on physical devices that leak: power consumption, EM radiation, timing, cache effects, and faults. In embedded systems, smart cards, HSMs, and IoT devices, power traces are a common leakage source.

If a device’s instantaneous power correlates with the number of 1-bits being processed (a common simplifying model), an attacker can collect many traces and test key guesses by checking which guess best predicts the observed power.

This lesson shows the core “signal processing loop” of correlation power analysis (CPA) using a toy trace generator so it runs deterministically without hardware.

## The Concept

CPA needs:

1. A **hypothesis** of what intermediate value depends on the key (e.g., `SBOX[pt XOR key]`).
2. A **leakage model** (e.g., Hamming weight of that intermediate).
3. Many measurements (traces) to average out noise.

For each key guess `k`, you compute predicted leakage for each plaintext and correlate it with measured power. The correct key guess produces the strongest correlation.

## Build It

### Step 1: A simple leakage model (Hamming weight)
```python
def hamming_weight(x: int) -> int:
    if x < 0 or x > 255:
        raise ValueError("expected byte")
    return x.bit_count()


def leakage_model(plaintext_byte: int, key_guess: int) -> int:
    return hamming_weight(AES_SBOX[plaintext_byte ^ key_guess])
```
This is a toy model: “power ≈ number of 1-bits in the S-box output”. Real leakage is messier, but the attack loop is the same.

### Step 2: Simulate power traces
```python
def simulate_traces(key_byte: int, plaintexts: Iterable[int]) -> List[Tuple[int, float]]:
    out: List[Tuple[int, float]] = []
    for pt in plaintexts:
        power = float(leakage_model(pt, key_byte))
        out.append((pt, power))
    return out
```
Each trace is `(plaintext_byte, observed_power)`. We keep it 1-sample-per-trace to focus on the statistics.

### Step 3: Correlation power analysis recovers the key byte
```python
def recover_key_byte_cpa(traces: List[Tuple[int, float]]) -> Tuple[int, float]:
    pts = [pt for pt, _ in traces]
    obs = [p for _, p in traces]
    best_k = 0
    best_abs = -1.0
    best_corr = 0.0
    for k in range(256):
        pred = [float(leakage_model(pt, k)) for pt in pts]
        c = pearson_corr(pred, obs)
        a = abs(c)
        if a > best_abs:
            best_abs = a
            best_corr = c
            best_k = k
    return best_k, best_corr
```
The correct guess aligns predicted leakage with measured leakage across traces, producing the highest correlation.

Run it:
python3 code/main.py

## Use It

- Use side-channel resistant implementations for your threat model.
- Consider masking, hiding, constant-time/table-free implementations, and hardware countermeasures.
- Treat “power analysis resistance” as an explicit requirement for embedded/HSM deployments.

## Pitfalls

- Assuming “AES is secure” implies “my device is secure”.
- Using lookup tables without countermeasures on exposed devices.
- Underestimating the attacker’s ability to collect many traces.
- Ignoring measurement alignment and preprocessing (real CPA needs it).
- Believing “add noise” is sufficient (attackers average noise away).

## Ship It

Save a side-channel assessment checklist: `outputs/side-channel-assessment-checklist.md`.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe the recovered key byte and correlation score.
2. Medium. Add noise to traces (e.g., +/- random jitter) and show recovery still works with enough traces.
3. Hard. Extend the simulator to multiple time samples per trace and recover the key by correlating at the sample point with the strongest leakage.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Leakage model | “power relates to bits” | A hypothesis mapping intermediates to expected leakage |
| Hamming weight | “number of 1s” | A common simple predictor for power consumption |
| CPA | “correlation attack” | Test each key guess by correlating predicted leakage with measured traces |
| Trace | “measurement” | Observed side-channel data from one execution |

## Further Reading

- Kocher, Jaffe, Jun, “Differential Power Analysis” (1999) — foundational DPA paper
- Mangard, Oswald, Popp, “Power Analysis Attacks” (2007) — practical side-channel reference
