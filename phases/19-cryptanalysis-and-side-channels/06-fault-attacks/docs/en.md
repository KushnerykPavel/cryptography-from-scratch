# Fault Attacks — RSA-CRT (Bellcore-Style)

> One faulty CRT result can reveal the factorization of N.

**Type:** Build
**Languages:** Python
**Prerequisites:** RSA basics; CRT intuition; GCD
**Time:** ~60 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain why CRT speeds up RSA and why it introduces a fault surface
- Compute CRT recombination for RSA decryption/signing
- Implement a toy fault injection into one CRT branch
- Distinguish “faulty output” from “wrong key” (how attackers exploit one glitch)
- Apply a GCD step to factor N given (correct, faulty) outputs

## The Problem

To speed up RSA decryption/signing, implementations often use CRT: compute mod `p` and mod `q` separately (faster) and recombine. On smart cards, embedded devices, and HSMs, attackers can sometimes induce faults: voltage glitches, clock glitches, EM pulses, lasers.

If the device returns a single faulty signature/decryption result, and the attacker also has the correct result (or can verify correctness), that pair can leak a prime factor of `N` via a GCD.

This is a classic example of “implementation security”: the math of RSA is unchanged, but the physical computation is vulnerable.

## The Concept

CRT-RSA computes:

- `m_p = c^d mod p` using `d_p = d mod (p-1)`
- `m_q = c^d mod q` using `d_q = d mod (q-1)`
- recombine into `m mod N` with a CRT formula

If a fault corrupts only one branch (say `m_p`), recombination produces a value that is correct mod `q` but wrong mod `p`. The difference between correct and faulty outputs becomes a multiple of one prime, enabling factoring via GCD.

## Build It

### Step 1: CRT-RSA decryption/signing
```python
def rsa_decrypt_crt(c: int, key: RSAKeyCRT, fault_mod_p: Optional[int] = None) -> int:
    if not (0 <= c < key.n):
        raise ValueError("c out of range")
    mp = pow(c, key.dp, key.p)
    mq = pow(c, key.dq, key.q)
    if fault_mod_p is not None:
        mp = fault_mod_p % key.p
    h = (key.qinv * (mp - mq)) % key.p
    return mq + h * key.q
```
CRT recombination recovers the full result mod `N=pq`. The `fault_mod_p` parameter lets us simulate “one-branch corruption”.

### Step 2: Inject a fault in one CRT branch
```python
s_faulty = rsa_decrypt_crt(c, key, fault_mod_p=(s_ok + 1) % key.p)
```
If the recombination uses a corrupted `m_p`, the output is inconsistent across moduli in a way attackers can exploit.

### Step 3: Use GCD to factor N from (correct, faulty)
```python
def factor_from_faulty_pair(n: int, correct: int, faulty: int) -> Tuple[int, int]:
    g = gcd((correct - faulty) % n, n)
    if g == 1 or g == n:
        raise ValueError("fault did not reveal a factor")
    p = g
    q = n // g
    return (min(p, q), max(p, q))
```
If `correct ≡ faulty (mod q)` but not (mod p), then `correct - faulty` is a multiple of `q`, so `gcd(correct - faulty, N)` reveals `q`.

Run it:
python3 code/main.py

## Use It

- Use hardened CRT-RSA countermeasures in real implementations:
  - verify result with a full exponentiation check
  - use “CRT with checksum” or recomputation checks
  - constant-time and fault-detection mechanisms
- For high-value keys: prefer dedicated, tamper-resistant hardware and vetted crypto libraries.

## Pitfalls

- Assuming “faults only cause crashes” (often they cause wrong-but-plausible outputs).
- Returning faulty outputs to callers (instead of detecting and aborting).
- Missing verification checks after CRT recombination.
- Treating hardware glitching as “out of scope” when you ship embedded devices.
- Reusing the same RSA key across many devices (a single compromised device leaks the key).

## Ship It

Save a fault-injection review checklist: `outputs/fault-injection-review-checklist.md`.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that a single faulty output factors `N`.
2. Medium. Change the fault model (corrupt `m_q` instead) and update the factor extraction accordingly.
3. Hard. Add a verification step after CRT recombination and show the attack fails when faults are detected.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Fault injection | “glitch the device” | Inducing computation errors via voltage/clock/EM/laser/etc. |
| CRT-RSA | “faster RSA” | Compute mod p and mod q separately, then recombine |
| Bellcore attack | “fault breaks RSA” | Factor N from one correct and one faulty CRT output using GCD |
| Countermeasure | “fault detection” | Extra checks to detect and abort on faulty computation |

## Further Reading

- Boneh, DeMillo, Lipton, “On the Importance of Checking Cryptographic Protocols for Faults” (1997) — classic fault attack perspective
- Joye et al., “Fault Attacks on RSA: A Survey” — overview of CRT-RSA fault attacks and mitigations
