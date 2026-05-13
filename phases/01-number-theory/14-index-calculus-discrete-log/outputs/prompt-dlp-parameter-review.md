# Finite-Field DLP Parameter Review

Use this prompt when reviewing finite-field Diffie-Hellman, DSA-style, or Schnorr-style parameters.

```text
Review these finite-field discrete-log parameters:

- p = <prime modulus>
- q = <claimed subgroup order>
- g = <claimed subgroup generator>
- protocol use = <DH / signatures / ZK / other>

Check:

1. Is p prime, and does q divide p - 1?
2. Is q large enough for the intended security level?
3. Does g have exact order q, not order 1 or a small divisor?
4. Are public keys validated with y^q ≡ 1 (mod p) and y not in {0, 1}?
5. Are small-subgroup and invalid-element attacks handled?
6. Are these standardized parameters, or custom parameters that need deeper review?
7. Is the finite-field size large enough against index-calculus / NFS-DL attacks?

Return:

- PASS / REVIEW / FAIL
- the highest-risk issue first
- concrete tests to add
- do not recommend educational or from-scratch code for production use
```
