# numth API Review Skill

Use this skill to review a small number-theory helper library before it becomes a dependency of later cryptography lessons.

## Inputs

- Public API list, including exception behavior.
- Supported input range.
- Factorization and primality-test strategy.
- Test-vector file.
- Any downstream primitive that will call the library.

## Review Checklist

1. Confirm every modular API validates a positive modulus.
2. Confirm inverse routines raise a typed error when `gcd(a, n) != 1`.
3. Confirm CRT either requires pairwise-coprime moduli or implements generalized CRT explicitly.
4. Confirm primality testing does not rely on Fermat alone.
5. Confirm factoring code labels its range and does not imply RSA-scale capability.
6. Confirm square-root APIs say whether they handle only prime moduli or also composite moduli with known factorization.
7. Confirm educational code is not described as constant-time or production-safe.
8. Confirm vectors include both successful cases and broken-precondition cases.

## Output Format

Return:

- `Verdict`: approve / revise.
- `Blocking issues`: correctness or safety problems.
- `Range limits`: what inputs are intentionally out of scope.
- `Downstream notes`: what later lessons can safely reuse.
