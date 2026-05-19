# Group Homomorphisms & Isomorphisms

> A homomorphism is a translation that preserves the algebra, not necessarily the labels.

**Type:** Learn
**Languages:** Python
**Prerequisites:** 02-abstract-algebra/01-groups, 02-abstract-algebra/02-cyclic-groups, 02-abstract-algebra/03-subgroups-cosets-lagrange
**Time:** ~45 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain the operation-preservation property that defines a group homomorphism and verify it exhaustively for finite examples
- Compute the kernel and image of a finite homomorphism and interpret their sizes using the first isomorphism theorem
- Distinguish injective, surjective, and isomorphic maps and determine which classification applies to a given mapping
- Apply the exponent map `f(k) = g^k` to show why Diffie-Hellman-style protocols depend on a homomorphism from addition to multiplication
- Identify how a non-trivial kernel causes distinct domain elements to become indistinguishable in the codomain, breaking uniqueness assumptions in protocols

## The Problem

Cryptography constantly moves between representations of the same structure.

An exponent `k` may be written as an integer modulo `q`, while the public value is written as `g^k` in a cyclic group. A scalar in an elliptic-curve protocol may become a point. A quotient may collapse several values into one residue class. A commitment scheme may rely on adding secrets while multiplying group elements.

Without homomorphisms, these moves look like notation tricks. With homomorphisms, you can ask the exact questions that keep a protocol honest:

```text
Does the map preserve the operation?
Which inputs collapse to the identity?
Which outputs are reachable?
Is this only a one-way representation, or truly the same group with new labels?
```

Those questions matter because maps can hide structure or destroy it. If two different secrets map to the same public value, the map is not injective. If outputs only land in a small subgroup, the image is smaller than the codomain. If a protocol assumes a map is reversible when it is not, the proof and the implementation are talking about different objects.

## The Concept

A group homomorphism is a function between groups that preserves the operation.

Let `(G, *)` and `(H, ·)` be groups. A function `f: G -> H` is a homomorphism when:

```text
f(a * b) = f(a) · f(b)
```

The symbols may look different because the operations may be different. The domain might use addition, while the codomain uses multiplication.

### Operation preservation

For additive groups:

```text
f(a + b) = f(a) + f(b)
```

For an exponent map into a multiplicative group:

```text
f(k) = g^k

f(a + b) = g^(a+b)
         = g^a * g^b
         = f(a) * f(b)
```

That line is the algebraic heartbeat of Diffie-Hellman-style protocols, Schnorr signatures, Pedersen commitments, and many zero-knowledge proofs.

### Kernel

The kernel is everything in the domain that maps to the codomain identity:

```text
ker(f) = {x in G : f(x) = e_H}
```

For the map:

```text
f: Z/12Z -> Z/4Z
f(x) = x mod 4
```

the codomain identity is `0`, and:

```text
ker(f) = {0, 4, 8}
```

The kernel measures collapse. If the kernel contains more than the identity, multiple domain elements become indistinguishable after the map.

### Image

The image is the set of codomain values actually reached:

```text
im(f) = {f(x) : x in G}
```

For `f: Z/12Z -> Z/4Z` by reduction modulo `4`:

```text
im(f) = {0, 1, 2, 3}
```

The map is surjective because the image is the whole codomain.

For a doubling map:

```text
f: Z/6Z -> Z/6Z
f(x) = 2x mod 6
```

the image is:

```text
{0, 2, 4}
```

It lands in a proper subgroup. That is not a failure by itself, but it is a dangerous thing to forget.

### Isomorphism

An isomorphism is a bijective homomorphism. It preserves the operation and pairs every domain element with exactly one codomain element.

If two groups are isomorphic, they have the same group structure under different labels.

Example:

```text
Z/4Z under addition

0 -> 0
1 -> 2
2 -> 4
3 -> 6

{0, 2, 4, 6} inside Z/8Z under addition
```

The map `x -> 2x mod 8` preserves addition and is a bijection onto the subgroup `{0, 2, 4, 6}`.

### First isomorphism theorem, finite-size version

For a finite homomorphism:

```text
|domain| = |kernel| * |image|
```

The kernel tells you how many domain elements collapse into each reached output. The image tells you how many outputs are reached.

For `Z/12Z -> Z/4Z`:

```text
|domain| = 12
|kernel| = 3
|image| = 4

12 = 3 * 4
```

This is the same tiling idea as cosets, now viewed through a map.

## Build It

This lesson builds a finite-group homomorphism inspector:

- test operation preservation
- compute a mapping table
- compute kernel and image
- distinguish injective, surjective, and isomorphic maps
- check the finite first-isomorphism size relation
- verify that homomorphisms preserve repeated operations

### Step 1: Keep finite group helpers

Use the same finite-group helpers from the earlier lessons:

```python
from math import gcd


def add_mod(a: int, b: int, n: int) -> int:
    if n <= 0:
        raise ValueError("modulus must be positive")
    return (a + b) % n


def mul_mod(a: int, b: int, n: int) -> int:
    if n <= 0:
        raise ValueError("modulus must be positive")
    return (a * b) % n


def residues_mod(n: int) -> list[int]:
    if n <= 0:
        raise ValueError("modulus must be positive")
    return list(range(n))


def units_mod(n: int) -> list[int]:
    if n <= 0:
        raise ValueError("modulus must be positive")
    return [a for a in range(n) if gcd(a, n) == 1]
```

These give you concrete domain and codomain groups for small tests.

### Step 2: Test operation preservation

A homomorphism must map into the codomain and preserve the operation:

```python
def is_homomorphism(
    domain_elements,
    codomain_elements,
    domain_operation,
    codomain_operation,
    mapping,
):
    if not is_group(domain_elements, domain_operation):
        return False
    if not is_group(codomain_elements, codomain_operation):
        return False

    codomain_set = set(codomain_elements)
    for element in domain_elements:
        if mapping(element) not in codomain_set:
            return False

    return all(
        mapping(domain_operation(a, b)) == codomain_operation(mapping(a), mapping(b))
        for a in domain_elements
        for b in domain_elements
    )
```

Example:

```python
z12 = residues_mod(12)
z4 = residues_mod(4)
z12_add = lambda a, b: add_mod(a, b, 12)
z4_add = lambda a, b: add_mod(a, b, 4)

assert is_homomorphism(z12, z4, z12_add, z4_add, lambda x: x % 4)
```

Reduction from `Z/12Z` to `Z/5Z` is not a homomorphism:

```text
11 + 1 = 0 in Z/12Z
f(11 + 1) = f(0) = 0

f(11) + f(1) = 1 + 1 = 2 in Z/5Z
```

The operation is not preserved.

### Step 3: Compute kernel and image

The kernel maps to the codomain identity:

```python
def kernel(domain_elements, codomain_elements, domain_operation, codomain_operation, mapping):
    if not is_homomorphism(
        domain_elements,
        codomain_elements,
        domain_operation,
        codomain_operation,
        mapping,
    ):
        raise ValueError("mapping must be a homomorphism")

    codomain_identity = find_identity(codomain_elements, codomain_operation)
    return [element for element in domain_elements if mapping(element) == codomain_identity]
```

The image is every reachable codomain value:

```python
def image(domain_elements, codomain_elements, domain_operation, codomain_operation, mapping):
    if not is_homomorphism(
        domain_elements,
        codomain_elements,
        domain_operation,
        codomain_operation,
        mapping,
    ):
        raise ValueError("mapping must be a homomorphism")

    return unique_in_order([mapping(element) for element in domain_elements])
```

For `Z/12Z -> Z/4Z`:

```python
assert kernel(z12, z4, z12_add, z4_add, lambda x: x % 4) == [0, 4, 8]
assert image(z12, z4, z12_add, z4_add, lambda x: x % 4) == [0, 1, 2, 3]
```

### Step 4: Classify the map

Injective means no two domain elements collide. Surjective means every codomain element is reached.

```python
def is_injective_homomorphism(domain_elements, codomain_elements, domain_operation, codomain_operation, mapping):
    if not is_homomorphism(
        domain_elements,
        codomain_elements,
        domain_operation,
        codomain_operation,
        mapping,
    ):
        return False

    values = [mapping(element) for element in domain_elements]
    return len(values) == len(set(values))
```

```python
def is_surjective_homomorphism(domain_elements, codomain_elements, domain_operation, codomain_operation, mapping):
    if not is_homomorphism(
        domain_elements,
        codomain_elements,
        domain_operation,
        codomain_operation,
        mapping,
    ):
        return False

    return set(image(
        domain_elements,
        codomain_elements,
        domain_operation,
        codomain_operation,
        mapping,
    )) == set(codomain_elements)
```

An isomorphism is both:

```python
def is_isomorphism(domain_elements, codomain_elements, domain_operation, codomain_operation, mapping):
    return is_injective_homomorphism(
        domain_elements,
        codomain_elements,
        domain_operation,
        codomain_operation,
        mapping,
    ) and is_surjective_homomorphism(
        domain_elements,
        codomain_elements,
        domain_operation,
        codomain_operation,
        mapping,
    )
```

The reduction map `Z/12Z -> Z/4Z` is surjective but not injective. The map `Z/4Z -> {0,2,4,6}` by `x -> 2x mod 8` is an isomorphism onto that subgroup.

### Step 5: Check the finite first-isomorphism size relation

For finite homomorphisms:

```python
def first_isomorphism_size_check(
    domain_elements,
    codomain_elements,
    domain_operation,
    codomain_operation,
    mapping,
):
    return len(domain_elements) == len(kernel(
        domain_elements,
        codomain_elements,
        domain_operation,
        codomain_operation,
        mapping,
    )) * len(image(
        domain_elements,
        codomain_elements,
        domain_operation,
        codomain_operation,
        mapping,
    ))
```

This does not prove the theorem for all groups. It is a practical sanity check for tiny finite examples.

### Step 6: Inspect the exponent map

Let `3` generate the subgroup:

```text
<3> = {1, 3, 9, 5, 4} inside (Z/11Z)^*
```

Define:

```text
f: Z/5Z -> <3>
f(k) = 3^k mod 11
```

This is a homomorphism from addition to multiplication:

```text
f(a + b) = 3^(a+b)
         = 3^a * 3^b
         = f(a) * f(b)
```

In this toy group, the map is an isomorphism because the domain is reduced modulo the exact order of `3`, and the codomain is exactly `<3>`.

The inverse direction asks for `k` from `3^k`. In large cryptographic groups, that inverse is the discrete logarithm problem.

Run it:

```
python3 code/main.py
```

## Use It

Real cryptographic libraries do not usually expose a function named `is_homomorphism`. Instead, they encode the intended algebra in types and APIs.

Examples:

- A scalar type represents exponents modulo the subgroup order.
- A group-element type represents points or residues in the intended group.
- Scalar multiplication maps a scalar to repeated group addition.
- Public-key validation checks whether incoming bytes decode to a valid element in the expected subgroup.

The from-scratch code in this lesson exhaustively checks tiny finite groups. Real libraries use mathematical proofs, fixed group parameters, subgroup-safe types, and validation routines instead of table checks.

## Attack It

This is a Learn lesson, not a cryptographic primitive implementation, but the failure mode is still security-shaped.

The dangerous move is treating every homomorphism as if it were an isomorphism.

Suppose a protocol reasons about secrets in `Z/12Z` but publishes only:

```text
f(x) = x mod 4
```

Then:

```text
0, 4, 8   all map to 0
1, 5, 9   all map to 1
2, 6, 10  all map to 2
3, 7, 11  all map to 3
```

The public value does not identify the secret. It identifies a coset of the kernel. If the proof assumes uniqueness, it is wrong.

For exponent maps, the kernel tells you the period:

```text
g^x = g^(x + ord(g))
```

So exponents are only represented modulo the order of `g`. If `g` has small order, public values reveal the secret modulo a small number. That is the same small-subgroup problem from the previous lesson seen through the homomorphism lens.

## Ship It

This lesson ships a review checklist:

```text
outputs/skill-homomorphism-map-review.md
```

Use it when a protocol maps between algebraic objects and the code or proof depends on kernel, image, or isomorphism assumptions.

## Exercises

1. Easy: For `f: Z/10Z -> Z/5Z` by `f(x) = x mod 5`, compute the kernel and image by hand.
2. Medium: Test whether `f: Z/8Z -> Z/8Z` by `f(x) = 3x mod 8` is an isomorphism.
3. Hard: Pick a generator of a subgroup of `(Z/17Z)^*`, build the exponent map from `Z/qZ`, and identify exactly when it becomes an isomorphism.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| Homomorphism | A map between groups | A function preserving the group operation |
| Kernel | Things that disappear | Domain elements that map to the codomain identity |
| Image | Outputs of the map | Codomain elements actually reached |
| Injective | No collisions | Distinct domain elements have distinct outputs |
| Surjective | Hits everything | The image equals the full codomain |
| Isomorphism | Same group | A bijective homomorphism, so structure is preserved exactly |
| First isomorphism theorem | Kernel times image | For finite groups, `|G| = |ker f| * |im f|` |

## Test Vectors

Source: project-internal finite group examples cross-checked by direct modular arithmetic over `Z/nZ` and generated subgroups of `(Z/nZ)^*`. The kernel/image size relation follows the finite first isomorphism theorem.

Run:

```bash
python phases/02-abstract-algebra/04-homomorphisms/tests/test_vectors.py
```

## Further Reading

- [Dummit and Foote, Abstract Algebra](https://www.wiley.com/en-us/Abstract+Algebra%2C+3rd+Edition-p-9780471433347) — standard reference for homomorphisms, kernels, quotient groups, and isomorphism theorems.
- [A Computational Introduction to Number Theory and Algebra](https://shoup.net/ntb/) — free text connecting algebraic structure to computational number theory.
- [Handbook of Applied Cryptography, Chapter 2](https://cacr.uwaterloo.ca/hac/about/chap2.pdf) — background on finite fields, groups, and number-theoretic structures used in cryptography.
