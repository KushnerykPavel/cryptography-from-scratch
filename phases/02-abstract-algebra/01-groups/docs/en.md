# Groups — Definition, Examples, Order

> A group is the smallest algebraic machine where you can combine, undo, and repeat without leaving the world you started in.

**Type:** Learn
**Languages:** Python
**Prerequisites:** 01-number-theory/02-gcd-bezout-eea, 01-number-theory/03-modular-inverse-and-fast-exp
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain the four group axioms (closure, associativity, identity, inverses) and why each is necessary for cryptographic groups
- Identify valid groups by constructing Cayley tables for additive and multiplicative residue groups
- Compute the order of a group element by counting repeated applications of the operation until returning to the identity
- Distinguish between the full residue set and the units-only subset and explain why multiplication requires the latter
- Apply the element-order concept to recognize why small-order generators create exploitable cycles in cryptographic protocols

## The Problem

Cryptography keeps asking the same question in different costumes:

```text
If I repeat this operation many times, can someone undo it without knowing my shortcut?
```

RSA repeats multiplication modulo `n`. Diffie-Hellman repeats multiplication modulo a prime. Elliptic-curve cryptography repeats point addition. Zero-knowledge systems talk about constraints over fields, but the protocol language still depends on operations that compose cleanly and have inverses.

Without the group lens, these examples look unrelated. With it, you can ask precise questions:

- What are the valid elements?
- What operation combines two elements?
- Does the result stay valid?
- Is there a do-nothing element?
- Can every move be undone?
- What happens when one element is repeated?

Those are not abstract niceties. A protocol that accidentally uses a non-group can leak information, reject valid values, accept invalid ones, or make a "hard problem" easy because the operation has unexpected structure.

## The Concept

A group is a set plus one operation. Write the operation as `*`.

The pair `(G, *)` is a group when four rules hold:

| Rule | Meaning | Example failure |
|------|---------|-----------------|
| Closure | `a * b` stays inside `G` | multiply two residues, get something outside the chosen set |
| Associativity | `(a * b) * c = a * (b * c)` | regrouping repeated operations changes the result |
| Identity | some `e` satisfies `e * a = a * e = a` | no do-nothing element exists |
| Inverses | every `a` has `a^-1` with `a * a^-1 = e` | a move cannot be undone |

The operation does not have to be ordinary multiplication. It can be addition, multiplication, function composition, matrix multiplication, permutation composition, or elliptic-curve point addition.

### Example 1: integers mod n under addition

For `Z/5Z`, the elements are:

```text
0, 1, 2, 3, 4
```

The operation is addition modulo `5`:

```text
3 + 4 = 7 ≡ 2 (mod 5)
```

Cayley tables make the whole operation visible:

```text
  + | 0 1 2 3 4
 ---+----------
  0 | 0 1 2 3 4
  1 | 1 2 3 4 0
  2 | 2 3 4 0 1
  3 | 3 4 0 1 2
  4 | 4 0 1 2 3
```

This is a group:

- closure: every cell is still one of `0..4`
- associativity: inherited from integer addition
- identity: `0`
- inverse of `a`: `-a mod 5`

The group order is the number of elements. So `|Z/5Z| = 5`.

### Example 2: units mod n under multiplication

Multiplication modulo `n` is trickier. The full set `Z/8Z = {0,1,2,3,4,5,6,7}` is not a group under multiplication because most elements have no inverse. For example, no residue `x` satisfies:

```text
2*x ≡ 1 (mod 8)
```

But the invertible residues do form a group:

```text
(Z/8Z)^* = {1, 3, 5, 7}
```

Each element is coprime to `8`, and multiplication modulo `8` keeps you inside that set:

```text
  * | 1 3 5 7
 ---+--------
  1 | 1 3 5 7
  3 | 3 1 7 5
  5 | 5 7 1 3
  7 | 7 5 3 1
```

This exact idea powers a lot of number-theoretic cryptography. When a lesson says "work in the multiplicative group modulo p", it means "use the nonzero residues modulo prime `p` under multiplication." For prime `p`, every nonzero residue is invertible.

### Element order

The order of a group is its size. The order of an element is how many repeats return to the identity.

In `Z/6Z` under addition:

```text
2
2 + 2 = 4
2 + 2 + 2 = 0
```

So the element `2` has order `3`. The element `5` has order `6`:

```text
5, 4, 3, 2, 1, 0
```

Element order matters because repeated operations are the heartbeat of public-key crypto:

```text
g, g^2, g^3, ..., g^x
```

If the order is small, an attacker can brute-force the cycle. If a protocol expects a large prime-order group but accepts points from a small subgroup, the secret can leak a few bits at a time.

## Build It

This is a Learn lesson, so the code is a verifier and playground rather than a new cryptographic primitive. It lets you inspect finite groups by checking the four axioms.

### Step 1: Define modular operations

Start with the two operations that will appear constantly in this course:

```python
def add_mod(a: int, b: int, n: int) -> int:
    if n <= 0:
        raise ValueError("modulus must be positive")
    return (a + b) % n


def mul_mod(a: int, b: int, n: int) -> int:
    if n <= 0:
        raise ValueError("modulus must be positive")
    return (a * b) % n
```

The element sets are different:

```python
from math import gcd


def residues_mod(n: int) -> list[int]:
    if n <= 0:
        raise ValueError("modulus must be positive")
    return list(range(n))


def units_mod(n: int) -> list[int]:
    if n <= 0:
        raise ValueError("modulus must be positive")
    return [a for a in range(n) if gcd(a, n) == 1]
```

Use all residues for addition. Use only coprime residues for multiplication.

### Step 2: Build a Cayley table

A Cayley table is a finite operation written out completely:

```python
def cayley_table(elements, operation):
    return [[operation(a, b) for b in elements] for a in elements]
```

For `Z/4Z` under addition:

```python
elements = residues_mod(4)
table = cayley_table(elements, lambda a, b: add_mod(a, b, 4))
assert table == [
    [0, 1, 2, 3],
    [1, 2, 3, 0],
    [2, 3, 0, 1],
    [3, 0, 1, 2],
]
```

This table is small enough to read. Later groups are too large to print, but the same logic still applies.

### Step 3: Check the axioms

Closure checks whether every result stays inside the set:

```python
def is_closed(elements, operation):
    element_set = set(elements)
    return all(operation(a, b) in element_set for a in elements for b in elements)
```

Associativity checks every triple:

```python
def is_associative(elements, operation):
    return all(
        operation(operation(a, b), c) == operation(a, operation(b, c))
        for a in elements
        for b in elements
        for c in elements
    )
```

For real cryptographic groups, you do not prove associativity by testing a table. You prove it from the construction. For this lesson, exhaustive checking is useful because it makes the axiom concrete.

### Step 4: Find identity and inverses

The identity works from both sides:

```python
def find_identity(elements, operation):
    for candidate in elements:
        if all(
            operation(candidate, x) == x and operation(x, candidate) == x
            for x in elements
        ):
            return candidate
    return None
```

An inverse also works from both sides:

```python
def inverse_of(element, elements, operation):
    identity = find_identity(elements, operation)
    if identity is None:
        return None

    for candidate in elements:
        if (
            operation(element, candidate) == identity
            and operation(candidate, element) == identity
        ):
            return candidate
    return None
```

For addition mod `7`, the inverse of `4` is `3`. For multiplication mod `10`, the inverse of `3` is `7`.

### Step 5: Measure element order

Once the group rules hold, repeat an element until you return to the identity:

```python
def element_order(element, elements, operation):
    if not is_group(elements, operation):
        raise ValueError("elements and operation must form a group")

    identity = find_identity(elements, operation)
    current = element

    for order in range(1, len(elements) + 1):
        if current == identity:
            return order
        current = operation(current, element)

    raise ValueError("element order not found")
```

Example:

```python
elements = residues_mod(6)
op = lambda a, b: add_mod(a, b, 6)

assert element_order(2, elements, op) == 3
assert element_order(5, elements, op) == 6
```

That second element is special: repeating `5` reaches every element of `Z/6Z`. The next lesson names this idea: a cyclic group generated by one element.

Run it:

```
python3 code/main.py
```

## Use It

Most production crypto libraries do not expose "group checker" APIs because their groups are fixed, audited, and represented by specialized types.

For example:

- RSA libraries use arithmetic in unit groups modulo primes and composites.
- Diffie-Hellman libraries use a carefully chosen subgroup of `(Z/pZ)^*`.
- Elliptic-curve libraries expose point addition and scalar multiplication, but hide most raw group mechanics behind validated point types.

The important production habit is not to rebuild group law code. It is to know what assumptions the library is enforcing:

```text
Are inputs checked?
Is the identity represented safely?
Are invalid elements rejected?
Is the subgroup order what the protocol expects?
```

Our code is a microscope for small examples. Real libraries are hardened machinery.

## Attack It

This lesson does not implement a cryptographic primitive, but group mistakes become attacks very quickly.

### Invalid-group thinking

Suppose a protocol says "multiply modulo `n`" but lets users submit any residue in `Z/nZ`. If the protocol needs inverses, that is wrong: only units are invertible. The value `2 mod 8` is a valid residue, but it is not a valid group element for multiplication.

That kind of mismatch leads to rejected transcripts at best and exploitable structure at worst.

### Small-subgroup leakage

If a protocol expects operations in a large group but accepts elements from a tiny subgroup, repeated operations cycle through only a few values. An attacker can send small-order elements and learn constraints on a secret exponent.

The defense is structural:

- validate elements before using them
- work in the intended subgroup
- clear cofactors when the curve/protocol requires it
- reject the identity when the protocol says it is not a valid public key

Crypto engineering starts with algebraic hygiene.

## Ship It

This lesson ships `outputs/skill-group-law-checklist.md`, a reusable checklist for later lessons. Use it whenever a proof, primitive, or protocol says "let G be a group" and then quietly relies on that sentence.

The checklist asks you to identify the set, operation, identity, inverses, order, and subgroup assumptions before trusting the construction.

## Exercises

1. **Easy.** Use `group_report` on `Z/9Z` under addition. What is the order of element `3`?
2. **Medium.** Compute `(Z/12Z)^*` with `units_mod(12)`, build its Cayley table, and list every inverse.
3. **Hard.** Create a small operation table that has closure and an identity but fails associativity. Use `is_group` to reject it.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|------------------------|
| Group | "A set with an operation" | A set and operation satisfying closure, associativity, identity, and inverses |
| Operation | "The multiplication" | The rule for combining two elements; it may be addition, multiplication, composition, or point addition |
| Identity | "Zero or one" | The element that leaves every element unchanged under the group operation |
| Inverse | "Undo button" | The element that combines with `a` to produce the identity |
| Group order | "The size" | The number of elements in the group |
| Element order | "Cycle length" | The number of repeats needed for one element to return to the identity |
| Unit | "Invertible residue" | A residue coprime to `n`, invertible under multiplication modulo `n` |
| Cayley table | "Multiplication table" | A complete finite table of the group operation |

## Test Vectors

Source: project-internal finite group examples cross-checked by direct Cayley table arithmetic; examples match standard `Z/nZ` additive groups and unit groups `(Z/nZ)^*`.

Run:

```bash
python phases/02-abstract-algebra/01-groups/tests/test_vectors.py
```

## Further Reading

- [Handbook of Applied Cryptography, Chapter 2](https://cacr.uwaterloo.ca/hac/about/toc/toc2.html) — modular arithmetic background used throughout public-key cryptography
- [A Computational Introduction to Number Theory and Algebra](https://shoup.net/ntb/) — clear treatment of groups, rings, and finite fields for cryptographic math
