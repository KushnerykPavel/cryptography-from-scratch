# SVP and CVP — The Hard Problems

> SVP and CVP are “find the closest lattice point” problems — easy in tiny dimensions, brutally hard in high dimensions.

**Type:** Learn
**Languages:** Python
**Prerequisites:** `04-lattices/01-what-is-a-lattice` (definition), `04-lattices/02-bases-determinant-minima` (λ1 intuition)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## The Problem

Lattice cryptography’s security story is basically: “breaking this scheme would let you solve a hard lattice problem.”

That sentence is only helpful if you can answer three questions:

1. What is the *hard lattice problem*, exactly?
2. What does “hard” mean here (hard in *dimension*, hard on *average*, hard *exactly* or *approximately*)?
3. Why do we keep talking about *bases* if the lattice is a set of points?

SVP (Shortest Vector Problem) and CVP (Closest Vector Problem) are the two canonical “hard problems” that show up in reductions, security arguments, and intuition. Even when a scheme is based on LWE, you repeatedly see SVP/CVP in the background through reductions and approximation factors.

## The Concept

We work with a full-rank lattice:

```text
L(B) = { B z : z ∈ Z^n }  ⊂ R^n
```

where `B` is an `n×n` basis matrix (think: basis vectors as columns).

### SVP: find a shortest non-zero lattice vector

**SVP** asks for a non-zero vector in the lattice with minimal norm:

```text
find v ∈ L(B)\{0} minimizing ||v||.
```

If you use Euclidean norm, SVP’s answer length is exactly the first successive minimum:

```text
||v|| = λ1(L).
```

### CVP: find the lattice point closest to a target

**CVP** adds an arbitrary target point `t ∈ R^n` and asks for the closest lattice point:

```text
find v ∈ L(B) minimizing ||v - t||.
```

The value `min_{v∈L} ||v - t||` is the **distance from t to the lattice**.

2D picture (lattice points `•`, target `t`):

```text
    •       •
       •
  •        t      •    <- CVP asks: which • is closest to t?
        •
    •       •
```

### Exact vs approximate

In cryptography you often see *approximate* versions (find a vector within a factor `α` of optimal). Exact SVP/CVP in high dimension is believed to require exponential time (worst case), and even approximation can be hard depending on the approximation factor.

This lesson won’t prove hardness. Instead, it builds the correct mental model:

- SVP/CVP are **geometry problems on a point set** (`L`)
- but you’re given **a basis** (a coordinate system), and in high dimension the basis can “hide” short vectors
- naive brute force explodes as `(2k+1)^n` when you search integer coefficients `z ∈ [-k,k]^n`

That last bullet is the key: dimension is the security knob.

## Build It

Even though this lesson is **Learn**, we’ll build a tiny brute-force microscope for SVP/CVP in very small dimensions. The goal is to make the problems feel concrete and to see the exponential blow-up.

### Step 1: Represent a full-rank integer basis and lattice vectors

```python
Vec = tuple[int, ...]
Basis = tuple[Vec, ...]  # column vectors (b1, ..., bn), each length n

def lattice_vector(basis: Basis, z: Vec) -> Vec:
    # returns v = Σ z_i * b_i
    ...
```

### Step 2: Brute-force SVP in a bounded coefficient window

Search all coefficient vectors `z ∈ [-k,k]^n` (excluding `z=0`), compute `v=Bz`, and keep the smallest `||v||`.

```python
def svp_bruteforce(basis: Basis, coeff_bound: int):
    ...
```

### Step 3: Brute-force CVP in a bounded coefficient window

Search all `z ∈ [-k,k]^n`, compute `v=Bz`, and keep the smallest `||v - t||`.

```python
def cvp_bruteforce(basis: Basis, target: Vec, coeff_bound: int):
    ...
```

### Step 4: See the exponential growth directly

The number of candidates is:

```text
(2k+1)^n
```

That is the “brute force is doomed” message in one line.

## Use It

Real lattice work needs more than brute force:

- **Reduction** (LLL/BKZ) to find “nicer” bases that reveal shorter vectors.
- **Enumeration** algorithms (and heavy pruning) to solve SVP/CVP in small-to-moderate dimensions.

In Python, the practical toolbox is often `fpylll` (wrapping fast C++ implementations). In this curriculum we’ll keep building the core ideas ourselves (LLL, BKZ, Babai, sampling), and you can use `fpylll` later as a sanity check when you explore real parameters.

## Attack It

**Attack the naive approach:** “I’ll just brute-force coefficients `z` and find the answer.”

That works in 2D or 3D, but the work scales as `(2k+1)^n`. Even with a tiny window `k=3`:

- `n=8` gives `7^8 ≈ 5.7M` candidates
- `n=16` gives `7^16 ≈ 3.3e13` candidates

This is why lattice crypto talks about dimensions like `n=256` and `n=1024`: the exponential in `n` is the security engine.

## Ship It

A reusable prompt for checking SVP/CVP mental models lives at `outputs/prompt-svp-cvp-mental-model.md`.

## Exercises

1. Easy: For the 2D basis `B=((2,0),(1,1))`, show that `(1,0)` is **not** in the lattice. (Solve `Bz=(1,0)` over integers.)
2. Medium: Pick a 2D basis and a target `t`. Run brute-force CVP with increasing bounds `k`. When does the answer stop changing?
3. Hard: Construct a basis where one basis vector is very long, but SVP still returns a very short vector. Explain why this does not contradict “basis vectors can be long.”

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| SVP | “find the shortest basis vector” | find the shortest **lattice** vector (basis-independent) |
| CVP | “round to the nearest lattice point” | given `t`, find `v ∈ L` minimizing `||v-t||` |
| exact vs approximate | “close enough” | approximation factor `α`: allow `||v|| ≤ α·OPT` |
| coefficient window | “search z in [-k,k]^n” | a *computational* restriction, not a lattice property |
| distance to lattice | “how far t is from the grid” | `dist(t,L)=min_{v∈L} ||v-t||` |

## Test Vectors

Project-internal SVP/CVP brute-force examples in tiny dimensions, chosen to make ties and edge cases visible.

## Further Reading

- Micciancio, Goldwasser — *Complexity of Lattice Problems* (book) — definitions and hardness landscape.
- Micciancio, Regev — *Lattice-based Cryptography* (survey) — big-picture cryptography framing.
- Nguyen, Vallée (eds.) — *The LLL Algorithm* — what you’ll use next to do better than brute force.
