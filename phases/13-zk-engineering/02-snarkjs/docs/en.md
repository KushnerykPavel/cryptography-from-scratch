# snarkjs — Trusted Setup, Prove, Verify
> Treat Groth16 artifacts like release binaries: validate, cross-check, and hash them.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** `phases/13-zk-engineering/01-circom/`, `phases/12-zk-proof-systems/05-groth16/`  
**Time:** ~60 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** what snarkjs artifacts are (`verification_key.json`, `public.json`, `proof.json`) and what they are *not*.
- **Compute** deterministic SHA-256 hashes for JSON artifacts using canonical JSON encoding.
- **Implement** a stdlib-only validator for snarkjs-style Groth16 artifacts (schema + consistency checks).
- **Distinguish** “cryptographic verification” (pairings) from “pipeline verification” (shape/provenance/consistency).
- **Apply** an artifact audit checklist to avoid real-world integration bugs (wrong key, wrong circuit, wrong ordering).

## The Problem
You get a PR that “just updates ZK artifacts”: a new `verification_key.json`, a new `.zkey`, and new fixtures (`proof.json`, `public.json`). Everything *looks* right, and the team says “snarkjs verify passes locally”.

Then production breaks. Or worse: production “works”, but you are verifying a different statement than you intended because public signals are in a different order, a different circuit build slipped in, or the verifier is accidentally pointed at the wrong curve/key.

This lesson is about ZK **engineering**: treating snarkjs outputs as **supply-chain artifacts** you must sanity-check, pin, and review like binaries. You’ll build a small stdlib-only tool that catches common mismatches *before* you burn time chasing cryptographic failures.

## The Concept
In a typical Circom + snarkjs Groth16 workflow, you end up with a small set of “contractual” artifacts:

| Artifact | What it is | What it’s used for |
|---|---|---|
| `circuit.r1cs` | Constraint system | Proving + key generation input |
| `circuit.wasm` | Witness generator | Turns `input.json` into `witness.wtns` |
| `circuit_final.zkey` | Circuit-specific setup output | Used to generate proofs; contains proving data |
| `verification_key.json` | Verifier parameters | Used by verifiers (backend/on-chain) |
| `public.json` | Public signals (field elements) | Inputs to verification alongside the proof |
| `proof.json` | Groth16 proof points (`pi_a/pi_b/pi_c`) | Proof data verified against vkey + public signals |

Two critical engineering facts:

1. **A Groth16 proof is not “standalone”.** It is tied to a specific circuit and verifying key, and it is validated against an *ordered vector* of public inputs.
2. **Most failures are not “pairing math failures”.** They’re pipeline bugs: wrong `IC` length, wrong `nPublic`, wrong curve, wrong public input order, or mismatched artifact provenance.

So we build:
- a **schema validator** (is this even shaped like snarkjs outputs?), and
- a **consistency checker** (do these three files match each other?), and
- a **reproducible hasher** (can we pin exact artifact bytes in reviews/releases?).

## Build It

### Step 1: Canonical JSON + SHA-256
We need a deterministic way to hash JSON artifacts. If two files contain the same data but different key ordering/whitespace, we still want the *same* digest.

```python
def canonical_json_dumps(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_json(obj: Any) -> str:
    return sha256_hex(canonical_json_dumps(obj).encode("utf-8"))
```

### Step 2: Validate decimal strings + points
snarkjs-style JSON encodes field elements and curve points as **decimal strings**. We’ll validate them structurally (digits, expected lengths) without doing elliptic-curve math.

```python
def parse_nonneg_decimal_str(value: Any, *, field: str) -> int:
    if not isinstance(value, str):
        raise TypeError(f"{field}: expected str, got {type(value).__name__}")
    if value == "":
        raise ValueError(f"{field}: empty string")
    if value.startswith("-"):
        raise ValueError(f"{field}: expected non-negative decimal string, got {value!r}")
    if not value.isdigit():
        raise ValueError(f"{field}: expected decimal string, got {value!r}")
    return int(value)


def normalize_g1_point(value: Any, *, field: str) -> Tuple[str, str]:
    if not isinstance(value, (list, tuple)):
        raise TypeError(f"{field}: expected list/tuple, got {type(value).__name__}")
    if len(value) not in (2, 3):
        raise ValueError(f"{field}: expected length 2 or 3, got {len(value)}")
    x = value[0]
    y = value[1]
    parse_nonneg_decimal_str(x, field=f"{field}[0]")
    parse_nonneg_decimal_str(y, field=f"{field}[1]")
    return (x, y)


def normalize_g2_point(value: Any, *, field: str) -> Tuple[Tuple[str, str], Tuple[str, str]]:
    if not isinstance(value, (list, tuple)):
        raise TypeError(f"{field}: expected list/tuple, got {type(value).__name__}")
    if len(value) not in (2, 3):
        raise ValueError(f"{field}: expected 2 or 3 rows, got {len(value)}")

    row0 = value[0]
    row1 = value[1]
    if not isinstance(row0, (list, tuple)) or not isinstance(row1, (list, tuple)):
        raise TypeError(f"{field}: expected row lists")
    if len(row0) != 2 or len(row1) != 2:
        raise ValueError(f"{field}: expected each row length=2")

    x0, x1 = row0[0], row0[1]
    y0, y1 = row1[0], row1[1]
    parse_nonneg_decimal_str(x0, field=f"{field}[0][0]")
    parse_nonneg_decimal_str(x1, field=f"{field}[0][1]")
    parse_nonneg_decimal_str(y0, field=f"{field}[1][0]")
    parse_nonneg_decimal_str(y1, field=f"{field}[1][1]")
    return ((x0, x1), (y0, y1))


def validate_public_signals(value: Any) -> List[str]:
    if not isinstance(value, list):
        raise TypeError(f"public_signals: expected list, got {type(value).__name__}")
    out: List[str] = []
    for i, s in enumerate(value):
        parse_nonneg_decimal_str(s, field=f"public_signals[{i}]")
        out.append(s)
    return out
```

### Step 3: Validate and cross-check Groth16 artifacts
Now we parse the three files into typed objects and enforce the most important consistency rule:

`len(IC) == len(public_signals) + 1` and `nPublic == len(public_signals)`.

```python
@dataclass(frozen=True)
class ProofJson:
    protocol: str
    curve: str
    pi_a: Tuple[str, str]
    pi_b: Tuple[Tuple[str, str], Tuple[str, str]]
    pi_c: Tuple[str, str]

    def as_jsonable(self) -> Dict[str, Any]:
        return {
            "protocol": self.protocol,
            "curve": self.curve,
            "pi_a": [self.pi_a[0], self.pi_a[1], "1"],
            "pi_b": [[self.pi_b[0][0], self.pi_b[0][1]], [self.pi_b[1][0], self.pi_b[1][1]], ["1", "0"]],
            "pi_c": [self.pi_c[0], self.pi_c[1], "1"],
        }


def validate_proof_json(value: Any) -> ProofJson:
    if not isinstance(value, Mapping):
        raise TypeError(f"proof: expected object, got {type(value).__name__}")

    protocol = value.get("protocol")
    curve = value.get("curve")
    if not isinstance(protocol, str) or protocol == "":
        raise ValueError("proof.protocol: expected non-empty string")
    if not isinstance(curve, str) or curve == "":
        raise ValueError("proof.curve: expected non-empty string")

    pi_a = normalize_g1_point(value.get("pi_a"), field="proof.pi_a")
    pi_b = normalize_g2_point(value.get("pi_b"), field="proof.pi_b")
    pi_c = normalize_g1_point(value.get("pi_c"), field="proof.pi_c")

    return ProofJson(protocol=protocol, curve=curve, pi_a=pi_a, pi_b=pi_b, pi_c=pi_c)


@dataclass(frozen=True)
class VerificationKeyJson:
    protocol: str
    curve: str
    n_public: int
    vk_alpha_1: Tuple[str, str]
    vk_beta_2: Tuple[Tuple[str, str], Tuple[str, str]]
    vk_gamma_2: Tuple[Tuple[str, str], Tuple[str, str]]
    vk_delta_2: Tuple[Tuple[str, str], Tuple[str, str]]
    ic: List[Tuple[str, str]]

    def as_jsonable(self) -> Dict[str, Any]:
        return {
            "protocol": self.protocol,
            "curve": self.curve,
            "nPublic": self.n_public,
            "vk_alpha_1": [self.vk_alpha_1[0], self.vk_alpha_1[1]],
            "vk_beta_2": [[self.vk_beta_2[0][0], self.vk_beta_2[0][1]], [self.vk_beta_2[1][0], self.vk_beta_2[1][1]]],
            "vk_gamma_2": [[self.vk_gamma_2[0][0], self.vk_gamma_2[0][1]], [self.vk_gamma_2[1][0], self.vk_gamma_2[1][1]]],
            "vk_delta_2": [[self.vk_delta_2[0][0], self.vk_delta_2[0][1]], [self.vk_delta_2[1][0], self.vk_delta_2[1][1]]],
            "IC": [[x, y] for (x, y) in self.ic],
        }


def validate_verification_key_json(value: Any) -> VerificationKeyJson:
    if not isinstance(value, Mapping):
        raise TypeError(f"verification_key: expected object, got {type(value).__name__}")

    protocol = value.get("protocol")
    curve = value.get("curve")
    if not isinstance(protocol, str) or protocol == "":
        raise ValueError("verification_key.protocol: expected non-empty string")
    if not isinstance(curve, str) or curve == "":
        raise ValueError("verification_key.curve: expected non-empty string")

    n_public_raw = None
    if "nPublic" in value:
        n_public_raw = value.get("nPublic")
    elif "n_public" in value:
        n_public_raw = value.get("n_public")
    elif "n_public_inputs" in value:
        n_public_raw = value.get("n_public_inputs")
    elif "nPublicInputs" in value:
        n_public_raw = value.get("nPublicInputs")

    if not isinstance(n_public_raw, int) or n_public_raw < 0:
        raise ValueError("verification_key.nPublic: expected non-negative int")
    n_public = n_public_raw

    alpha_1 = normalize_g1_point(value.get("vk_alpha_1"), field="verification_key.vk_alpha_1")
    beta_2 = normalize_g2_point(value.get("vk_beta_2"), field="verification_key.vk_beta_2")
    gamma_2 = normalize_g2_point(value.get("vk_gamma_2"), field="verification_key.vk_gamma_2")
    delta_2 = normalize_g2_point(value.get("vk_delta_2"), field="verification_key.vk_delta_2")

    ic_raw = value.get("IC")
    if not isinstance(ic_raw, list):
        raise TypeError(f"verification_key.IC: expected list, got {type(ic_raw).__name__}")
    ic: List[Tuple[str, str]] = []
    for i, p in enumerate(ic_raw):
        ic.append(normalize_g1_point(p, field=f"verification_key.IC[{i}]"))

    return VerificationKeyJson(
        protocol=protocol,
        curve=curve,
        n_public=n_public,
        vk_alpha_1=alpha_1,
        vk_beta_2=beta_2,
        vk_gamma_2=gamma_2,
        vk_delta_2=delta_2,
        ic=ic,
    )


@dataclass(frozen=True)
class Groth16Bundle:
    verification_key: VerificationKeyJson
    public_signals: List[str]
    proof: ProofJson


def validate_groth16_bundle(*, verification_key: Any, public_signals: Any, proof: Any) -> Groth16Bundle:
    vk = validate_verification_key_json(verification_key)
    pub = validate_public_signals(public_signals)
    prf = validate_proof_json(proof)

    if vk.protocol != "groth16":
        raise ValueError(f"verification_key.protocol: expected 'groth16', got {vk.protocol!r}")
    if prf.protocol != "groth16":
        raise ValueError(f"proof.protocol: expected 'groth16', got {prf.protocol!r}")
    if vk.curve != prf.curve:
        raise ValueError(f"curve mismatch: vk.curve={vk.curve!r} proof.curve={prf.curve!r}")

    if vk.n_public != len(pub):
        raise ValueError(f"nPublic mismatch: vk.nPublic={vk.n_public} public_signals={len(pub)}")
    if len(vk.ic) != len(pub) + 1:
        raise ValueError(f"IC length mismatch: len(IC)={len(vk.ic)} expected={len(pub) + 1}")

    return Groth16Bundle(verification_key=vk, public_signals=pub, proof=prf)
```

### Step 4: Build a manifest you can pin in reviews/releases
Finally we create a small “bundle manifest” with deterministic hashes you can attach to releases, PRs, or CI logs.

```python
def build_bundle_manifest(bundle: Groth16Bundle) -> Dict[str, Any]:
    vk_json = bundle.verification_key.as_jsonable()
    proof_json = bundle.proof.as_jsonable()
    public_json = list(bundle.public_signals)

    return {
        "kind": "snarkjs.groth16.bundle",
        "version": 1,
        "protocol": bundle.verification_key.protocol,
        "curve": bundle.verification_key.curve,
        "n_public": bundle.verification_key.n_public,
        "checks": {
            "ic_len_ok": len(bundle.verification_key.ic) == len(bundle.public_signals) + 1,
            "protocol_ok": bundle.verification_key.protocol == "groth16" and bundle.proof.protocol == "groth16",
            "curve_match": bundle.verification_key.curve == bundle.proof.curve,
        },
        "sha256": {
            "verification_key_json": sha256_json(vk_json),
            "proof_json": sha256_json(proof_json),
            "public_json": sha256_json(public_json),
        },
    }
```

Run it:

```bash
python3 code/main.py
```

## Use It
snarkjs is a JavaScript/WASM toolchain commonly used with Circom. Typical CLI steps (Groth16) look like:

- Compile circuit: `circom circuit.circom --r1cs --wasm --sym`
- Trusted setup (high-level): produce `circuit_final.zkey` (often via Powers of Tau + phase 2)
- Export verifying key: `snarkjs zkey export verificationkey circuit_final.zkey verification_key.json`
- Create proof: `snarkjs groth16 prove circuit_final.zkey witness.wtns proof.json public.json`
- Verify proof: `snarkjs groth16 verify verification_key.json public.json proof.json`

Production equivalents / adjacent tooling:
- On-chain verifiers: snarkjs can export Solidity verifiers; other ecosystems use arkworks/gnark/halo2 tooling.
- Alternative formats: many libraries can import/export snarkjs-compatible JSON for interoperability.

## Pitfalls
1. **IC off-by-one bugs:** forgetting that `len(IC) == nPublic + 1` (constant slot) breaks verification and reviews.
2. **Public signal ordering drift:** prover and verifier disagree about ordering, so you “verify” the wrong semantics.
3. **Curve naming confusion:** BN254 is often labeled `bn128`; mixing BN254 vs BLS12-381 artifacts is fatal.
4. **Unpinned artifact provenance:** regenerating `.zkey`/vkeys without checksums causes silent mismatches across environments.
5. **Skipping cheap checks:** teams jump straight to cryptographic verification without validating lengths/fields first, wasting time.

## Ship It
Keep and reuse: `outputs/snarkjs-artifact-audit-checklist.md`.

Use it when:
- reviewing PRs that update ZK artifacts,
- preparing releases that ship vkeys/proofs,
- debugging “it works on my machine” verification failures.

## Exercises
1. Easy: Run `python3 code/main.py`. Observe the three deterministic SHA-256 hashes and the manifest JSON.
2. Medium: Edit the demo data in `code/main.py` so `nPublic` and `public.json` mismatch. Confirm the validator fails with a clear error.
3. Hard: Integrate the validator into your CI: load real `verification_key.json`, `public.json`, `proof.json` fixtures from a build step and fail the job if the manifest checks fail.

## Key Terms
| Term | What people say | What it actually means |
|---|---|---|
| Trusted setup | “ceremony” | Generating parameters a prover/verifier will trust; for Groth16, circuit-specific `.zkey` is derived from it. |
| `verification_key.json` | “the vkey” | Public parameters used by verifiers; includes `IC` points and curve/protocol metadata. |
| `public.json` | “public inputs” | Ordered list of field elements that the verifier binds into the statement. |
| `proof.json` | “the proof” | Three proof points (`pi_a/pi_b/pi_c`) verified against the vkey and public signals. |
| `IC` | “input commitment points” | Points used to combine public inputs into `vk_x = IC[0] + Σ input[i]·IC[i+1]`. |

## Further Reading
- Bellés-Muñoz et al., *CIRCOM: A Robust and Scalable Language for Building Complex Zero-Knowledge Circuits* (2022) — how Circom compiles programs to R1CS and fits into a snarkjs pipeline.
- Iden3 contributors, *snarkjs* (2018) — reference implementation + CLI commands for Groth16 proving/verification and trusted setup tooling.
- arkworks-rs contributors, *ark-snarkjs* (n.d.) — snarkjs-compatible JSON shapes for proofs and verifying keys (handy for interoperability across toolchains).
