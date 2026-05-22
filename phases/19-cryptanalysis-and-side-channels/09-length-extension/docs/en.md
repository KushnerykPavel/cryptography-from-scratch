# Length Extension — Secret-Prefix MAC is a Trap (MD4)

> If your MAC is `Hash(key||msg)`, attackers can append data without the key.

**Type:** Build
**Languages:** Python
**Prerequisites:** Hash functions as Merkle–Damgård; padding intuition; bytes/bit lengths
**Time:** ~90 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain why Merkle–Damgård hash constructions support length extension
- Compute MD-style padding for a given message length
- Implement MD4 to expose internal state chaining
- Distinguish secret-prefix MAC from HMAC and why HMAC is safe here
- Apply a length extension attack to forge `MD4(key||msg)` for an extended message

## The Problem

You build an API that authenticates requests with `mac = Hash(key || message)`. The key is secret, so you assume attackers can’t forge MACs.

But Merkle–Damgård hashes (MD5/SHA-1/SHA-256 in classic form) work by iteratively compressing blocks and carrying a chaining state forward. If an attacker knows the final digest of `key||message` and can guess the key length, they can continue hashing additional blocks *from that digest state*.

Result: attackers can forge a valid MAC for `message || glue_padding || suffix` without knowing the key.

## The Concept

Merkle–Damgård hashes compute:

`state_{i+1} = Compress(state_i, block_i)`

The digest is just the final state. If you know the final state for `key||msg`, you can continue compressing more blocks. The only missing piece is correct padding, which depends on the total length of `key||msg`.

So the attacker:

1. Guesses `len(key)`.
2. Computes the glue padding that `key||msg` would have had.
3. Initializes the hash state to the known digest.
4. Hashes `suffix` as if it came after `key||msg||glue_padding`.

## Build It

### Step 1: Implement MD4 and validate a known digest
```python
def md4_pad(message_len_bytes: int) -> bytes:
    bit_len = (message_len_bytes * 8) & 0xFFFFFFFFFFFFFFFF
    pad = b"\x80"
    while ((message_len_bytes + len(pad)) % 64) != 56:
        pad += b"\x00"
    pad += struct.pack("<Q", bit_len)
    return pad


def md4_digest(message: bytes) -> bytes:
    state = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)
    msg = message + md4_pad(len(message))
    for off in range(0, len(msg), 64):
        state = md4_compress(msg[off : off + 64], state)
    return struct.pack("<4I", *state)
```
MD4 is an old Merkle–Damgård hash. Implementing it makes the chaining state explicit, which is the heart of length extension.

### Step 2: Build a secret-prefix MAC (insecure)
```python
def secret_prefix_mac_md4(key: bytes, msg: bytes) -> bytes:
    return md4_digest(key + msg)
```
This looks reasonable, but it’s vulnerable because the attacker can continue hashing from the digest state.

### Step 3: Forge a MAC via length extension
```python
def md4_length_extension_attack(
    mac: bytes, original_msg: bytes, suffix: bytes, key_len_guess: int
) -> Tuple[bytes, bytes]:
    glue = md4_pad(key_len_guess + len(original_msg))
    forged_msg = original_msg + glue + suffix
    state = md4_state_from_digest(mac)
    forged_mac = md4_digest_with_state(
        suffix, state, message_len_so_far=(key_len_guess + len(original_msg) + len(glue))
    )
    return forged_msg, forged_mac
```
The forged MAC is computed without the key, by restarting the hash from the known digest state and using the correct total-length padding.

Run it:
python3 code/main.py

## Use It

- Never use `Hash(key||msg)` as a MAC with Merkle–Damgård hashes.
- Use HMAC (`HMAC(key, msg)`), which is designed to avoid length extension.
- In modern designs, prefer AEADs and standardized authentication mechanisms.

## Pitfalls

- Assuming “hash = MAC” without understanding the construction.
- Forgetting that padding depends on total length (including secret key length).
- Using raw SHA-256/MD5 for request signing without HMAC.
- Leaking or standardizing key lengths that make guessing easier.
- Rolling your own “fix” instead of using HMAC.

## Ship It

Save a checklist for hash/MAC misuse: `outputs/hash-mac-misuse-checklist.md`.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe `forged_mac_ok: True`.
2. Medium. Change the key length guess and show the forgery fails when the guessed length is wrong.
3. Hard. Replace MD4 with a Merkle–Damgård-style toy hash of your own and demonstrate the same attack pattern.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Merkle–Damgård | “iterative hash” | Hash construction that chains a compression function over blocks |
| Glue padding | “the padding bytes” | The padding that would be appended to `key||msg` before hashing |
| Length extension | “append without key” | Ability to compute Hash(key||msg||pad||suffix) from Hash(key||msg) |
| HMAC | “real MAC” | A MAC construction designed to resist length extension for MD hashes |

## Further Reading

- RFC 1320, “The MD4 Message-Digest Algorithm” (1992) — MD4 spec and test vectors
- Krawczyk, Bellare, Canetti, “HMAC: Keyed-Hashing for Message Authentication” — why HMAC avoids these issues
