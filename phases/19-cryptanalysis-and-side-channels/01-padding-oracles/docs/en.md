# Padding Oracle Attacks — CBC

> A one-bit “valid padding?” oracle can decrypt your ciphertexts.

**Type:** Build
**Languages:** Python
**Prerequisites:** CBC mode + PKCS#7 padding basics; “don’t roll your own crypto” mindset
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain why a padding-validity oracle breaks CBC confidentiality
- Compute PKCS#7 padding and validate it strictly
- Implement CBC encryption/decryption over a reversible toy block cipher
- Distinguish “decryption oracle” from “padding oracle” and why both are dangerous
- Apply a classic byte-at-a-time padding-oracle attack to recover plaintext

## The Problem

You ship an API that decrypts an encrypted cookie. The server returns `200 OK` if the cookie parses and `400 Bad Request` if padding is invalid. You never return the plaintext. You never return the key. You think you’re safe.

An attacker can still send chosen ciphertexts and observe the one-bit signal: “padding valid?” Over many queries, that signal becomes enough to recover the plaintext of captured ciphertexts (and sometimes forge valid cookies) without ever learning the key.

Padding oracles show up in real systems because the leak is rarely obvious: different error messages, different HTTP status codes, different response lengths, or just different timing between the padding failure path and the “MAC failed” path.

## The Concept

CBC decryption for one block is:

`P_i = D_K(C_i) XOR C_{i-1}` (with `C_0 = IV`).

If you can influence `C_{i-1}` (the previous ciphertext block / IV), you can flip bits in `P_i`. PKCS#7 padding gives you a structured target: the last byte should be `0x01`, or the last two bytes should be `0x02 0x02`, etc.

So you do this:

1. Keep `C_i` fixed (the block you want to decrypt).
2. Modify `C_{i-1}` (or IV) to force the last byte of `P_i` to be `0x01`.
3. When the oracle says “valid padding”, you’ve learned one byte of `D_K(C_i)` and therefore one byte of `P_i`.
4. Repeat, moving left across the block and increasing the padding length.

This works even though the attacker never learns `D_K` directly: the oracle turns padding validity into information about intermediate values.

## Build It

### Step 1: PKCS#7 padding
```python
def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if block_size <= 0 or block_size > 255:
        raise ValueError("invalid block_size")
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(padded: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if block_size <= 0 or block_size > 255:
        raise ValueError("invalid block_size")
    if not padded or (len(padded) % block_size) != 0:
        raise ValueError("invalid padded length")
    pad_len = padded[-1]
    if pad_len == 0 or pad_len > block_size:
        raise ValueError("invalid padding")
    if padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("invalid padding")
    return padded[:-pad_len]
```
PKCS#7 padding makes plaintext block-aligned by appending `N` bytes of value `N`. Strict unpadding is critical: “almost valid” padding must be rejected, or your API’s behavior becomes attacker-controlled.

### Step 2: A reversible toy block cipher
```python
def toy_cipher_encrypt_block(key: bytes, block: bytes, rounds: int = 6) -> bytes:
    if len(key) != 16:
        raise ValueError("toy cipher expects 16-byte key")
    if len(block) != 16:
        raise ValueError("toy cipher expects 16-byte block")
    left, right = block[:8], block[8:]
    for r in range(rounds):
        f = _toy_round_f(key, r, right)
        left, right = right, xor_bytes(left, f)
    return left + right


def toy_cipher_decrypt_block(key: bytes, block: bytes, rounds: int = 6) -> bytes:
    if len(key) != 16:
        raise ValueError("toy cipher expects 16-byte key")
    if len(block) != 16:
        raise ValueError("toy cipher expects 16-byte block")
    left, right = block[:8], block[8:]
    for r in reversed(range(rounds)):
        prev_right = left
        f = _toy_round_f(key, r, prev_right)
        prev_left = xor_bytes(right, f)
        left, right = prev_left, prev_right
    return left + right
```
We need a reversible block function to demonstrate CBC. This is a small Feistel network using HMAC-SHA256 as a round function. It is not meant to be secure; it is meant to be deterministic, reversible, and stdlib-only.

### Step 3: CBC mode
```python
def cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be 16 bytes")
    padded = pkcs7_pad(plaintext, BLOCK_SIZE)
    out = bytearray()
    prev = iv
    for off in range(0, len(padded), BLOCK_SIZE):
        block = padded[off : off + BLOCK_SIZE]
        x = xor_bytes(block, prev)
        c = toy_cipher_encrypt_block(key, x)
        out += c
        prev = c
    return bytes(out)


def cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be 16 bytes")
    if (len(ciphertext) % BLOCK_SIZE) != 0:
        raise ValueError("ciphertext must be block-aligned")
    out = bytearray()
    prev = iv
    for off in range(0, len(ciphertext), BLOCK_SIZE):
        c = ciphertext[off : off + BLOCK_SIZE]
        x = toy_cipher_decrypt_block(key, c)
        p = xor_bytes(x, prev)
        out += p
        prev = c
    return pkcs7_unpad(bytes(out), BLOCK_SIZE)
```
CBC chains blocks: each plaintext block is XORed with the previous ciphertext block (or IV) before encryption. During decryption, the XOR happens after block decryption. That XOR is what the attacker manipulates.

### Step 4: A padding oracle
```python
def padding_oracle_factory(key: bytes) -> Callable[[bytes, bytes], bool]:
    def oracle(iv: bytes, ciphertext: bytes) -> bool:
        try:
            _ = cbc_decrypt(key, iv, ciphertext)
            return True
        except ValueError:
            return False

    return oracle
```
The oracle compresses decryption into a single bit: “did unpadding succeed?” In real apps, this “bit” leaks through error messages, status codes, response length, or timing.

### Step 5: Recover plaintext via the oracle
```python
def recover_plaintext_via_padding_oracle(
    iv: bytes, ciphertext: bytes, oracle: Callable[[bytes, bytes], bool], block_size: int = BLOCK_SIZE
) -> bytes:
    if len(iv) != block_size:
        raise ValueError("bad IV length")
    if (len(ciphertext) % block_size) != 0 or not ciphertext:
        raise ValueError("ciphertext must be non-empty and block-aligned")

    blocks = [iv] + list(_chunks(ciphertext, block_size))
    recovered = bytearray()

    for block_idx in range(1, len(blocks)):
        prev = bytearray(blocks[block_idx - 1])
        cur = blocks[block_idx]

        inter = bytearray(block_size)
        plain = bytearray(block_size)

        for pad_len in range(1, block_size + 1):
            byte_idx = block_size - pad_len

            base = bytearray(prev)
            for j in range(block_size - 1, byte_idx, -1):
                base[j] = inter[j] ^ pad_len

            found = None
            for guess in range(256):
                trial = bytearray(base)
                trial[byte_idx] = guess

                trial_iv = bytes(trial)
                trial_ct = cur
                if not oracle(trial_iv, trial_ct):
                    continue
                if pad_len == 1:
                    probe = bytearray(trial)
                    probe[byte_idx - 1] ^= 1
                    if not oracle(bytes(probe), trial_ct):
                        continue
                found = guess
                break

            if found is None:
                raise RuntimeError("oracle attack failed (no byte found)")

            inter_byte = found ^ pad_len
            inter[byte_idx] = inter_byte
            plain[byte_idx] = inter_byte ^ prev[byte_idx]

        recovered += plain

    return pkcs7_unpad(bytes(recovered), block_size)
```
This is the classic byte-at-a-time padding oracle attack. It brute-forces one byte until the oracle says the resulting plaintext ends with a valid padding pattern, then moves left and repeats.

Run it:
python3 code/main.py

## Use It

- Use an AEAD mode: AES-GCM / ChaCha20-Poly1305 (encrypt-then-authenticate).
- If you must use CBC in legacy systems: authenticate ciphertexts (HMAC) and verify the MAC before attempting to decrypt; make all failures indistinguishable (same status, same body length, similar timing).
- In TLS terms: this is why modern stacks moved away from “MAC-then-encrypt” CBC constructions and standardized safer designs.

## Pitfalls

- Returning different errors for “bad padding” vs “bad MAC” (or different HTTP codes).
- Decrypting before authenticating (padding check happens before MAC check).
- Leaking the oracle through timing: padding failure returns faster than full parse.
- Logging decrypted-but-invalid data (turns oracle into plaintext exfiltration).
- “Fixing” by adding random delays (often bypassed; still leaks statistically).

## Ship It

Save an audit checklist you can paste into a PR review to look for padding-oracle risks in real codebases: `outputs/padding-oracle-audit-checklist.md`.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that the oracle plus many queries recovers the full plaintext.
2. Medium. Modify the demo to recover only a single chosen block (e.g., block 2) and print the number of oracle queries.
3. Hard. Extend the oracle to leak different error codes and show how “normalized errors” (single error) closes the attack in the demo.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| CBC | “A block cipher mode” | `P_i = D(C_i) XOR C_{i-1}`; the XOR with previous ciphertext makes malleability exploitable |
| PKCS#7 padding | “Padding bytes” | A structured suffix that gives attackers a target predicate to probe (“valid padding?”) |
| Padding oracle | “Server says padding bad” | Any observable signal that correlates with padding validity during decryption |
| Chosen-ciphertext attack | “Attacker can tamper ciphertext” | Security model where attacker queries a decryption-related oracle adaptively |

## Further Reading

- Vaudenay, “Security Flaws Induced by CBC Padding — Applications to SSL, IPSEC, WTLS…” (2002) — the classic padding-oracle analysis
- AlFardan & Paterson, “Lucky Thirteen: Breaking the TLS and DTLS Record Protocols” (2013) — timing side channels in CBC padding/MAC code paths
