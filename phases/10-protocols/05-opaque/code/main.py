"""OPAQUE (RFC 9807) — OPRF-hardened passwords + envelope-based aPAKE (educational).

Run:
  python3 code/main.py

This script is stdlib-only and walks through the core moving parts behind OPAQUE:
1) A prime-order subgroup for DH-style “group math”
2) A DH-style OPRF flow (blind -> evaluate -> finalize)
3) Envelope Store/Recover (deriving client key material from a hardened password)
4) A toy OPAQUE-3DH-style AKE (KE1/KE2/KE3) with explicit MACs

Notes:
- Educational implementation. Not constant-time. Not production-safe.
- Real OPAQUE uses carefully specified groups, encodings, validation rules, and a
  proper OPRF/HashToGroup construction; see RFC 9807 and RFC 9497.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import secrets


HASHLEN = 32
Nh = 32
Nm = 32
Nn = 32
Nseed = 32

PBKDF2_ITERS = 6000


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def parse_hex_int(text: str) -> int:
    cleaned = "".join(ch for ch in text if ch.strip()).replace("0x", "").replace("0X", "")
    if not cleaned:
        raise ValueError("empty hex string")
    return int(cleaned, 16)


def modexp(base: int, exponent: int, modulus: int) -> int:
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    if exponent < 0:
        raise ValueError("exponent must be non-negative")

    base %= modulus
    result = 1
    e = exponent
    while e:
        if e & 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        e >>= 1
    return result


def egcd(a: int, b: int) -> tuple[int, int, int]:
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)


def modinv(a: int, modulus: int) -> int:
    a %= modulus
    if a == 0:
        raise ValueError("inverse does not exist")
    g, x, _ = egcd(a, modulus)
    if g != 1:
        raise ValueError("inverse does not exist")
    return x % modulus


def int_to_bytes(value: int, length: int | None = None) -> bytes:
    if value < 0:
        raise ValueError("value must be non-negative")
    if length is None:
        length = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(length, "big")


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))


def hkdf_extract_sha256(salt: bytes | None, ikm: bytes) -> bytes:
    if salt is None:
        salt = b"\x00" * HASHLEN
    return hmac_sha256(salt, ikm)


def hkdf_expand_sha256(prk: bytes, info: bytes, length: int) -> bytes:
    if len(prk) != HASHLEN:
        raise ValueError("prk must be 32 bytes")
    if length < 0:
        raise ValueError("length must be non-negative")
    if length > 255 * HASHLEN:
        raise ValueError("length too large")

    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac_sha256(prk, t + info + bytes([counter]))
        out += t
        counter += 1
    return out[:length]


def i2osp_u16(n: int) -> bytes:
    if not (0 <= n <= 0xFFFF):
        raise ValueError("u16 out of range")
    return n.to_bytes(2, "big")


def encode_len_prefixed(data: bytes) -> bytes:
    return i2osp_u16(len(data)) + data


@dataclass(frozen=True)
class PrimeOrderGroup:
    name: str
    p: int
    q: int
    g: int

    @property
    def byte_len(self) -> int:
        return (self.p.bit_length() + 7) // 8

    def serialize_elem(self, x: int) -> bytes:
        return int_to_bytes(x, self.byte_len)

    def validate_elem(self, x: int) -> None:
        if not (2 <= x <= self.p - 2):
            raise ValueError("element out of range")
        if modexp(x, self.q, self.p) != 1:
            raise ValueError("element not in subgroup")


RFC3526_GROUP14_P_HEX = """
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
"""


def rfc3526_group14_subgroup_qr() -> PrimeOrderGroup:
    p = parse_hex_int(RFC3526_GROUP14_P_HEX)
    q = (p - 1) // 2
    g = modexp(2, 2, p)
    group = PrimeOrderGroup(name="RFC3526 group14 QR subgroup", p=p, q=q, g=g)
    group.validate_elem(group.g)
    return group


def hash_to_scalar(password: bytes, group: PrimeOrderGroup) -> int:
    digest = sha256(b"cryptography-from-scratch:OPAQUE:HashToScalar:" + password)
    x = int.from_bytes(digest, "big") % group.q
    if x == 0:
        x = 1
    return x


def hash_to_group(password: bytes, group: PrimeOrderGroup) -> int:
    x = hash_to_scalar(password, group)
    elem = modexp(group.g, x, group.p)
    if elem == 1:
        raise ValueError("hash_to_group mapped to identity")
    return elem


def oprf_blind(password: bytes, blind: int, group: PrimeOrderGroup) -> int:
    blind %= group.q
    if blind == 0:
        raise ValueError("blind must be non-zero")
    _ = modinv(blind, group.q)
    input_elem = hash_to_group(password, group)
    blinded = modexp(input_elem, blind, group.p)
    group.validate_elem(blinded)
    return blinded


def oprf_evaluate(blinded_element: int, oprf_key: int, group: PrimeOrderGroup) -> int:
    oprf_key %= group.q
    if oprf_key == 0:
        raise ValueError("oprf_key must be non-zero")
    group.validate_elem(blinded_element)
    evaluated = modexp(blinded_element, oprf_key, group.p)
    group.validate_elem(evaluated)
    return evaluated


def oprf_finalize(password: bytes, blind: int, evaluated_element: int, group: PrimeOrderGroup) -> bytes:
    group.validate_elem(evaluated_element)
    inv = modinv(blind, group.q)
    unblinded = modexp(evaluated_element, inv, group.p)
    group.validate_elem(unblinded)

    unblinded_bytes = group.serialize_elem(unblinded)
    hash_input = (
        encode_len_prefixed(password)
        + encode_len_prefixed(unblinded_bytes)
        + b"Finalize"
    )
    return sha256(hash_input)


def stretch_password(oprf_output: bytes, *, iters: int = PBKDF2_ITERS) -> bytes:
    if iters <= 0:
        raise ValueError("iters must be positive")
    stretched = hashlib.pbkdf2_hmac("sha256", oprf_output, b"cryptography-from-scratch:OPAQUE:Stretch", iters, dklen=Nh)
    prk = hkdf_extract_sha256(b"", oprf_output + stretched)
    return hkdf_expand_sha256(prk, b"cryptography-from-scratch:OPAQUE:RandomizedPassword", Nh)


def derive_dh_keypair_from_seed(seed: bytes, group: PrimeOrderGroup) -> tuple[int, int]:
    if len(seed) != Nseed:
        raise ValueError("seed must be 32 bytes")
    sk = int.from_bytes(sha256(b"cryptography-from-scratch:OPAQUE:DHKeyPair:" + seed), "big") % group.q
    if sk == 0:
        sk = 1
    pk = modexp(group.g, sk, group.p)
    group.validate_elem(pk)
    return sk, pk


def encode_cleartext_credentials(
    *,
    server_public_key: int,
    client_public_key: int,
    server_identity: bytes,
    client_identity: bytes,
    group: PrimeOrderGroup,
) -> bytes:
    spk = group.serialize_elem(server_public_key)
    cpk = group.serialize_elem(client_public_key)
    return (
        b"OPAQUE-CredentialsV1"
        + encode_len_prefixed(server_identity)
        + encode_len_prefixed(client_identity)
        + encode_len_prefixed(spk)
        + encode_len_prefixed(cpk)
    )


@dataclass(frozen=True)
class Envelope:
    nonce: bytes
    auth_tag: bytes

    def to_bytes(self) -> bytes:
        if len(self.nonce) != Nn:
            raise ValueError("bad envelope nonce length")
        if len(self.auth_tag) != Nm:
            raise ValueError("bad envelope auth_tag length")
        return self.nonce + self.auth_tag

    @staticmethod
    def from_bytes(data: bytes) -> "Envelope":
        if len(data) != Nn + Nm:
            raise ValueError("bad envelope length")
        return Envelope(nonce=data[:Nn], auth_tag=data[Nn:])


def store_envelope(
    *,
    randomized_password: bytes,
    server_public_key: int,
    server_identity: bytes,
    client_identity: bytes,
    envelope_nonce: bytes,
    group: PrimeOrderGroup,
) -> tuple[Envelope, int, bytes, bytes]:
    if len(randomized_password) != Nh:
        raise ValueError("randomized_password must be 32 bytes")
    if len(envelope_nonce) != Nn:
        raise ValueError("envelope_nonce must be 32 bytes")
    group.validate_elem(server_public_key)

    masking_key = hkdf_expand_sha256(randomized_password, b"MaskingKey", Nh)
    auth_key = hkdf_expand_sha256(randomized_password, envelope_nonce + b"AuthKey", Nh)
    export_key = hkdf_expand_sha256(randomized_password, envelope_nonce + b"ExportKey", Nh)
    seed = hkdf_expand_sha256(randomized_password, envelope_nonce + b"PrivateKey", Nseed)

    _, client_public_key = derive_dh_keypair_from_seed(seed, group)
    cleartext = encode_cleartext_credentials(
        server_public_key=server_public_key,
        client_public_key=client_public_key,
        server_identity=server_identity,
        client_identity=client_identity,
        group=group,
    )
    auth_tag = hmac_sha256(auth_key, envelope_nonce + cleartext)
    envelope = Envelope(nonce=envelope_nonce, auth_tag=auth_tag)
    return envelope, client_public_key, masking_key, export_key


def recover_envelope(
    *,
    randomized_password: bytes,
    server_public_key: int,
    envelope: Envelope,
    server_identity: bytes,
    client_identity: bytes,
    group: PrimeOrderGroup,
) -> tuple[int, bytes, bytes]:
    if len(randomized_password) != Nh:
        raise ValueError("randomized_password must be 32 bytes")
    group.validate_elem(server_public_key)
    if len(envelope.nonce) != Nn:
        raise ValueError("envelope nonce length")
    if len(envelope.auth_tag) != Nm:
        raise ValueError("envelope auth_tag length")

    auth_key = hkdf_expand_sha256(randomized_password, envelope.nonce + b"AuthKey", Nh)
    export_key = hkdf_expand_sha256(randomized_password, envelope.nonce + b"ExportKey", Nh)
    seed = hkdf_expand_sha256(randomized_password, envelope.nonce + b"PrivateKey", Nseed)
    client_private_key, client_public_key = derive_dh_keypair_from_seed(seed, group)

    cleartext = encode_cleartext_credentials(
        server_public_key=server_public_key,
        client_public_key=client_public_key,
        server_identity=server_identity,
        client_identity=client_identity,
        group=group,
    )
    expected_tag = hmac_sha256(auth_key, envelope.nonce + cleartext)
    if not hmac.compare_digest(envelope.auth_tag, expected_tag):
        raise ValueError("EnvelopeRecoveryError")
    return client_private_key, cleartext, export_key


@dataclass(frozen=True)
class RegistrationRecord:
    client_public_key: int
    masking_key: bytes
    envelope: Envelope


@dataclass(frozen=True)
class CredentialRequest:
    blinded_message: int


@dataclass(frozen=True)
class CredentialResponse:
    evaluated_message: int
    masking_nonce: bytes
    masked_response: bytes


@dataclass(frozen=True)
class AuthRequest:
    client_nonce: bytes
    client_public_keyshare: int


@dataclass(frozen=True)
class AuthResponse:
    server_nonce: bytes
    server_public_keyshare: int
    server_mac: bytes


@dataclass(frozen=True)
class KE1:
    credential_request: CredentialRequest
    auth_request: AuthRequest


@dataclass(frozen=True)
class KE2:
    credential_response: CredentialResponse
    auth_response: AuthResponse


@dataclass(frozen=True)
class KE3:
    client_mac: bytes


def serialize_ke1(ke1: KE1, group: PrimeOrderGroup) -> bytes:
    return (
        group.serialize_elem(ke1.credential_request.blinded_message)
        + ke1.auth_request.client_nonce
        + group.serialize_elem(ke1.auth_request.client_public_keyshare)
    )


def serialize_credential_response(cr: CredentialResponse, group: PrimeOrderGroup) -> bytes:
    return group.serialize_elem(cr.evaluated_message) + cr.masking_nonce + cr.masked_response


def preamble(
    *,
    client_identity: bytes,
    ke1: KE1,
    server_identity: bytes,
    credential_response: CredentialResponse,
    server_nonce: bytes,
    server_public_keyshare: int,
    group: PrimeOrderGroup,
    context: bytes = b"",
) -> bytes:
    if len(server_nonce) != Nn:
        raise ValueError("server_nonce must be 32 bytes")
    return (
        b"OPAQUEv1-"
        + encode_len_prefixed(context)
        + encode_len_prefixed(client_identity)
        + serialize_ke1(ke1, group)
        + encode_len_prefixed(server_identity)
        + serialize_credential_response(credential_response, group)
        + server_nonce
        + group.serialize_elem(server_public_keyshare)
    )


def dh_shared_secret_bytes(*, sk: int, pk: int, group: PrimeOrderGroup) -> bytes:
    if not (1 <= sk < group.q):
        raise ValueError("bad DH scalar")
    group.validate_elem(pk)
    shared = modexp(pk, sk, group.p)
    group.validate_elem(shared)
    return group.serialize_elem(shared)


def derive_ake_keys(*, ikm: bytes, preamble_bytes: bytes) -> tuple[bytes, bytes, bytes]:
    prk = hkdf_extract_sha256(b"", ikm)
    transcript_hash = sha256(preamble_bytes)
    handshake_secret = hkdf_expand_sha256(prk, b"HandshakeSecret|" + transcript_hash, HASHLEN)
    session_key = hkdf_expand_sha256(prk, b"SessionKey|" + transcript_hash, HASHLEN)
    km2 = hkdf_expand_sha256(handshake_secret, b"ServerMAC", HASHLEN)
    km3 = hkdf_expand_sha256(handshake_secret, b"ClientMAC", HASHLEN)
    return km2, km3, session_key


@dataclass
class ClientAkeState:
    password: bytes
    blind: int
    client_identity: bytes
    client_nonce: bytes
    client_secret: int
    ke1: KE1


@dataclass
class ServerAkeState:
    expected_client_mac: bytes
    session_key: bytes


def client_start(
    *,
    password: bytes,
    client_identity: bytes,
    blind: int,
    client_nonce: bytes,
    client_keyshare_seed: bytes,
    group: PrimeOrderGroup,
) -> ClientAkeState:
    if len(client_nonce) != Nn:
        raise ValueError("client_nonce must be 32 bytes")
    blinded_message = oprf_blind(password, blind, group)
    credential_request = CredentialRequest(blinded_message=blinded_message)
    client_secret, client_public_keyshare = derive_dh_keypair_from_seed(client_keyshare_seed, group)
    auth_request = AuthRequest(client_nonce=client_nonce, client_public_keyshare=client_public_keyshare)
    ke1 = KE1(credential_request=credential_request, auth_request=auth_request)
    return ClientAkeState(
        password=password,
        blind=blind,
        client_identity=client_identity,
        client_nonce=client_nonce,
        client_secret=client_secret,
        ke1=ke1,
    )


def server_respond(
    *,
    client_identity: bytes,
    server_identity: bytes,
    server_private_key: int,
    server_public_key: int,
    oprf_key: int,
    record: RegistrationRecord,
    ke1: KE1,
    masking_nonce: bytes,
    server_nonce: bytes,
    server_keyshare_seed: bytes,
    group: PrimeOrderGroup,
) -> tuple[ServerAkeState, KE2]:
    if len(masking_nonce) != Nn:
        raise ValueError("masking_nonce must be 32 bytes")
    if len(server_nonce) != Nn:
        raise ValueError("server_nonce must be 32 bytes")

    evaluated_message = oprf_evaluate(ke1.credential_request.blinded_message, oprf_key, group)
    pad_len = group.byte_len + (Nn + Nm)
    pad = hkdf_expand_sha256(record.masking_key, masking_nonce + b"CredentialResponsePad", pad_len)
    masked_response = xor_bytes(pad, group.serialize_elem(server_public_key) + record.envelope.to_bytes())
    credential_response = CredentialResponse(
        evaluated_message=evaluated_message,
        masking_nonce=masking_nonce,
        masked_response=masked_response,
    )

    server_private_keyshare, server_public_keyshare = derive_dh_keypair_from_seed(server_keyshare_seed, group)
    prem = preamble(
        client_identity=client_identity,
        ke1=ke1,
        server_identity=server_identity,
        credential_response=credential_response,
        server_nonce=server_nonce,
        server_public_keyshare=server_public_keyshare,
        group=group,
        context=b"",
    )

    dh1 = dh_shared_secret_bytes(sk=server_private_keyshare, pk=ke1.auth_request.client_public_keyshare, group=group)
    dh2 = dh_shared_secret_bytes(sk=server_private_key, pk=ke1.auth_request.client_public_keyshare, group=group)
    dh3 = dh_shared_secret_bytes(sk=server_private_keyshare, pk=record.client_public_key, group=group)
    km2, km3, session_key = derive_ake_keys(ikm=dh1 + dh2 + dh3, preamble_bytes=prem)
    server_mac = hmac_sha256(km2, sha256(prem))
    expected_client_mac = hmac_sha256(km3, sha256(prem + server_mac))

    auth_response = AuthResponse(server_nonce=server_nonce, server_public_keyshare=server_public_keyshare, server_mac=server_mac)
    ke2 = KE2(credential_response=credential_response, auth_response=auth_response)
    return ServerAkeState(expected_client_mac=expected_client_mac, session_key=session_key), ke2


def recover_credentials(
    *,
    password: bytes,
    blind: int,
    credential_response: CredentialResponse,
    server_identity: bytes,
    client_identity: bytes,
    group: PrimeOrderGroup,
) -> tuple[int, bytes, bytes, int]:
    oprf_output = oprf_finalize(password, blind, credential_response.evaluated_message, group)
    randomized_password = stretch_password(oprf_output)
    masking_key = hkdf_expand_sha256(randomized_password, b"MaskingKey", Nh)

    pad_len = group.byte_len + (Nn + Nm)
    pad = hkdf_expand_sha256(masking_key, credential_response.masking_nonce + b"CredentialResponsePad", pad_len)
    unmasked = xor_bytes(pad, credential_response.masked_response)
    server_public_key_bytes = unmasked[: group.byte_len]
    envelope_bytes = unmasked[group.byte_len :]
    server_public_key = int.from_bytes(server_public_key_bytes, "big")
    envelope = Envelope.from_bytes(envelope_bytes)

    client_private_key, cleartext, export_key = recover_envelope(
        randomized_password=randomized_password,
        server_public_key=server_public_key,
        envelope=envelope,
        server_identity=server_identity,
        client_identity=client_identity,
        group=group,
    )
    return client_private_key, cleartext, export_key, server_public_key


def client_finalize(
    *,
    state: ClientAkeState,
    server_identity: bytes,
    ke2: KE2,
    group: PrimeOrderGroup,
) -> tuple[KE3, bytes, bytes]:
    client_private_key, cleartext, export_key, server_public_key = recover_credentials(
        password=state.password,
        blind=state.blind,
        credential_response=ke2.credential_response,
        server_identity=server_identity,
        client_identity=state.client_identity,
        group=group,
    )

    prem = preamble(
        client_identity=state.client_identity,
        ke1=state.ke1,
        server_identity=server_identity,
        credential_response=ke2.credential_response,
        server_nonce=ke2.auth_response.server_nonce,
        server_public_keyshare=ke2.auth_response.server_public_keyshare,
        group=group,
        context=b"",
    )

    dh1 = dh_shared_secret_bytes(sk=state.client_secret, pk=ke2.auth_response.server_public_keyshare, group=group)
    dh2 = dh_shared_secret_bytes(sk=state.client_secret, pk=server_public_key, group=group)
    dh3 = dh_shared_secret_bytes(sk=client_private_key, pk=ke2.auth_response.server_public_keyshare, group=group)
    km2, km3, session_key = derive_ake_keys(ikm=dh1 + dh2 + dh3, preamble_bytes=prem)
    expected_server_mac = hmac_sha256(km2, sha256(prem))
    if not hmac.compare_digest(ke2.auth_response.server_mac, expected_server_mac):
        raise ValueError("ServerAuthenticationError")
    client_mac = hmac_sha256(km3, sha256(prem + expected_server_mac))
    return KE3(client_mac=client_mac), session_key, export_key


def server_finalize(*, server_state: ServerAkeState, ke3: KE3) -> bytes:
    if not hmac.compare_digest(ke3.client_mac, server_state.expected_client_mac):
        raise ValueError("ClientAuthenticationError")
    return server_state.session_key


def register_user(
    *,
    password: bytes,
    client_identity: bytes,
    server_identity: bytes,
    blind: int,
    envelope_nonce: bytes,
    server_public_key: int,
    oprf_key: int,
    group: PrimeOrderGroup,
) -> tuple[RegistrationRecord, bytes]:
    evaluated = oprf_evaluate(oprf_blind(password, blind, group), oprf_key, group)
    oprf_output = oprf_finalize(password, blind, evaluated, group)
    randomized_password = stretch_password(oprf_output)
    envelope, client_public_key, masking_key, export_key = store_envelope(
        randomized_password=randomized_password,
        server_public_key=server_public_key,
        server_identity=server_identity,
        client_identity=client_identity,
        envelope_nonce=envelope_nonce,
        group=group,
    )
    return RegistrationRecord(client_public_key=client_public_key, masking_key=masking_key, envelope=envelope), export_key


def _print_step(n: int, name: str) -> None:
    print(f"=== Step {n}: {name} ===")


def step1_group_and_dh() -> PrimeOrderGroup:
    _print_step(1, "Prime-order subgroup (DH math)")
    group = rfc3526_group14_subgroup_qr()
    print(f"group: {group.name}")
    print(f"p bits: {group.p.bit_length()}")
    print(f"q bits: {group.q.bit_length()}")
    print(f"g in subgroup: {modexp(group.g, group.q, group.p) == 1}")
    return group


def step2_oprf_demo(group: PrimeOrderGroup) -> tuple[bytes, bytes]:
    _print_step(2, "DH-style OPRF output -> randomized_password")
    password = b"correct horse battery staple"
    blind = 123456789
    oprf_key = 42424242
    blinded = oprf_blind(password, blind, group)
    evaluated = oprf_evaluate(blinded, oprf_key, group)
    oprf_output = oprf_finalize(password, blind, evaluated, group)
    randomized_password = stretch_password(oprf_output, iters=2000)
    print(f"oprf_output (Nh=32):        {oprf_output.hex()}")
    print(f"randomized_password (Nh=32): {randomized_password.hex()}")
    return password, randomized_password


def step3_store_recover_demo(group: PrimeOrderGroup) -> None:
    _print_step(3, "Envelope Store/Recover (key recovery)")
    password = b"correct horse battery staple"
    blind = 123456789
    oprf_key = 42424242
    server_identity = b"example.com"
    client_identity = b"alice"

    server_private_key, server_public_key = derive_dh_keypair_from_seed(b"\x11" * 32, group)
    envelope_nonce = b"\x22" * 32

    record, export_key_reg = register_user(
        password=password,
        client_identity=client_identity,
        server_identity=server_identity,
        blind=blind,
        envelope_nonce=envelope_nonce,
        server_public_key=server_public_key,
        oprf_key=oprf_key,
        group=group,
    )
    print(f"record.client_public_key (hex, first 16 bytes): {group.serialize_elem(record.client_public_key)[:16].hex()}")
    print(f"record.envelope.nonce: {record.envelope.nonce.hex()}")
    print(f"record.envelope.auth_tag (first 16 bytes): {record.envelope.auth_tag[:16].hex()}")
    print(f"export_key (first 16 bytes): {export_key_reg[:16].hex()}")

    evaluated = oprf_evaluate(oprf_blind(password, blind, group), oprf_key, group)
    oprf_output = oprf_finalize(password, blind, evaluated, group)
    randomized_password = stretch_password(oprf_output)
    client_private_key, cleartext, export_key_login = recover_envelope(
        randomized_password=randomized_password,
        server_public_key=server_public_key,
        envelope=record.envelope,
        server_identity=server_identity,
        client_identity=client_identity,
        group=group,
    )
    print(f"recovered client_private_key (non-zero): {client_private_key != 0}")
    print(f"cleartext_credentials bytes: {len(cleartext)}")
    print(f"export_key matches: {export_key_login == export_key_reg}")


def step4_toy_opaque_3dh_demo(group: PrimeOrderGroup) -> None:
    _print_step(4, "Toy OPAQUE-3DH login (KE1/KE2/KE3)")
    password = b"correct horse battery staple"
    wrong_password = b"tr0ub4dor&3"
    client_identity = b"alice"
    server_identity = b"example.com"

    server_private_key, server_public_key = derive_dh_keypair_from_seed(b"\x11" * 32, group)
    oprf_key = 42424242
    blind = 123456789
    record, _ = register_user(
        password=password,
        client_identity=client_identity,
        server_identity=server_identity,
        blind=blind,
        envelope_nonce=b"\x22" * 32,
        server_public_key=server_public_key,
        oprf_key=oprf_key,
        group=group,
    )

    client_state = client_start(
        password=password,
        client_identity=client_identity,
        blind=blind,
        client_nonce=b"\x33" * 32,
        client_keyshare_seed=b"\x44" * 32,
        group=group,
    )
    server_state, ke2 = server_respond(
        client_identity=client_identity,
        server_identity=server_identity,
        server_private_key=server_private_key,
        server_public_key=server_public_key,
        oprf_key=oprf_key,
        record=record,
        ke1=client_state.ke1,
        masking_nonce=b"\x55" * 32,
        server_nonce=b"\x66" * 32,
        server_keyshare_seed=b"\x77" * 32,
        group=group,
    )

    ke3, client_session_key, export_key = client_finalize(state=client_state, server_identity=server_identity, ke2=ke2, group=group)
    server_session_key = server_finalize(server_state=server_state, ke3=ke3)
    print(f"session_key matches: {client_session_key == server_session_key}")
    print(f"session_key (first 16 bytes): {client_session_key[:16].hex()}")
    print(f"export_key (first 16 bytes): {export_key[:16].hex()}")

    try:
        bad_client_state = client_start(
            password=wrong_password,
            client_identity=client_identity,
            blind=blind,
            client_nonce=b"\x33" * 32,
            client_keyshare_seed=b"\x44" * 32,
            group=group,
        )
        ke3_bad, _, _ = client_finalize(state=bad_client_state, server_identity=server_identity, ke2=ke2, group=group)
        _ = server_finalize(server_state=server_state, ke3=ke3_bad)
        print("wrong password unexpectedly authenticated")
    except ValueError as e:
        print(f"wrong password rejected: {e}")


def main() -> None:
    group = step1_group_and_dh()
    print()
    _ = step2_oprf_demo(group)
    print()
    step3_store_recover_demo(group)
    print()
    step4_toy_opaque_3dh_demo(group)


if __name__ == "__main__":
    main()
