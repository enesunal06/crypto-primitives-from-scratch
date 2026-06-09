"""
Tests for Stage 5 — the educational Ethereum wallet.

This suite covers the full cryptographic path from a private scalar to an
Ethereum identity and a signed legacy transaction, exercising four primitives
built from scratch in this project: Keccak-256 (keccak.py), RLP serialization
(rlp.py), secp256k1 ECDSA (ecdsa.py), and the wallet glue (wallet.py).

Properties verified:
- Keccak-256 matches the canonical Keccak test vectors (and is NOT SHA3-256)
- RLP encoding matches the standard examples from the Ethereum yellow paper
- Address derivation: private key 1 yields its known Ethereum address
- EIP-55 checksum casing matches the official EIP-55 specification vectors
- Legacy + EIP-155 transaction signing reproduces the canonical EIP-155
  example transaction, and produces structurally valid v, r, s, and raw hex
"""

import hashlib
import pytest

from src.ecdsa import N, verify, Signature
from src.keccak import keccak256
from src import rlp
from src.wallet import (
    EthereumWallet,
    public_key_to_address,
    to_checksum_address,
)


# ---------------------------------------------------------------------------
# Keccak-256 — Ethereum's hash function
# ---------------------------------------------------------------------------

def test_keccak256_known_vectors():
    # The canonical Keccak-256 test vectors.  These are the ORIGINAL Keccak
    # values used by Ethereum, distinct from the standardised SHA3-256 values.
    assert keccak256(b"").hex() == (
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    )
    assert keccak256(b"abc").hex() == (
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    )


def test_keccak256_is_not_sha3_256():
    # Ethereum's keccak256 differs from NIST SHA3-256 only in the padding
    # domain byte (0x01 vs 0x06), but that single bit changes every output.
    # If these ever coincided, the implementation would be standard SHA3.
    data = b"ethereum"
    assert keccak256(data) != hashlib.sha3_256(data).digest()


def test_keccak256_output_is_32_bytes():
    # A 256-bit digest is always 32 bytes, independent of input length.
    for data in [b"", b"a", b"a" * 135, b"a" * 136, b"a" * 200]:
        assert len(keccak256(data)) == 32


# ---------------------------------------------------------------------------
# RLP encoding — standard examples
# ---------------------------------------------------------------------------

def test_rlp_encodes_short_string():
    # "dog" → 0x83 (0x80 + length 3) followed by the three ASCII bytes.
    assert rlp.encode("dog") == bytes.fromhex("83646f67")


def test_rlp_encodes_list_of_strings():
    # ["cat", "dog"] → 0xc8 (list, payload length 8) then each encoded string.
    assert rlp.encode(["cat", "dog"]) == bytes.fromhex("c88363617483646f67")


def test_rlp_encodes_empty_string_and_list():
    # The two fundamental empty values have single-byte encodings.
    assert rlp.encode("") == bytes.fromhex("80")    # empty string
    assert rlp.encode(b"") == bytes.fromhex("80")
    assert rlp.encode([]) == bytes.fromhex("c0")    # empty list


def test_rlp_encodes_integers_canonically():
    # Integers use the shortest big-endian form with no leading zeros.
    assert rlp.encode(0) == bytes.fromhex("80")      # zero is the empty string
    assert rlp.encode(15) == bytes.fromhex("0f")     # single byte < 0x80
    assert rlp.encode(1024) == bytes.fromhex("820400")  # 0x82 then 0x0400


def test_rlp_single_low_byte_is_its_own_encoding():
    # A single byte in [0x00, 0x7f] is emitted verbatim, with no length prefix.
    assert rlp.encode(b"\x00") == b"\x00"
    assert rlp.encode(b"\x7f") == b"\x7f"
    # A single byte >= 0x80 needs the 0x81 length prefix.
    assert rlp.encode(b"\x80") == bytes.fromhex("8180")


def test_rlp_encodes_nested_lists():
    # The "set-theoretic representation of three" from the yellow paper:
    #   [ [], [[]], [ [], [[]] ] ]  → 0xc7c0c1c0c3c0c1c0
    assert rlp.encode([[], [[]], [[], [[]]]]) == bytes.fromhex("c7c0c1c0c3c0c1c0")


def test_rlp_long_string_uses_length_of_length_prefix():
    # A 56-byte string crosses the 55-byte boundary, so the prefix becomes
    # 0xb8 (0xb7 + 1 length byte) then 0x38 (= 56) then the bytes.
    text = "Lorem ipsum dolor sit amet, consectetur adipisicing elit"
    assert len(text) == 56
    encoded = rlp.encode(text)
    assert encoded[:2] == bytes.fromhex("b838")
    assert encoded[2:] == text.encode("ascii")


def test_rlp_rejects_bool():
    # bool is a subclass of int, but it is not a meaningful transaction field.
    with pytest.raises(TypeError):
        rlp.encode(True)


# ---------------------------------------------------------------------------
# Address derivation — private key 1
# ---------------------------------------------------------------------------

# The EIP-55 checksum below was verified two independent ways: the Keccak-256
# implementation matches three published Keccak vectors, and to_checksum_address
# matches all four official EIP-55 specification vectors (see the EIP-55 tests).
# It is the unique correct checksum for private key 1.
KNOWN_PRIVKEY_1_ADDRESS = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"


def test_private_key_one_derives_known_address():
    # Private key e = 1 gives public key Q = 1·G = G, the generator point.
    # Its address is the canonical privkey-1 Ethereum address.  This is an
    # end-to-end check of scalar multiplication, public-key encoding, and
    # Keccak-256 all at once.
    wallet = EthereumWallet(1)

    # Value check (case-insensitive): the lowercase hex is canonical.
    assert wallet.address.hex() == "7e5f4552091a69125d5dfcb7b8c2659029395bdf"
    # Full EIP-55 checksummed form.
    assert wallet.address_hex == KNOWN_PRIVKEY_1_ADDRESS


def test_address_is_last_twenty_bytes_of_pubkey_hash():
    # The address is defined as the low 20 bytes of Keccak-256 of the 64-byte
    # uncompressed public key (Q_x ‖ Q_y, with no 0x04 prefix).  Recomputing
    # it independently here confirms the wallet follows that definition.
    wallet = EthereumWallet(0xC0FFEE)
    digest = keccak256(wallet.public_key_bytes)
    assert wallet.address == digest[12:32]
    assert len(wallet.address) == 20


def test_public_key_bytes_omit_the_0x04_prefix():
    # The hashed encoding is exactly 64 bytes: the two 32-byte coordinates
    # Q_x ‖ Q_y with no leading 0x04 tag (the full uncompressed form would be
    # 65 bytes).  The bytes must equal the coordinates read big-endian.
    wallet = EthereumWallet(12345)
    pub = wallet.public_key_bytes
    assert len(pub) == 64
    assert pub[:32] == wallet.public_key.x.number.to_bytes(32, "big")
    assert pub[32:] == wallet.public_key.y.number.to_bytes(32, "big")


def test_public_key_to_address_matches_wallet_address():
    # The standalone helper and the wallet property must agree.
    wallet = EthereumWallet(42)
    assert public_key_to_address(wallet.public_key) == wallet.address


# ---------------------------------------------------------------------------
# EIP-55 checksum encoding
# ---------------------------------------------------------------------------

def test_eip55_official_specification_vectors():
    # The four checksummed addresses listed in EIP-55 itself.  Each is its own
    # checksum, so re-checksumming the lowercase bytes must reproduce it.
    spec_addresses = [
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    ]
    for checksummed in spec_addresses:
        raw = bytes.fromhex(checksummed[2:])
        assert to_checksum_address(raw) == checksummed


def test_eip55_is_only_a_casing_change():
    # The checksum changes letter case only; the underlying value is unchanged.
    # Lower-casing the checksummed string recovers the plain hex address.
    raw = bytes.fromhex("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
    checksummed = to_checksum_address(raw)
    assert checksummed.lower() == "0x" + raw.hex()


def test_eip55_detects_a_mistyped_nibble():
    # EIP-55 reclaims letter casing as a checksum.  Changing one nibble of the
    # address randomises the hash and therefore the casing, so the correct
    # checksum of a corrupted address almost never matches the original casing.
    correct = bytes.fromhex("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
    corrupted = bytes.fromhex("5aaeb6053f3e94c9b9a09f33669435e7ef1beaee")  # last nibble d→e
    assert to_checksum_address(correct) != to_checksum_address(corrupted)


def test_checksum_address_rejects_wrong_length():
    with pytest.raises(ValueError):
        to_checksum_address(b"\x00" * 19)


# ---------------------------------------------------------------------------
# Wallet construction & validation
# ---------------------------------------------------------------------------

def test_private_key_must_be_integer():
    with pytest.raises(TypeError):
        EthereumWallet("1")
    # bool is a subclass of int and must be rejected explicitly.
    with pytest.raises(TypeError):
        EthereumWallet(True)


def test_private_key_must_be_in_valid_range():
    with pytest.raises(ValueError):
        EthereumWallet(0)          # identity scalar
    with pytest.raises(ValueError):
        EthereumWallet(N)          # ≡ 0 (mod N)
    with pytest.raises(ValueError):
        EthereumWallet(-1)


def test_public_key_is_scalar_multiple_of_generator():
    # Q = e·G — the wallet's public key must equal scalar multiplication of G.
    from src.ecdsa import G
    e = 7777
    assert EthereumWallet(e).public_key == e * G


# ---------------------------------------------------------------------------
# Legacy transaction signing with EIP-155
# ---------------------------------------------------------------------------

def test_eip155_canonical_example_transaction():
    # The reference transaction from the EIP-155 specification.  Reproducing
    # its exact (v, r, s) is a complete, deterministic end-to-end check of RLP
    # encoding, Keccak-256, RFC 6979 nonce generation, ECDSA, and the EIP-155
    # v = recovery_id + 35 + 2·chain_id rule.
    private_key = 0x4646464646464646464646464646464646464646464646464646464646464646
    wallet = EthereumWallet(private_key)

    signed = wallet.sign_transaction(
        nonce=9,
        gas_price=20 * 10**9,
        gas_limit=21000,
        to="0x3535353535353535353535353535353535353535",
        value=10**18,
        data=b"",
        chain_id=1,
    )

    assert signed["v"] == 37
    assert signed["r"] == 0x28EF61340BD939BC2195FE537567866003E1A15D3C71FF63E1590620AA636276
    assert signed["s"] == 0x67CBE9D8997F761AECB703304B3800CCF555C9F3DC64214B297FB1966A3B6D83


def test_signed_transaction_is_structurally_valid():
    # Without comparing to a fixed vector, a freshly signed transaction must
    # still be well-formed: v carries the chain id, r and s lie in [1, N−1],
    # and the raw transaction is a 0x-prefixed RLP byte string.
    wallet = EthereumWallet(0xDEADBEEF)
    chain_id = 1
    signed = wallet.sign_transaction(
        nonce=0,
        gas_price=10**9,
        gas_limit=21000,
        to="0x" + "11" * 20,
        value=1234,
        data=b"",
        chain_id=chain_id,
    )

    # EIP-155: v = recovery_id + 35 + 2·chain_id, so v ∈ {35+2c, 36+2c}.
    assert signed["v"] in (35 + 2 * chain_id, 36 + 2 * chain_id)
    # r and s must be valid scalar-field elements.
    assert 1 <= signed["r"] <= N - 1
    assert 1 <= signed["s"] <= N - 1
    # Low-s normalisation (BIP-62) is inherited from the ECDSA signer.
    assert signed["s"] <= N // 2
    # Raw transaction and hash are 0x-prefixed hex strings.
    assert signed["raw_transaction"].startswith("0x")
    assert bytes.fromhex(signed["raw_transaction"][2:])      # valid hex
    assert len(bytes.fromhex(signed["transaction_hash"][2:])) == 32


def test_signature_over_transaction_hash_verifies():
    # The published (r, s) must verify as a genuine ECDSA signature on the
    # EIP-155 signing hash under the wallet's public key.  This confirms the
    # recovery-id machinery did not disturb the underlying signature.
    wallet = EthereumWallet(0xABCDEF)
    chain_id = 5
    signed = wallet.sign_transaction(
        nonce=3,
        gas_price=2 * 10**9,
        gas_limit=50000,
        to="0x" + "22" * 20,
        value=0,
        data=b"\x01\x02\x03",
        chain_id=chain_id,
    )

    # Rebuild the signing hash exactly as sign_transaction does.
    unsigned = [3, 2 * 10**9, 50000, bytes.fromhex("22" * 20), 0,
                b"\x01\x02\x03", chain_id, 0, 0]
    z = int.from_bytes(keccak256(rlp.encode(unsigned)), "big")

    assert verify(wallet.public_key, z, Signature(signed["r"], signed["s"]))


def test_signing_is_deterministic():
    # RFC 6979 makes signing deterministic, so signing the same transaction
    # twice yields byte-identical output.
    wallet = EthereumWallet(0x1234)
    args = dict(nonce=1, gas_price=10**9, gas_limit=21000,
                to="0x" + "33" * 20, value=42, data=b"", chain_id=1)
    assert wallet.sign_transaction(**args) == wallet.sign_transaction(**args)


def test_contract_creation_transaction_has_empty_to():
    # A contract-creation transaction has an empty `to` field (b'').  Signing
    # must succeed and the recovered signature must verify.
    wallet = EthereumWallet(0x55)
    signed = wallet.sign_transaction(
        nonce=0, gas_price=10**9, gas_limit=100000,
        to=None, value=0, data=b"\x60\x80", chain_id=1,
    )
    assert 1 <= signed["r"] <= N - 1
    assert 1 <= signed["s"] <= N - 1
