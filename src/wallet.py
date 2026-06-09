# Stage 5 — an educational Ethereum wallet.
#
# This module ties together every primitive built earlier in the project to
# walk the full cryptographic path that turns a single secret integer into an
# Ethereum identity and lets it sign a transaction:
#
#   private key  e            (a scalar in [1, N−1])
#        │  scalar multiplication on secp256k1   (point.py, ecc.py)
#        ▼
#   public key   Q = e·G      (a point on the curve)
#        │  Keccak-256 of the 64-byte coordinate pair        (keccak.py)
#        ▼
#   address      last 20 bytes of the hash
#        │  EIP-55 checksum casing
#        ▼
#   0x-string    a human-checkable address
#
# and, separately,
#
#   transaction fields
#        │  RLP serialization of the unsigned tuple          (rlp.py)
#        ▼  Keccak-256 → message hash z
#   ECDSA sign with EIP-155 replay protection                (ecdsa.py)
#        ▼
#   signed transaction (v, r, s) and its raw RLP bytes
#
# It is intentionally NOT a real wallet: there is no networking, no
# broadcasting, no mnemonic/HD-key derivation, and only the pre-EIP-1559
# "legacy" transaction format is supported.  The goal is to make every
# mathematical step visible.

from src.ecdsa import G, N, P, A, B, S256Field, sign
from src.keccak import keccak256
from src.point import Point
from src import rlp


# secp256k1 curve coefficients as field elements.  Reconstructing R during
# public-key recovery requires a Point on the same curve as G, so we rebuild
# a = 0 and b = 7 in F_P here.  By FieldElement equality these compare equal
# to the coefficients stored inside G, so the two points add cleanly.
_A = S256Field(A)
_B = S256Field(B)


# ---------------------------------------------------------------------------
# Address helpers
# ---------------------------------------------------------------------------

def public_key_to_address(public_key: Point) -> bytes:
    """Derive the 20-byte Ethereum address from a secp256k1 public key.

    Why hash the public key at all?  The public key Q = e·G is a curve point;
    revealing it is safe because recovering e from Q is the elliptic-curve
    discrete logarithm problem (see ecdsa.py).  An address is simply a shorter,
    fixed-length *fingerprint* of Q, convenient for humans and for storage.

    The derivation, mathematically:

      1. Write Q in uncompressed affine form.  Q has two 256-bit coordinates
         (Q_x, Q_y).  The standard "uncompressed" serialization is the 65-byte
         string 0x04 ‖ Q_x ‖ Q_y, where 0x04 is merely a tag announcing "both
         coordinates follow".  Ethereum hashes ONLY the 64 coordinate bytes
         Q_x ‖ Q_y and drops the 0x04 prefix — the prefix carries no
         information about the key (it is the same constant for every
         uncompressed key), so including it would add nothing.

      2. h = Keccak-256(Q_x ‖ Q_y), a 32-byte digest.

      3. address = h[12:32], the LAST 20 bytes of h.  Keccak-256 behaves like
         a random function, so any 20-bit-aligned slice is an equally good
         fingerprint; Ethereum fixes the convention as the low 20 bytes.  20
         bytes (160 bits) gives a ~2^80 collision bound, deemed sufficient.

    Args:
        public_key: The public key point Q = e·G on secp256k1.

    Returns:
        The 20-byte address.
    """
    if public_key.x is None:
        raise ValueError("the point at infinity has no address")

    # Q_x ‖ Q_y as 64 bytes — the uncompressed encoding without the 0x04 tag.
    x_bytes = public_key.x.number.to_bytes(32, "big")
    y_bytes = public_key.y.number.to_bytes(32, "big")
    digest = keccak256(x_bytes + y_bytes)

    return digest[12:32]


def to_checksum_address(address: bytes) -> str:
    """Encode a 20-byte address as an EIP-55 mixed-case checksum string.

    A raw address is case-insensitive hex, so a single mistyped character is
    silently accepted.  EIP-55 (Buterin & Van de Sande, 2016) reclaims the
    otherwise-unused *letter casing* as a checksum, without changing the
    address's value:

      1. Let s be the 40-character lowercase hex of the address (no 0x).
      2. Let h = Keccak-256(s) — hashing the ASCII text of the hex string.
      3. For each hex character of s:
           • digits 0–9 are emitted unchanged (they have no case);
           • a letter a–f is upper-cased iff the corresponding hex nibble of h
             is ≥ 8, i.e. iff the top bit of that nibble is 1.

    Error-detection argument: each of the (up to 40) letters independently
    encodes one bit of the hash, chosen by a function of the entire address.
    Mistyping any nibble changes the address, which changes h, which
    randomises every casing bit.  A random typo therefore produces correct
    casing only with probability ~2^(−k), where k is the number of letters in
    the address (commonly ~30), so the overwhelming majority of single-
    character errors are caught.

    Args:
        address: The 20-byte address.

    Returns:
        The checksummed address as a '0x'-prefixed string.
    """
    if len(address) != 20:
        raise ValueError("an Ethereum address is exactly 20 bytes")

    lowercase_hex = address.hex()
    hash_hex = keccak256(lowercase_hex.encode("ascii")).hex()

    checksummed = []
    for character, hash_nibble in zip(lowercase_hex, hash_hex):
        if character in "0123456789":
            checksummed.append(character)
        elif int(hash_nibble, 16) >= 8:
            checksummed.append(character.upper())
        else:
            checksummed.append(character)

    return "0x" + "".join(checksummed)


def _normalize_recipient(to) -> bytes:
    """Turn a recipient address into its 20-byte (or empty) form.

    Accepts a 20-byte address, a hex string (with or without 0x), or None /
    empty (a contract-creation transaction, where the `to` field is the empty
    byte string b'').
    """
    if to is None or to == "" or to == b"":
        return b""
    if isinstance(to, (bytes, bytearray)):
        value = bytes(to)
    elif isinstance(to, str):
        value = bytes.fromhex(to[2:] if to.startswith("0x") else to)
    else:
        raise TypeError("recipient must be bytes, a hex string, or None")
    if len(value) != 20:
        raise ValueError("recipient address must be 20 bytes")
    return value


# ---------------------------------------------------------------------------
# Public-key recovery — used to compute the signature's recovery id
# ---------------------------------------------------------------------------

def _recovery_id(r: int, s: int, z: int, public_key: Point) -> int:
    """Return the ECDSA recovery id (0 or 1) for a signature.

    A bare ECDSA signature (r, s) does not say which point R = k·G produced r:
    r is only the x-coordinate of R reduced mod N, and a curve has *two*
    points with a given x (they are reflections P and −P).  Ethereum therefore
    stores one extra bit, the recovery id, equal to the parity of R's
    y-coordinate.  That bit lets anyone reconstruct R, and from R the signer's
    public key — which is how a node learns the sender of a transaction
    without it being transmitted.

    Recovery works by inverting the signing relation.  Signing sets
    s ≡ k⁻¹(z + r·e) (mod N), and Q = e·G, so:

        R = k·G = s⁻¹·(z + r·e)·G = s⁻¹·(z·G + r·Q)
        ⇒  Q = r⁻¹·(s·R − z·G).

    We do not know R yet, but we know its x-coordinate is r.  For each possible
    y-parity we rebuild R from the curve equation y² = x³ + 7, recover a
    candidate Q, and keep the parity whose Q matches the wallet's real public
    key.  (We ignore the astronomically rare case r + N < P where R.x wrapped
    past N; the signer in this module never produces it.)

    The modular square root uses the fact that P ≡ 3 (mod 4) for secp256k1, so
    a square root of α is α^((P+1)/4) mod P whenever α is a quadratic residue.

    Args:
        r, s: Signature components.
        z:    The message hash that was signed, as an integer.
        public_key: The signer's known public key Q, used to disambiguate.

    Returns:
        0 or 1 — the parity of R.y for the R consistent with (r, s, Q).

    Raises:
        ValueError: If neither parity recovers the given public key.
    """
    r_inverse = pow(r, -1, N)
    z_mod = z % N

    for recovery_id in (0, 1):
        # Rebuild R from x = r and the chosen y-parity.
        x = r
        alpha = (pow(x, 3, P) + B) % P           # α = x³ + 7  (mod P)
        beta = pow(alpha, (P + 1) // 4, P)        # one square root of α
        y = beta if (beta % 2) == recovery_id else (P - beta)

        R = Point(S256Field(x), S256Field(y), _A, _B)

        # Q = r⁻¹·(s·R − z·G).  Subtraction in the group is adding the
        # negation, and −z·G = (N − z)·G since N·G = O.
        candidate = r_inverse * (s * R + (N - z_mod) * G)

        if candidate == public_key:
            return recovery_id

    raise ValueError("could not recover a recovery id for this signature")


# ---------------------------------------------------------------------------
# Wallet
# ---------------------------------------------------------------------------

class EthereumWallet:
    """An educational Ethereum wallet built from this project's primitives.

    A wallet is nothing more than a private scalar e together with everything
    derivable from it.  Construction computes the public key Q = e·G once via
    secp256k1 scalar multiplication; the address and its checksum form are
    derived on demand.

    The single secret is `private_key`; everything else (public key, address,
    signatures) is public and reproducible by anyone holding e.
    """

    def __init__(self, private_key: int):
        """Create a wallet from a private scalar e ∈ [1, N−1].

        The bound is the group order N: scalars are reduced mod N during curve
        arithmetic, so values outside [1, N−1] are either the identity (e ≡ 0)
        or an alias of a smaller key.  Both are rejected to keep keys canonical.

        Args:
            private_key: The private scalar e.

        Raises:
            TypeError:  If private_key is not an int (bool is rejected too).
            ValueError: If private_key is not in [1, N−1].
        """
        if isinstance(private_key, bool) or not isinstance(private_key, int):
            raise TypeError("private_key must be an integer")
        if not (1 <= private_key <= N - 1):
            raise ValueError("private_key must be in [1, N-1]")

        self.private_key = private_key
        # Q = e·G — the same scalar multiplication used for every public key.
        self.public_key = private_key * G

    # -- derived identity ---------------------------------------------------

    @property
    def public_key_bytes(self) -> bytes:
        """The 64-byte uncompressed public key Q_x ‖ Q_y (no 0x04 prefix)."""
        x_bytes = self.public_key.x.number.to_bytes(32, "big")
        y_bytes = self.public_key.y.number.to_bytes(32, "big")
        return x_bytes + y_bytes

    @property
    def address(self) -> bytes:
        """The raw 20-byte Ethereum address derived from the public key."""
        return public_key_to_address(self.public_key)

    @property
    def address_hex(self) -> str:
        """The EIP-55 checksummed, '0x'-prefixed address string."""
        return to_checksum_address(self.address)

    # -- transaction signing ------------------------------------------------

    def sign_transaction(
        self,
        nonce: int,
        gas_price: int,
        gas_limit: int,
        to,
        value: int,
        data: bytes = b"",
        chain_id: int = 1,
    ) -> dict:
        """Sign a legacy (pre-EIP-1559) Ethereum transaction with EIP-155.

        EIP-155 replay protection — the problem and the fix:

          Originally the signed data was the six fields
          [nonce, gas_price, gas_limit, to, value, data].  A signature valid on
          one Ethereum network was therefore equally valid on every other
          network with the same accounts (e.g. a mainnet transfer could be
          "replayed" on a testnet or a fork).  EIP-155 binds a signature to a
          specific chain by folding the chain id into BOTH the signed preimage
          and the published v value.

          Signing preimage.  The hash is taken over the NINE-element list

              [nonce, gas_price, gas_limit, to, value, data, chain_id, 0, 0]

          i.e. the six real fields followed by (chain_id, 0, 0).  The two
          trailing zeros stand in the r and s positions so that the unsigned
          and signed transactions share the same shape.  Because chain_id is
          inside the hash, a signature computed for one chain hashes a
          different message than the same fields on another chain, so it cannot
          be replayed.

          The v value.  A legacy signature publishes v = recovery_id + 27.
          EIP-155 instead publishes

              v = recovery_id + 35 + 2 · chain_id,

          which lets a verifier read the chain id back out of v and confirms,
          a second time, which chain the signature was meant for.

        Procedure:
          1. RLP-encode the nine-element unsigned list.
          2. z = Keccak-256(that encoding), read as a big-endian integer.
          3. (r, s) = ECDSA sign(e, z) using the project's deterministic signer.
          4. Compute the recovery id, then v as above.
          5. RLP-encode [nonce, gas_price, gas_limit, to, value, data, v, r, s]
             to obtain the raw signed transaction bytes.

        Args:
            nonce:     The sender's transaction count (an int ≥ 0).
            gas_price: Price per unit of gas, in wei.
            gas_limit: Maximum gas the transaction may consume.
            to:        Recipient as 20 bytes, a hex string, or None for a
                       contract-creation transaction (empty `to`).
            value:     Amount to transfer, in wei.
            data:      Calldata payload bytes (default empty).
            chain_id:  EIP-155 chain id (1 = Ethereum mainnet).

        Returns:
            A dict with the integer signature components and the serialized
            transaction:
              'v', 'r', 's'           — the published signature values,
              'raw_transaction'       — '0x'-prefixed signed RLP bytes,
              'transaction_hash'      — '0x'-prefixed Keccak-256 of the raw tx.
        """
        recipient = _normalize_recipient(to)

        # 1–2: hash the EIP-155 unsigned preimage.
        unsigned = [nonce, gas_price, gas_limit, recipient, value, data,
                    chain_id, 0, 0]
        signing_hash = keccak256(rlp.encode(unsigned))
        z = int.from_bytes(signing_hash, "big")

        # 3: ECDSA signature (deterministic k via RFC 6979, low-s normalised).
        signature = sign(self.private_key, z)
        r, s = signature.r, signature.s

        # 4: recovery id, then the EIP-155 v.
        recovery_id = _recovery_id(r, s, z, self.public_key)
        v = recovery_id + 35 + 2 * chain_id

        # 5: serialize the signed transaction.
        signed = [nonce, gas_price, gas_limit, recipient, value, data, v, r, s]
        raw = rlp.encode(signed)

        return {
            "v": v,
            "r": r,
            "s": s,
            "raw_transaction": "0x" + raw.hex(),
            "transaction_hash": "0x" + keccak256(raw).hex(),
        }
