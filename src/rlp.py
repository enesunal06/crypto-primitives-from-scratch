# RLP — Recursive Length Prefix encoding (Ethereum's serialization format).
#
# Ethereum needs a single, canonical way to turn structured data (a
# transaction is a list of numbers and byte strings) into a flat byte string,
# so that two implementations always hash the *same* bytes and therefore agree
# on transaction identities and signatures.
#
# ── Why a bespoke format instead of JSON or protobuf? ──────────────────────
#
# A signature commits to a hash of the serialized transaction.  If two valid
# encodings of the same logical transaction existed, they would hash
# differently, and a signature over one would not cover the other — opening
# the door to malleability.  RLP is deliberately minimal and *canonical*:
# there is exactly one valid encoding of any value (integers carry no leading
# zero bytes, short strings cannot be written with a long-form prefix, etc.).
# It also encodes nothing about *types* — only the nesting structure of byte
# strings and lists.  Interpreting the bytes as numbers or addresses is left
# entirely to the layer above.  This is what keeps the rules tiny.
#
# ── The two grammars ───────────────────────────────────────────────────────
#
# RLP encodes exactly two kinds of item: a byte string, or a list of items.
#
#   Byte string:
#     • a single byte in [0x00, 0x7f] is its own encoding (no prefix);
#     • a string of length 0–55 is prefixed with 0x80 + length;
#     • a longer string is prefixed with 0xb7 + (length of the length), then
#       the length itself in big-endian, then the bytes.
#
#   List (let P be the concatenated encodings of its items):
#     • if len(P) is 0–55, prefix with 0xc0 + len(P);
#     • otherwise prefix with 0xf7 + (length of len(P)), then len(P), then P.
#
# The offsets 0x80 and 0xc0 are what let a decoder tell a string from a list
# just by looking at the first byte.

# ---------------------------------------------------------------------------
# Length prefixes
# ---------------------------------------------------------------------------

def _int_to_big_endian(value: int) -> bytes:
    """Encode a non-negative integer as its shortest big-endian byte string.

    Canonicality requires no leading zero bytes, so the integer 0 maps to the
    *empty* string b'' rather than b'\\x00'.  This is the same convention RLP
    uses for the number zero inside a transaction.
    """
    if value < 0:
        raise ValueError("RLP cannot encode negative integers")
    if value == 0:
        return b""
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def _encode_length(length: int, offset: int) -> bytes:
    """Build the length prefix for a payload of `length` bytes.

    `offset` is 0x80 for byte strings and 0xc0 for lists.  Payloads up to 55
    bytes fold the length directly into a single prefix byte; longer payloads
    use the "length of the length" long form.
    """
    if length < 56:
        return bytes([offset + length])
    length_bytes = _int_to_big_endian(length)
    # offset + 55 is the boundary; adding len(length_bytes) selects the
    # long-form prefix (0xb7+.. for strings, 0xf7+.. for lists).
    return bytes([offset + 55 + len(length_bytes)]) + length_bytes


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------

def _encode_bytes(raw: bytes) -> bytes:
    """Encode a raw byte string under the RLP string grammar."""
    # A single low byte is already its own canonical encoding — adding a 0x80
    # prefix would be a second, non-canonical way to write the same value.
    if len(raw) == 1 and raw[0] < 0x80:
        return raw
    return _encode_length(len(raw), 0x80) + raw


def encode(item) -> bytes:
    """RLP-encode an item: bytes, int, str, or a (possibly nested) list.

    Type handling — RLP itself only knows byte strings and lists, so we map
    Python types down to byte strings as Ethereum does:

      bytes / bytearray : taken verbatim (e.g. a 20-byte address).
      int               : the shortest big-endian encoding; 0 → b'' (the
                          empty string), matching RLP's canonical form for
                          numbers such as a zero nonce or value.
      str               : UTF-8 encoded, then treated as a byte string.
      list / tuple      : each element is encoded recursively and the results
                          are concatenated, then wrapped with a list prefix.

    bool is rejected explicitly: although bool is a subclass of int in Python,
    True/False are not meaningful transaction fields and silently encoding
    them as 1/0 would hide bugs.

    Args:
        item: The value to encode.

    Returns:
        The RLP byte string.

    Raises:
        TypeError: If `item` is not one of the supported types.
    """
    if isinstance(item, (bytes, bytearray)):
        return _encode_bytes(bytes(item))
    if isinstance(item, bool):
        raise TypeError("RLP will not encode a bool; pass an int explicitly")
    if isinstance(item, int):
        return _encode_bytes(_int_to_big_endian(item))
    if isinstance(item, str):
        return _encode_bytes(item.encode("utf-8"))
    if isinstance(item, (list, tuple)):
        payload = b"".join(encode(element) for element in item)
        return _encode_length(len(payload), 0xC0) + payload
    raise TypeError(f"cannot RLP-encode object of type {type(item).__name__}")
