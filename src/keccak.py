# Keccak-256 — the hash function Ethereum uses for addresses and transaction
# hashing.
#
# Keccak is built on the *sponge construction*, a different paradigm from the
# Merkle-Damgård design of SHA-256 (see merkle.py).  A sponge has an internal
# state of b = r + c bits, split into:
#
#   rate     r — the part of the state that exchanges data with the outside.
#   capacity c — the part that is never touched directly; it is the secret
#                "reservoir" that provides the security margin.
#
# Hashing proceeds in two phases:
#
#   Absorb:  the padded message is cut into r-bit blocks.  Each block is XORed
#            into the first r bits of the state, then the whole state is run
#            through the permutation f.
#   Squeeze: output bits are read from the first r bits of the state, applying
#            f again whenever more output is needed.
#
# For Keccak-256 the parameters are b = 1600, c = 512, r = 1088 bits
# (= 136 bytes), and the digest is 256 bits (= 32 bytes).  A single squeeze of
# 32 bytes fits inside one rate block, so the squeeze phase never needs a
# second permutation here.
#
# ── Why Keccak-256 and not SHA3-256? ───────────────────────────────────────
#
# When NIST standardised Keccak as SHA-3 (FIPS 202, 2015) it changed ONE
# detail: the domain-separation bits appended during padding.  SHA3-256
# appends the bits 01 before the pad10*1 rule (yielding a first pad byte of
# 0x06), whereas the original Keccak submission appends nothing extra (first
# pad byte 0x01).  Ethereum was built in 2014–2015 against the original
# Keccak, before FIPS 202 froze the standard, and never migrated.  As a
# result Ethereum's "keccak256" is NOT interchangeable with hashlib.sha3_256:
# the two functions produce completely different digests for the same input.
# This file therefore implements the original Keccak padding (0x01), which is
# why we cannot simply call hashlib.

# ---------------------------------------------------------------------------
# Keccak-f[1600] permutation constants
# ---------------------------------------------------------------------------
#
# The permutation operates on a 5×5 grid of 64-bit "lanes" (25 × 64 = 1600
# bits).  We store the grid as a flat list of 25 integers; the lane at column
# x and row y lives at index x + 5·y.

_NUMBER_OF_ROUNDS = 24
_LANE_MASK = (1 << 64) - 1   # keeps every lane within 64 bits


# Round constants RC[i] for the iota step.  They are the output of a small
# linear-feedback shift register and break the symmetry between rounds, so
# that no two rounds are identical.  These values are fixed by the standard.
_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)

# Rotation offsets for the rho step, indexed _ROTATION_OFFSETS[x][y].  Each
# lane is cyclically rotated left by a fixed amount; the amounts are the
# triangular numbers laid out across the grid in the order prescribed by the
# standard.  This is what gives Keccak its diffusion across lane positions.
_ROTATION_OFFSETS = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)


def _rotl64(value: int, shift: int) -> int:
    """Cyclically rotate a 64-bit word left by `shift` bits."""
    shift %= 64
    return ((value << shift) | (value >> (64 - shift))) & _LANE_MASK


def _keccak_f(state: list) -> None:
    """Apply the Keccak-f[1600] permutation to `state` in place.

    Each of the 24 rounds is the composition of five invertible step mappings,
    each named with a Greek letter in the specification:

      θ (theta): mixes every lane with the parity of two neighbouring columns,
                 giving long-range diffusion across the whole state.
      ρ (rho):   rotates each lane by a fixed offset (intra-lane diffusion).
      π (pi):    permutes the positions of the lanes within the 5×5 grid.
      χ (chi):   the only non-linear step — combines each lane with two of its
                 row neighbours through AND and NOT.  Without χ the entire
                 permutation would be linear and trivially invertible.
      ι (iota):  XORs a round constant into lane (0,0) to break round symmetry.

    The permutation is bijective: every step is reversible, so f is a genuine
    permutation of the 2^1600 possible states, not a compressing function.
    """
    for round_index in range(_NUMBER_OF_ROUNDS):
        # --- θ (theta) ---
        # C[x] is the XOR of the whole column x; D[x] folds in the parity of
        # the two columns x−1 and x+1 (the latter rotated by one bit).
        column_parity = [
            state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
            for x in range(5)
        ]
        theta_d = [
            column_parity[(x - 1) % 5] ^ _rotl64(column_parity[(x + 1) % 5], 1)
            for x in range(5)
        ]
        for x in range(5):
            for y in range(0, 25, 5):
                state[x + y] ^= theta_d[x]

        # --- ρ (rho) and π (pi), fused into one rebuild of the grid ---
        # ρ rotates lane (x,y) by its offset; π then moves it to position
        # (y, 2x+3y).  Doing both at once avoids a temporary copy per step.
        permuted = [0] * 25
        for x in range(5):
            for y in range(5):
                new_x = y
                new_y = (2 * x + 3 * y) % 5
                permuted[new_x + 5 * new_y] = _rotl64(
                    state[x + 5 * y], _ROTATION_OFFSETS[x][y]
                )

        # --- χ (chi): the non-linear mixing within each row ---
        for y in range(0, 25, 5):
            for x in range(5):
                state[x + y] = permuted[x + y] ^ (
                    (~permuted[(x + 1) % 5 + y] & _LANE_MASK) & permuted[(x + 2) % 5 + y]
                )

        # --- ι (iota): inject the round constant ---
        state[0] ^= _ROUND_CONSTANTS[round_index]


# ---------------------------------------------------------------------------
# Sponge: absorb → squeeze
# ---------------------------------------------------------------------------

_RATE_BYTES = 136   # r = 1088 bits = 136 bytes for Keccak-256
_OUTPUT_BYTES = 32  # 256-bit digest


def keccak256(data: bytes) -> bytes:
    """Return the 32-byte Keccak-256 digest of `data` (Ethereum's hash).

    Steps:

      1. Pad the message with the original-Keccak pad10*1 rule so its length
         becomes a multiple of the rate.  Concretely: append the byte 0x01,
         then zero bytes, then set the top bit (0x80) of the final byte.  When
         only one padding byte is needed it becomes 0x01 ^ 0x80 = 0x81.

      2. Absorb: XOR each 136-byte block into the first 17 lanes of the state
         (lanes are read little-endian, the Keccak byte convention) and run
         the permutation after every block.

      3. Squeeze: read the first 32 bytes back out of the state, again
         little-endian.  Since 32 < 136, one block of output suffices.

    Args:
        data: The message to hash, as a bytes object.

    Returns:
        The 32-byte Keccak-256 digest.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("keccak256 expects bytes")

    # --- padding (original Keccak pad10*1, domain byte 0x01) ---
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % _RATE_BYTES != 0:
        padded.append(0x00)
    padded[-1] ^= 0x80

    # --- absorb ---
    state = [0] * 25
    lanes_per_block = _RATE_BYTES // 8   # 17 lanes carry message data
    for offset in range(0, len(padded), _RATE_BYTES):
        block = padded[offset:offset + _RATE_BYTES]
        for i in range(lanes_per_block):
            lane = int.from_bytes(block[i * 8:i * 8 + 8], "little")
            state[i] ^= lane
        _keccak_f(state)

    # --- squeeze ---
    output = bytearray()
    while len(output) < _OUTPUT_BYTES:
        for i in range(lanes_per_block):
            output += state[i].to_bytes(8, "little")
            if len(output) >= _OUTPUT_BYTES:
                break
        if len(output) < _OUTPUT_BYTES:
            _keccak_f(state)

    return bytes(output[:_OUTPUT_BYTES])


if __name__ == "__main__":
    # Two standard Keccak-256 test vectors (NOT SHA3-256 values):
    #   keccak256("")    = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
    #   keccak256("abc") = 4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
    print("keccak256('')    =", keccak256(b"").hex())
    print("keccak256('abc') =", keccak256(b"abc").hex())
