# A Merkle tree (Merkle, 1979) is a binary hash tree that provides a
# succinct, tamper-evident commitment to an ordered dataset.  Given a
# dataset T = {d_0, d_1, ..., d_{n-1}}, the tree is built bottom-up:
#
#   Leaf layer:       L_i = H(d_i)                 for each datum d_i
#   Internal nodes:   parent = H(left_child || right_child)
#   Root:             R — the unique node at depth 0
#
# where H is a cryptographic hash function and || denotes concatenation.
#
# ── Integrity guarantee ───────────────────────────────────────────────────
#
# R is a commitment to T.  Formally: suppose an adversary replaces d_j
# with d_j' ≠ d_j and claims the tree root is still R.  The path from
# leaf L_j to the root consists of ⌈log₂ n⌉ hash evaluations.  For the
# claimed root to remain R after the substitution, some internal node on
# that path would need to hash two distinct inputs to the same output —
# a collision in H.  Collision resistance therefore implies root integrity:
# no efficient adversary can alter any leaf without changing the root.
#
# ── Proof of inclusion (Merkle proof) ────────────────────────────────────
#
# To prove d_i ∈ T without transmitting all of T, it suffices to transmit
# only the sibling hash at each level along the path from L_i to the root:
#
#     π_i = [(s_0, b_0), (s_1, b_1), ..., (s_{k-1}, b_{k-1})]
#
# where s_j is the sibling hash at level j and b_j ∈ {left, right}
# indicates on which side of the path node the sibling sits.
#
# Verification recomputes the root from d_i and π_i:
#
#     c_0   = H(d_i)
#     c_{j+1} = H(s_j || c_j)   if b_j = left   (path node is right child)
#             = H(c_j || s_j)   if b_j = right  (path node is left child)
#
# Accept iff c_k = R.
#
# Why this is sound: c_k is an independent computation of what the root
# must be if d_i is the i-th leaf.  If c_k = R and H is collision-resistant,
# the leaf d_i must genuinely be in the tree — constructing a false proof
# for a leaf not in the tree would require finding a hash collision along
# the proof path.
#
# ── Efficiency ────────────────────────────────────────────────────────────
#
# A balanced binary tree with n leaves has ⌈log₂ n⌉ levels, so a Merkle
# proof has O(log n) elements.  For the Bitcoin blockchain, a block with
# 2^13 = 8 192 transactions requires only 13 sibling hashes to prove any
# single transaction — far less than the O(n) cost of listing the whole block.
# This efficiency underpins Bitcoin's Simplified Payment Verification (SPV).
#
# ── Odd leaf counts ───────────────────────────────────────────────────────
#
# Binary pairing requires every internal node to have exactly two children.
# When a level has an odd number of nodes, Bitcoin's convention is to
# duplicate the last node so that every pair is well-defined.  The security
# argument is unaffected: the duplicate is hashed and therefore committed to.

import hashlib


# ---------------------------------------------------------------------------
# Double SHA-256 — dSHA256(x) = SHA256(SHA256(x))
# ---------------------------------------------------------------------------
#
# SHA-256 uses the Merkle-Damgård construction.  Its internal state is
# updated iteratively: given a previous state S and a message block M, the
# compression function yields S' = compress(S, M).  After all blocks are
# processed the final state becomes the digest.
#
# Length extension attack on Merkle-Damgård:
#   Given H(m), an adversary who does NOT know m can compute
#   H(m || pad(m) || suffix) for an arbitrary suffix by initialising the
#   compression function at the final state of H(m) and feeding the extra
#   blocks.  Here pad(m) is the deterministic padding appended inside H.
#
#   In a Merkle tree using single SHA-256, an attacker who observes an
#   internal node hash H(left || right) could exploit length extension to
#   derive H(H(left || right) || pad(left || right) || garbage) and present
#   it as a plausible parent hash — forging tree structure without solving
#   any hard problem.
#
# Why double hashing defeats the attack:
#   dSHA256(x) = SHA256(SHA256(x)).  The inner hash reduces x — regardless
#   of its length — to a fixed 32-byte digest.  The outer SHA256 takes
#   exactly those 32 bytes as its complete input; no extension is possible
#   because the outer hash processes only a single, fixed-length block.
#   The original variable-length x is entirely hidden inside the inner
#   digest; the outer hash has no knowledge of it and cannot be extended.
#
#   Formally: an adversary who knows SHA256(x) cannot compute SHA256(x')
#   for any x' ≠ x without breaking second-preimage resistance of SHA256,
#   so no suffix can be appended to the outer hash's input.
#
# Bitcoin adopted dSHA256 in its original 2009 implementation for block
# headers, transaction IDs, and Merkle tree construction.  (SHA-3/Keccak
# uses a sponge construction that is intrinsically immune to length
# extension and does not require double hashing.)

def _dsha256(data: bytes) -> bytes:
    """SHA256(SHA256(data)) — Bitcoin-style double hashing."""
    inner = hashlib.sha256(data).digest()
    return hashlib.sha256(inner).digest()


# ---------------------------------------------------------------------------
# Merkle Tree
# ---------------------------------------------------------------------------

class MerkleTree:
    """A binary Merkle hash tree over an ordered list of byte-string leaves.

    The tree provides two guarantees rooted in collision resistance of
    double SHA-256:

      1. Commitment: the 32-byte root hash commits to the entire leaf set.
         Any modification to any leaf changes the root with overwhelming
         probability — the probability equals the collision probability of
         dSHA256, which is negligible (~2^{-128} for a random input).

      2. Succinct inclusion proof: for a tree with n leaves, a Merkle proof
         for any single leaf requires O(log n) sibling hashes, not O(n).

    Leaves are raw bytes; the tree hashes them with dSHA256 internally.

    Internal representation:
        self._levels[0]   — leaf hashes  L_i = dSHA256(d_i)
        self._levels[1]   — hashes of pairs from level 0
        ...
        self._levels[-1]  — [root]

    When a level contains an odd number of nodes, the last node is
    duplicated before pairing (Bitcoin convention).  The stored levels
    retain the original unpadded nodes; padding is applied on the fly
    during proof generation so that sibling indices remain well-defined.
    """

    def __init__(self, leaves: list):
        """Build a Merkle tree from an ordered list of byte-string leaves.

        Each leaf d_i is hashed to L_i = dSHA256(d_i), then the tree is
        built bottom-up: each adjacent pair (left, right) at level k
        produces a single node dSHA256(left || right) at level k + 1.

        Args:
            leaves: Non-empty list of bytes objects — the raw data items.

        Raises:
            ValueError: If leaves is empty.
            TypeError:  If any element of leaves is not bytes.
        """
        if not leaves:
            raise ValueError("MerkleTree requires at least one leaf")
        for i, leaf in enumerate(leaves):
            if not isinstance(leaf, bytes):
                raise TypeError(
                    f"every leaf must be bytes; leaf {i} is {type(leaf).__name__}"
                )

        # L_i = dSHA256(d_i) — hash each raw datum into a fixed 32-byte node
        leaf_hashes = [_dsha256(leaf) for leaf in leaves]
        self._levels = _build_levels(leaf_hashes)

    @property
    def root(self) -> bytes:
        """The 32-byte Merkle root — a commitment to the entire leaf set."""
        return self._levels[-1][0]

    def prove(self, index: int) -> list:
        """Generate a Merkle proof of inclusion for the leaf at position index.

        A proof π_i is the minimal set of hashes that lets an independent
        verifier recompute the root from only L_i = dSHA256(d_i):

            π_i = [(s_0, b_0), (s_1, b_1), ..., (s_{k-1}, b_{k-1})]

        where s_j is the sibling hash at level j and b_j is True when
        s_j is the LEFT sibling (meaning the current path node is the
        RIGHT child), and False when s_j is the RIGHT sibling.

        Proof length:
            A balanced tree with n leaves has ⌈log₂ n⌉ levels, so the
            proof has exactly ⌈log₂ n⌉ elements.  For a single leaf the
            proof is empty (no siblings exist); the root equals dSHA256(d_0).

        Args:
            index: Zero-based leaf index, 0 ≤ index < n.

        Returns:
            List of (sibling_hash: bytes, sibling_is_left: bool) tuples.

        Raises:
            IndexError: If index is out of range [0, n).
        """
        n = len(self._levels[0])
        if not (0 <= index < n):
            raise IndexError(
                f"leaf index {index} is out of range for a tree with {n} leaves"
            )

        proof = []
        idx = index

        # Traverse every level except the root (which has no sibling)
        for level in self._levels[:-1]:
            # Odd-length levels are padded by duplicating the last node so
            # that every node — including the last — has a well-defined sibling.
            if len(level) % 2 == 1:
                padded = level + [level[-1]]
            else:
                padded = level

            if idx % 2 == 0:
                # idx is a LEFT child; its sibling is the node to the right.
                # During verification: combine as dSHA256(current || sibling).
                sibling = padded[idx + 1]
                sibling_is_left = False
            else:
                # idx is a RIGHT child; its sibling is the node to the left.
                # During verification: combine as dSHA256(sibling || current).
                sibling = padded[idx - 1]
                sibling_is_left = True

            proof.append((sibling, sibling_is_left))
            idx //= 2   # move to the parent's position in the next level

        return proof

    @staticmethod
    def verify_proof(leaf_data: bytes, proof: list, expected_root: bytes) -> bool:
        """Verify a Merkle proof of inclusion.

        Recomputes the root by applying sibling hashes one level at a time,
        starting from dSHA256(leaf_data):

            c_0   = dSHA256(leaf_data)
            c_{j+1} = dSHA256(s_j || c_j)   if s_j is the left sibling
                    = dSHA256(c_j || s_j)   if s_j is the right sibling

        c_k is what the root must equal if leaf_data is the claimed leaf.
        Comparing c_k to expected_root completes the verification.

        Security argument:
            Suppose an adversary wants to produce a false proof that
            some data d' (not in the tree) is a leaf.  The adversary must
            supply sibling hashes s_0, ..., s_{k-1} such that c_k equals
            the honest root R.  At the first level where c_j diverges from
            the real path value, the adversary must find s_j such that
            dSHA256(... || c_j_fake || ...) = dSHA256(... || c_j_real || ...).
            This is a second-preimage attack on dSHA256, which is believed
            infeasible (~2^{256} work against the best known attacks).

        Args:
            leaf_data:     Raw bytes of the claimed leaf (before hashing).
            proof:         List of (sibling_hash, sibling_is_left) tuples
                           as returned by MerkleTree.prove().
            expected_root: The trusted 32-byte Merkle root.

        Returns:
            True iff the recomputed root equals expected_root.
        """
        current = _dsha256(leaf_data)

        for sibling_hash, sibling_is_left in proof:
            if sibling_is_left:
                # Path node is the right child: parent = H(sibling || current)
                current = _dsha256(sibling_hash + current)
            else:
                # Path node is the left child: parent = H(current || sibling)
                current = _dsha256(current + sibling_hash)

        return current == expected_root


# ---------------------------------------------------------------------------
# Internal helper — build all tree levels from leaf hashes
# ---------------------------------------------------------------------------

def _build_levels(leaf_hashes: list) -> list:
    """Return all levels of the Merkle tree, from leaves to root.

    result[0]  = leaf_hashes (unchanged)
    result[j]  = parent hashes of result[j-1]
    result[-1] = [root]

    Odd-length levels are padded by one duplicated node before computing
    parent hashes, but the stored levels are unpadded.  This separation
    keeps level[i] length equal to the number of actual nodes at that
    depth, which is what prove() expects when computing sibling indices.
    """
    levels = [list(leaf_hashes)]
    current = levels[0]

    while len(current) > 1:
        # Pad to even length (Bitcoin convention: duplicate the last node)
        if len(current) % 2 == 1:
            padded = current + [current[-1]]
        else:
            padded = current

        # parent_i = dSHA256(padded[2i] || padded[2i+1])
        next_level = [
            _dsha256(padded[i] + padded[i + 1])
            for i in range(0, len(padded), 2)
        ]
        levels.append(next_level)
        current = next_level

    return levels
