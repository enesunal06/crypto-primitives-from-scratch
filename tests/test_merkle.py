"""
Tests for MerkleTree — binary hash tree with proof of inclusion.

A Merkle tree over a dataset T = {d_0, ..., d_{n-1}} commits to T via a
root hash R.  Altering any d_i changes R with probability negligible in the
security parameter (collision resistance of dSHA256 gives ~2^{-128}).

Mathematical properties verified:
- Root correctness: R is computed correctly for all leaf-count cases
- Bitcoin odd-leaf convention: last node is duplicated at odd-length levels
- Proof completeness: every leaf index generates a proof accepted by verify_proof()
- Proof soundness: altering the leaf, any sibling hash, or the expected root
  causes verify_proof() to return False
- Double SHA-256: dSHA256(x) = SHA256(SHA256(x)), not single SHA-256
- Proof size: ⌈log₂ n⌉ sibling hashes suffice for a tree with n leaves
"""

import hashlib
import math
import pytest

from src.merkle import MerkleTree, _dsha256


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def dsha256(data: bytes) -> bytes:
    """Reference implementation of double SHA-256, independent of src/merkle.py."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


# ---------------------------------------------------------------------------
# Double SHA-256 — hash function correctness
# ---------------------------------------------------------------------------

def test_dsha256_is_double_not_single_sha256():
    # dSHA256(x) must equal SHA256(SHA256(x)), not SHA256(x).
    # Single SHA256 is vulnerable to length extension; double SHA256 is not.
    data = b"hello world"
    single_hash = hashlib.sha256(data).digest()
    double_hash = hashlib.sha256(single_hash).digest()

    assert _dsha256(data) == double_hash
    assert _dsha256(data) != single_hash


def test_dsha256_output_is_always_32_bytes():
    # SHA-256 always produces a 256-bit = 32-byte digest, regardless of
    # input length.  This fixed output size is what makes tree nodes uniform.
    for data in [b"", b"a", b"a" * 55, b"a" * 56, b"a" * 1000]:
        assert len(_dsha256(data)) == 32, f"wrong length for input of {len(data)} bytes"


def test_dsha256_is_deterministic():
    # The same input always produces the same digest.
    data = b"determinism"
    assert _dsha256(data) == _dsha256(data)


def test_dsha256_distinct_inputs_produce_distinct_outputs():
    # Given collision resistance, distinct inputs must produce distinct outputs
    # with overwhelming probability.  This property underlies the integrity
    # guarantee: changing any leaf changes the root.
    assert _dsha256(b"left") != _dsha256(b"right")
    assert _dsha256(b"abc") != _dsha256(b"abd")        # differ in the last byte


# ---------------------------------------------------------------------------
# Root Computation — correctness derived from first principles
# ---------------------------------------------------------------------------

def test_single_leaf_root_equals_hash_of_leaf():
    # For n = 1 there are no internal nodes; the root is simply dSHA256(d_0).
    leaf = b"satoshi"
    tree = MerkleTree([leaf])
    assert tree.root == dsha256(leaf)


def test_two_leaf_root_equals_hash_of_concatenated_leaf_hashes():
    # For n = 2:
    #   L_0 = dSHA256(d_0),  L_1 = dSHA256(d_1)
    #   root = dSHA256(L_0 || L_1)
    #
    # The root commits to both leaves and their ORDER: swapping d_0 and d_1
    # produces a different concatenation and therefore a different root.
    d0, d1 = b"left", b"right"
    L0, L1 = dsha256(d0), dsha256(d1)
    expected_root = dsha256(L0 + L1)

    assert MerkleTree([d0, d1]).root == expected_root


def test_four_leaf_root_matches_manual_computation():
    # For n = 4 (a balanced tree with two internal levels):
    #   L_0, L_1, L_2, L_3  (leaf hashes)
    #   I_01 = dSHA256(L_0 || L_1),  I_23 = dSHA256(L_2 || L_3)
    #   root = dSHA256(I_01 || I_23)
    leaves = [b"a", b"b", b"c", b"d"]
    L = [dsha256(x) for x in leaves]
    I01 = dsha256(L[0] + L[1])
    I23 = dsha256(L[2] + L[3])
    expected_root = dsha256(I01 + I23)

    assert MerkleTree(leaves).root == expected_root


def test_odd_leaf_count_duplicates_last_node():
    # For n = 3 (Bitcoin odd-leaf convention: L_2 is duplicated):
    #   L_0, L_1, L_2
    #   I_01 = dSHA256(L_0 || L_1),  I_22 = dSHA256(L_2 || L_2)
    #   root = dSHA256(I_01 || I_22)
    #
    # The duplicate is committed to via I_22, so the security argument is
    # unchanged: altering d_2 still changes I_22 and therefore the root.
    leaves = [b"tx0", b"tx1", b"tx2"]
    L = [dsha256(x) for x in leaves]
    I01 = dsha256(L[0] + L[1])
    I22 = dsha256(L[2] + L[2])          # last leaf duplicated to form a pair
    expected_root = dsha256(I01 + I22)

    assert MerkleTree(leaves).root == expected_root


def test_five_leaf_root_matches_manual_computation():
    # For n = 5 the duplication happens at two distinct levels:
    #
    #   Level 0 (5 nodes → pad to 6):
    #     I_01 = dSHA256(L_0 || L_1)
    #     I_23 = dSHA256(L_2 || L_3)
    #     I_44 = dSHA256(L_4 || L_4)   ← duplicate L_4
    #
    #   Level 1 (3 nodes → pad to 4):
    #     P_0123 = dSHA256(I_01 || I_23)
    #     P_4444 = dSHA256(I_44 || I_44)  ← duplicate I_44
    #
    #   Level 2 (2 nodes → no padding needed):
    #     root = dSHA256(P_0123 || P_4444)
    leaves = [b"a", b"b", b"c", b"d", b"e"]
    L = [dsha256(x) for x in leaves]
    I01   = dsha256(L[0] + L[1])
    I23   = dsha256(L[2] + L[3])
    I44   = dsha256(L[4] + L[4])
    P0123 = dsha256(I01 + I23)
    P4444 = dsha256(I44 + I44)
    expected_root = dsha256(P0123 + P4444)

    assert MerkleTree(leaves).root == expected_root


def test_leaf_order_affects_root():
    # Concatenation is not commutative: H(L_0 || L_1) ≠ H(L_1 || L_0) in general.
    # Swapping two leaves must therefore change the root.
    # This is essential: if order did not matter, a reordering attack could
    # produce the same root for a different transaction sequence.
    tree1 = MerkleTree([b"alpha", b"beta"])
    tree2 = MerkleTree([b"beta", b"alpha"])
    assert tree1.root != tree2.root


def test_different_leaf_sets_produce_different_roots():
    # Collision resistance implies distinct trees have distinct roots (except
    # with negligible probability 2^{-128}).  This is the binding property
    # of the commitment: the root uniquely determines the leaf set.
    t1 = MerkleTree([b"a", b"b"])
    t2 = MerkleTree([b"a", b"c"])
    assert t1.root != t2.root


def test_root_is_32_bytes():
    # dSHA256 output is always 256 bits = 32 bytes, so the root is too.
    for n in [1, 2, 3, 7, 8]:
        leaves = [i.to_bytes(4, "big") for i in range(n)]
        assert len(MerkleTree(leaves).root) == 32


# ---------------------------------------------------------------------------
# Proof Completeness — every leaf produces a valid proof
# ---------------------------------------------------------------------------

def test_single_leaf_proof_is_empty_and_verifies():
    # A single-leaf tree has no siblings; the proof has zero elements.
    # Verification degenerates to: dSHA256(leaf) == root, which holds by
    # definition since the root IS the single leaf hash.
    leaf = b"lone"
    tree = MerkleTree([leaf])
    proof = tree.prove(0)
    assert proof == []
    assert MerkleTree.verify_proof(leaf, proof, tree.root)


def test_proof_verifies_for_every_leaf_in_two_leaf_tree():
    leaves = [b"left", b"right"]
    tree = MerkleTree(leaves)
    root = tree.root
    for i, leaf in enumerate(leaves):
        proof = tree.prove(i)
        assert MerkleTree.verify_proof(leaf, proof, root), f"proof failed for leaf {i}"


def test_proof_verifies_for_every_leaf_in_four_leaf_tree():
    # Balanced tree: no duplicate-last-node logic is triggered.
    leaves = [b"tx0", b"tx1", b"tx2", b"tx3"]
    tree = MerkleTree(leaves)
    root = tree.root
    for i, leaf in enumerate(leaves):
        proof = tree.prove(i)
        assert MerkleTree.verify_proof(leaf, proof, root), f"proof failed for leaf {i}"


def test_proof_verifies_for_every_leaf_in_odd_tree():
    # Odd-length tree: the duplicate-last-node path must be exercised at
    # least once and the last leaf (whose duplicate acts as its own sibling)
    # must still produce a valid proof.
    leaves = [b"a", b"b", b"c", b"d", b"e"]
    tree = MerkleTree(leaves)
    root = tree.root
    for i, leaf in enumerate(leaves):
        proof = tree.prove(i)
        assert MerkleTree.verify_proof(leaf, proof, root), f"proof failed for leaf {i}"


def test_proof_verifies_for_large_tree():
    # Stress test: all leaves in a 16-leaf tree must be individually provable.
    leaves = [i.to_bytes(4, "big") for i in range(16)]
    tree = MerkleTree(leaves)
    root = tree.root
    for i, leaf in enumerate(leaves):
        assert MerkleTree.verify_proof(leaf, tree.prove(i), root)


# ---------------------------------------------------------------------------
# Proof Structure — manual verification from first principles
# ---------------------------------------------------------------------------

def test_proof_structure_for_two_leaf_tree_left_leaf():
    # For n = 2, the proof for leaf 0 (left child) is:
    #   [(L_1, False)]  — L_1 is the right sibling; combine as H(L_0 || L_1).
    #
    # Verification:
    #   c_0 = dSHA256(d_0) = L_0
    #   (L_1, right sibling): c_1 = dSHA256(L_0 || L_1) = root  ✓
    d0, d1 = b"left", b"right"
    L0, L1 = dsha256(d0), dsha256(d1)
    tree = MerkleTree([d0, d1])

    proof = tree.prove(0)
    assert len(proof) == 1
    sibling_hash, sibling_is_left = proof[0]
    assert sibling_hash == L1
    assert sibling_is_left == False     # L_1 is the right sibling of L_0


def test_proof_structure_for_two_leaf_tree_right_leaf():
    # For n = 2, the proof for leaf 1 (right child) is:
    #   [(L_0, True)]  — L_0 is the left sibling; combine as H(L_0 || L_1).
    #
    # Verification:
    #   c_0 = dSHA256(d_1) = L_1
    #   (L_0, left sibling): c_1 = dSHA256(L_0 || L_1) = root  ✓
    d0, d1 = b"left", b"right"
    L0 = dsha256(d0)
    tree = MerkleTree([d0, d1])

    proof = tree.prove(1)
    assert len(proof) == 1
    sibling_hash, sibling_is_left = proof[0]
    assert sibling_hash == L0
    assert sibling_is_left == True      # L_0 is the left sibling of L_1


def test_proof_structure_for_four_leaf_tree_index_0():
    # For n = 4, the proof for leaf 0 traces the left spine:
    #
    #   Level 0: sibling = L_1 (right), so proof[0] = (L_1, False)
    #   Level 1: sibling = I_23 (right), so proof[1] = (I_23, False)
    #
    # Verification:
    #   c_0 = L_0
    #   c_1 = dSHA256(L_0 || L_1) = I_01
    #   c_2 = dSHA256(I_01 || I_23) = root  ✓
    leaves = [b"a", b"b", b"c", b"d"]
    L = [dsha256(x) for x in leaves]
    I01 = dsha256(L[0] + L[1])
    I23 = dsha256(L[2] + L[3])

    tree = MerkleTree(leaves)
    proof = tree.prove(0)

    assert len(proof) == 2
    assert proof[0] == (L[1], False)    # right sibling at level 0
    assert proof[1] == (I23, False)     # right sibling at level 1

    # Manual one-step reconstruction
    assert dsha256(L[0] + proof[0][0]) == I01
    assert dsha256(I01 + proof[1][0]) == tree.root


def test_proof_structure_for_four_leaf_tree_index_3():
    # For n = 4, the proof for leaf 3 traces the right spine:
    #
    #   Level 0: sibling = L_2 (left), so proof[0] = (L_2, True)
    #   Level 1: sibling = I_01 (left), so proof[1] = (I_01, True)
    #
    # Verification:
    #   c_0 = L_3
    #   c_1 = dSHA256(L_2 || L_3) = I_23
    #   c_2 = dSHA256(I_01 || I_23) = root  ✓
    leaves = [b"a", b"b", b"c", b"d"]
    L = [dsha256(x) for x in leaves]
    I01 = dsha256(L[0] + L[1])

    tree = MerkleTree(leaves)
    proof = tree.prove(3)

    assert len(proof) == 2
    assert proof[0] == (L[2], True)     # left sibling at level 0
    assert proof[1] == (I01, True)      # left sibling at level 1


def test_proof_size_equals_ceil_log2_of_leaf_count():
    # A binary tree with n leaves has ⌈log₂ n⌉ internal levels, so each
    # proof requires exactly ⌈log₂ n⌉ sibling hashes.
    for n in [1, 2, 3, 4, 5, 7, 8, 9, 16, 17]:
        leaves = [i.to_bytes(4, "big") for i in range(n)]
        tree = MerkleTree(leaves)
        expected_len = math.ceil(math.log2(n)) if n > 1 else 0
        proof = tree.prove(0)
        assert len(proof) == expected_len, (
            f"wrong proof length for n={n}: expected {expected_len}, got {len(proof)}"
        )


# ---------------------------------------------------------------------------
# Proof Soundness — tampered inputs are rejected
# ---------------------------------------------------------------------------

def test_wrong_leaf_data_fails_verification():
    # A proof for d_i is not valid for any d' ≠ d_i.
    # Substituting d' changes c_0 = dSHA256(d'), and the recomputed chain
    # diverges from the root at the first level (unless a collision occurs,
    # which has probability ~2^{-256}).
    leaves = [b"correct", b"other"]
    tree = MerkleTree(leaves)
    proof = tree.prove(0)

    assert not MerkleTree.verify_proof(b"tampered", proof, tree.root)


def test_tampered_sibling_hash_fails_verification():
    # Flipping any bit of a sibling hash changes the recomputed internal
    # node at that level, causing the chain to diverge from the root.
    # This is the collision resistance argument applied at one level.
    leaves = [b"a", b"b", b"c", b"d"]
    tree = MerkleTree(leaves)
    proof = tree.prove(0)

    # Flip the lowest bit of the first sibling hash
    bad_sibling, side = proof[0]
    bad_proof = [(bytes([bad_sibling[0] ^ 1]) + bad_sibling[1:], side)] + proof[1:]
    assert not MerkleTree.verify_proof(b"a", bad_proof, tree.root)


def test_wrong_expected_root_fails_verification():
    # A valid proof is specific to the exact root it was generated from.
    # A different root represents a different tree; the recomputed value
    # will match only the original root, not the altered one.
    leaves = [b"a", b"b"]
    tree = MerkleTree(leaves)
    proof = tree.prove(0)

    wrong_root = bytes([tree.root[0] ^ 1]) + tree.root[1:]
    assert not MerkleTree.verify_proof(b"a", proof, wrong_root)


def test_proof_for_one_leaf_cannot_prove_another():
    # A proof generated for index i is keyed to that path in the tree.
    # Using proof_i to claim that a different datum d_j is at position i
    # produces a wrong recomputed root because dSHA256(d_j) ≠ dSHA256(d_i).
    leaves = [b"alpha", b"beta", b"gamma", b"delta"]
    tree = MerkleTree(leaves)
    proof_for_0 = tree.prove(0)

    # Try to "prove" that b"beta" (leaf 1) verifies with proof_for_0 — must fail
    assert not MerkleTree.verify_proof(b"beta", proof_for_0, tree.root)


def test_proof_from_different_tree_fails_for_same_leaf():
    # Two trees that share the same leaves in different order have different
    # roots and different proof paths.  A proof from tree A is invalid for
    # tree B even if the leaf datum is the same.
    tree_a = MerkleTree([b"x", b"y", b"z", b"w"])
    tree_b = MerkleTree([b"z", b"y", b"x", b"w"])

    # Proof that b"x" is at index 0 in tree_a
    proof = tree_a.prove(0)
    # Must fail against tree_b's root (x is at index 2 in tree_b)
    assert not MerkleTree.verify_proof(b"x", proof, tree_b.root)


# ---------------------------------------------------------------------------
# Edge Cases and Input Validation
# ---------------------------------------------------------------------------

def test_empty_leaves_raises_value_error():
    # A tree with no leaves has no root to commit to — raise ValueError.
    with pytest.raises(ValueError):
        MerkleTree([])


def test_non_bytes_leaf_raises_type_error():
    # Leaves must be bytes; strings, integers, etc. are rejected so that
    # the caller cannot accidentally mix encodings.
    with pytest.raises(TypeError):
        MerkleTree(["string leaf"])
    with pytest.raises(TypeError):
        MerkleTree([b"valid", 42])
    with pytest.raises(TypeError):
        MerkleTree([b"valid", b"valid", b"valid", None])


def test_out_of_range_index_raises_index_error():
    tree = MerkleTree([b"a", b"b", b"c"])
    with pytest.raises(IndexError):
        tree.prove(3)          # n = 3, valid range is [0, 2]
    with pytest.raises(IndexError):
        tree.prove(-1)         # negative indices are not supported
