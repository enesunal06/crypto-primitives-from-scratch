"""
Tests for the secp256k1 curve parameters.

secp256k1 is the elliptic curve y^2 = x^3 + 7 over the prime field F_P,
standardised by SECG (Standards for Efficient Cryptography Group, SEC 2,
2010).  It is the curve underlying Bitcoin's and Ethereum's key pairs.

Mathematical properties verified:
- G lies on the curve: G.y^2 ≡ G.x^3 + 7 (mod P)
- G has order N: N · G = O (the additive identity)
- Scalar multiplication is consistent with repeated addition
- The homomorphism (a + b) · G = a · G + b · G holds in the group
"""

import pytest

from src.ecdsa import G, Gx, Gy, INF, N, P, A, B, S256Field


# ---------------------------------------------------------------------------
# Generator Point Membership
# ---------------------------------------------------------------------------

def test_generator_point_satisfies_curve_equation():
    # G = (Gx, Gy) must satisfy y^2 ≡ x^3 + 7 (mod P).
    # This confirms that the hard-coded coordinates are actually on the curve
    # and that S256Field arithmetic is working correctly.
    gx = S256Field(Gx)
    gy = S256Field(Gy)
    assert gy ** 2 == gx ** 3 + S256Field(B)


def test_generator_point_coordinates_match_standard():
    # The coordinates stored in G must equal the standard-specified constants.
    assert G.x.number == Gx
    assert G.y.number == Gy


def test_generator_point_is_on_secp256k1_curve():
    # Point.__init__ raises ValueError if the point does not satisfy the curve
    # equation.  Successful construction of G already implies membership, but
    # we re-verify the field parameters explicitly.
    assert G.a.number == A   # coefficient a = 0 (no x term)
    assert G.b.number == B   # coefficient b = 7


# ---------------------------------------------------------------------------
# Group Order
# ---------------------------------------------------------------------------

def test_generator_has_order_N():
    # The group order N satisfies N · G = O (the point at infinity).
    # This is the defining property of N: it is the smallest positive integer
    # for which scalar multiplication by G returns the identity.
    # If this assertion fails, N is wrong and every ECDSA computation breaks.
    assert N * G == INF


def test_scalar_zero_gives_point_at_infinity():
    # 0 · G = O by definition of scalar multiplication: the empty sum.
    assert 0 * G == INF


def test_scalar_one_gives_generator():
    # 1 · G = G — scalar multiplication by 1 is the identity map.
    assert 1 * G == G


def test_order_minus_one_gives_negation_of_generator():
    # (N − 1) · G = −G, because N · G = O implies (N − 1) · G + G = O.
    # −G has the same x-coordinate as G but the negated y-coordinate.
    neg_G = (N - 1) * G
    assert neg_G.x.number == Gx
    assert neg_G.y.number == P - Gy   # additive inverse in F_P: −y ≡ P − y


# ---------------------------------------------------------------------------
# Scalar Multiplication Consistency
# ---------------------------------------------------------------------------

def test_two_times_G_equals_G_plus_G():
    # 2 · G must equal G + G — verifies that the double-and-add algorithm
    # agrees with direct point addition for the smallest nontrivial case.
    assert 2 * G == G + G


def test_three_times_G_equals_G_plus_G_plus_G():
    assert 3 * G == G + G + G


def test_scalar_multiplication_is_consistent_for_larger_values():
    # Verify that the double-and-add algorithm gives the same result as
    # repeated addition for a non-trivial scalar.
    k = 10
    by_scalar = k * G
    by_addition = G
    for _ in range(k - 1):
        by_addition = by_addition + G
    assert by_scalar == by_addition


# ---------------------------------------------------------------------------
# Group Homomorphism
# ---------------------------------------------------------------------------

def test_distributive_law_holds():
    # (a + b) · G = a · G + b · G follows from the distributive law in the
    # underlying abelian group.  This is the mathematical foundation of
    # Diffie-Hellman key exchange: Alice's contribution a·G and Bob's b·G
    # combine to (a + b)·G without either party revealing their scalar.
    a, b = 3, 7
    assert (a + b) * G == a * G + b * G


def test_scalar_multiplication_is_deterministic():
    # For a fixed private key e, the public key e · G must be unique.
    # Two independent computations must produce the same point.
    e = 42
    assert e * G == e * G


def test_commutativity_of_scalar_addition():
    # (a + b) · G = (b + a) · G — follows from commutativity of integers.
    a, b = 11, 17
    assert (a + b) * G == (b + a) * G
