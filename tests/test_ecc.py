"""
Tests for ecc.py — public key generation via scalar multiplication.

We work over the small finite field F_223 with the curve:
    y^2 = x^3 + 7  (a=0, b=7)

This mirrors the shape of Bitcoin's secp256k1 curve over a tiny field,
so results can be verified by hand or by repeated point addition.

Properties verified:
- K = k * G equals k repeated additions of G to itself
- Known precomputed outputs for specific private keys
- Input validation: type and value errors are raised correctly
"""

import pytest

from src.ecc import generate_public_key
from src.field_element import FieldElement
from src.point import Point


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def finite_field_point(x, y):
    # Construct a point on y^2 = x^3 + 7 over F_223.
    # F_223 is small enough to verify results by hand,
    # yet large enough to exercise the full group law.
    prime = 223
    a = FieldElement(0, prime)
    b = FieldElement(7, prime)
    return Point(FieldElement(x, prime), FieldElement(y, prime), a, b)


# ---------------------------------------------------------------------------
# Correctness
# ---------------------------------------------------------------------------

def test_generate_public_key_uses_scalar_multiplication():
    # 2 * G must equal G + G — verifies that scalar multiplication
    # is consistent with repeated point addition.
    generator = finite_field_point(47, 71)
    public_key = generate_public_key(2, generator)

    assert public_key == generator + generator
    assert public_key == finite_field_point(36, 111)


def test_generate_public_key_works_for_larger_private_key():
    # Precomputed: 4 * G = (194, 51) on y^2 = x^3 + 7 over F_223.
    # Verifiable by computing G+G, then (G+G)+(G+G) manually.
    generator = finite_field_point(47, 71)
    public_key = generate_public_key(4, generator)

    assert public_key == finite_field_point(194, 51)


# ---------------------------------------------------------------------------
# Input Validation
# ---------------------------------------------------------------------------

def test_private_key_must_be_an_integer():
    generator = finite_field_point(47, 71)

    with pytest.raises(TypeError):
        generate_public_key("2", generator)

    # bool is a subclass of int in Python — True and False must be
    # rejected explicitly, as they are not meaningful private keys.
    with pytest.raises(TypeError):
        generate_public_key(True, generator)


def test_private_key_must_be_positive():
    generator = finite_field_point(47, 71)

    # k = 0 yields the point at infinity (the identity), which has
    # no cryptographic value and reveals nothing about the generator.
    with pytest.raises(ValueError):
        generate_public_key(0, generator)

    # # Negative keys are not accepted in this educational public key function.
    with pytest.raises(ValueError):
        generate_public_key(-1, generator)


def test_generator_point_must_be_a_point():
    with pytest.raises(TypeError):
        generate_public_key(2, "not a point")


def test_generator_point_cannot_be_point_at_infinity():
    # The point at infinity generates only the trivial subgroup {O}.
    # k * O = O for all k, so it cannot produce meaningful public keys.
    prime = 223
    infinity = Point(None, None, FieldElement(0, prime), FieldElement(7, prime))

    with pytest.raises(ValueError):
        generate_public_key(2, infinity)