"""
Tests for FieldElement — arithmetic in a finite field F_p.

A finite field F_p = {0, 1, ..., p-1} with arithmetic modulo a prime p.
These tests verify the core algebraic properties that every finite field
must satisfy, grounded in the mathematical theory behind the implementation.

Mathematical properties verified:
- Closure: all operations return elements within the same field
- Fermat's Little Theorem: a^(p-1) ≡ 1 (mod p) for all nonzero a
- Multiplicative inverse: a^(p-2) ≡ a^(-1) (mod p)
- Additive and multiplicative identity elements
- Additive inverse: a + (-a) ≡ 0 (mod p)
"""

import pytest

from src.field_element import FieldElement


# ---------------------------------------------------------------------------
# Representation & Equality
# ---------------------------------------------------------------------------

def test_numbers_are_represented_modulo_prime():
    # Any integer reduces to its canonical representative in {0, ..., p-1}
    assert FieldElement(17, 13) == FieldElement(4, 13)   # 17 mod 13 = 4
    assert FieldElement(-1, 13) == FieldElement(12, 13)  # -1 mod 13 = 12


def test_equality_requires_same_field_and_value():
    # Two elements are equal only if both their value and field match
    assert FieldElement(7, 13) == FieldElement(20, 13)   # 20 mod 13 = 7
    assert FieldElement(7, 13) != FieldElement(7, 17)    # same value, different field
    assert FieldElement(7, 13) != FieldElement(5, 13)    # same field, different value


def test_repr():
    assert repr(FieldElement(7, 13)) == "FieldElement_13(7)"


# ---------------------------------------------------------------------------
# Basic Arithmetic
# ---------------------------------------------------------------------------

def test_addition():
    a = FieldElement(7, 13)
    b = FieldElement(12, 13)
    # (7 + 12) mod 13 = 19 mod 13 = 6
    assert a + b == FieldElement(6, 13)


def test_subtraction_wraps_around():
    a = FieldElement(7, 13)
    b = FieldElement(12, 13)
    # (7 - 12) mod 13 = -5 mod 13 = 8 — Python's % always returns non-negative
    assert a - b == FieldElement(8, 13)


def test_multiplication():
    a = FieldElement(7, 13)
    b = FieldElement(12, 13)
    # (7 * 12) mod 13 = 84 mod 13 = 6
    assert a * b == FieldElement(6, 13)


def test_exponentiation():
    a = FieldElement(7, 13)
    # 7^3 = 343, 343 mod 13 = 5
    assert a ** 3 == FieldElement(5, 13)


# ---------------------------------------------------------------------------
# Identity Elements
# ---------------------------------------------------------------------------

def test_additive_identity():
    # 0 is the additive identity: a + 0 = a for all a
    a = FieldElement(7, 13)
    zero = FieldElement(0, 13)
    assert a + zero == a


def test_multiplicative_identity():
    # 1 is the multiplicative identity: a * 1 = a for all a
    a = FieldElement(7, 13)
    one = FieldElement(1, 13)
    assert a * one == a


# ---------------------------------------------------------------------------
# Inverse Elements
# ---------------------------------------------------------------------------

def test_additive_inverse():
    # -a is the unique element such that a + (-a) = 0
    # In F_p: -a ≡ (p - a) mod p
    a = FieldElement(7, 13)
    assert a + (-a) == FieldElement(0, 13)


def test_multiplicative_inverse_via_division():
    # a / b = a * b^(p-2) mod p, derived from Fermat's Little Theorem
    a = FieldElement(7, 13)
    b = FieldElement(12, 13)
    assert a / b == FieldElement(6, 13)


def test_division_recovers_original():
    # Fundamental property: (a / b) * b must equal a
    a = FieldElement(7, 13)
    b = FieldElement(12, 13)
    assert (a / b) * b == a


def test_negative_exponent_is_multiplicative_inverse():
    # a^(-1) is the multiplicative inverse: a * a^(-1) ≡ 1 (mod p)
    a = FieldElement(7, 13)
    assert a ** -1 * a == FieldElement(1, 13)
    assert a ** -1 == FieldElement(2, 13)  # 7^(-1) mod 13 = 2


# ---------------------------------------------------------------------------
# Fermat's Little Theorem
# ---------------------------------------------------------------------------

def test_fermats_little_theorem():
    # For any nonzero a in F_p: a^(p-1) ≡ 1 (mod p)
    # This is the mathematical foundation of our inverse and division operations
    a = FieldElement(7, 13)
    b = FieldElement(12, 13)
    assert a ** (a.prime - 1) == FieldElement(1, 13)
    assert b ** (b.prime - 1) == FieldElement(1, 13)


def test_fermats_theorem_holds_for_all_nonzero_elements():
    # Verify across every nonzero element of F_13
    prime = 13
    one = FieldElement(1, prime)
    for n in range(1, prime):
        a = FieldElement(n, prime)
        assert a ** (prime - 1) == one, f"Fermat's theorem failed for a={n}"


# ---------------------------------------------------------------------------
# Cross-Field Operations
# ---------------------------------------------------------------------------

def test_operations_between_different_fields_raise_error():
    # Elements from different fields live in entirely separate structures.
    # Operating across fields is mathematically undefined.
    a = FieldElement(7, 13)
    b = FieldElement(7, 17)

    with pytest.raises(TypeError):
        a + b
    with pytest.raises(TypeError):
        a - b
    with pytest.raises(TypeError):
        a * b
    with pytest.raises(TypeError):
        a / b


# ---------------------------------------------------------------------------
# Error Handling
# ---------------------------------------------------------------------------

def test_division_by_zero_raises_error():
    with pytest.raises(ZeroDivisionError):
        FieldElement(7, 13) / FieldElement(0, 13)


def test_negative_exponent_on_zero_raises_error():
    with pytest.raises(ZeroDivisionError):
        FieldElement(0, 13) ** -1


def test_composite_modulus_raises_error():
    # Composite moduli have zero divisors and break multiplicative inverses.
    # Example: in Z_6, 2 * 3 = 6 ≡ 0, so neither 2 nor 3 has an inverse.
    with pytest.raises(ValueError):
        FieldElement(1, 12)  # 12 = 4 * 3, not prime


def test_non_integer_inputs_raise_error():
    with pytest.raises(TypeError):
        FieldElement(1.5, 13)
    with pytest.raises(TypeError):
        FieldElement(1, 13.0)