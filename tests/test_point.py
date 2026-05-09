"""
Tests for Point — the elliptic curve group law on y^2 = x^3 + ax + b.

Algebraic properties verified:
- Curve membership (ValueError for invalid points)
- Additive identity: P + O = O + P = P
- Additive inverse: P + (-P) = O
- Secant-line addition: P + Q for P != Q
- Tangent-line addition: P + P (point doubling)
"""

import pytest
from src.point import Point


# ---------------------------------------------------------------------------
# Curve Membership
# ---------------------------------------------------------------------------

def test_valid_points_are_accepted():
    Point(-1, -1, 5, 7)
    Point(-1,  1, 5, 7)
    Point( 2,  5, 5, 7)
    Point( 3, -7, 5, 7)
    Point(18, 77, 5, 7)


def test_invalid_points_raise_value_error():
    with pytest.raises(ValueError):
        Point(-1, -2, 5, 7)
    with pytest.raises(ValueError):
        Point(5, 7, 5, 7)


# ---------------------------------------------------------------------------
# Equality
# ---------------------------------------------------------------------------

def test_equality_works():
    assert Point(3, -7, 5, 7) == Point(3, -7, 5, 7)
    assert Point(3, -7, 5, 7) != Point(18, 77, 5, 7)  # different coordinates
    assert Point(3, -7, 5, 7) != Point(3, -7, 6, 4)   # different curve


# ---------------------------------------------------------------------------
# Additive Identity
# ---------------------------------------------------------------------------

def test_point_at_infinity_is_left_identity():
    infinity = Point(None, None, 5, 7)
    p = Point(2, 5, 5, 7)
    assert infinity + p == p


def test_point_at_infinity_is_right_identity():
    infinity = Point(None, None, 5, 7)
    p = Point(2, 5, 5, 7)
    assert p + infinity == p


# ---------------------------------------------------------------------------
# Additive Inverse
# ---------------------------------------------------------------------------

def test_adding_inverse_points_gives_infinity():
    # P and -P share the same x but opposite y-values.
    # The line through them is vertical — it yields the point at infinity.
    p     = Point(-1,  1, 5, 7)
    neg_p = Point(-1, -1, 5, 7)
    infinity = Point(None, None, 5, 7)
    assert p + neg_p == infinity


# ---------------------------------------------------------------------------
# Secant-Line Addition  (P + Q, P != Q)
# ---------------------------------------------------------------------------

def test_point_addition_general_case():
    p1 = Point( 2,  5, 5, 7)
    p2 = Point(-1, -1, 5, 7)
    assert p1 + p2 == Point(3, -7, 5, 7)


# ---------------------------------------------------------------------------
# Tangent-Line Addition  (P + P)
# ---------------------------------------------------------------------------

def test_point_doubling():
    # The tangent at P intersects the curve at a second point; reflect it.
    p = Point(-1, -1, 5, 7)
    assert p + p == Point(18, 77, 5, 7)


# ---------------------------------------------------------------------------
# Error Handling
# ---------------------------------------------------------------------------

def test_adding_points_from_different_curves_raises_type_error():
    p1 = Point(-1, -1, 5, 7)
    p2 = Point(0, 2, 6, 4)  # 2^2 = 0^3 + 6*0 + 4

    with pytest.raises(TypeError):
        p1 + p2


def test_adding_non_point_raises_type_error():
    p = Point(-1, -1, 5, 7)
    with pytest.raises(TypeError):
        p + 5
    with pytest.raises(TypeError):
        p + "point"