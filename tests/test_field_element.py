import pytest

from src.field_element import FieldElement


def test_numbers_are_represented_modulo_prime():
    assert FieldElement(17, 13) == FieldElement(4, 13)
    assert FieldElement(-1, 13) == FieldElement(12, 13)


def test_addition_subtraction_and_multiplication():
    a = FieldElement(7, 13)
    b = FieldElement(12, 13)

    assert a + b == FieldElement(6, 13)
    assert a - b == FieldElement(8, 13)
    assert a * b == FieldElement(6, 13)


def test_exponentiation():
    a = FieldElement(7, 13)

    assert a**3 == FieldElement(5, 13)
    assert a**-1 == FieldElement(2, 13)


def test_division_uses_multiplicative_inverse():
    a = FieldElement(7, 13)
    b = FieldElement(12, 13)

    assert a / b == FieldElement(6, 13)
    assert (a / b) * b == a


def test_equality_and_repr():
    assert FieldElement(7, 13) == FieldElement(20, 13)
    assert FieldElement(7, 13) != FieldElement(7, 17)
    assert repr(FieldElement(7, 13)) == "FieldElement_13(7)"


def test_operations_between_different_fields_raise_error():
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


def test_zero_division_and_invalid_prime_raise_error():
    with pytest.raises(ZeroDivisionError):
        FieldElement(7, 13) / FieldElement(0, 13)

    with pytest.raises(ValueError):
        FieldElement(1, 12)
