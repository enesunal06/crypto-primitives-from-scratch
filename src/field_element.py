class FieldElement:
    """ Field is basicly a ring with unity, commutative multiplication, and multiplicative inverses for all nonzero elements.
    An element of the finite field F_p.

    The field F_p contains the integers {0, 1, ..., p - 1}, with all
    arithmetic performed modulo the prime number p.
    """

    def __init__(self, number, prime):
        if not isinstance(prime, int):
            raise TypeError("prime must be an integer")
        if not _is_prime(prime):
            raise ValueError("prime must be prime")
        if not isinstance(number, int):
            raise TypeError("number must be an integer")

        self.number = number % prime
        self.prime = prime

    def __repr__(self):
        return f"FieldElement_{self.prime}({self.number})"

    def __eq__(self, other):
        if other is None:
            return False
        if not isinstance(other, FieldElement):
            return False
        return self.number == other.number and self.prime == other.prime

    def __add__(self, other):
        self._check_same_field(other)
        number = (self.number + other.number) % self.prime
        return FieldElement(number, self.prime)

    def __sub__(self, other):
        self._check_same_field(other)
        number = (self.number - other.number) % self.prime
        return FieldElement(number, self.prime)

    def __mul__(self, other):
        self._check_same_field(other)
        number = (self.number * other.number) % self.prime
        return FieldElement(number, self.prime)

    def __pow__(self, exponent):
        if not isinstance(exponent, int):
            raise TypeError("exponent must be an integer")
        if self.number == 0 and exponent < 0:
            raise ZeroDivisionError("0 cannot be raised to a negative power")

        reduced_exponent = exponent % (self.prime - 1)
        number = pow(self.number, reduced_exponent, self.prime)
        return FieldElement(number, self.prime)

    def __truediv__(self, other):
        self._check_same_field(other)
        if other.number == 0:
            raise ZeroDivisionError("cannot divide by zero in a field")

        # Fermat's Little Theorem says a^(p - 1) = 1 mod p for nonzero a.
        # Therefore a^(p - 2) is the multiplicative inverse of a mod p.
        inverse = pow(other.number, self.prime - 2, self.prime)
        number = (self.number * inverse) % self.prime
        return FieldElement(number, self.prime)

    def _check_same_field(self, other):
        if not isinstance(other, FieldElement):
            raise TypeError("operation requires another FieldElement")
        if self.prime != other.prime:
            raise TypeError("cannot operate on elements from different fields")


# p must be prime to ensure that every nonzero element has a multiplicative inverse.
def _is_prime(number):
    if number < 2:
        return False
    if number == 2:
        return True
    if number % 2 == 0:
        return False

    divisor = 3
    while divisor * divisor <= number:
        if number % divisor == 0:
            return False
        divisor += 2
    return True


if __name__ == "__main__":
    a = FieldElement(7, 13)
    b = FieldElement(12, 13)

    print("a =", a)
    print("b =", b)
    print("a + b =", a + b)
    print("a - b =", a - b)
    print("a * b =", a * b)
    print("a ** 3 =", a**3)
    print("a / b =", a / b)
