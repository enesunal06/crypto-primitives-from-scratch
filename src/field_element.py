# A finite field F_p is a set {0, 1, ..., p-1} equipped with addition and
# multiplication modulo a prime p. The prime requirement guarantees that every
# nonzero element has a multiplicative inverse, making division always possible.

class FieldElement:
    """
    An element of the finite field F_p.

    A field is a ring with unity, commutative multiplication, and multiplicative
    inverses for all nonzero elements. Using a prime modulus p ensures these
    properties hold: by Fermat's Little Theorem, a^(p-1) ≡ 1 (mod p) for all
    nonzero a, so a^(p-2) is always the multiplicative inverse of a.

    The field F_p contains the integers {0, 1, ..., p-1}, with all arithmetic performed modulo p.
    """

    def __init__(self, number, prime):
        if not isinstance(prime, int):
            raise TypeError("prime must be an integer")
        if not _is_prime(prime):
            raise ValueError("prime must be prime")
        if not isinstance(number, int):
            raise TypeError("number must be an integer")

        # Any integer reduces to a unique representative in {0, ..., p-1}
        # via the division algorithm: number = q*prime + r, we keep r.
        
        self.number = number % prime
        self.prime = prime

    def __repr__(self):
        return f"FieldElement_{self.prime}({self.number})"

    def __eq__(self, other):
        if other is None:
            return False
        if not isinstance(other, FieldElement):
            return False
        # Two field elements are equal only if they share the same field (prime)
        # and the same value. Elements from different fields are never equal.
        return self.number == other.number and self.prime == other.prime

    def __ne__(self, other):
        return not self.__eq__(other)
    
    def __add__(self, other):
        self._check_same_field(other)
        # Closure under addition: (a + b) mod p always stays in {0, ..., p-1}
        number = (self.number + other.number) % self.prime
        return FieldElement(number, self.prime)

    def __sub__(self, other):
        self._check_same_field(other)
        # Python's % operator always returns a non-negative result, so
        # subtraction naturally wraps around: e.g. (3 - 7) mod 13 = 9
        number = (self.number - other.number) % self.prime
        return FieldElement(number, self.prime)

    def __mul__(self, other):
        self._check_same_field(other)
        # Closure under multiplication: (a * b) mod p always stays in {0, ..., p-1}
        number = (self.number * other.number) % self.prime
        return FieldElement(number, self.prime)

    def __rmul__(self, coefficient):
        return self * self.__class__(coefficient, self.prime)
    
    def __neg__(self):
        # Additive inverse: -a is the unique element such that a + (-a) = 0
        # In F_p, the additive inverse of a is (p - a) mod p.
        return FieldElement(-self.number, self.prime)
    
    def __pow__(self, exponent):
        if not isinstance(exponent, int):
            raise TypeError("exponent must be an integer")
        if self.number == 0 and exponent < 0:
            raise ZeroDivisionError("0 cannot be raised to a negative power")
        # By Fermat's Little Theorem, a^(p-1) ≡ 1 (mod p) for nonzero a.
        # So exponents are periodic with period (p-1): a^n = a^(n mod (p-1)).
        # This reduction also correctly handles negative exponents.
        reduced_exponent = exponent % (self.prime - 1)
        number = pow(self.number, reduced_exponent, self.prime)
        return FieldElement(number, self.prime)

    def __truediv__(self, other):
        self._check_same_field(other)
        if other.number == 0:
            raise ZeroDivisionError("cannot divide by zero in a field")

       # Division is multiplication by the multiplicative inverse.
        # Fermat's Little Theorem: a^(p-1) ≡ 1 (mod p) => a * a^(p-2) ≡ 1 (mod p), so a^(p-2) is the inverse of a.
        # Therefore: a / b = a * b^(p-2) mod p
        inverse = pow(other.number, self.prime - 2, self.prime)
        number = (self.number * inverse) % self.prime
        return FieldElement(number, self.prime)

    def _check_same_field(self, other):
        if not isinstance(other, FieldElement):
            raise TypeError("operation requires another FieldElement")
        if self.prime != other.prime:
            # Adding elements from different fields is undefined — like adding
            # metres and seconds. The fields are entirely separate structures.
            raise TypeError("cannot operate on elements from different fields")


# The primality of p is essential: composite moduli have zero divisors,
# meaning nonzero elements whose product is 0, which breaks multiplicative
# inverses. Example: in Z_6, 2 * 3 = 6 ≡ 0, so 2 and 3 have no inverses.
def _is_prime(number):
    if number < 2:
        return False
    if number == 2:
        return True
    if number % 2 == 0:
        return False
# Only check odd divisors up to sqrt(n): if n = a*b with a <= b,
    # then a <= sqrt(n), so we never miss a factor.
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
    print("a + b =", a + b)       # (7 + 12) mod 13 = 6
    print("a - b =", a - b)       # (7 - 12) mod 13 = 8
    print("a * b =", a * b)       # (7 * 12) mod 13 = 6
    print("a ** 3 =", a ** 3)     # 7^3 mod 13 = 343 mod 13 = 5
    print("a / b =", a / b)       # 7 * 12^(13-2) mod 13 = 7 * 12^11 mod 13 = 4
    print("-a =", -a)             # additive inverse: (13 - 7) = 6
