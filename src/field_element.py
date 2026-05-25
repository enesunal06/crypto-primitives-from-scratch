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

# Cache of verified primes.  FieldElement.__init__ is called for every
# intermediate result of arithmetic, so testing the same prime repeatedly
# would dominate the cost.  Caching reduces each repeated call to O(1).
_verified_primes: set = set()

def _is_prime(number):
    if number < 2:
        return False
    if number in _verified_primes:
        return True

    if number == 2:
        _verified_primes.add(number)
        return True
    if number % 2 == 0:
        return False

    # For small numbers, trial division up to √n is fast and exact.
    # If n = a·b with a ≤ b, then a ≤ √n, so we never miss a factor.
    if number < 1_000_000_000_000:
        divisor = 3
        while divisor * divisor <= number:
            if number % divisor == 0:
                return False
            divisor += 2
        _verified_primes.add(number)
        return True

    # For large numbers (e.g. 256-bit cryptographic primes), trial division
    # would require ≈ √n ≈ 2^128 steps — computationally infeasible.
    # The Miller-Rabin test decides primality in O(k · log² n) time, where k
    # is the number of witness rounds.
    result = _miller_rabin_is_prime(number)
    if result:
        _verified_primes.add(number)
    return result


# Miller-Rabin primality test.
#
# Mathematical basis: if n is prime, then for any a not divisible by n,
# Fermat's Little Theorem gives a^{n-1} ≡ 1 (mod n).  Write n-1 = 2^r · d
# with d odd.  Then either a^d ≡ 1, or a^{2^j · d} ≡ -1 for some j < r.
# If neither holds, n is composite (a is a "witness" to compositeness).
#
# Witness set:
#   {2,3,5,7,11,13,17,19,23,29,31,37} is provably deterministic for all
#   n < 3.317 × 10^24 (Sorenson & Webster, 2015).  For larger n, such as
#   256-bit cryptographic primes, the test is probabilistic: each composite
#   passes all 12 witnesses with probability at most 4^{-12} ≈ 6 × 10^{-8}.
#   In practice, every prime used in a published standard is confirmed prime.
_MILLER_RABIN_WITNESSES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)

def _miller_rabin_is_prime(n):
    # Write n - 1 = 2^r · d with d odd
    d, r = n - 1, 0
    while d % 2 == 0:
        d >>= 1
        r += 1

    for a in _MILLER_RABIN_WITNESSES:
        if a >= n:
            continue
        x = pow(a, d, n)                 # a^d mod n — fast modular exponentiation
        if x == 1 or x == n - 1:
            continue                      # this witness does not detect compositeness
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False                  # n is definitely composite
    return True                           # n is prime (or an astronomically rare pseudoprime)


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
