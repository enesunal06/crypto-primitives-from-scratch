# Elliptic curves are the main mathematical object behind ECC (Elliptic Curve Cryptography).
#
# A curve is given by the equation:
#   y^2 = x^3 + ax + b
#
# Every point (x, y) satisfying this equation lies on the curve.
# We also include a special extra point called the "point at infinity",
# which acts like the zero element of the group.
#
# One of the beautiful facts is that points on the curve can be "added"
# together with a geometric rule, and this turns the curve into an abelian group.
#
# At first we work over ordinary numbers to understand the geometry.
# Later we move to finite fields F_p, which is where elliptic curve
# cryptography actually comes from.
#
# This Point class is written so it works for both real-number examples and finite-field examples using FieldElement.


class Point:
    """A point on an elliptic curve y^2 = x^3 + ax + b.

    The curve is parameterised by constants a and b. Coordinates x and y
    may be plain numbers or FieldElement instances; arithmetic is delegated
    to whatever type is passed in.

    The special point at infinity O is represented by x = None, y = None.
    It acts as the additive identity of the group:
        P + O = O + P = P  for every point P on the curve.
    """

    def __init__(self, x, y, a, b):
        self.a = a
        self.b = b
        self.x = x
        self.y = y

        # The point at infinity does not satisfy the affine curve equation —
        # it lives at the projective "end" of every vertical line.
        if self.x is None and self.y is None:
            return

        # Verify the point satisfies y^2 = x^3 + ax + b.
        # This guards against constructing points that are not on the curve.
        if self.y**2 != self.x**3 + self.a * self.x + self.b:
            raise ValueError(f"({self.x}, {self.y}) is not on the curve")

    def __repr__(self):
        if self.x is None:
            return f"Point(infinity)_({self.a}, {self.b})"
        return f"Point({self.x}, {self.y})_({self.a}, {self.b})"

    def __eq__(self, other):
        if not isinstance(other, Point):
            return False
        # Two points are equal only if they lie on the same curve (same a, b) and share the same coordinates.
        return (
            self.x == other.x
            and self.y == other.y
            and self.a == other.a
            and self.b == other.b
        )

    def __ne__(self, other):
        return not self == other

    def __add__(self, other):
        if not isinstance(other, Point):
            raise TypeError("Can only add Point to Point")
        if self.a != other.a or self.b != other.b:
            raise TypeError("Points are not on the same curve")

        # Case 1: O + P = P  (O is the additive identity)
        if self.x is None:
            return other

        # Case 2: P + O = P
        if other.x is None:
            return self

        # Case 3: P + (-P) = O
        # P and -P share the same x-coordinate but have opposite y-values.
        # The line through them is vertical and has no third intersection
        # with the curve, so the result is the point at infinity.
        if self.x == other.x and self.y != other.y:
            return Point(None, None, self.a, self.b)

        # Case 4: P + Q where P != Q
        # Draw the secant line through P and Q. It intersects the curve at
        # a third point; reflect that point over the x-axis to get P + Q.
        #   slope m = (y2 - y1) / (x2 - x1)
        #   x3 = m^2 - x1 - x2
        #   y3 = m(x1 - x3) - y1
        if self.x != other.x:
            slope = (other.y - self.y) / (other.x - self.x)
            x = slope**2 - self.x - other.x
            y = slope * (self.x - x) - self.y
            return Point(x, y, self.a, self.b)

        # Case 5: P + P where y = 0
        # The tangent at this point is vertical, so it does not intersect
        # the curve at any other affine point — result is the point at infinity.
        if self == other and self.y == 0 * self.x:
            return Point(None, None, self.a, self.b)

        # Case 6: P + P  (point doubling, general case)
        # Take the tangent line at P; find its second intersection with the curve, then reflect over the x-axis.
        # Slope from implicit differentiation of y^2 = x^3 + ax + b:
        #   2y dy = (3x^2 + a) dx  =>  m = (3x^2 + a) / (2y)
        #   x3 = m^2 - 2x
        #   y3 = m(x - x3) - y
        if self == other:
            slope = (3 * self.x**2 + self.a) / (2 * self.y)
            x = slope**2 - 2 * self.x
            y = slope * (self.x - x) - self.y
            return Point(x, y, self.a, self.b)


    def __rmul__(self, coefficient):
        coef = coefficient
        current = self
        result = Point(None, None, self.a, self.b)

        while coef:
            if coef & 1:
                result += current

            coef >>= 1

            if coef:
                current += current

        return result

if __name__ == "__main__":
    # --- Basic addition ---
    # Curve: y^2 = x^3 + 5x + 7
    p1 = Point(-1,  1, 5, 7)
    p2 = Point(-1, -1, 5, 7)
    print("p1 =", p1)
    print("p2 =", p2)
    print("p1 + p2 =", p1 + p2)   # P + (-P) = O

    p3 = Point( 2,  5, 5, 7)
    p4 = Point(-1, -1, 5, 7)
    print("p3 + p4 =", p3 + p4)   # secant-line addition

    # --- Point doubling ---
    p5 = Point(-1, 1, 5, 7)
    print("p5 + p5 =", p5 + p5)   # tangent-line addition

    # --- Identity element ---
    inf = Point(None, None, 5, 7)
    print("p1 + O =", p1 + inf)   # should equal p1
    print("O + p1 =", inf + p1)   # should equal p1
    p = Point(-1, 1, 5, 7)
    
    print("p =", p)
    print("2 * p =", 2 * p)
