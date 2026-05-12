# In ECC, the basic public key operation is:
#
#   public_key = private_key * G
#
# where private_key is an integer and G is a chosen point on the curve.
#
# This file does not implement real-world key validation, ECDSA,
# signatures, addresses, or serialization. Its purpose is educational:
# to connect finite-field elliptic curve arithmetic with public key generation.

from src.point import Point


def generate_public_key(private_key, generator_point):
    """Return the elliptic curve public key for a private scalar.

    In ECC, public key generation is scalar multiplication:

        K = k * G

    where k is the private scalar and G is a chosen generator point.
    The multiplication itself is implemented by Point.__rmul__ using
    the double-and-add algorithm.

    Args:
        private_key: A positive integer used as the scalar k.
        generator_point: A Point on the elliptic curve.

    Returns:
        The public key K = k * G as a Point on the same curve.

    Raises:
        TypeError: If private_key is not an int, or generator_point is not a Point.
        ValueError: If private_key <= 0, or generator_point is the point at infinity.
    """
    if isinstance(private_key, bool) or not isinstance(private_key, int):
        raise TypeError("private_key must be an integer")

    if private_key <= 0:
        raise ValueError("private_key must be a positive integer")

    if not isinstance(generator_point, Point):
        raise TypeError("generator_point must be a Point")

    if generator_point.x is None:
        raise ValueError("generator_point cannot be the point at infinity")

    return private_key * generator_point