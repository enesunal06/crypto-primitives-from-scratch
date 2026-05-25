"""
Tests for ECDSA — signing and verification over secp256k1.

ECDSA is a digital signature scheme based on the Elliptic Curve Discrete
Logarithm Problem.  These tests verify two fundamental properties:

  Completeness: every signature produced by sign() passes verify().
  Soundness:    altering the message, public key, or any signature component
                causes verify() to return False.

Additional properties covered:
  - RFC 6979 determinism: identical (private_key, z) always produces the
    same k, and therefore the same signature.
  - Known test vectors: for a hand-checkable (private_key, z, k) triple,
    the computed (r, s) must match values derived from first principles.
  - Low-s normalisation: sign() always returns s ≤ N // 2.
  - Signature malleability: (r, N − s) is a mathematically valid alternate
    signature; verify() accepts both forms.
"""

import hashlib
import pytest

from src.ecdsa import G, N, Signature, _rfc6979_k, sign, verify


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_public_key(private_key: int):
    """Return the secp256k1 public key Q = e · G for scalar e."""
    return private_key * G


def sha256_int(message: bytes) -> int:
    """SHA-256 hash of a byte string, interpreted as a big-endian integer."""
    return int.from_bytes(hashlib.sha256(message).digest(), 'big')


# ---------------------------------------------------------------------------
# Completeness — valid signatures verify
# ---------------------------------------------------------------------------

def test_sign_then_verify():
    # A signature produced by sign() must be accepted by verify().
    # This is the completeness property: the verifier equation
    #   u1·G + u2·Q = k·G   ⟹   (u1·G + u2·Q).x ≡ r  (mod N)
    # must hold whenever (r, s) was produced by the signing equation.
    private_key = 12345
    z = sha256_int(b"Hello, ECDSA!")
    sig = sign(private_key, z)
    assert verify(make_public_key(private_key), z, sig)


def test_sign_and_verify_multiple_messages():
    # Different messages must produce different, individually valid signatures.
    # RFC 6979 guarantees a distinct k per (private_key, message) pair,
    # so distinct messages yield distinct (r, s) values.
    private_key = 0xDEADBEEF
    for message in [b"alpha", b"beta", b"gamma"]:
        z = sha256_int(message)
        sig = sign(private_key, z)
        assert verify(make_public_key(private_key), z, sig), (
            f"Verification failed for {message}"
        )


def test_sign_and_verify_different_private_keys():
    # Each private key produces a distinct public key, and signatures verify
    # only under the matching public key.
    z = sha256_int(b"shared message")
    for private_key in [1, 2, 12345, 0xCAFEBABE]:
        sig = sign(private_key, z)
        assert verify(make_public_key(private_key), z, sig)


# ---------------------------------------------------------------------------
# Soundness — tampered inputs fail verification
# ---------------------------------------------------------------------------

def test_verify_fails_for_wrong_message():
    # A signature on z is not valid for a different z'.
    # Altering z changes u1 = s^{-1}·z and u2 = s^{-1}·r, so the
    # reconstructed point u1·G + u2·Q lands at a different x-coordinate.
    private_key = 12345
    z = sha256_int(b"correct message")
    z_wrong = sha256_int(b"wrong message")
    sig = sign(private_key, z)
    assert not verify(make_public_key(private_key), z_wrong, sig)


def test_verify_fails_for_wrong_public_key():
    # (r, s) produced with private key e is not valid under e' ≠ e.
    # With the wrong Q = e'·G, u2·Q ≠ u2·(e·G), so the reconstructed
    # point differs from the original R = k·G.
    z = sha256_int(b"message")
    sig = sign(12345, z)
    assert not verify(make_public_key(99999), z, sig)


def test_verify_fails_for_modified_r():
    # Flipping any bit of r changes the expected x-coordinate that the
    # verification equation must produce.  The reconstructed point
    # u1·G + u2·Q has the original x-coordinate, which no longer matches.
    private_key = 12345
    z = sha256_int(b"message")
    sig = sign(private_key, z)
    bad_sig = Signature(sig.r ^ 1, sig.s)  # flip the lowest bit of r
    assert not verify(make_public_key(private_key), z, bad_sig)


def test_verify_fails_for_modified_s():
    # Flipping any bit of s changes the inverse w = s^{-1}, which alters
    # both u1 and u2.  The reconstructed point therefore lands elsewhere.
    private_key = 12345
    z = sha256_int(b"message")
    sig = sign(private_key, z)
    bad_sig = Signature(sig.r, sig.s ^ 1)
    assert not verify(make_public_key(private_key), z, bad_sig)


# ---------------------------------------------------------------------------
# Known Test Vector (Explicit k)
# ---------------------------------------------------------------------------

def test_known_signature_values_with_explicit_k():
    # For private_key = 1, z = 1, k = 1 we can derive (r, s) by hand:
    #
    #   R = 1 · G = G,  so  r = G.x mod N = Gx  (since Gx < N).
    #
    #   k^{-1} = 1^{-1} mod N = 1.
    #
    #   s = k^{-1} · (z + r · e) mod N
    #     = 1 · (1 + Gx · 1) mod N
    #     = 1 + Gx mod N.
    #
    #   Since Gx ≈ 0.474 · 2^{256} and N ≈ 2^{256}, we have 1 + Gx < N,
    #   so no modular wrap-around occurs.
    #
    #   s ≈ 0.474 · 2^{256} < N // 2 ≈ 0.5 · 2^{256},
    #   so low-s normalisation does NOT change s.
    Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    expected_r = Gx
    expected_s = (1 + Gx) % N

    sig = sign(private_key=1, z=1, k=1)

    assert sig.r == expected_r
    assert sig.s == expected_s


def test_known_signature_verifies():
    # The hand-derived signature from the test above must verify against
    # Q = 1 · G = G.
    #
    # Proof that verification succeeds:
    #   w = s^{-1} = (1 + Gx)^{-1} mod N
    #   u1 = w · z = w · 1 = w
    #   u2 = w · r = w · Gx
    #   u1 + u2 = w(1 + Gx) = s^{-1} · s = 1  (mod N)
    #   X = (u1 + u2) · G = 1 · G = G
    #   X.x = Gx = r  ✓
    Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    sig = Signature(r=Gx, s=(1 + Gx) % N)
    assert verify(public_key=make_public_key(1), z=1, sig=sig)


def test_second_known_vector_explicit_k():
    # For private_key = 2, z = 1, k = 2:
    #
    #   R = 2 · G = G + G (point doubling)
    #   r = R.x mod N  — this x-coordinate is a fixed point on the curve.
    #
    #   k^{-1} = 2^{-1} mod N = (N + 1) // 2  (N is odd, so this is exact).
    #
    #   s = 2^{-1} · (1 + r · 2) mod N.
    #
    # We do not hard-code R.x here; instead we derive r from the curve and
    # verify that the signature equation is self-consistent.
    R = 2 * G
    r = R.x.number % N
    k_inv = pow(2, -1, N)
    expected_s_raw = k_inv * (1 + r * 2) % N
    expected_s = expected_s_raw if expected_s_raw <= N // 2 else N - expected_s_raw

    sig = sign(private_key=2, z=1, k=2)

    assert sig.r == r
    assert sig.s == expected_s
    assert verify(make_public_key(2), z=1, sig=sig)


# ---------------------------------------------------------------------------
# RFC 6979 — Deterministic k
# ---------------------------------------------------------------------------

def test_rfc6979_is_deterministic():
    # RFC 6979 must produce the same k for the same (private_key, z).
    # This is the core guarantee that removes the need for a strong
    # random number generator at signing time.
    private_key = 42
    z = sha256_int(b"determinism test")
    assert _rfc6979_k(private_key, z) == _rfc6979_k(private_key, z)


def test_rfc6979_differs_for_different_messages():
    # Different messages must yield different k values.
    # If two messages shared a k, an observer could compute:
    #   k = (z1 − z2)(s1 − s2)^{-1} mod N
    # and then recover the private key.
    private_key = 42
    k1 = _rfc6979_k(private_key, sha256_int(b"message one"))
    k2 = _rfc6979_k(private_key, sha256_int(b"message two"))
    assert k1 != k2


def test_rfc6979_differs_for_different_private_keys():
    # Different private keys must yield different k values for the same z.
    # This ensures that the k of one key holder cannot be correlated with
    # the k of another, preventing cross-signer attacks.
    z = sha256_int(b"same message")
    k1 = _rfc6979_k(42, z)
    k2 = _rfc6979_k(43, z)
    assert k1 != k2


def test_sign_is_deterministic():
    # Two calls to sign() with the same (private_key, z) must produce the
    # same Signature, because RFC 6979 generates the same k both times.
    private_key = 12345
    z = sha256_int(b"determinism")
    assert sign(private_key, z) == sign(private_key, z)


def test_rfc6979_k_is_in_valid_range():
    # RFC 6979 must produce k ∈ [1, N − 1].
    # k = 0 is invalid (it makes R = O and r = 0, which are excluded).
    # k ≥ N would be redundant since k · G = (k mod N) · G.
    private_key = 99
    z = sha256_int(b"range check")
    k = _rfc6979_k(private_key, z)
    assert 1 <= k <= N - 1


# ---------------------------------------------------------------------------
# Low-s Normalisation
# ---------------------------------------------------------------------------

def test_s_is_always_in_lower_half():
    # Bitcoin's BIP-62 requires s ≤ N // 2 to produce canonical signatures.
    # Without this, a third party can flip s → N − s without invalidating
    # the signature, altering the transaction ID (txid) after broadcast.
    private_key = 99
    for message in [b"alpha", b"beta", b"gamma", b"delta", b"epsilon"]:
        z = sha256_int(message)
        sig = sign(private_key, z)
        assert sig.s <= N // 2, (
            f"s = {sig.s} exceeds N // 2 for message {message}"
        )


def test_flipped_s_signature_is_mathematically_valid():
    # Both (r, s) and (r, N − s) are equally valid ECDSA signatures.
    # Proof: (N − s) corresponds to nonce k' = −k mod N.  The point
    # R' = k' · G = −R has the same x-coordinate as R (reflection over the
    # x-axis preserves x), so r' = r.  The verifier computes:
    #
    #   w' = (N − s)^{-1} = −s^{-1} mod N
    #   u1' = w'·z = −u1,   u2' = w'·r = −u2
    #   X' = u1'·G + u2'·Q = −(u1·G + u2·Q) = −X
    #
    # −X shares the same x-coordinate as X, so X'.x = X.x = r. ✓
    #
    # sign() normalises to the lower s; verify() accepts either form.
    private_key = 12345
    z = sha256_int(b"malleability test")
    sig = sign(private_key, z)               # s ≤ N // 2
    high_s_sig = Signature(sig.r, N - sig.s) # the "other" valid s value
    assert verify(make_public_key(private_key), z, high_s_sig)


# ---------------------------------------------------------------------------
# Invalid Signature Components
# ---------------------------------------------------------------------------

def test_verify_rejects_r_equal_zero():
    # r = 0 means (k·G).x ≡ 0 (mod N), which the sign() function can never
    # produce (RFC 6979 would regenerate k if r = 0).
    z = sha256_int(b"message")
    assert not verify(make_public_key(12345), z, Signature(0, 1))


def test_verify_rejects_s_equal_zero():
    # s = 0 makes the verification computation degenerate (s^{-1} is undefined
    # for s = 0 in Z_N).  The range check catches this before any inversion.
    z = sha256_int(b"message")
    assert not verify(make_public_key(12345), z, Signature(1, 0))


def test_verify_rejects_r_equal_N():
    # r = N ≡ 0 (mod N), which is out of the valid range [1, N − 1].
    z = sha256_int(b"message")
    assert not verify(make_public_key(12345), z, Signature(N, 1))


def test_verify_rejects_s_equal_N():
    # s = N ≡ 0 (mod N), same reasoning as above.
    z = sha256_int(b"message")
    assert not verify(make_public_key(12345), z, Signature(1, N))
