# Crypto Primitives From Scratch

Implementing the core cryptographic primitives behind Bitcoin and Ethereum
from scratch in Python. No external crypto libraries, pure mathematics.

## Motivation

Most cryptography courses teach the theory. Most blockchain tutorials skip
the math and jump straight to libraries. This project sits in between:
every primitive is built from first principles, starting from finite field
arithmetic and working up to a working ECDSA implementation over secp256k1.

The mathematical foundation comes from abstract algebra and number theory,
specifically group theory, finite fields, and elliptic curves over F_p,
applied directly to the cryptographic constructions that underpin Bitcoin
and Ethereum.

## Project Structure

```
src/
├── field_element.py   # Finite field arithmetic (F_p)
├── point.py           # Elliptic curve points, group law, scalar multiplication
├── ecc.py             # Elliptic curve abstraction and public key generation
├── ecdsa.py           # secp256k1 parameters, ECDSA signing and verification (RFC 6979)
└── merkle.py          # Bitcoin-style Merkle tree construction and proof verification
tests/
└── ...                # Unit tests for each primitive
```

## Progress

- [x] **Stage 1 — Finite Fields** (`field_element.py`)
  Modular arithmetic, field element operations, Fermat's little theorem for inversion.

- [x] **Stage 2 — Elliptic Curves** (`point.py`, `ecc.py`)
  Point addition and doubling over F_p, scalar multiplication via double-and-add,
  public key derivation from private key.

- [x] **Stage 3 — ECDSA** (`ecdsa.py`)
  secp256k1 curve parameters, signature generation and verification.
  Deterministic nonce generation following RFC 6979 to avoid nonce-reuse vulnerabilities.

- [x] **Stage 4 — Merkle Trees** (`merkle.py`) 
  Bitcoin-style Merkle tree construction and inclusion proof verification.

- [ ] **Stage 5 — Ethereum-compatible Wallet** *(planned)*
  Address derivation, RLP encoding, transaction signing.

## Principles

- No external cryptography libraries
- Everything implemented from mathematical definitions
- Focus on correctness and clarity over performance
- Each file is self-contained and readable independently