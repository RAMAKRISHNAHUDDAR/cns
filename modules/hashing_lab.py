
"""Local experiments comparing SHA-256 and Argon2id password hashing."""

from dataclasses import dataclass
from hashlib import sha256
from time import perf_counter
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import (
    InvalidHashError,
    VerificationError,
    VerifyMismatchError,
)


@dataclass(frozen=True)
class HashingBenchmark:
    """Measured hashing and verification performance."""

    algorithm: str
    iterations: int
    average_hash_seconds: float
    average_verify_seconds: float
    memory_cost_kib: int | None


def _validate_password(password: str) -> None:
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    if not password:
        raise ValueError("password must not be empty")


def _validate_iterations(iterations: int) -> None:
    if isinstance(iterations, bool) or not isinstance(iterations, int):
        raise TypeError("iterations must be an integer")
    if iterations < 1:
        raise ValueError("iterations must be at least 1")


def hash_sha256(password: str) -> str:
    """Return a SHA-256 digest for comparison experiments only.

    SHA-256 alone is not suitable for password storage.
    """
    _validate_password(password)
    return sha256(password.encode("utf-8")).hexdigest()


def verify_sha256(password: str, digest: str) -> bool:
    """Verify a password against a SHA-256 comparison digest."""
    _validate_password(password)

    if not isinstance(digest, str):
        raise TypeError("digest must be a string")

    candidate_digest = hash_sha256(password)

    # Compare fixed-length digests using a constant-time comparison.
    import hmac
    return hmac.compare_digest(candidate_digest, digest)


def hash_argon2id(
    password: str,
    *,
    hasher: PasswordHasher | None = None,
) -> str:
    """Hash a password with Argon2id and a randomly generated salt.

    The encoded hash contains the salt and parameters needed for verification.
    """
    _validate_password(password)

    if hasher is None:
        hasher = PasswordHasher()

    if not isinstance(hasher, PasswordHasher):
        raise TypeError("hasher must be a PasswordHasher instance")

    return hasher.hash(password)


def verify_argon2id(
    password: str,
    encoded_hash: str,
    *,
    hasher: PasswordHasher | None = None,
) -> bool:
    """Verify a password against an encoded Argon2id hash."""
    _validate_password(password)

    if not isinstance(encoded_hash, str):
        raise TypeError("encoded_hash must be a string")

    if hasher is None:
        hasher = PasswordHasher()

    if not isinstance(hasher, PasswordHasher):
        raise TypeError("hasher must be a PasswordHasher instance")

    try:
        return hasher.verify(encoded_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def benchmark_hashing(
    password: str,
    *,
    iterations: int = 3,
    hasher: PasswordHasher | None = None,
) -> list[HashingBenchmark]:
    """Measure average hash and verification times for both algorithms.

    Timing results depend on the machine, system load, and Argon2 parameters.
    The supplied password is used only in memory and is not logged.
    """
    _validate_password(password)
    _validate_iterations(iterations)

    if hasher is None:
        hasher = PasswordHasher()

    if not isinstance(hasher, PasswordHasher):
        raise TypeError("hasher must be a PasswordHasher instance")

    results = []

    # SHA-256 comparison baseline.
    sha_hash_time = 0.0
    sha_verify_time = 0.0

    for _ in range(iterations):
        start = perf_counter()
        digest = hash_sha256(password)
        sha_hash_time += perf_counter() - start

        start = perf_counter()
        verified = verify_sha256(password, digest)
        sha_verify_time += perf_counter() - start

        if not verified:
            raise RuntimeError("SHA-256 verification unexpectedly failed")

    results.append(
        HashingBenchmark(
            algorithm="SHA-256 (comparison only)",
            iterations=iterations,
            average_hash_seconds=sha_hash_time / iterations,
            average_verify_seconds=sha_verify_time / iterations,
            memory_cost_kib=None,
        )
    )

    # Argon2id password-hashing implementation.
    argon_hash_time = 0.0
    argon_verify_time = 0.0

    for _ in range(iterations):
        start = perf_counter()
        encoded_hash = hash_argon2id(password, hasher=hasher)
        argon_hash_time += perf_counter() - start

        start = perf_counter()
        verified = verify_argon2id(
            password,
            encoded_hash,
            hasher=hasher,
        )
        argon_verify_time += perf_counter() - start

        if not verified:
            raise RuntimeError("Argon2id verification unexpectedly failed")

    results.append(
        HashingBenchmark(
            algorithm="Argon2id",
            iterations=iterations,
            average_hash_seconds=argon_hash_time / iterations,
            average_verify_seconds=argon_verify_time / iterations,
            memory_cost_kib=hasher.memory_cost,
        )
    )

    return results
