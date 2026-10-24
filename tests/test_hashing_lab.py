
import pytest
from argon2 import PasswordHasher

from modules.hashing_lab import (
    benchmark_hashing,
    hash_argon2id,
    hash_sha256,
    verify_argon2id,
    verify_sha256,
)


@pytest.fixture
def test_hasher():
    # Fast parameters for unit tests only, not production storage.
    return PasswordHasher(
        time_cost=1,
        memory_cost=1024,
        parallelism=1,
    )


def test_sha256_is_deterministic():
    assert hash_sha256("SyntheticTest123!") == hash_sha256(
        "SyntheticTest123!"
    )


def test_sha256_verifies_correct_password():
    digest = hash_sha256("SyntheticTest123!")
    assert verify_sha256("SyntheticTest123!", digest) is True


def test_sha256_rejects_wrong_password():
    digest = hash_sha256("SyntheticTest123!")
    assert verify_sha256("WrongPassword!", digest) is False


def test_argon2id_hash_verifies_correct_password(test_hasher):
    encoded = hash_argon2id(
        "SyntheticTest123!",
        hasher=test_hasher,
    )

    assert verify_argon2id(
        "SyntheticTest123!",
        encoded,
        hasher=test_hasher,
    ) is True


def test_argon2id_rejects_wrong_password(test_hasher):
    encoded = hash_argon2id(
        "SyntheticTest123!",
        hasher=test_hasher,
    )

    assert verify_argon2id(
        "WrongPassword!",
        encoded,
        hasher=test_hasher,
    ) is False


def test_argon2id_uses_unique_salts(test_hasher):
    first = hash_argon2id("SyntheticTest123!", hasher=test_hasher)
    second = hash_argon2id("SyntheticTest123!", hasher=test_hasher)

    assert first != second
    assert verify_argon2id(
        "SyntheticTest123!", first, hasher=test_hasher
    )
    assert verify_argon2id(
        "SyntheticTest123!", second, hasher=test_hasher
    )


def test_argon2id_rejects_malformed_hash(test_hasher):
    assert verify_argon2id(
        "SyntheticTest123!",
        "not-a-valid-argon2-hash",
        hasher=test_hasher,
    ) is False


@pytest.mark.parametrize("bad_password", ["", None, 123, True])
def test_hash_functions_validate_passwords(bad_password):
    if bad_password == "":
        expected_error = ValueError
    else:
        expected_error = TypeError

    with pytest.raises(expected_error):
        hash_sha256(bad_password)

    with pytest.raises(expected_error):
        hash_argon2id(
            bad_password,
            hasher=PasswordHasher(
                time_cost=1,
                memory_cost=1024,
                parallelism=1,
            ),
        )


def test_sha256_rejects_non_string_digest():
    with pytest.raises(TypeError):
        verify_sha256("SyntheticTest123!", None)


def test_benchmark_returns_both_algorithms(test_hasher):
    results = benchmark_hashing(
        "SyntheticTest123!",
        iterations=1,
        hasher=test_hasher,
    )

    assert len(results) == 2
    assert results[0].algorithm.startswith("SHA-256")
    assert results[1].algorithm == "Argon2id"


def test_benchmark_metrics_are_valid(test_hasher):
    results = benchmark_hashing(
        "SyntheticTest123!",
        iterations=1,
        hasher=test_hasher,
    )

    for result in results:
        assert result.iterations == 1
        assert result.average_hash_seconds >= 0
        assert result.average_verify_seconds >= 0

    assert results[0].memory_cost_kib is None
    assert results[1].memory_cost_kib == test_hasher.memory_cost


def test_benchmark_rejects_invalid_iterations():
    with pytest.raises(ValueError):
        benchmark_hashing("SyntheticTest123!", iterations=0)
