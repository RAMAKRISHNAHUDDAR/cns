
"""Bounded, local-only password attack simulations.

These functions operate on synthetic plaintext test targets. They do not
connect to external services or attempt authentication.
"""

from dataclasses import dataclass
from itertools import product
from time import perf_counter
from typing import Iterable, Iterator


@dataclass(frozen=True)
class AttackResult:
    """Immutable summary of a simulation."""

    attack_type: str
    attempts: int
    elapsed_seconds: float
    match_found: bool
    matched_candidate: str | None
    stop_reason: str


def _validate_target(target: str) -> None:
    if not isinstance(target, str):
        raise TypeError("target must be a string")
    if not target:
        raise ValueError("target must not be empty")


def _validate_max_attempts(max_attempts: int) -> None:
    if isinstance(max_attempts, bool) or not isinstance(max_attempts, int):
        raise TypeError("max_attempts must be an integer")
    if max_attempts < 1:
        raise ValueError("max_attempts must be at least 1")


def _validate_candidates(candidates: Iterable[str]) -> Iterator[str]:
    if isinstance(candidates, (str, bytes)):
        raise TypeError("candidates must be an iterable of strings, not one string")

    try:
        iterator = iter(candidates)
    except TypeError as exc:
        raise TypeError("candidates must be iterable") from exc

    for candidate in iterator:
        if not isinstance(candidate, str):
            raise TypeError("every candidate must be a string")
        yield candidate


def run_dictionary_attack(
    target: str,
    candidates: Iterable[str],
    *,
    max_attempts: int = 10_000,
) -> AttackResult:
    """Search a candidate iterable against a synthetic plaintext target.

    At most max_attempts candidates are examined. Duplicate candidates
    count as separate attempts because they were separately examined.
    """
    _validate_target(target)
    _validate_max_attempts(max_attempts)

    attempts = 0
    started = perf_counter()
    matched_candidate = None
    stop_reason = "candidate_list_exhausted"

    for candidate in _validate_candidates(candidates):
        if attempts >= max_attempts:
            stop_reason = "attempt_limit_reached"
            break

        attempts += 1

        if candidate == target:
            matched_candidate = candidate
            stop_reason = "match_found"
            break

    elapsed = perf_counter() - started

    return AttackResult(
        attack_type="dictionary",
        attempts=attempts,
        elapsed_seconds=elapsed,
        match_found=matched_candidate is not None,
        matched_candidate=matched_candidate,
        stop_reason=stop_reason,
    )


def run_exhaustive_search(
    target: str,
    *,
    charset: str = "abcdefghijklmnopqrstuvwxyz",
    min_length: int = 1,
    max_length: int = 4,
    max_attempts: int = 100_000,
) -> AttackResult:
    """Search candidates in exhaustive, increasing-length order.

    The search is local and bounded. The attempt limit is mandatory
    in practice and defaults to a finite value.
    """
    _validate_target(target)
    _validate_max_attempts(max_attempts)

    if not isinstance(charset, str):
        raise TypeError("charset must be a string")
    if not charset:
        raise ValueError("charset must not be empty")
    if len(set(charset)) != len(charset):
        raise ValueError("charset must not contain duplicate characters")

    for name, value in (
        ("min_length", min_length),
        ("max_length", max_length),
    ):
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{name} must be an integer")

    if min_length < 1:
        raise ValueError("min_length must be at least 1")
    if max_length < min_length:
        raise ValueError("max_length must be greater than or equal to min_length")

    attempts = 0
    started = perf_counter()
    matched_candidate = None
    stop_reason = "search_space_exhausted"

    for length in range(min_length, max_length + 1):
        for chars in product(charset, repeat=length):
            if attempts >= max_attempts:
                stop_reason = "attempt_limit_reached"
                break

            candidate = "".join(chars)
            attempts += 1

            if candidate == target:
                matched_candidate = candidate
                stop_reason = "match_found"
                break

        if matched_candidate is not None or stop_reason == "attempt_limit_reached":
            break

    elapsed = perf_counter() - started

    return AttackResult(
        attack_type="exhaustive",
        attempts=attempts,
        elapsed_seconds=elapsed,
        match_found=matched_candidate is not None,
        matched_candidate=matched_candidate,
        stop_reason=stop_reason,
    )
