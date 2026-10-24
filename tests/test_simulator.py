
import pytest

from modules.simulator import (
    AttackResult,
    run_dictionary_attack,
    run_exhaustive_search,
)


def test_dictionary_finds_target():
    result = run_dictionary_attack(
        "cat",
        ["dog", "bird", "cat", "fox"],
    )

    assert isinstance(result, AttackResult)
    assert result.match_found is True
    assert result.matched_candidate == "cat"
    assert result.attempts == 3
    assert result.stop_reason == "match_found"


def test_dictionary_target_not_found():
    result = run_dictionary_attack("cat", ["dog", "bird"])

    assert result.match_found is False
    assert result.matched_candidate is None
    assert result.attempts == 2
    assert result.stop_reason == "candidate_list_exhausted"


def test_dictionary_respects_attempt_limit():
    result = run_dictionary_attack(
        "never",
        ["a", "b", "c", "d"],
        max_attempts=2,
    )

    assert result.attempts == 2
    assert result.stop_reason == "attempt_limit_reached"


def test_dictionary_stops_at_match_before_limit():
    result = run_dictionary_attack(
        "b",
        ["a", "b", "c"],
        max_attempts=2,
    )

    assert result.match_found is True
    assert result.attempts == 2


def test_dictionary_rejects_string_as_candidate_collection():
    with pytest.raises(TypeError):
        run_dictionary_attack("cat", "cat")


def test_dictionary_rejects_empty_target():
    with pytest.raises(ValueError):
        run_dictionary_attack("", ["a"])


def test_dictionary_rejects_invalid_candidate():
    with pytest.raises(TypeError):
        run_dictionary_attack("cat", ["dog", 123])


def test_invalid_attempt_limit():
    with pytest.raises(ValueError):
        run_dictionary_attack("cat", ["cat"], max_attempts=0)


def test_exhaustive_search_finds_target():
    result = run_exhaustive_search(
        "ba",
        charset="ab",
        min_length=1,
        max_length=2,
    )

    # Order: a, b, aa, ab, ba
    assert result.match_found is True
    assert result.matched_candidate == "ba"
    assert result.attempts == 5


def test_exhaustive_search_respects_limit():
    result = run_exhaustive_search(
        "zz",
        charset="ab",
        min_length=1,
        max_length=3,
        max_attempts=3,
    )

    assert result.match_found is False
    assert result.attempts == 3
    assert result.stop_reason == "attempt_limit_reached"


def test_exhaustive_search_space_exhausted():
    result = run_exhaustive_search(
        "z",
        charset="ab",
        min_length=1,
        max_length=1,
    )

    assert result.match_found is False
    assert result.attempts == 2
    assert result.stop_reason == "search_space_exhausted"


def test_exhaustive_search_rejects_duplicate_charset():
    with pytest.raises(ValueError):
        run_exhaustive_search("a", charset="aab")


def test_exhaustive_search_rejects_invalid_lengths():
    with pytest.raises(ValueError):
        run_exhaustive_search("a", min_length=3, max_length=2)


def test_result_has_nonnegative_elapsed_time():
    result = run_dictionary_attack("a", ["a"])

    assert result.elapsed_seconds >= 0
