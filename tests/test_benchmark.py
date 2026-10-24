
import pytest

from experiments.benchmark import calculate_search_space


def test_calculates_search_space_correctly():
    assert calculate_search_space(26, 4) == 456_976


def test_single_character_space():
    assert calculate_search_space(1, 5) == 1


def test_rejects_zero_or_negative_values():
    with pytest.raises(ValueError):
        calculate_search_space(0, 4)

    with pytest.raises(ValueError):
        calculate_search_space(26, 0)

    with pytest.raises(ValueError):
        calculate_search_space(26, -1)


@pytest.mark.parametrize("value", [True, False, 4.5, "26", None])
def test_rejects_invalid_character_set_size(value):
    with pytest.raises(TypeError):
        calculate_search_space(value, 4)


@pytest.mark.parametrize("value", [True, False, 3.5, "4", None])
def test_rejects_invalid_password_length(value):
    with pytest.raises(TypeError):
        calculate_search_space(26, value)
