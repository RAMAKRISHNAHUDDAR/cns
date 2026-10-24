
import pytest

from modules.generator import generate_password


def test_default_password_length():
    password = generate_password()
    assert len(password) == 16


def test_requested_length():
    password = generate_password(24)
    assert len(password) == 24


def test_all_enabled_groups_are_present():
    password = generate_password(
        12,
        use_lowercase=True,
        use_uppercase=True,
        use_digits=True,
        use_symbols=True,
    )

    assert any(c.islower() for c in password)
    assert any(c.isupper() for c in password)
    assert any(c.isdigit() for c in password)
    assert any(c in "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~" for c in password)


def test_lowercase_only():
    password = generate_password(
        20,
        use_lowercase=True,
        use_uppercase=False,
        use_digits=False,
        use_symbols=False,
    )

    assert len(password) == 20
    assert all(c in "abcdefghijklmnopqrstuvwxyz" for c in password)


def test_excludes_ambiguous_characters():
    password = generate_password(100, exclude_ambiguous=True)
    assert not set(password).intersection(set("Il1O0"))


def test_no_character_group_enabled():
    with pytest.raises(ValueError):
        generate_password(
            use_lowercase=False,
            use_uppercase=False,
            use_digits=False,
            use_symbols=False,
        )


def test_length_must_be_positive():
    with pytest.raises(ValueError):
        generate_password(0)


def test_boolean_length_is_rejected():
    with pytest.raises(TypeError):
        generate_password(True)


def test_impossible_required_groups():
    with pytest.raises(ValueError):
        generate_password(2)


def test_invalid_option_type():
    with pytest.raises(TypeError):
        generate_password(12, use_digits=1)
