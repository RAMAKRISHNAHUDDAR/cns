import pytest

from modules.recommendations import generate_recommendations


def make_findings(**overrides):
    findings = {
        "length": 16,
        "is_common": False,
        "has_repeated_chars": False,
        "has_predictable_sequence": False,
        "character_groups": 4,
    }
    findings.update(overrides)
    return findings


def test_flags_common_password():
    result = generate_recommendations(make_findings(is_common=True))
    assert any("common" in item.lower() for item in result)


def test_recommends_longer_password():
    result = generate_recommendations(make_findings(length=8))
    assert any("12 characters" in item for item in result)


def test_flags_low_character_group_count():
    result = generate_recommendations(
        make_findings(character_groups=2)
    )
    assert any("character types" in item for item in result)


def test_flags_repeated_characters():
    result = generate_recommendations(
        make_findings(has_repeated_chars=True)
    )
    assert any("repeated-character" in item for item in result)


def test_flags_predictable_sequences():
    result = generate_recommendations(
        make_findings(has_predictable_sequence=True)
    )
    assert any("predictable sequences" in item for item in result)


def test_general_advice_when_no_findings_are_flagged():
    result = generate_recommendations(make_findings())
    assert any("multi-factor authentication" in item for item in result)
    assert any("password manager" in item for item in result)


def test_missing_key_is_rejected():
    findings = make_findings()
    del findings["length"]

    with pytest.raises(ValueError, match="Missing required findings"):
        generate_recommendations(findings)


def test_invalid_boolean_is_rejected():
    with pytest.raises(TypeError, match="is_common"):
        generate_recommendations(make_findings(is_common=1))


def test_negative_length_is_rejected():
    with pytest.raises(ValueError, match="cannot be negative"):
        generate_recommendations(make_findings(length=-1))


def test_invalid_character_group_count_is_rejected():
    with pytest.raises(ValueError, match="between 0 and 4"):
        generate_recommendations(make_findings(character_groups=5))


def test_non_mapping_is_rejected():
    with pytest.raises(TypeError, match="findings must be a mapping"):
        generate_recommendations([])
