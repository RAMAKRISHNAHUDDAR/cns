
import pytest

from modules import analyzer
from modules.recommendations import generate_recommendations


def test_analyzes_password_length_and_character_groups():
    result = analyzer.analyze_password("Abcdef12!")

    assert result["length"] == 9
    assert result["character_groups"] == 4


def test_detects_repeated_characters():
    result = analyzer.analyze_password("Passsword123!")

    assert result["has_repeated_chars"] is True


def test_detects_predictable_sequence():
    result = analyzer.analyze_password("Myabcde!789")

    assert result["has_predictable_sequence"] is True


def test_does_not_flag_password_without_obvious_patterns():
    result = analyzer.analyze_password("V7$mQ2!zLp9@")

    assert result["has_repeated_chars"] is False
    assert result["has_predictable_sequence"] is False


def test_detects_common_password_case_insensitively(
    tmp_path, monkeypatch
):
    password_file = tmp_path / "common_passwords.txt"
    password_file.write_text(
        "password\nwelcome\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        analyzer,
        "COMMON_PASSWORDS_FILE",
        password_file,
    )

    result = analyzer.analyze_password("PASSWORD")

    assert result["is_common"] is True


def test_empty_password_is_rejected():
    with pytest.raises(ValueError, match="cannot be empty"):
        analyzer.analyze_password("")


def test_non_string_password_is_rejected():
    with pytest.raises(TypeError, match="must be a string"):
        analyzer.analyze_password(123)


def test_empty_common_password_file_is_supported(
    tmp_path, monkeypatch
):
    password_file = tmp_path / "common_passwords.txt"
    password_file.write_text("", encoding="utf-8")
    monkeypatch.setattr(
        analyzer,
        "COMMON_PASSWORDS_FILE",
        password_file,
    )

    result = analyzer.analyze_password("SomethingUnique!29")

    assert result["is_common"] is False



def test_analyzer_findings_work_with_recommendations():
    findings = analyzer.analyze_password("abcde123")
    recommendations = generate_recommendations(findings)

    assert isinstance(recommendations, list)
    assert recommendations
    assert any(
        "predictable sequences" in item.lower()
        for item in recommendations
    )



def test_strong_sample_gets_general_security_advice():
    findings = analyzer.analyze_password("V7$mQ2!zLp9@")
    recommendations = generate_recommendations(findings)

    assert any(
        "password manager" in item.lower()
        for item in recommendations
    )
