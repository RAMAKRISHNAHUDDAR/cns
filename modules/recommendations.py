
"""Generate actionable password-security recommendations."""

from collections.abc import Mapping


def generate_recommendations(
    findings: Mapping[str, object],
) -> list[str]:
    """Generate recommendations from password analyzer findings.

    Expected keys:
        length: Password length as an integer.
        is_common: Whether the password is in a common-password list.
        has_repeated_chars: Whether characters repeat consecutively.
        has_predictable_sequence: Whether a predictable sequence exists.
        character_groups: Number of distinct character groups used.

    Raises:
        TypeError: If findings or its values have invalid types.
        ValueError: If numeric findings are outside valid ranges.
    """
    if not isinstance(findings, Mapping):
        raise TypeError("findings must be a mapping")

    required = {
        "length",
        "is_common",
        "has_repeated_chars",
        "has_predictable_sequence",
        "character_groups",
    }

    missing = required - findings.keys()
    if missing:
        raise ValueError(
            f"Missing required findings: {', '.join(sorted(missing))}"
        )

    length = findings["length"]
    is_common = findings["is_common"]
    has_repeated_chars = findings["has_repeated_chars"]
    has_predictable_sequence = findings["has_predictable_sequence"]
    character_groups = findings["character_groups"]

    if isinstance(length, bool) or not isinstance(length, int):
        raise TypeError("length must be an integer")
    if length < 0:
        raise ValueError("length cannot be negative")

    if isinstance(character_groups, bool) or not isinstance(
        character_groups, int
    ):
        raise TypeError("character_groups must be an integer")
    if not 0 <= character_groups <= 4:
        raise ValueError("character_groups must be between 0 and 4")

    for name, value in (
        ("is_common", is_common),
        ("has_repeated_chars", has_repeated_chars),
        ("has_predictable_sequence", has_predictable_sequence),
    ):
        if not isinstance(value, bool):
            raise TypeError(f"{name} must be a boolean")

    recommendations = []

    if is_common:
        recommendations.append(
            "Avoid common or previously exposed passwords; choose a unique one."
        )

    if length < 12:
        recommendations.append(
            "Use at least 12 characters; a longer passphrase is even better."
        )

    if character_groups < 3:
        recommendations.append(
            "Consider using a broader mix of character types, "
            "or choose a longer passphrase."
        )

    if has_repeated_chars:
        recommendations.append(
            "Avoid obvious repeated-character patterns."
        )

    if has_predictable_sequence:
        recommendations.append(
            "Avoid predictable sequences such as '12345' or 'abcdef'."
        )

    if not recommendations:
        recommendations.append(
            "No flagged patterns were found by these checks. "
            "Use a unique password and enable multi-factor authentication."
        )

    recommendations.append(
        "Never reuse passwords across accounts; use a password manager."
    )

    return recommendations
