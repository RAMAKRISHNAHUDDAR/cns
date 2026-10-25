
"""Analyze password characteristics without storing the password."""

import string
from pathlib import Path


COMMON_PASSWORDS_FILE = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "common_passwords.txt"
)


def analyze_password(password: str) -> dict[str, object]:
    """Return password findings for the recommendation module.

    The password is processed in memory and is not stored or logged.
    """
    if not isinstance(password, str):
        raise TypeError("password must be a string")

    if not password:
        raise ValueError("password cannot be empty")

    common_passwords = set()

    if COMMON_PASSWORDS_FILE.is_file():
        with COMMON_PASSWORDS_FILE.open(
            "r", encoding="utf-8"
        ) as password_file:
            common_passwords = {
                line.strip().casefold()
                for line in password_file
                if line.strip()
            }

    character_groups = sum(
        (
            any(char in string.ascii_lowercase for char in password),
            any(char in string.ascii_uppercase for char in password),
            any(char in string.digits for char in password),
            any(char in string.punctuation for char in password),
        )
    )

    has_repeated_chars = any(
        password[index] == password[index - 1]
        for index in range(1, len(password))
    )

    lowered = password.casefold()
    sequences = (
        "abcdefghijklmnopqrstuvwxyz",
        "0123456789",
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
    )

    has_predictable_sequence = any(
        sequence[index:index + 4] in lowered
        or sequence[index:index + 4][::-1] in lowered
        for sequence in sequences
        for index in range(len(sequence) - 3)
    )

    return {
        "length": len(password),
        "is_common": lowered in common_passwords,
        "has_repeated_chars": has_repeated_chars,
        "has_predictable_sequence": has_predictable_sequence,
        "character_groups": character_groups,
    }
