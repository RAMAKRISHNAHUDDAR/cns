
"""Cryptographically secure password generation."""

import secrets
import string


LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = string.punctuation

AMBIGUOUS_CHARACTERS = frozenset("Il1O0")


def generate_password(
    length: int = 16,
    *,
    use_lowercase: bool = True,
    use_uppercase: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_ambiguous: bool = False,
    require_each: bool = True,
) -> str:
    """Generate a cryptographically secure random password.

    Args:
        length: Required password length.
        use_lowercase: Include lowercase ASCII letters.
        use_uppercase: Include uppercase ASCII letters.
        use_digits: Include decimal digits.
        use_symbols: Include ASCII punctuation.
        exclude_ambiguous: Exclude visually similar characters.
        require_each: Include at least one character from each
            enabled character group.

    Returns:
        A randomly generated password.

    Raises:
        TypeError: If an argument has an invalid type.
        ValueError: If the requested configuration is impossible.
    """
    if isinstance(length, bool) or not isinstance(length, int):
        raise TypeError("length must be an integer")

    if length < 1:
        raise ValueError("length must be at least 1")

    options = {
        "use_lowercase": use_lowercase,
        "use_uppercase": use_uppercase,
        "use_digits": use_digits,
        "use_symbols": use_symbols,
        "exclude_ambiguous": exclude_ambiguous,
        "require_each": require_each,
    }

    for name, value in options.items():
        if not isinstance(value, bool):
            raise TypeError(f"{name} must be a boolean")

    groups = []

    if use_lowercase:
        groups.append(LOWERCASE)
    if use_uppercase:
        groups.append(UPPERCASE)
    if use_digits:
        groups.append(DIGITS)
    if use_symbols:
        groups.append(SYMBOLS)

    if not groups:
        raise ValueError("At least one character group must be enabled")

    if exclude_ambiguous:
        groups = [
            "".join(c for c in group if c not in AMBIGUOUS_CHARACTERS)
            for group in groups
        ]

    if any(not group for group in groups):
        raise ValueError("A selected character group is empty")

    if require_each and length < len(groups):
        raise ValueError(
            "length must be at least the number of enabled character groups"
        )

    alphabet = "".join(groups)

    # Securely select one character from every enabled group first.
    if require_each:
        password_chars = [secrets.choice(group) for group in groups]
    else:
        password_chars = []

    # Fill remaining positions using the combined alphabet.
    password_chars.extend(
        secrets.choice(alphabet)
        for _ in range(length - len(password_chars))
    )

    # Securely shuffle to avoid predictable character positions.
    secrets.SystemRandom().shuffle(password_chars)

    return "".join(password_chars)
