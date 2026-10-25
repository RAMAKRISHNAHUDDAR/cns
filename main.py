"""Interactive command-line interface for the CNS password security project."""

from modules.analyzer import analyze_password
from modules.recommendations import generate_recommendations
from modules.generator import generate_password
from modules.hashing_lab import (
    benchmark_hashing,
    hash_argon2id,
    verify_argon2id,
)
from modules.simulator import run_dictionary_attack, run_exhaustive_search


def show_menu() -> None:
    print("\n=== CNS Password Security Toolkit ===")
    print("1. Generate a secure password")
    print("2. Run a dictionary attack simulation")
    print("3. Run an exhaustive-search simulation")
    print("4. Demonstrate Argon2id hashing")
    print("5. Compare SHA-256 and Argon2id performance")
    print("6. Analyze password security and get recommendations")
    print("0. Exit")


def ask_yes_no(prompt: str, default: bool = True) -> bool:
    """Ask a yes/no question and return the selected value."""
    suffix = "Y/n" if default else "y/N"
    answer = input(f"{prompt} ({suffix}): ").strip().lower()

    if not answer:
        return default
    if answer in ("y", "yes"):
        return True
    if answer in ("n", "no"):
        return False

    raise ValueError("Please enter y or n.")


def generate_password_menu() -> None:
    """Generate a password using the user's selected options."""
    raw_length = input("Password length (default 16): ").strip()
    length = int(raw_length) if raw_length else 16

    use_lowercase = ask_yes_no("Include lowercase letters?")
    use_uppercase = ask_yes_no("Include uppercase letters?")
    use_digits = ask_yes_no("Include digits?")
    use_symbols = ask_yes_no("Include symbols?")

    exclude_ambiguous = ask_yes_no(
        "Exclude ambiguous characters (I, l, 1, O, 0)?",
        default=False,
    )

    password = generate_password(
        length=length,
        use_lowercase=use_lowercase,
        use_uppercase=use_uppercase,
        use_digits=use_digits,
        use_symbols=use_symbols,
        exclude_ambiguous=exclude_ambiguous,
    )

    print(f"\nGenerated password: {password}")
    print("Store it securely; this application does not save it.")


def dictionary_attack_menu() -> None:
    """Demonstrate a dictionary attack using synthetic local data."""
    target = "cns"
    candidates = ["password", "welcome", "student", "cns", "security"]

    result = run_dictionary_attack(
        target,
        candidates,
        max_attempts=100,
    )

    print("\nDictionary Attack Simulation")
    print("Target: synthetic demonstration value")
    print(f"Attempts: {result.attempts}")
    print(f"Match found: {result.match_found}")
    print(f"Elapsed time: {result.elapsed_seconds:.6f} seconds")
    print(f"Stop reason: {result.stop_reason}")


def exhaustive_search_menu() -> None:
    """Demonstrate a bounded exhaustive search with synthetic data."""
    target = "cab"

    result = run_exhaustive_search(
        target,
        charset="abc",
        min_length=1,
        max_length=3,
        max_attempts=100,
    )

    print("\nExhaustive-Search Simulation")
    print("Character set: abc")
    print("Search lengths: 1 to 3")
    print("Maximum attempts: 100")
    print(f"Attempts: {result.attempts}")
    print(f"Match found: {result.match_found}")
    print(f"Elapsed time: {result.elapsed_seconds:.6f} seconds")
    print(f"Stop reason: {result.stop_reason}")


def argon2id_menu() -> None:
    """Demonstrate Argon2id hashing and password verification."""
    password = input(
        "Enter a disposable sample password for this demonstration: "
    )

    if not password:
        print("Password cannot be empty.")
        return

    encoded_hash = hash_argon2id(password)

    print("\nEncoded Argon2id hash:")
    print(encoded_hash)

    candidate = input("Re-enter the sample password to verify it: ")
    verified = verify_argon2id(candidate, encoded_hash)

    print(f"Verification successful: {verified}")


def hashing_benchmark_menu() -> None:
    """Compare hashing performance using a synthetic sample password."""
    sample_password = "Demo-Password-Only-42!"
    measurements = benchmark_hashing(sample_password, iterations=3)

    print("\nHashing Performance Comparison")
    print("Input: synthetic demonstration password")

    for item in measurements:
        print(f"\nAlgorithm: {item.algorithm}")
        print(f"Iterations: {item.iterations}")
        print(
            f"Average hash time: "
            f"{item.average_hash_seconds:.6f} seconds"
        )
        print(
            f"Average verification time: "
            f"{item.average_verify_seconds:.6f} seconds"
        )

        if item.memory_cost_kib is not None:
            print(f"Memory cost: {item.memory_cost_kib:,} KiB")

    print("\nSecurity note:")
    print("SHA-256 alone is not suitable for password storage.")
    print("Argon2id is designed for password hashing.")


def main() -> None:
    actions = {
        "1": generate_password_menu,
        "2": dictionary_attack_menu,
        "3": exhaustive_search_menu,
        "4": argon2id_menu,
        "5": hashing_benchmark_menu,
        "6": analyze_password_menu,
    }

    while True:
        try:
            show_menu()
            choice = input("Select an option: ").strip()

            if choice == "0":
                print("Exiting CNS Password Security Toolkit.")
                break

            action = actions.get(choice)

            if action is None:
                print("Invalid option. Please select 0 through 6.")
                continue

            try:
                action()
            except (TypeError, ValueError) as exc:
                print(f"Invalid input: {exc}")

            input("\nPress Enter to return to the menu...")

        except (EOFError, KeyboardInterrupt):
            print("\nExiting CNS Password Security Toolkit.")
            break

def analyze_password_menu() -> None:
    """Analyze a password and display actionable recommendations."""
    password = input(
        "Enter a password to analyze (not stored by this application): "
    )

    if not password:
        print("Password cannot be empty.")
        return

    findings = analyze_password(password)
    recommendations = generate_recommendations(findings)

    print("\nPassword Security Analysis")
    print(f"Length: {findings['length']} characters")
    print(f"Character groups used: {findings['character_groups']} of 4")
    print(f"Common password match: {findings['is_common']}")
    print(f"Repeated characters detected: {findings['has_repeated_chars']}")
    print(
        "Predictable sequence detected: "
        f"{findings['has_predictable_sequence']}"
    )

    print("\nRecommendations:")
    for number, recommendation in enumerate(recommendations, start=1):
        print(f"{number}. {recommendation}")

    print(
        "\nNote: These checks are heuristics, not a guarantee "
        "of password security."
    )


if __name__ == "__main__":
    main()
