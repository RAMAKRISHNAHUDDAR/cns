
"""Run reproducible, bounded CNS security experiments."""

from math import log2

from modules.hashing_lab import benchmark_hashing
from modules.simulator import run_exhaustive_search


def calculate_search_space(charset_size: int, password_length: int) -> int:
    """Return the number of possible fixed-length passwords."""
    if isinstance(charset_size, bool) or not isinstance(charset_size, int):
        raise TypeError("charset_size must be an integer")
    if isinstance(password_length, bool) or not isinstance(password_length, int):
        raise TypeError("password_length must be an integer")
    if charset_size < 1:
        raise ValueError("charset_size must be at least 1")
    if password_length < 1:
        raise ValueError("password_length must be at least 1")

    return charset_size**password_length


def main() -> None:
    # Experiment 1: estimate the search space for a lowercase alphabet.
    charset = "abcdefghijklmnopqrstuvwxyz"
    password_length = 4
    search_space = calculate_search_space(len(charset), password_length)

    print("=== CNS Password Security Benchmark ===")
    print("\n[1] Search-space analysis")
    print(f"Character set size: {len(charset)}")
    print(f"Password length: {password_length}")
    print(f"Possible passwords: {search_space:,}")
    print(f"Maximum search-space entropy: {password_length * log2(len(charset)):.2f} bits")

    # Experiment 2: bounded exhaustive search against a synthetic target.
    # This target is test data, not a real user's password.
    target = "cns"
    print("\n[2] Local exhaustive-search simulation")
    result = run_exhaustive_search(
        target,
        charset=charset,
        min_length=1,
        max_length=4,
        max_attempts=100_000,
    )
    print(f"Attack type: {result.attack_type}")
    print(f"Attempts: {result.attempts:,}")
    print(f"Elapsed time: {result.elapsed_seconds:.6f} seconds")
    print(f"Match found: {result.match_found}")
    print(f"Stop reason: {result.stop_reason}")

    # Experiment 3: compare fast general-purpose hashing with password hashing.
    # This fixed value is synthetic benchmark input only; never use it as a
    # real credential or store real passwords in benchmark output.
    benchmark_password = "Example-Only-Password-42!"
    print("\n[3] Hashing-performance comparison")
    for measurement in benchmark_hashing(benchmark_password, iterations=3):
        print(f"\nAlgorithm: {measurement.algorithm}")
        print(f"Iterations: {measurement.iterations}")
        print(f"Average hash time: {measurement.average_hash_seconds:.6f} seconds")
        print(
            "Average verification time: "
            f"{measurement.average_verify_seconds:.6f} seconds"
        )
        if measurement.memory_cost_kib is not None:
            print(f"Memory cost: {measurement.memory_cost_kib:,} KiB")


if __name__ == "__main__":
    main()
