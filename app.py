from pathlib import Path

import streamlit as st

from modules.analyzer import analyze_password
from modules.generator import generate_password
from modules.hashing_lab import (
    benchmark_hashing,
    hash_argon2id,
    verify_argon2id,
)
from modules.recommendations import generate_recommendations
from modules.simulator import run_dictionary_attack, run_exhaustive_search


BASE_DIR = Path(__file__).resolve().parent
COMMON_PASSWORDS_FILE = BASE_DIR / "data" / "common_passwords.txt"


st.set_page_config(
    page_title="CNS Password Security Toolkit",
    layout="wide",
)

st.title("CNS Password Security Toolkit")
st.caption("Cryptography and Network Security — Educational Demonstrations")

st.warning(
    "Use disposable sample passwords only. Password checks are heuristic "
    "and do not guarantee security. This app is intended for local educational use."
)

page = st.sidebar.radio(
    "Choose a feature",
    [
        "Home",
        "Password Generator",
        "Dictionary Attack",
        "Exhaustive Search",
        "Argon2id Hashing",
        "Hashing Benchmark",
        "Password Analyzer",
    ],
)


if page == "Home":
    st.subheader("Welcome")
    st.write(
        "Explore secure password generation, bounded password-guessing "
        "simulations, password hashing, performance comparisons, and analysis."
    )

    st.markdown(
        """
        ### Features
        - Generate passwords with configurable character groups.
        - Simulate dictionary attacks using a local candidate list.
        - Demonstrate exhaustive search with a strict attempt limit.
        - Hash and verify disposable sample passwords with Argon2id.
        - Compare SHA-256 and Argon2id performance.
        - Identify common password patterns and get recommendations.
        """
    )

    st.info(
        "SHA-256 is included only as a comparison baseline. "
        "It should not be used alone for password storage."
    )


elif page == "Password Generator":
    st.subheader("Generate a Secure Password")

    length = st.slider("Password length", 8, 64, 16)
    use_lowercase = st.checkbox("Lowercase letters", value=True)
    use_uppercase = st.checkbox("Uppercase letters", value=True)
    use_digits = st.checkbox("Digits", value=True)
    use_symbols = st.checkbox("Symbols", value=True)
    exclude_ambiguous = st.checkbox(
        "Exclude ambiguous characters", value=False
    )

    if st.button("Generate Password"):
        try:
            password = generate_password(
                length=length,
                use_lowercase=use_lowercase,
                use_uppercase=use_uppercase,
                use_digits=use_digits,
                use_symbols=use_symbols,
                exclude_ambiguous=exclude_ambiguous,
            )
            st.success("Password generated.")
            st.code(password)
            st.caption(
                "If you intend to use this password, store it in a trusted "
                "password manager. Avoid sharing or saving screenshots of it."
            )
        except (ValueError, TypeError) as exc:
            st.error(str(exc))


elif page == "Dictionary Attack":
    st.subheader("Dictionary Attack Simulation")
    st.write(
        "Tests candidate strings against a synthetic plaintext target. "
        "It does not connect to accounts or external services."
    )

    target = st.text_input(
        "Disposable target password", type="password", key="dictionary_target"
    )
    max_attempts = st.number_input(
        "Maximum attempts", min_value=1, max_value=10000, value=100, step=1
    )

    if st.button("Run Dictionary Simulation"):
        if not target:
            st.error("Enter a non-empty disposable target password.")
        elif not COMMON_PASSWORDS_FILE.is_file():
            st.error(f"Candidate list not found: {COMMON_PASSWORDS_FILE}")
        else:
            try:
                with COMMON_PASSWORDS_FILE.open(
                    "r", encoding="utf-8"
                ) as file:
                    candidates = [
                        line.strip() for line in file if line.strip()
                    ]

                result = run_dictionary_attack(
                    target,
                    candidates,
                    max_attempts=int(max_attempts),
                )

                st.metric("Attempts", result.attempts)
                st.write(f"Match found: **{result.match_found}**")
                st.write(
                    f"Elapsed time: {result.elapsed_seconds:.6f} seconds"
                )
                st.write(f"Stop reason: `{result.stop_reason}`")
            except (ValueError, TypeError, OSError) as exc:
                st.error(str(exc))
            finally:
                target = ""


elif page == "Exhaustive Search":
    st.subheader("Exhaustive-Search Simulation")
    st.warning(
        "Keep the character set and password lengths small. "
        "This simulation is bounded by the maximum-attempt limit."
    )

    target = st.text_input(
        "Disposable target password", type="password", key="exhaustive_target"
    )
    charset = st.text_input("Character set", value="abc")
    min_length = st.number_input(
        "Minimum length", min_value=1, max_value=8, value=1, step=1
    )
    max_length = st.number_input(
        "Maximum length", min_value=1, max_value=8, value=3, step=1
    )
    max_attempts = st.number_input(
        "Maximum attempts", min_value=1, max_value=100000, value=100, step=1
    )

    if st.button("Run Exhaustive Search"):
        if not target:
            st.error("Enter a non-empty disposable target password.")
        else:
            try:
                result = run_exhaustive_search(
                    target,
                    charset=charset,
                    min_length=int(min_length),
                    max_length=int(max_length),
                    max_attempts=int(max_attempts),
                )

                st.metric("Attempts", result.attempts)
                st.write(f"Match found: **{result.match_found}**")
                st.write(
                    f"Elapsed time: {result.elapsed_seconds:.6f} seconds"
                )
                st.write(f"Stop reason: `{result.stop_reason}`")
            except (ValueError, TypeError) as exc:
                st.error(str(exc))


elif page == "Argon2id Hashing":
    st.subheader("Argon2id Hashing and Verification")
    st.write(
        "Enter a disposable sample password. The app keeps the generated "
        "hash in session state only so you can demonstrate verification."
    )

    password = st.text_input(
        "Disposable sample password",
        type="password",
        key="argon_password",
    )

    if st.button("Hash Password"):
        if not password:
            st.error("Enter a non-empty sample password.")
        else:
            try:
                st.session_state["argon_hash"] = hash_argon2id(password)
                st.success("Argon2id hash generated.")
            except (ValueError, TypeError) as exc:
                st.error(str(exc))

    encoded_hash = st.session_state.get("argon_hash")

    if encoded_hash:
        with st.expander("View encoded Argon2id hash"):
            st.code(encoded_hash)

        verification_password = st.text_input(
            "Re-enter the sample password to verify",
            type="password",
            key="argon_verify_password",
        )

        if st.button("Verify Password"):
            if not verification_password:
                st.error("Enter the password to verify.")
            else:
                try:
                    verified = verify_argon2id(
                        verification_password,
                        encoded_hash,
                    )
                    if verified:
                        st.success("Verification successful.")
                    else:
                        st.error("Verification failed.")
                except (ValueError, TypeError) as exc:
                    st.error(str(exc))


elif page == "Hashing Benchmark":
    st.subheader("SHA-256 vs. Argon2id Performance")

    st.warning(
        "Enter a disposable sample password only. "
        "Do not use a real account password."
    )

    password = st.text_input(
        "Sample password for benchmarking",
        type="password",
        key="benchmark_password",
    )

    iterations = st.slider(
    "Benchmark iterations",
    1,
    10,
    3,
    key="benchmark_iterations",
    )

    if st.button("Run Benchmark", key="run_hashing_benchmark"):
        if not password:
            st.error("Enter a non-empty sample password.")
        else:
            try:
                results = benchmark_hashing(
                    password=password,
                    iterations=iterations,
                )

                for result in results:
                    st.markdown(f"### {result.algorithm}")

                    col1, col2, col3 = st.columns(3)

                    col1.metric(
                        "Average hash time",
                        f"{result.average_hash_seconds:.6f} s",
                    )
                    col2.metric(
                        "Average verification time",
                        f"{result.average_verify_seconds:.6f} s",
                    )
                    col3.metric("Iterations", result.iterations)

                    if result.memory_cost_kib is not None:
                        st.write(
                            f"Memory cost: {result.memory_cost_kib:,} KiB"
                        )

                st.info(
                    "SHA-256 is included for comparison only. "
                    "Argon2id is designed for password hashing."
                )

            except (ValueError, TypeError, RuntimeError) as exc:
                st.error(str(exc))





elif page == "Password Analyzer":
    st.subheader("Password Security Analyzer")

    password = st.text_input(
        "Enter a disposable password to analyze",
        type="password",
        key="analyzer_password",
    )

    if st.button("Analyze Password"):
        if not password:
            st.error("Enter a non-empty sample password.")
        else:
            try:
                findings = analyze_password(password)
                recommendations = generate_recommendations(findings)

                st.markdown("### Analysis Results")

                col1, col2 = st.columns(2)
                col1.metric("Password length", findings["length"])
                col2.metric(
                    "Character groups",
                    f'{findings["character_groups"]} / 4',
                )

                st.write(
                    f'Common password match: **{findings["is_common"]}**'
                )
                st.write(
                    "Repeated consecutive characters: "
                    f'**{findings["has_repeated_chars"]}**'
                )
                st.write(
                    "Predictable sequence detected: "
                    f'**{findings["has_predictable_sequence"]}**'
                )

                st.markdown("### Recommendations")
                for recommendation in recommendations:
                    st.write(f"- {recommendation}")

                st.caption(
                    "These checks are simple heuristics. They do not check "
                    "every password breach or guarantee password strength."
                )
            except (ValueError, TypeError, OSError) as exc:
                st.error(str(exc))
