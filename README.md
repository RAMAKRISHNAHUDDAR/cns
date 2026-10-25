# Password Security Analyzer

## 1. Project Overview

The Password Security Analyzer is a Python-based project developed for the Cryptography and Network Security (CNS).

It helps users understand password security by analyzing passwords, generating strong passwords, simulating password attacks, and demonstrating password hashing.

## 2. Features

- **Password Generator:** Generates strong passwords using letters, numbers, and symbols.
- **Password Analyzer:** Checks password length, common passwords, repeated characters, and predictable sequences.
- **Security Recommendations:** Suggests ways to improve password security.
- **Dictionary Attack Simulation:** Demonstrates how an attacker can guess a password using a list of common passwords.
- **Exhaustive Search Simulation:** Demonstrates password guessing by trying different character combinations.
- **Password Hashing:** Demonstrates SHA-256 and Argon2id hashing.
- **Hashing Benchmark:** Compares the time required to hash and verify passwords using SHA-256 and Argon2id.
- **Web Interface:** Provides a simple interface using Streamlit.

## 3. Technologies Used

- Python
- Streamlit
- Argon2id
- SHA-256
- Pytest

## 4. Project Structure

```text
cns/
├── app.py
├── main.py
├── requirements.txt
├── README.md
├── .gitignore
│
├── data/
│   └── common_passwords.txt
│
├── modules/
│   ├── analyzer.py
│   ├── generator.py
│   ├── hashing_lab.py
│   ├── recommendations.py
│   └── simulator.py
│
├── experiments/
│   └── benchmark.py
│
└── tests/
    ├── test_analyzer.py
    ├── test_benchmark.py
    ├── test_generator.py
    ├── test_hashing_lab.py
    ├── test_recommendations.py
    └── test_simulator.py
```

## 5. CNS Concepts Used

- **Password Security:** Evaluates password strength and identifies common patterns.
- **Brute-Force Attack:** Demonstrates password guessing through exhaustive search.
- **Dictionary Attack:** Demonstrates password guessing using common passwords.
- **Cryptographic Hashing:** Uses SHA-256 and Argon2id to demonstrate password hashing.
- **Password Security Testing:** Measures hashing performance and tests the implemented features.

## 6. Installation

Make sure Python is installed on your system.

Install the required packages:

```bash
pip install -r requirements.txt
```

## 7. How to Run

### Run the Web Interface

```bash
python -m streamlit run app.py
```

Open the local URL displayed in the terminal.

### Run the Command-Line Interface

```bash
python main.py
```

Follow the menu displayed in the terminal to use the available features.

## 8. Run Tests

Run the following command to test the project:

```bash
python -m pytest -q
```

## 9. Important Note

The dictionary attack and exhaustive search features are simulations for educational purposes. They do not attack real accounts or external systems.

SHA-256 is included for comparison and learning. Argon2id is designed for password hashing and is more appropriate for securely storing passwords.

## 10. Conclusion

This project demonstrates important Cryptography and Network Security concepts through password analysis, password generation, attack simulations, hashing, and security recommendations.
