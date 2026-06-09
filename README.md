# Semgrep Evaluation for SAST of AI-Generated Code

This repository contains a Proof of Concept (PoC) demonstrating the use of Semgrep to identify and remediate security vulnerabilities in AI-generated code. A Python application generated using GitHub Copilot was used as the Application Under Test (AUT).
## Objective
Evaluate Semgrep's effectiveness in identifying vulnerabilities in AI-generated code.

## Scope
- Security Audit Ruleset
- OWASP Top 10 Ruleset
- Custom Security Rules

## Vulnerabilities Tested
- Command Injection
- SQL Injection
- Unsafe Serialization
- Unsafe Deserialization
- Weak Cryptography
- Hardcoded Credentials

## Outcome
All vulnerabilities were detected, remediated, and validated successfully.

## Tools Used
- GitHub Copilot
- Semgrep
- Python
- SQLite

## Project Structure

- ai_generated_auth.py – AI-generated vulnerable application
- ai_generated_auth_fixed.py – Remediated version
- ai-security.yml – Custom Semgrep security rules
- report.json – Semgrep JSON output
- report.sarif – SARIF report for integration tools


## Findings

- Command Injection
- Unsafe Serialization
- Unsafe Deserialization
- Weak Password Hashing (MD5)
- Hardcoded Credentials (via custom rules)

## Result

All findings were remediated and validation scans reported zero findings.

## Setup

```bash
pip install semgrep
```

## Run Security Audit Scan

```bash
semgrep --config=p/security-audit ai_generated_auth.py
```

## Run OWASP Top 10 Scan

```bash
semgrep --config=p/owasp-top-ten ai_generated_auth.py
```

## Run Custom Security Rule

```bash
semgrep --config ai-security.yml ai_generated_auth.py
```