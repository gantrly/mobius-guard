"""Fake secrets and PII used across the tests. None of these are real credentials."""

from __future__ import annotations

from mobiusguard_redact.validators import _V_D, _V_P  # pyright: ignore[reportPrivateUsage]


def _verhoeff_check_digit(body: str) -> str:
    c = 0
    for i, ch in enumerate(reversed(body + "0")):
        c = _V_D[c][_V_P[i % 8][int(ch)]]
    inv = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)
    return str(inv[c])


AADHAAR = "2345 6789 012" + _verhoeff_check_digit("23456789012")

# (pattern id, text that must be redacted, the exact part that must disappear)
POSITIVES: list[tuple[str, str, str]] = [
    ("aws_access_key_id", "key AKIAQWERTYUIOPASDFGH here", "AKIAQWERTYUIOPASDFGH"),
    (
        "aws_secret_access_key",
        'aws_secret_access_key = "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"',
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzQ9tP3kLmN",
    ),
    ("github_token", "use ghp_" + "Zx9Q" * 9 + " now", "ghp_" + "Zx9Q" * 9),
    (
        "github_fine_grained_token",
        "github_pat_" + "A1b2C3d4E5_" * 7 + "x" * 5,
        "github_pat_" + "A1b2C3d4E5_" * 7 + "x" * 5,
    ),
    ("gitlab_token", "token glpat-Ab3dEf6hIj9kLm2nOp5q ok", "glpat-Ab3dEf6hIj9kLm2nOp5q"),
    (
        "openai_api_key",
        "OPENAI_API_KEY=sk-proj-" + "Q7w_E9r-T2y" * 5,
        "sk-proj-" + "Q7w_E9r-T2y" * 5,
    ),
    (
        "anthropic_api_key",
        "sk-ant-api03-" + "aB3_dE6-gH9" * 8 + "AA",
        "sk-ant-api03-" + "aB3_dE6-gH9" * 8 + "AA",
    ),
    (
        "google_api_key",
        "AIzaSyD3kF9mQ2xV7bN1pL6tR8wY4cZ0hJ5uE2a",
        "AIzaSyD3kF9mQ2xV7bN1pL6tR8wY4cZ0hJ5uE2a",
    ),
    ("huggingface_token", "hf_" + "kQ3mZ8xW1v" * 4, "hf_" + "kQ3mZ8xW1v" * 4),
    ("slack_token", "xoxb-2048-4096-Zq8Lm3Np7Rt1", "xoxb-2048-4096-Zq8Lm3Np7Rt1"),
    (
        "stripe_secret_key",
        "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc",
        "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc",
    ),
    ("npm_token", "npm_" + "Xk2Lq9Wm4Rz7" * 3, "npm_" + "Xk2Lq9Wm4Rz7" * 3),
    (
        "json_web_token",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    ),
    (
        "private_key",
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEA3Tz2mr7SZiAMfQyuvBjM2\n"
        "-----END RSA PRIVATE KEY-----",
        "MIIEpAIBAAKCAQEA3Tz2mr7SZiAMfQyuvBjM2",
    ),
    (
        "connection_string_password",
        "postgres://app:Sup3rS3cret!@db.internal:5432/x",
        "Sup3rS3cret!",
    ),
    ("bearer_token", "Authorization: Bearer abcDEF123456ghiJKL789mno", "abcDEF123456ghiJKL789mno"),
    ("email", "write to jo.doe+test@example.co.uk today", "jo.doe+test@example.co.uk"),
    ("payment_card", "card 4111 1111 1111 1111 exp", "4111 1111 1111 1111"),
    ("payment_card", "amex 378282246310005.", "378282246310005"),
    ("iban", "IBAN GB82 WEST 1234 5698 7654 32 ok", "GB82 WEST 1234 5698 7654 32"),
    ("iban", "DE89370400440532013000", "DE89370400440532013000"),
    ("us_ssn", "SSN 123-45-6789.", "123-45-6789"),
    ("in_aadhaar", f"Aadhaar {AADHAAR} done", AADHAAR),
    ("in_pan", "PAN ABCPE1234F", "ABCPE1234F"),
    ("phone_international", "call +91 98765 43210 now", "+91 98765 43210"),
    ("phone_international", "or +1 (415) 555-0132.", "+1 (415) 555-0132"),
]

# Text that looks close to a pattern but must be left alone.
NEGATIVES: list[str] = [
    "card 4111 1111 1111 1112 (bad Luhn)",
    "order number 1234567890123456",
    "IBAN GB82 WEST 1234 5698 7654 33 (bad check)",
    "SSN 000-12-3456 is invalid",
    "Aadhaar 1234 5678 9012 starts with 1",
    "version 1.2.3, port 8080, year 2026",
    "call 555-0132 locally",
    "the akia prefix in lowercase akiaqwertyuiopasdfg",
    "email me at name at example dot com",
    "sk-live is not a key",
    "a normal sentence about base64 encoding and how API keys work.",
]
