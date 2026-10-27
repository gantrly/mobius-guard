"""Curated high-precision patterns. These win over gitleaks rules on the same text."""

from __future__ import annotations

from collections.abc import Callable

from .patterns import Pattern
from .validators import aadhaar_valid, card_number_valid, iban_valid, phone_valid

# Characters that may appear inside a base64url / API-key style token.
_TOK = r"[A-Za-z0-9_-]"
# Not preceded or followed by another token character.
_L = r"(?<![A-Za-z0-9_-])"
_R = r"(?![A-Za-z0-9_-])"


def _secret(id_: str, rx: str, desc: str, *, group: int | str | None = 0) -> Pattern:
    return Pattern(
        id=id_, category="secret", source="curated", regex=rx, description=desc, group=group
    )


def _pii(
    id_: str, rx: str, desc: str, *, validator: Callable[[str], bool] | None = None
) -> Pattern:
    return Pattern(
        id=id_, category="pii", source="curated", regex=rx, description=desc, validator=validator
    )


CURATED: tuple[Pattern, ...] = (
    # ------------------------------------------------------------------ cloud and APIs
    _secret(
        "aws_access_key_id",
        r"(?<![A-Z0-9])(?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}(?![A-Z0-9])",
        "AWS access key ID",
    ),
    _secret(
        "aws_secret_access_key",
        r"(?i)aws.{0,20}?(?:secret|sk).{0,20}?[\s'\"=:]{1,5}([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])",
        "AWS secret access key next to an AWS label",
        group=1,
    ),
    _secret(
        "github_token",
        _L + r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}" + _R,
        "GitHub personal, OAuth, app or refresh token",
    ),
    _secret(
        "github_fine_grained_token",
        _L + r"github_pat_[A-Za-z0-9_]{82}" + _R,
        "GitHub fine-grained personal access token",
    ),
    _secret(
        "gitlab_token",
        _L + r"glpat-[A-Za-z0-9_-]{20,}" + _R,
        "GitLab personal access token",
    ),
    _secret(
        "openai_api_key",
        _L
        + r"sk-(?:(?:proj|svcacct|admin)-"
        + _TOK
        + r"{40,}|[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})"
        + _R,
        "OpenAI API key",
    ),
    _secret(
        "anthropic_api_key",
        _L + r"sk-ant-(?:api|admin)\d{2}-" + _TOK + r"{80,}" + _R,
        "Anthropic API key",
    ),
    _secret(
        "google_api_key",
        _L + r"AIza[0-9A-Za-z_-]{35}" + _R,
        "Google API key",
    ),
    _secret(
        "huggingface_token",
        _L + r"hf_[A-Za-z0-9]{34,}" + _R,
        "Hugging Face access token",
    ),
    _secret(
        "slack_token",
        _L + r"xox[abposr]-[A-Za-z0-9-]{10,}" + _R,
        "Slack token",
    ),
    _secret(
        "slack_webhook_url",
        r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{24}",
        "Slack incoming webhook URL",
    ),
    _secret(
        "stripe_secret_key",
        _L + r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,}" + _R,
        "Stripe secret or restricted key",
    ),
    _secret(
        "npm_token",
        _L + r"npm_[A-Za-z0-9]{36}" + _R,
        "npm access token",
    ),
    _secret(
        "json_web_token",
        _L + r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}" + _R,
        "JSON Web Token",
    ),
    _secret(
        "private_key",
        r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]{1,8000}?"
        r"-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----",
        "PEM private key block",
    ),
    _secret(
        "connection_string_password",
        r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql)"
        r"://[^\s:/@]+:([^\s:/@]{3,})@",
        "Password inside a database or broker URL",
        group=1,
    ),
    _secret(
        "bearer_token",
        r"(?i)\bauthorization\s*:\s*bearer\s+([A-Za-z0-9._~+/-]{20,}=*)",
        "Bearer token in an Authorization header",
        group=1,
    ),
    # ------------------------------------------------------------------ personal data
    _pii(
        "email",
        r"(?<![\w.%+-])[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}(?![\w-])",
        "Email address",
    ),
    _pii(
        "payment_card",
        r"(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d-])",
        "Payment card number (issuer prefix, length and Luhn check)",
        validator=card_number_valid,
    ),
    _pii(
        "iban",
        r"(?<![A-Za-z0-9])[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}(?![A-Za-z0-9])",
        "International bank account number (mod-97 check)",
        validator=iban_valid,
    ),
    _pii(
        "us_ssn",
        r"(?<![\d-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\d-])",
        "US Social Security number (dashed form only)",
    ),
    _pii(
        "in_aadhaar",
        r"(?<![\d-])[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?![\d-])",
        "Indian Aadhaar number (Verhoeff check)",
        validator=aadhaar_valid,
    ),
    _pii(
        "in_pan",
        r"(?<![A-Za-z0-9])[A-Z]{3}[ABCFGHJLPT][A-Z]\d{4}[A-Z](?![A-Za-z0-9])",
        "Indian PAN (permanent account number)",
    ),
    _pii(
        "phone_international",
        r"(?<![\w+])\+[1-9]\d{0,2}(?:[ .-]?\(?\d{1,4}\)?){2,5}(?![\w])",
        "Phone number in international format (+country code, 8-15 digits)",
        validator=phone_valid,
    ),
)
