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
    id_: str,
    rx: str,
    desc: str,
    *,
    validator: Callable[[str], bool] | None = None,
    not_after: str = "",
) -> Pattern:
    return Pattern(
        id=id_,
        category="pii",
        source="curated",
        regex=rx,
        description=desc,
        validator=validator,
        not_after=not_after,
    )


CURATED: tuple[Pattern, ...] = (
    # ------------------------------------------------------------------ cloud and APIs
    _secret(
        "aws_access_key_id",
        # 16 characters after the prefix; 12 to 24 are taken because a model repeating a key
        # can drop or add a few, and most of the key would still go out (garbled echoes).
        r"(?<![A-Z0-9])(?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{12,24}(?![A-Z0-9])",
        "AWS access key ID",
    ),
    _secret(
        "aws_secret_access_key",
        r"(?i)(?:aws.{0,20}?(?:secret|sk)|secret[ _-]?(?:access[ _-]?)?key).{0,20}?"
        r"[\s'\"=:`*(<\[]{1,6}([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])",
        "AWS secret access key next to an AWS or secret-key label",
        group=1,
    ),
    _secret(
        "github_token",
        # 36 characters; 30 or more are taken: a model echoing a token can add or drop
        # characters, and the rest of the token must still go (live check, garbled echoes).
        _L + r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,255}" + _R,
        "GitHub personal, OAuth, app or refresh token",
    ),
    _secret(
        "github_fine_grained_token",
        _L + r"github_pat_[A-Za-z0-9_]{76,255}" + _R,  # 82, give or take
        "GitHub fine-grained personal access token",
    ),
    _secret(
        "gitlab_token",
        _L + r"glpat-[A-Za-z0-9_-]{16,}" + _R,  # 20 or more, minus a few
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
        _L + r"AIza[0-9A-Za-z_-]{30,45}" + _R,  # 35, give or take
        "Google API key",
    ),
    _secret(
        "huggingface_token",
        _L + r"hf_[A-Za-z0-9]{30,}" + _R,  # 34 or more, minus a few
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
        _L + r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}" + _R,  # 24 or more, minus a few
        "Stripe secret or restricted key",
    ),
    _secret(
        "npm_token",
        _L + r"npm_[A-Za-z0-9]{30,}" + _R,  # 36, give or take
        "npm access token",
    ),
    _secret(
        "json_web_token",
        _L + r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}" + _R,
        "JSON Web Token",
    ),
    _secret(
        "private_key",
        # The body may not contain "-----END": the block ends at the first END line, so the
        # text after it is not held back waiting for a later one. With no END line, it ends
        # with the reply (a model cut off mid-key); mid-reply it is held until the holdback
        # limit and then redacted (decision 0007).
        r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----(?:(?!-----END)[\s\S])+"
        r"(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----|\Z)",
        "PEM private key block, also one cut off before its END line",
    ),
    _secret(
        "connection_string_password",
        r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql)"
        r"://[^\s:/@]*:(?:([^\s:/@]{3,})@|([^\s:/@]*[^\d\s:/@][^\s:/@]*)(?=[/?#\s]))",
        "Password inside a database or broker URL (also when the @host part is missing: a "
        "'port' that isn't a number is a password)",
        group=None,
    ),
    _secret(
        "bearer_token",
        r"(?i)\bbearer\s+[`'\"<(\[*]{0,2}([A-Za-z0-9._~+/-]{20,}=*)",
        "Bearer token (in an Authorization header or written on its own)",
        group=1,
    ),
    # ------------------------------------------------------------------ personal data
    _pii(
        "email",
        r"(?<![\w.%+-])[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}(?![\w-])",
        "Email address",
        # Not the password in scheme://user:password@host: that is connection_string_password.
        not_after=r"://[^\s:/@]{1,256}:",
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
        # Not a 12-digit block inside a card written 4-4-4-4 (fixed-width lookarounds only).
        r"(?<![\d-])(?<!\d{4} )[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?![\d-])(?! \d{4}(?!\d))",
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
