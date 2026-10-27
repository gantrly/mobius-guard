import pytest
import regex
from mobiusguard_redact import (
    Pattern,
    StreamRedactor,
    default_patterns,
    gitleaks_patterns,
    redact,
)
from mobiusguard_redact._gitleaks_rules import GITLEAKS_VERSION, RULES
from mobiusguard_redact.curated import CURATED
from samples import NEGATIVES, POSITIVES

ALL = default_patterns()


def test_every_gitleaks_rule_with_a_regex_is_shipped() -> None:
    ids = {p.id for p in gitleaks_patterns()}
    assert len(ids) == len(RULES) == 221
    assert GITLEAKS_VERSION == "v8.30.1"


def test_ids_are_unique_and_curated_come_first() -> None:
    ids = [p.id for p in ALL]
    assert len(ids) == len(set(ids))
    assert ALL[: len(CURATED)] == CURATED


def test_exclude_drops_patterns_by_id() -> None:
    kept = default_patterns(exclude={"email", "generic-api-key"})
    assert {"email", "generic-api-key"}.isdisjoint(p.id for p in kept)
    assert len(kept) == len(ALL) - 2


@pytest.mark.parametrize(("pattern_id", "text", "secret"), POSITIVES)
def test_curated_positive(pattern_id: str, text: str, secret: str) -> None:
    out = redact(text, CURATED)
    assert secret not in out
    assert f"[REDACTED:{pattern_id}]" in out


@pytest.mark.parametrize(("pattern_id", "text", "secret"), POSITIVES)
def test_positive_still_redacted_with_all_patterns(pattern_id: str, text: str, secret: str) -> None:
    assert secret not in redact(text, ALL)


@pytest.mark.parametrize("text", NEGATIVES)
def test_negative_left_alone(text: str) -> None:
    assert redact(text, ALL) == text


def test_only_the_secret_group_is_replaced() -> None:
    out = redact("postgres://app:Sup3rS3cret!@db:5432/x", CURATED)
    assert out == "postgres://app:[REDACTED:connection_string_password]@db:5432/x"


# ---------------------------------------------------------------- gitleaks semantics


def _rule(rule_id: str) -> Pattern:
    return next(p for p in gitleaks_patterns() if p.id == rule_id)


def test_gitleaks_first_non_empty_group_is_the_secret() -> None:
    rule = _rule("sendgrid-api-token")
    token = "SG." + "aZ3_" * 16 + "k9"
    out = redact(f'key = "{token}"', [rule])
    assert token not in out
    assert out.startswith('key = "[REDACTED:sendgrid-api-token]')


def test_gitleaks_low_entropy_is_skipped() -> None:
    rule = _rule("generic-api-key")
    assert redact("api_key = aaaaaaaaaaaaaaaaaaaa", [rule]) == "api_key = aaaaaaaaaaaaaaaaaaaa"
    out = redact("api_key = Zx81kQ0vLp3mW7rT2yB9", [rule])
    assert "Zx81kQ0vLp3mW7rT2yB9" not in out


def test_gitleaks_global_allowlist_applies() -> None:
    rule = _rule("generic-api-key")
    # ${VAR} placeholders are excused by gitleaks' global allowlist.
    assert redact("api_key = ${MY_SECRET_TOKEN}", [rule]) == "api_key = ${MY_SECRET_TOKEN}"


def test_gitleaks_rule_allowlist_applies() -> None:
    rule = _rule("aws-access-token")
    assert redact("AKIAIOSFODNN7EXAMPLE", [rule]) == "AKIAIOSFODNN7EXAMPLE"


def test_mid_pattern_inline_flag_is_scoped_like_go() -> None:
    p = regex.compile(r"^/Users/(?i)[a-z0-9]+/x$")
    assert p.match("/Users/AB/x")
    assert not p.match("/USERS/ab/x")


def test_email_is_not_the_password_inside_a_url() -> None:
    out = redact("mongodb+srv://admin:Hunter2pass@c0.x.net/db")
    assert out == "mongodb+srv://admin:[REDACTED:connection_string_password]@c0.x.net/db"


def test_a_finished_email_is_not_held_back() -> None:
    # Regression: a variable-length lookbehind in the email regex made `regex` report the
    # match as still growing, so everything after it was held until the holdback overflowed.
    text = 'echo "confirmation:contact@contact.com" | base64\n' + "word " * 3000
    r = StreamRedactor()
    out = r.feed(text)
    assert r.held < 20
    assert "holdback_overflow" not in out + r.flush()


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # Found by the evaluation harness: a following short token joined the match, the
        # longer string failed its check, and the real number went out unredacted.
        ("IBAN: GB12QWGV85573393572200 5. next", "IBAN: [REDACTED:iban] 5. next"),
        ("IBAN: GB82MHNG22494737015024 VITE", "IBAN: [REDACTED:iban] VITE"),
        ("my card is 4121 5299 1419 9801 2) Coach", "my card is [REDACTED:payment_card] 2) Coach"),
    ],
)
def test_a_trailing_piece_does_not_hide_a_valid_number(text: str, expected: str) -> None:
    assert redact(text) == expected


def test_an_invalid_card_is_not_taken_for_an_aadhaar_number() -> None:
    # Its last 12 digits can pass the Aadhaar check by chance; 4-4-4-4 blocks are a card.
    assert redact("card 4121 5299 1419 9802 x") == "card 4121 5299 1419 9802 x"
