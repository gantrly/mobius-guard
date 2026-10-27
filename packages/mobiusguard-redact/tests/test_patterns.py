import pytest
import regex
from mobiusguard_redact import Pattern, default_patterns, gitleaks_patterns, redact
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
