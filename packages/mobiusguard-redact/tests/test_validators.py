import pytest
from mobiusguard_redact.validators import (
    aadhaar_valid,
    card_number_valid,
    iban_valid,
    luhn_valid,
    phone_valid,
    shannon_entropy,
)
from samples import AADHAAR


@pytest.mark.parametrize(
    ("number", "ok"),
    [
        ("4111 1111 1111 1111", True),
        ("4111-1111-1111-1112", False),
        ("378282246310005", True),  # Amex
        ("5555555555554444", True),  # Mastercard
        ("2223003122003222", True),  # Mastercard 2-series
        ("6011111111111117", True),  # Discover
        ("1234567812345670", False),  # passes Luhn, unknown issuer
        ("41111111111111", False),  # Visa prefix, wrong length
    ],
)
def test_card_number(number: str, ok: bool) -> None:
    assert card_number_valid(number) is ok


def test_luhn_empty_is_invalid() -> None:
    assert not luhn_valid("")


@pytest.mark.parametrize(
    ("iban", "ok"),
    [
        ("GB82 WEST 1234 5698 7654 32", True),
        ("DE89370400440532013000", True),
        ("FR1420041010050500013M02606", True),
        ("GB82 WEST 1234 5698 7654 33", False),
        ("GB82WEST123456987654", False),  # too short for GB
        ("ZZ82WEST12345698765432", False),  # unknown country
    ],
)
def test_iban(iban: str, ok: bool) -> None:
    assert iban_valid(iban) is ok


def test_aadhaar() -> None:
    assert aadhaar_valid(AADHAAR)
    wrong = AADHAAR[:-1] + str((int(AADHAAR[-1]) + 1) % 10)
    assert not aadhaar_valid(wrong)
    assert not aadhaar_valid("1" + AADHAAR[1:])


def test_phone_digit_count() -> None:
    assert phone_valid("+91 98765 43210")
    assert not phone_valid("+1 555")
    assert not phone_valid("+1 2345 6789 0123 4567")


def test_entropy_matches_gitleaks_definition() -> None:
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abcd") == pytest.approx(2.0)
