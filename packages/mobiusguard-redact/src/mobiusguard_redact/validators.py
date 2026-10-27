"""Checks that confirm a regex match is real, to cut false positives."""

from __future__ import annotations

import math
from collections import Counter


def digits(text: str) -> str:
    return "".join(c for c in text if c.isdigit())


def shannon_entropy(text: str) -> float:
    """Bits per character, the same way gitleaks computes it."""
    if not text:
        return 0.0
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in Counter(text).values())


def luhn_valid(number: str) -> bool:
    """Payment card check digit (ISO/IEC 7812)."""
    ds = [int(c) for c in digits(number)]
    if not ds:
        return False
    total = 0
    for i, d in enumerate(reversed(ds)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# Card number lengths per issuer prefix (major networks only).
_CARD_PREFIXES: tuple[tuple[tuple[str, ...], tuple[int, ...]], ...] = (
    (("4",), (13, 16, 19)),  # Visa
    (tuple(str(p) for p in range(51, 56)), (16,)),  # Mastercard
    (tuple(str(p) for p in range(2221, 2721)), (16,)),  # Mastercard 2-series
    (("34", "37"), (15,)),  # American Express
    (("6011", "65", *(str(p) for p in range(644, 650))), (16, 19)),  # Discover
    (tuple(str(p) for p in range(3528, 3590)), (16, 19)),  # JCB
    (("36", "300", "301", "302", "303", "304", "305", "38", "39"), (14, 16, 19)),  # Diners
    (("60", "65", "81", "82", "508", "353", "356"), (16, 19)),  # RuPay
    (("62",), (16, 17, 18, 19)),  # UnionPay
)


def card_number_valid(text: str) -> bool:
    """A known issuer prefix, a valid length for it, and a correct Luhn digit."""
    number = digits(text)
    for prefixes, lengths in _CARD_PREFIXES:
        if len(number) in lengths and number.startswith(prefixes):
            return luhn_valid(number)
    return False


# IBAN length per country (ISO 13616 registry, common countries).
_IBAN_LENGTHS: dict[str, int] = {
    "AD": 24, "AE": 23, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22, "BH": 22, "BR": 29,
    "CH": 21, "CR": 22, "CY": 28, "CZ": 24, "DE": 22, "DK": 18, "DO": 28, "EE": 20, "EG": 29,
    "ES": 24, "FI": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27,
    "GT": 28, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27, "JO": 30,
    "KW": 30, "KZ": 20, "LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20, "LV": 21, "MC": 27,
    "MD": 24, "ME": 22, "MK": 19, "MR": 27, "MT": 31, "MU": 30, "NL": 18, "NO": 15, "PK": 24,
    "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22, "SA": 24, "SC": 31, "SE": 24,
    "SI": 19, "SK": 24, "SM": 27, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20,
}  # fmt: skip


def iban_valid(text: str) -> bool:
    """Country length and the ISO 7064 mod-97 check."""
    iban = "".join(text.split()).upper()
    if _IBAN_LENGTHS.get(iban[:2]) != len(iban) or not iban.isalnum():
        return False
    rearranged = iban[4:] + iban[:4]
    numeric = "".join(str(int(c, 36)) for c in rearranged)
    return int(numeric) % 97 == 1


# Verhoeff tables (dihedral group D5), used by Aadhaar.
_V_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6), (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8), (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2), (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4), (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)  # fmt: skip
_V_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2), (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0), (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5), (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)  # fmt: skip


def verhoeff_valid(number: str) -> bool:
    ds = digits(number)
    if not ds:
        return False
    c = 0
    for i, ch in enumerate(reversed(ds)):
        c = _V_D[c][_V_P[i % 8][int(ch)]]
    return c == 0


def aadhaar_valid(text: str) -> bool:
    """12 digits, not starting with 0 or 1, with a correct Verhoeff check digit."""
    number = digits(text)
    return len(number) == 12 and number[0] not in "01" and verhoeff_valid(number)


def phone_valid(text: str) -> bool:
    """E.164 allows at most 15 digits; require at least 8 to skip short codes."""
    return 8 <= len(digits(text)) <= 15
