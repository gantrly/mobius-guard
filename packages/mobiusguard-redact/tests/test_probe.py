import pytest
import regex
from mobiusguard_redact import default_patterns
from mobiusguard_redact._probe import make_greedy


@pytest.mark.parametrize(
    ("lazy", "greedy"),
    [
        (r"\w*?abc", r"\w*abc"),
        (r"x{0,5}?y", r"x{0,5}y"),
        (r"a??b", r"a?b"),
        (r"(?:a|b)+?", r"(?:a|b)+"),
        (r"(?i)[\w.-]{0,50}?(?:k)", r"(?i)[\w.-]{0,50}(?:k)"),
        (r"\*?x", r"\*?x"),  # escaped star, then a real optional
        (r"\*??x", r"\*?x"),
        (r"[*?]+?z", r"[*?]+z"),  # '?' inside a class is literal
        (r"[]?]*?q", r"[]?]*q"),  # ']' first in a class is literal
        (r"[^]?]*?q", r"[^]?]*q"),
        (r"\{0,5}?", r"\{0,5}?"),  # escaped brace is not a quantifier
        (r"a{2}?", r"a{2}"),
        (r"(?<=x)y+?", r"(?<=x)y+"),
    ],
)
def test_make_greedy(lazy: str, greedy: str) -> None:
    assert make_greedy(lazy) == greedy


def test_regex_lazy_partial_quirk_is_still_worked_around() -> None:
    # If this starts failing, the regex library may have fixed the quirk (decision 0007).
    m = regex.search(r"\w*?abc", "Hello there", partial=True)
    assert m is not None
    assert m.partial
    assert m.start() == 0
    g = regex.search(make_greedy(r"\w*?abc"), "Hello there", partial=True)
    assert g is not None
    assert g.start() == len("Hello ")


def test_every_shipped_probe_compiles() -> None:
    for p in default_patterns():
        assert p.probe.pattern == make_greedy(p.regex)
