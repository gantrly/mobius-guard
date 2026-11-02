"""Streaming redaction for LLM output.

Rewrites secrets and PII that are split across chunks, without buffering the whole reply.
"""

from .patterns import Pattern, default_patterns, gitleaks_patterns
from .redactor import Finding, StreamRedactor, aredact_stream, redact, redact_stream

__version__ = "0.1.0"

__all__ = [
    "Finding",
    "Pattern",
    "StreamRedactor",
    "aredact_stream",
    "default_patterns",
    "gitleaks_patterns",
    "redact",
    "redact_stream",
]
