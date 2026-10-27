"""Streaming redaction for LLM output.

Rewrites secrets and PII that are split across chunks, without buffering the
whole reply.
"""

__version__ = "0.0.0"
