"""Small, conservative redaction boundary for operational text.

This module accepts text supplied by an error or diagnostic caller. It never
reads process state and never attempts to discover credentials. Suspicious
credential-shaped values are replaced before operational text is serialized.
"""

from __future__ import annotations

import re

__all__ = ["redact_text"]


_URL_CREDENTIALS = re.compile(
    r"(?P<prefix>\bhttps?://)(?P<user>[^\s/:@]+):(?P<secret>[^\s/@]+)@",
    re.IGNORECASE,
)
_NAMED_VALUE = re.compile(
    r"(?P<label>\b(?:api[ _-]?key|access[ _-]?token|authorization|bearer)\b)"
    r"(?P<separator>\s*[:=]\s*|\s+)"
    r"(?P<value>(?:bearer\s+)?[^,;\s]+)",
    re.IGNORECASE,
)
_PEM_BLOCK = re.compile(
    r"-----BEGIN [^-\r\n]+-----.*?-----END [^-\r\n]+-----",
    re.IGNORECASE | re.DOTALL,
)
_LONG_HEX = re.compile(r"(?<![0-9a-f])0x[0-9a-f]{64}(?![0-9a-f])", re.IGNORECASE)
_WORD_RUN = re.compile(r"(?<!\S)(?:[A-Za-z]+\s+){11,23}[A-Za-z]+(?!\S)")


def redact_text(value: object) -> str:
    """Return deterministic text with common credential-shaped values removed."""
    text = str(value)
    text = _PEM_BLOCK.sub("[REDACTED_BLOCK]", text)
    text = _URL_CREDENTIALS.sub(r"\g<prefix>[REDACTED]@", text)
    text = _NAMED_VALUE.sub(r"\g<label>\g<separator>[REDACTED]", text)
    text = _LONG_HEX.sub("[REDACTED_HEX]", text)
    text = _WORD_RUN.sub("[REDACTED_PHRASE]", text)
    return text
