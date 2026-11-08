"""Redaction filter and registry for sensitive credentials, keys, and tokens.
Ensures zero-leak credential requirements in logs and diagnostic artifacts.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Set

_SECRETS: Set[str] = set()

# Pre-compiled patterns for common secrets: JWT, Private Keys, Bearer tokens
_PATTERNS = [
    # Private Key PEM blocks
    re.compile(r"-----BEGIN (?:[A-Z ]+)?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z ]+)?PRIVATE KEY-----"),
    # JWT tokens (standard 3-segment base64url)
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
]


def register_secret(secret: str | None) -> None:
    """Register a plaintext secret string to be redacted from all outputs."""
    if not secret:
        return
    s = str(secret).strip()
    # Only register secrets of meaningful length to avoid redacting common single characters
    if len(s) >= 4:
        _SECRETS.add(s)


def register_pattern(pattern: re.Pattern | str) -> None:
    """Register a regular expression pattern to be redacted."""
    if isinstance(pattern, str):
        _PATTERNS.append(re.compile(pattern))
    else:
        _PATTERNS.append(pattern)


def clear_secrets() -> None:
    """Clear all registered secrets (useful in tests)."""
    _SECRETS.clear()


def redact(text: str) -> str:
    """Redact all registered secrets and sensitive patterns from text."""
    if not text:
        return ""
    result = text
    # 1. Apply regex patterns
    for pat in _PATTERNS:
        result = pat.sub("[REDACTED]", result)

    # 2. Apply registered literal secrets (sorted by length descending to redact longest first)
    for sec in sorted(_SECRETS, key=len, reverse=True):
        result = result.replace(sec, "[REDACTED]")

    return result


def write_redacted_text(path: str | Path, text: str, mode: int = 0o600) -> None:
    """Write text to file with all secrets redacted and enforced mode."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    redacted_content = redact(text)
    tmp_path = p.with_name(f".{p.name}.tmp")
    tmp_path.write_text(redacted_content, encoding="utf-8")
    tmp_path.chmod(mode)
    os_replace(tmp_path, p)


def os_replace(src: Path, dst: Path) -> None:
    import os
    os.replace(str(src), str(dst))
