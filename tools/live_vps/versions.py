"""The one rule both contours use to compare a reported version to a configured one.

The live runner interrogates the Master's Panel, Node and Node-managed core over
SSH, and the container suite interrogates the same three binaries inside its
target. A second copy of the matching rule would let the two contours disagree
about what "the configured version" means — an explicit pin is an exact token,
while the shipped default is the floating channel and can only be asked to
report a version at all — so the rule lives here and both import it.
"""
from __future__ import annotations

import re

# A version, as the rule above reads one: at least two numeric components, not
# glued to a word or to a longer number (so "26.11.9" does not match inside
# "26.11.90" and "v1.19.34-linux" still yields "1.19.34").
VERSION_RE = re.compile(r"(?<![A-Za-z0-9])v?([0-9]+(?:\.[0-9]+)+)(?![A-Za-z0-9])")


def version_token(output: str) -> str:
    """The first version the text reports, or an empty string.

    Two components are compared with the same lexer that decides whether a pin
    was met, so "the client core matches the server core" cannot be true under
    one rule and false under the other.
    """
    match = VERSION_RE.search(output or "")
    return match.group(1) if match else ""


def output_matches_expected_version(output: str, expected: str) -> bool:
    """Match a tool's reported version against the configured release channel.

    The configured value is normally ``latest``: the installers resolve the
    upstream channel, so the only honest assertion is that the component reports
    a version at all. An explicit version/tag keeps the exact-token comparison
    for a deliberate pin.
    """
    text = output or ""
    normalized = str(expected).strip()
    if normalized.lower() in ("", "latest"):
        return VERSION_RE.search(text) is not None
    pinned = normalized.lstrip("vV")
    if not pinned:
        return False
    pattern = rf"(?<![A-Za-z0-9])v?{re.escape(pinned)}(?![A-Za-z0-9])"
    return re.search(pattern, text, flags=re.IGNORECASE) is not None
