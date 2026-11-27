"""Best-effort redaction of secret-shaped substrings in raw text before
it's written to the audit log (audit.py).

Deliberately not exhaustive, and not a claim that the audit log is safe
to treat as non-sensitive afterward (see SECURITY.md) - this can't
recognize an arbitrary, unlabeled secret value with no structural
signature at all. What it does catch reliably: the concrete shapes that
show up in practice (confirmed by external review: a live bearer token
passed to curl's `-H` landed in the log verbatim before this existed) -
Authorization headers, credentials embedded in a URL, well-known API
token prefixes from major providers, and an inline `VARNAME=value`
assignment where the name itself announces what it is.

The last of these is deliberately over-inclusive rather than exact:
matching any variable name ending in TOKEN/SECRET/KEY/PASSWORD/PASS/
CREDENTIAL(S) also redacts a false positive like `MONKEY=banana`
(ends in "KEY"). That asymmetry is the right one for a security log -
an occasional over-redacted benign value costs a little audit-log
detail; an under-redacted real secret costs the secret.
"""

import re

_REDACTED = "***REDACTED***"

_AUTH_BEARER_RE = re.compile(r"(Authorization:\s*Bearer\s+)\S+", re.IGNORECASE)
_AUTH_BASIC_RE = re.compile(r"(Authorization:\s*Basic\s+)\S+", re.IGNORECASE)
_URL_CREDENTIALS_RE = re.compile(r"(://[^/\s:@]+:)[^/\s:@]+(@)")
_KNOWN_TOKEN_PREFIXES_RE = re.compile(
    r"\b(?:"
    r"sk-[A-Za-z0-9_-]{10,}"              # OpenAI-style
    r"|gh[pousr]_[A-Za-z0-9]{20,}"        # GitHub PAT/OAuth/user/server/refresh tokens
    r"|AKIA[0-9A-Z]{16}"                  # AWS access key ID
    r"|AIza[0-9A-Za-z_-]{20,}"            # Google API key
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"      # Slack tokens
    r"|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"  # JWT
    r")\b"
)
_SECRET_ASSIGNMENT_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*(?:TOKEN|SECRET|KEY|PASSWORD|PASS|CREDENTIAL)S?=)\S+",
    re.IGNORECASE,
)


def redact(text: str) -> str:
    if not text:
        return text
    text = _AUTH_BEARER_RE.sub(r"\1" + _REDACTED, text)
    text = _AUTH_BASIC_RE.sub(r"\1" + _REDACTED, text)
    text = _URL_CREDENTIALS_RE.sub(r"\1" + _REDACTED + r"\2", text)
    text = _KNOWN_TOKEN_PREFIXES_RE.sub(_REDACTED, text)
    text = _SECRET_ASSIGNMENT_RE.sub(r"\1" + _REDACTED, text)
    return text
