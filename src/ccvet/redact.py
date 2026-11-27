"""Best-effort redaction of secret-shaped substrings in raw text before
it's written to the audit log (audit.py).

Deliberately not exhaustive, and not a claim that the audit log is safe
to treat as non-sensitive afterward (see SECURITY.md) - this can't
recognize an arbitrary, unlabeled secret value with no structural
signature at all. What it does catch reliably: the concrete shapes that
show up in practice (confirmed by external review: a live bearer token
passed to curl's `-H` landed in the log verbatim before this existed) -
Authorization headers, credentials embedded in a URL or a curl -u/--user
flag, well-known API token prefixes from major providers, and an inline
`VARNAME=value` assignment where the name itself announces what it is.

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
# The username is split off at the *first* colon only (": " further in
# is part of the password, not a second field) - found by external
# review: an earlier version excluded ":" from the password class too,
# so a password containing its own colon (legal; curl/URLs don't
# forbid it) either leaked a trailing tail after a partial redaction
# (the -u/--user case) or, worse, matched nothing at all and left the
# whole credential unredacted (the URL case, since the password class
# couldn't cross the colon to ever reach the required trailing "@").
#
# A previous version then excluded "?" (and, by the same logic, would
# have needed to exclude "#") from both halves entirely, to stop
# misreading a port-plus-query-string shape with an "@" in a query
# value as credentials, e.g. "https://api.host:8443?email=a@b.com"
# read as "8443?email=a" being the password. That fix was too blunt:
# found by a further review, it also meant a password that legitimately
# (if unconventionally - RFC 3986 doesn't allow a raw "?"/"#" in
# userinfo either, so this is already malformed URL syntax either way)
# contains a literal "?" or "#" and is embedded directly in a URL now
# silently leaked in full, e.g. "https://alice:pa?sword@host/x" -
# simply excluding the character can't distinguish "this ? starts a
# password" from "this ? starts a query string", because both shapes
# are, in isolation, exactly the same text.
#
# What actually distinguishes them: in the false-positive shape, the
# text between the colon and the "?"/"#" is *purely digits* (a port
# number) with nothing else before the query/fragment starts. A real
# password containing "?"/"#" virtually never looks like that (pure
# digits then immediately a literal "?"/"#"). The negative lookahead
# below rejects only that specific "digits-then-?/#" shape, rather than
# "?"/"#" everywhere, so a password that happens to be purely numeric
# with no "?"/"#" following still redacts correctly (confirmed:
# "https://alice:8443@host" redacts), and a password containing "?"/"#"
# anywhere else in it redacts correctly too.
_URL_CREDENTIALS_RE = re.compile(r"(://[^/\s:@?#]+:)(?!\d+[?#])([^/\s@]+)(@)")
# curl's -u/--user USER:PASS basic-auth flag: a second shape for the
# same "credentials glued to a username by a colon" idea the URL
# pattern above already covers, just not behind a URL. The username
# isn't the secret, same as the URL case - keep it visible, redact
# only the password half (everything after the first colon up to
# whitespace, which may itself contain colons - see note above).
_BASIC_AUTH_FLAG_RE = re.compile(r"((?:^|\s)(?:-u|--user)[ =]+)([^\s:]+):(\S+)")
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
# Found by external review: the leading identifier segment was required
# (`[A-Za-z_][A-Za-z0-9_]*`, one-or-more), so a bare `password=`/
# `secret=`/`token=`/`key=` - arguably the single most common real-world
# form - passed through untouched; only a *prefixed* name like
# `API_PASSWORD=` matched. Made the leading segment optional so a bare
# keyword matches too. Also widened the character class to allow a
# hyphen in the name (not just the trailing keyword check), since a
# header-style flag value like `x-access-token=...` is a hyphenated
# name, not a shell-variable one, and hyphens aren't otherwise special
# here - `--max-key-size=100` still correctly doesn't match, since the
# name has to end in one of the literal keywords, and "size" isn't one.
_SECRET_ASSIGNMENT_RE = re.compile(
    r"\b((?:[A-Za-z_][A-Za-z0-9_-]*)?(?:TOKEN|SECRET|KEY|PASSWORD|PASS|CREDENTIAL)S?=)\S+",
    re.IGNORECASE,
)


def redact(text: str) -> str:
    if not text:
        return text
    text = _AUTH_BEARER_RE.sub(r"\1" + _REDACTED, text)
    text = _AUTH_BASIC_RE.sub(r"\1" + _REDACTED, text)
    text = _URL_CREDENTIALS_RE.sub(r"\1" + _REDACTED + r"\3", text)
    text = _BASIC_AUTH_FLAG_RE.sub(r"\1\2:" + _REDACTED, text)
    text = _KNOWN_TOKEN_PREFIXES_RE.sub(_REDACTED, text)
    text = _SECRET_ASSIGNMENT_RE.sub(r"\1" + _REDACTED, text)
    return text
