"""Heuristic (not a real SQL parser) check for destructive statements that
might be embedded in a Bash command, e.g. `psql -c "DROP TABLE users"`. This
is a textual regex check on the raw command, independent of the
bashlex-based argv classification, since SQL is usually passed as a single
quoted string argument rather than its own shell command.
"""

import re

from .verdict import Verdict

_DROP_OR_TRUNCATE = re.compile(r"\b(drop\s+(table|database)|truncate)\b", re.IGNORECASE)

# The WHERE check is scoped to the statement itself (up to the next `;` or
# quote close), not the whole command text. Checking the whole command
# text was a real gap: `psql -c "DELETE FROM users" -c "... WHERE ..."` is
# a genuinely unconditional delete, but the unrelated WHERE elsewhere in
# the command made the old whole-text check miss it entirely.
_DELETE_STATEMENT = re.compile(r"\bdelete\s+from\s+\S+([^;\"']*)", re.IGNORECASE)
_UPDATE_STATEMENT = re.compile(r"\bupdate\s+\S+\s+set\b([^;\"']*)", re.IGNORECASE)


def check(raw_command: str):
    if _DROP_OR_TRUNCATE.search(raw_command):
        return Verdict.deny("command contains a DROP TABLE/DATABASE or TRUNCATE statement")

    for match in _DELETE_STATEMENT.finditer(raw_command):
        if "where" not in match.group(0).lower():
            return Verdict.deny("DELETE FROM with no WHERE clause found in the command")

    for match in _UPDATE_STATEMENT.finditer(raw_command):
        if "where" not in match.group(0).lower():
            return Verdict.deny("UPDATE ... SET with no WHERE clause found in the command")

    return None
