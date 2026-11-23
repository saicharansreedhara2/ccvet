"""Heuristic (not a real SQL parser) check for destructive statements that
might be embedded in a Bash command, e.g. `psql -c "DROP TABLE users"`. This
is a textual substring/regex check on the raw command, independent of the
bashlex-based argv classification, since SQL is usually passed as a single
quoted string argument rather than its own shell command.
"""

import re

from .verdict import Verdict

_DROP_OR_TRUNCATE = re.compile(r"\b(drop\s+(table|database)|truncate)\b", re.IGNORECASE)


def check(raw_command: str):
    if _DROP_OR_TRUNCATE.search(raw_command):
        return Verdict.deny("command contains a DROP TABLE/DATABASE or TRUNCATE statement")

    lowered = raw_command.lower()
    if "delete from" in lowered and "where" not in lowered:
        return Verdict.deny("DELETE FROM with no WHERE clause found in the command")
    if re.search(r"\bupdate\b.*\bset\b", lowered) and "where" not in lowered:
        return Verdict.deny("UPDATE ... SET with no WHERE clause found in the command")

    return None
