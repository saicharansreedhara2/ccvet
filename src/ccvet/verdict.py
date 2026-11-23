"""The four decisions ccvet can hand back on the wire, per Docs/hook-contract.md.

`defer` and `ask` are deliberately not interchangeable fallbacks: `defer`
hands the decision to Claude Code's normal permission flow (whose behavior
depends on the session's permission_mode, including bypassPermissions),
while `ask` is an explicit escalation regardless of mode. Internal errors
must use `ask`; "no rule matched this tool at all" uses `defer`.

`overridable` marks whether a user policy.yaml rule (Phase 3) is allowed to
replace this particular verdict. It defaults to False, and every named
safety-floor guard in rules.py/shell.py/sql_guard.py (sudo, rm -rf, git
push --force, obfuscation, secret paths, ...) leaves it at that default
deliberately — those are the floor and must stay non-overridable from a
config file. Only the generic program-list/gray-zone fallbacks set it True.
"""

from dataclasses import dataclass

_RANK = {"allow": 0, "ask": 1, "deny": 2}


@dataclass(frozen=True)
class Verdict:
    decision: str
    reason: str
    overridable: bool = False

    def rank(self) -> int:
        return _RANK[self.decision]

    @staticmethod
    def allow(reason: str, overridable: bool = False) -> "Verdict":
        return Verdict("allow", f"Allowed by ccvet: {reason}", overridable)

    @staticmethod
    def ask(reason: str, overridable: bool = False) -> "Verdict":
        return Verdict("ask", f"ccvet: {reason} — escalating for your review", overridable)

    @staticmethod
    def deny(reason: str, overridable: bool = False) -> "Verdict":
        return Verdict("deny", f"Blocked by ccvet: {reason}", overridable)

    @staticmethod
    def defer(reason: str) -> "Verdict":
        return Verdict("defer", f"ccvet: {reason}")


def most_severe(verdicts: list) -> Verdict:
    """Highest-risk verdict wins — a pipeline is only as safe as its worst
    segment. On a rank tie, a non-overridable verdict wins over an
    overridable one: if one sub-command hit a hard safety-floor guard and
    another merely hit a generic ask-tier fallback at the same rank, the
    combined result must stay non-overridable — a user policy rule aimed
    at promoting the generic one must not incidentally bypass the other.
    """
    return max(verdicts, key=lambda v: (v.rank(), not v.overridable))
