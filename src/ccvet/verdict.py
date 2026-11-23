"""The four decisions ccvet can hand back on the wire, per Docs/hook-contract.md.

`defer` and `ask` are deliberately not interchangeable fallbacks: `defer`
hands the decision to Claude Code's normal permission flow (whose behavior
depends on the session's permission_mode, including bypassPermissions),
while `ask` is an explicit escalation regardless of mode. Internal errors
must use `ask`; "no rule matched this tool at all" uses `defer`.
"""

from dataclasses import dataclass

_RANK = {"allow": 0, "ask": 1, "deny": 2}


@dataclass(frozen=True)
class Verdict:
    decision: str
    reason: str

    def rank(self) -> int:
        return _RANK[self.decision]

    @staticmethod
    def allow(reason: str) -> "Verdict":
        return Verdict("allow", f"Allowed by ccvet: {reason}")

    @staticmethod
    def ask(reason: str) -> "Verdict":
        return Verdict("ask", f"ccvet: {reason} — escalating for your review")

    @staticmethod
    def deny(reason: str) -> "Verdict":
        return Verdict("deny", f"Blocked by ccvet: {reason}")

    @staticmethod
    def defer(reason: str) -> "Verdict":
        return Verdict("defer", f"ccvet: {reason}")


def most_severe(verdicts: list) -> Verdict:
    """Highest-risk verdict wins — a pipeline is only as safe as its worst segment."""
    return max(verdicts, key=lambda v: v.rank())
