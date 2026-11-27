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

from . import redact

_RANK = {"allow": 0, "ask": 1, "deny": 2}


@dataclass(frozen=True)
class Verdict:
    decision: str
    reason: str
    overridable: bool = False

    def rank(self) -> int:
        return _RANK[self.decision]

    # redact.redact() is applied here, once, rather than at each of the
    # many call sites across rules.py/shell.py/sql_guard.py that build a
    # reason by interpolating raw argv/command text - found by external
    # review, twice: first that a deny reason could embed a live secret
    # value (curl --header "Authorization: token=<live token>"), then
    # that the *same* pattern already existed, unfixed, in the much more
    # common ASK_PROGRAMS fallback (f"{program} {' '.join(args)}", the
    # reason text for most non-read-only commands). Patching each f-
    # string individually is exactly the kind of fix that's easy to
    # apply inconsistently - as the first fix itself did, missing the
    # ask path - so this redacts every reason uniformly at the one
    # choke point every Verdict passes through, regardless of where it
    # was built. This matters beyond audit.py's own redaction:
    # `reason` is also `permissionDecisionReason`, the hook message
    # Claude Code displays live and records in the session transcript,
    # a durable store ccvet doesn't own and can't redact after the
    # fact the way it redacts its own audit log.
    @staticmethod
    def allow(reason: str, overridable: bool = False) -> "Verdict":
        return Verdict("allow", f"Allowed by ccvet: {redact.redact(reason)}", overridable)

    @staticmethod
    def ask(reason: str, overridable: bool = False) -> "Verdict":
        return Verdict("ask", f"ccvet: {redact.redact(reason)}, escalating for your review", overridable)

    @staticmethod
    def deny(reason: str, overridable: bool = False) -> "Verdict":
        return Verdict("deny", f"Blocked by ccvet: {redact.redact(reason)}", overridable)

    @staticmethod
    def defer(reason: str) -> "Verdict":
        return Verdict("defer", f"ccvet: {redact.redact(reason)}")


def most_severe(verdicts: list) -> Verdict:
    """Highest-risk verdict wins — a pipeline is only as safe as its worst
    segment. On a rank tie, a non-overridable verdict wins over an
    overridable one: if one sub-command hit a hard safety-floor guard and
    another merely hit a generic ask-tier fallback at the same rank, the
    combined result must stay non-overridable — a user policy rule aimed
    at promoting the generic one must not incidentally bypass the other.
    """
    return max(verdicts, key=lambda v: (v.rank(), not v.overridable))
