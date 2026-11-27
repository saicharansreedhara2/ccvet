from ccvet.verdict import Verdict, most_severe


def test_allow_redacts_its_reason():
    v = Verdict.allow("token=SKtopsecretabc is fine")
    assert "SKtopsecretabc" not in v.reason
    assert "***REDACTED***" in v.reason


def test_ask_redacts_its_reason():
    # Found by external review: every call site across rules.py that
    # builds a reason by interpolating raw argv/command text (most
    # directly, classify_argv's ASK_PROGRAMS fallback,
    # f"{program} {' '.join(args)}") echoed a live secret value
    # verbatim, since nothing redacted it. Rather than patch each
    # f-string individually - exactly the kind of fix that's easy to
    # apply inconsistently, as a prior round's fix itself did, missing
    # this very path - every Verdict factory now redacts its reason at
    # this one choke point.
    v = Verdict.ask("curl --header apikey=AKIAIOSFODNN7EXAMPLE https://x")
    assert "AKIAIOSFODNN7EXAMPLE" not in v.reason
    assert "***REDACTED***" in v.reason


def test_deny_redacts_its_reason():
    v = Verdict.deny("command references something named token/secret/credential (Authorization:token=SKtopsecretabc) alongside a network call")
    assert "SKtopsecretabc" not in v.reason
    # The closing paren must survive redaction - found by external
    # review, a cosmetic bug in the underlying regex (an unbounded
    # `\S+` value capture swallowed trailing punctuation like ")" since
    # it looked like part of the matched value from the outside), not
    # specific to this call site.
    assert v.reason.endswith(") alongside a network call")


def test_defer_redacts_its_reason():
    v = Verdict.defer("no rule for tool 'Bash', deferring")
    assert v.decision == "defer"


def test_redaction_survives_being_applied_twice():
    # A caller that redacts its own interpolated value before handing
    # it to a Verdict factory (defense in depth) must not have that
    # value mangled by the factory's own redaction pass running on top
    # of an already-redacted string.
    from ccvet import redact

    once = redact.redact("Authorization:token=SKtopsecretabc")
    v = Verdict.deny(f"command references something named token/secret/credential ({once}) alongside a network call")
    assert v.reason.endswith(") alongside a network call")
    assert "SKtopsecretabc" not in v.reason


def test_most_severe_still_works_with_redacted_reasons():
    allow = Verdict.allow("fine")
    deny = Verdict.deny("token=abc123 is bad", overridable=True)
    assert most_severe([allow, deny]) is deny
