"""Evaluates a raw Bash command string end to end: parse, check pipeline-
level obfuscation/exfil shapes, check for embedded destructive SQL, check
for credential-path references (both as plain arguments and as shell
redirection targets, which never appear in argv), then classify each
extracted sub-command individually and take the most severe result.
"""

from . import classifier, rules, shell, sql_guard, userpolicy
from .verdict import Verdict, most_severe


def evaluate(command: str, cwd: str = ".") -> Verdict:
    if not command or not command.strip():
        return Verdict.allow("empty command")

    commands = shell.extract_simple_commands(command)
    if commands is None:
        return Verdict.ask(f"could not parse as shell syntax: {command!r}")
    if not commands:
        return Verdict.allow("empty command")

    # pipeline_risk and sql_guard never produce an overridable verdict
    # (always a hard, unconditional deny), so returning early here rather
    # than folding them into the candidate list below is a safe, cheap
    # shortcut, not a shortcut around the override pipeline.
    pipeline_verdict = shell.pipeline_risk(commands)
    if pipeline_verdict is not None:
        return pipeline_verdict

    sql_verdict = sql_guard.check(command)
    if sql_verdict is not None:
        return sql_verdict

    all_argvs = [argv for argv, _dynamic_name, _has_dynamic_arg in commands]

    # secret_path_guard and redirect_target_guard CAN each produce an
    # overridable verdict (the generic token/secret/credential-name
    # heuristic; a $(mktemp)-style redirect target). Early-returning
    # straight from either one, like this function used to, meant that
    # overridable=True was silently inert: the override-check block
    # below was only ever reached via the classify_argv path, so a
    # `ccvet allow` for a generic-secret-name match genuinely never
    # took effect, with no test ever having caught it. Every candidate
    # now goes through the same most_severe() + override pipeline,
    # regardless of which guard produced it.
    candidates = []

    secret_verdict = rules.secret_path_guard(all_argvs)
    if secret_verdict is not None:
        candidates.append(secret_verdict)

    redirect_targets = shell.extract_redirect_targets(command) or []
    redirect_verdict = rules.redirect_target_guard(redirect_targets)
    if redirect_verdict is not None:
        candidates.append(redirect_verdict)

    candidates.extend(
        rules.classify_argv(argv, has_dynamic_arg=has_dynamic_arg)
        for argv, _dynamic_name, has_dynamic_arg in commands
    )

    verdict = most_severe(candidates)

    if verdict.overridable:
        override = userpolicy.find_override(command, cwd)
        if override is not None:
            return override

        # Layer 2 is deliberately restricted to the "ask" tier only, even
        # though a secret_path_guard/redirect_target_guard verdict can
        # also be an overridable "deny" (e.g. the generic token/secret/
        # credential-name heuristic). classifier.classify() itself has no
        # opinion on the input decision - it's purely gated by this
        # caller - so without this check, fixing the overridable-is-
        # inert bug above would have silently widened Layer 2's reach: a
        # one-shot, unreviewed local-model opinion could promote an
        # overridable *deny* to allow, not just an *ask*, contradicting
        # classifier.py's own documented contract ("can only turn an ask
        # into an allow"). A human-reviewed `ccvet allow` policy rule
        # (just above) is a different trust tier and keeps working on
        # any overridable verdict, deny included.
        if verdict.decision == "ask":
            classifier_verdict = classifier.classify(command)
            if classifier_verdict is not None:
                return classifier_verdict

    return verdict
