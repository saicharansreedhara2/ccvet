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

    pipeline_verdict = shell.pipeline_risk(commands)
    if pipeline_verdict is not None:
        return pipeline_verdict

    sql_verdict = sql_guard.check(command)
    if sql_verdict is not None:
        return sql_verdict

    all_argvs = [argv for argv, _dynamic in commands]
    secret_verdict = rules.secret_path_guard(all_argvs)
    if secret_verdict is not None:
        return secret_verdict

    redirect_targets = shell.extract_redirect_targets(command) or []
    redirect_verdict = rules.redirect_target_guard(redirect_targets)
    if redirect_verdict is not None:
        return redirect_verdict

    verdicts = [rules.classify_argv(argv) for argv in all_argvs]
    verdict = most_severe(verdicts)

    if verdict.overridable:
        override = userpolicy.find_override(command, cwd)
        if override is not None:
            return override

        classifier_verdict = classifier.classify(command)
        if classifier_verdict is not None:
            return classifier_verdict

    return verdict
