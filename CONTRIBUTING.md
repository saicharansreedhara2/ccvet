# Contributing to ccvet

Thanks for considering a contribution. The most valuable thing you can add is almost never code: it's a command that ccvet classifies wrong.

## Proposing a new rule or a correction to an existing one

Open an issue or a pull request with:

1. The exact command or tool call.
2. What ccvet currently decides (`allow`, `ask`, or `deny`). You can check this yourself without installing anything into Claude Code at all:
   ```
   ccvet check "the command in question"
   ```
3. What you think it should decide, and why. A short, concrete reason is more useful than a long one. "This can overwrite a production database with no confirmation" is better than a general statement that something feels risky.

If you're proposing a new hard-coded safety guard (something that should always be blocked, with no override possible), explain why it belongs on that floor rather than in the ordinary allow or ask lists. See [`Docs/risk-taxonomy.md`](Docs/risk-taxonomy.md) for how the existing rules are organized, and the reasoning behind which things are hard-coded versus user-configurable.

## Code contributions

- Every change to the rule engine (`rules.py`, `shell.py`, `sql_guard.py`, `fsrules.py`, `paths.py`) needs a test. If you're fixing a misclassification, add the case to the relevant table in `tests/test_bash_rules.py` or `tests/test_fs_rules.py` so it can't silently regress.
- Run the full test suite before opening a pull request:
  ```
  pip install -e ".[dev]"
  pytest tests/
  ```
- Keep the safety invariant intact: a user-configurable rule (anything in `userpolicy.py`, or the optional Layer 2 classifier in `classifier.py`) must never be able to override one of the hard-coded guards. If you're not sure whether your change respects this, say so explicitly in the pull request and it'll get extra scrutiny.
- No em dashes in user-facing text (README, CLI output, `Verdict` reason strings, docs). Code comments and docstrings are fine either way.

## Reporting a security issue

See [`SECURITY.md`](SECURITY.md).

## Questions

Open an issue. If you're not sure whether something is a bug, a missing rule, or working as intended, ask anyway; that ambiguity is useful information on its own.
