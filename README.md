# ccvet

A risk-classifying `PreToolUse` gate for [Claude Code](https://code.claude.com): auto-approve low-risk tool calls, hard-block dangerous ones, and ask about everything in between — without needing an LLM call for most of it.

**Status: early development, not yet published.** See `Docs/PLAN.md` for the build plan and `Docs/risk-taxonomy.md` for the rule set.

## Why

Claude Code's permission prompts protect you, but on a busy session the constant "allow this?" for obviously-safe commands (`git status`, `cat`, `ls`) trains people to stop reading them. ccvet front-loads a deterministic + heuristic rule engine (Layer 0/1) that handles the overwhelming majority of traffic with zero model calls, and only escalates genuinely ambiguous actions to an optional local-LLM classifier (Layer 2) or to you.

## Install (not yet published to PyPI)

```
pip3 install ccvet
ccvet init
```

`ccvet init` wires a `PreToolUse` hook into your project's `.claude/settings.json` (or `~/.claude/settings.json` with `--global`), merging into any existing hooks rather than overwriting them.

## Seeing what ccvet decided

Claude Code doesn't show a hook's reason in the normal chat transcript for auto-approved ("allow") actions — only for blocks and escalations. To see ccvet's reasoning for *every* decision, including allows, in real time:

```
claude --debug
```

Otherwise, check `ccvet log` for a running record of every decision ccvet has made, independent of whether you're in debug mode. (The raw audit log lives at `~/.ccvet/audit.jsonl` in the meantime, before the `ccvet log` viewer command exists.)

## Uninstalling

```
ccvet uninstall
```

Removes just ccvet's hook entry from `.claude/settings.json` (or `~/.claude/settings.json` with `--global`), leaving any other hooks you have configured untouched.

## License

MIT
