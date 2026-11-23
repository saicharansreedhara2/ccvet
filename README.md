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

## License

MIT
