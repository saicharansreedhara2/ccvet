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

Otherwise, run:

```
ccvet log --tail 20
```

for a human-readable record of every decision ccvet has made, independent of whether you're in debug mode. `ccvet status` summarizes the overall state (hooks wired, policy files, Layer 2 config, audit log size).

## Tuning the policy

```
ccvet check "docker build ."      # see what ccvet would decide, without running it for real
ccvet allow "docker build ."      # promote it to allow after you've reviewed it
ccvet policy edit                 # hand-edit the project's .ccvet/policy.yaml directly
```

User rules can only loosen (or further restrict) ccvet's own judgment-call defaults — they can never bypass a hard-coded safety-floor guard like `rm -rf /` or `git push --force`, even if you explicitly try to `allow` one.

## Layer 2 (optional): an LLM second opinion on the gray zone

For commands that don't match any rule at all, you can point ccvet at any OpenAI-compatible local model server (Ollama, LM Studio, vLLM, or whatever your setup routes through):

```
ccvet config set classifier.base_url http://localhost:11434/v1
ccvet config set classifier.model <your-model-name>
```

`ccvet init` also auto-detects a running Ollama/LM Studio server and offers to wire this up for you. Layer 2 is advisory only in one specific direction: it can promote a gray-zone command to `allow`, but it can never turn anything into a `deny` — the hard-coded safety-floor guards keep exclusive authority to block, so a misconfigured or hallucinating local model can't unilaterally stop your agent from working. If Layer 2 is unreachable, times out, or returns something that doesn't parse, ccvet just falls back to asking you, same as if Layer 2 were never configured.

## Uninstalling

```
ccvet uninstall
```

Removes just ccvet's hook entry from `.claude/settings.json` (or `~/.claude/settings.json` with `--global`), leaving any other hooks you have configured untouched.

## License

MIT
