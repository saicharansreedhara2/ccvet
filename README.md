# ccvet

**A risk-classifying permission gate for [Claude Code](https://code.claude.com).**

ccvet is a `PreToolUse` hook that auto-approves low-risk tool calls, hard-blocks dangerous ones, and only asks you about the genuinely ambiguous middle. Most of that classification happens with plain rules and heuristics, not a model call. For the leftover gray zone, you can optionally point it at any local LLM server (Ollama, LM Studio, vLLM) for a second opinion, without ever giving that model the power to block anything on its own.

**Status: early development, not yet published to PyPI.** See [`Docs/PLAN.md`](Docs/PLAN.md) for the build plan and [`Docs/risk-taxonomy.md`](Docs/risk-taxonomy.md) for the full rule set.

## Contents

- [Why this exists](#why-this-exists)
- [How it works](#how-it-works)
- [Install](#install)
- [Seeing what ccvet decided](#seeing-what-ccvet-decided)
- [Tuning the policy](#tuning-the-policy)
- [Layer 2: an optional LLM second opinion](#layer-2-optional-an-llm-second-opinion-on-the-gray-zone)
- [Uninstalling](#uninstalling)
- [Security model and limitations](#security-model-and-limitations)
- [Contributing](#contributing)
- [License](#license)

## Why this exists

Claude Code's permission prompts protect you, but on a busy session the constant "allow this?" for obviously safe commands (`git status`, `cat`, `ls`) trains people to stop reading them. The next prompt that actually matters gets approved on autopilot too.

ccvet front-loads a deterministic, rule-based engine that handles the overwhelming majority of tool calls with zero model calls at all, and only escalates genuinely ambiguous actions to an optional local model or to you. The goal is fewer prompts overall, so the ones that remain are worth reading.

## How it works

Four layers, evaluated in order:

1. **Hard-coded safety guards.** Things like `rm -rf /`, `sudo`, `git push --force`, credential-file access, and obfuscated or piped-to-shell commands are always blocked. No configuration, LLM opinion, or user override can bypass this layer. It is the floor everything else sits on.
2. **Program allow and ask lists.** Read-only commands (`ls`, `cat`, `git status`, `git log`, and so on) are auto-approved. Mutating-but-reversible commands (`git commit`, `npm install`, `docker build`) ask by default. This list ships in a plain YAML file you can extend.
3. **Your own policy rules.** Once you've reviewed a specific command and decided it's fine, promote it with one command (`ccvet allow`) so you never get asked about it again. These rules can loosen or further restrict ccvet's own defaults, but they can never override layer 1.
4. **Optional LLM classifier.** For anything left in the gray zone, point ccvet at a local model server for a second opinion. It can only promote a command toward "allow". It can never produce a "deny", so a misconfigured or hallucinating model can't block your agent's work.

Full detail, including the exact command-by-command classification table, is in [`Docs/risk-taxonomy.md`](Docs/risk-taxonomy.md).

## Install

Not yet published. Once it is:

```
pip3 install ccvet
ccvet init
```

`ccvet init` wires the `PreToolUse` hook into your project's `.claude/settings.json` (or `~/.claude/settings.json` with `--global`), merging into any hooks you already have rather than overwriting them.

## Seeing what ccvet decided

Claude Code does not show a hook's reason in the normal chat transcript for auto-approved ("allow") actions, only for blocks and escalations. To see ccvet's reasoning for every decision, including allows, in real time, run Claude Code with:

```
claude --debug
```

Otherwise, use ccvet's own audit log:

```
ccvet log --tail 20
```

That gives a human-readable record of every decision ccvet has made, regardless of whether you're in debug mode. `ccvet status` summarizes the overall state: which hooks are wired, which policy files exist, whether Layer 2 is configured, and how large the audit log has grown.

## Tuning the policy

```
ccvet check "docker build ."      # see what ccvet would decide, without running it for real
ccvet allow "docker build ."      # promote it to allow after you've reviewed it
ccvet policy edit                 # hand-edit the project's .ccvet/policy.yaml directly
```

Your rules can only loosen, or further restrict, ccvet's own judgment-call defaults. They can never bypass a hard-coded safety guard like `rm -rf /` or `git push --force`, even if you explicitly try to `allow` one.

## Layer 2 (optional): an LLM second opinion on the gray zone

For commands that don't match any rule at all, point ccvet at any OpenAI-compatible local model server:

```
ccvet config set classifier.base_url http://localhost:11434/v1
ccvet config set classifier.model <your-model-name>
```

`ccvet init` also auto-detects a running Ollama or LM Studio server and offers to wire it up for you. Layer 2 is advisory in one specific direction only: it can promote a gray-zone command to "allow", but it can never turn anything into a "deny". The hard-coded safety guards keep exclusive authority to block, so a misconfigured or hallucinating local model cannot unilaterally stop your agent from working. If Layer 2 is unreachable, times out, or returns something that doesn't parse, ccvet simply falls back to asking you, exactly as if Layer 2 were never configured.

## Uninstalling

```
ccvet uninstall
```

Removes only ccvet's own hook entry from `.claude/settings.json` (or `~/.claude/settings.json` with `--global`), leaving any other hooks you've configured untouched.

## Security model and limitations

ccvet is a heuristic and optional-LLM advisory gate, not a sandbox. It reduces the chance of an obviously destructive command slipping through on autopilot. It does not replace running Claude Code with least-privilege permissions, in a container, or on a disposable machine for anything you don't fully trust. See [`SECURITY.md`](SECURITY.md) for the full threat model and known gaps.

## Contributing

Issues and pull requests are welcome, especially new entries for the risk taxonomy (a command you think should be classified differently, or a pattern that's missing entirely). See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

MIT. See [`LICENSE`](LICENSE).
