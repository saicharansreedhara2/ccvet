# Security model and limitations

This document says plainly what ccvet does and does not protect against, so nobody over-trusts it.

## What ccvet is

ccvet is a heuristic and optional-LLM advisory gate for Claude Code's `PreToolUse` hook. It classifies each tool call before it runs and returns one of four decisions: allow it automatically, block it outright, ask you, or defer to Claude Code's normal permission flow. The goal is to reduce how often an obviously destructive command slips through approval on autopilot, and to cut down on the prompt fatigue that makes people stop reading permission prompts in the first place.

## What ccvet is not

- **Not a sandbox.** ccvet classifies the command text before it runs. It does not isolate, contain, or limit what an approved command can actually do on your system.
- **Not a substitute for least privilege.** If you run Claude Code with broad filesystem or network access, ccvet reduces risk but does not eliminate it. Running Claude Code in a container or on a disposable machine for anything you don't fully trust is still the stronger control.
- **Not a complete static analyzer.** The rule engine (Layers 0 and 1) and the obfuscation heuristics catch known-dangerous patterns and known evasion shapes. They do not exhaustively enumerate every way a command could be dangerous, and a sufficiently novel or convoluted command may reach the gray zone (an "ask", or an LLM opinion) instead of being correctly identified as dangerous outright.
- **The optional LLM classifier (Layer 2) cannot block anything.** This is by design, not an oversight. Layer 2 can only promote a gray-zone command toward "allow". It can never produce a "deny". This means a misconfigured or hallucinating local model can accidentally approve something it should not, but it can never be tricked into unilaterally blocking your agent's legitimate work. Denial authority stays exclusively with the hard-coded guards in Layer 0, which no configuration, user policy, or model opinion can override.

## Threat model

ccvet assumes:

- The person running it trusts the Claude Code agent's general intent, and wants a safety net against a wrong turn (a destructive command generated or run by mistake), not protection against a Claude Code session that has itself been fully compromised by an attacker with arbitrary code execution.
- The command text passed to the hook is the actual command about to run. ccvet does not execute anything itself; it only reads and classifies the text Claude Code hands it.
- A local LLM used for Layer 2 may be unreliable, slow, or occasionally wrong, and the design accounts for all three (timeouts fail safe, malformed output fails safe, and incorrect-but-well-formed output can only ever loosen a decision toward "allow", never block one).

ccvet does **not** defend against:

- A fully compromised or adversarially controlled Claude Code process that bypasses the hook mechanism entirely (for example, by disabling hooks or by running commands through a path ccvet never sees).
- Prompt injection that convinces the agent to generate a dangerous command in the first place. ccvet classifies the command once it exists; it does not prevent the agent from deciding to write one. (Its own Layer 2 prompt is hardened against the specific case of injected text trying to talk the *classifier* into approving itself, but that is a narrower claim.)
- Any risk introduced by a command ccvet classifies correctly as safe, but which is genuinely safe only in some other context ccvet cannot see (for example, a command that is safe on your laptop but destructive against a shared production system you happen to be connected to).

## Known gaps

- **`case` statements in Bash are not parseable by the underlying shell parser (`bashlex`).** They fall back to `ask` rather than being actively classified. This is a library limitation, not a ccvet bug, and it fails toward asking, not toward silently allowing.
- **Windows and PowerShell are out of scope for v1.** The rule engine targets POSIX shells (bash and zsh on macOS and Linux). This is a deliberate, stated scope decision, not an unnoticed gap.
- **The rule engine covers Bash, file read/write tools, and a few other built-in Claude Code tools.** Third-party or future MCP tools ccvet has no rule for are deferred to Claude Code's own normal permission flow rather than auto-approved, but they are not actively classified by ccvet either.

## Reporting a vulnerability

If you find a way to make ccvet auto-approve something it clearly should not (a bypass of Layer 0's hard-coded guards in particular), please open an issue describing the command and the expected versus actual decision. If the bypass is severe enough that public disclosure before a fix would be actively harmful, say so in the issue and we'll coordinate privately first.
