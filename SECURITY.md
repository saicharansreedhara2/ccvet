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
- Prompt injection that convinces the agent to generate a dangerous command in the first place. ccvet classifies the command once it exists; it does not prevent the agent from deciding to write one. (Its own Layer 2 prompt is hardened against the specific case of injected text trying to talk the *classifier* into approving itself: the command is passed as a JSON-encoded string rather than interpolated into a markdown fence, so a command containing literal triple-backticks can't structurally break out of the "this is data" framing. That's a narrower claim than defending against injection in general.)
- Any risk introduced by a command ccvet classifies correctly as safe, but which is genuinely safe only in some other context ccvet cannot see (for example, a command that is safe on your laptop but destructive against a shared production system you happen to be connected to).

## Known gaps

- **`case`, `select`, `coproc`, `[[ ... ]]` test expressions, and arithmetic `for ((...))` loops in Bash are not parseable by the underlying shell parser (`bashlex`).** They fall back to `ask` rather than being actively classified. This is a library limitation, not a ccvet bug, and it fails toward asking, not toward silently allowing.
- **ANSI-C quoting (`$'...'`) around a flag argument can downgrade a hard-coded guard's result from `deny` to `ask`.** `rm $'-rf' /` is one example: bashlex mis-parses the quoted flag rather than dequoting it, so the catastrophic-rm check doesn't recognize it as `-rf`. This still fails toward asking you, never toward silently allowing the command. Ordinary single and double quotes are unaffected.
- **Windows and PowerShell are out of scope for v1.** The rule engine targets POSIX shells (bash and zsh on macOS and Linux). This is a deliberate, stated scope decision, not an unnoticed gap.
- **The rule engine covers Bash, file read/write tools, and a few other built-in Claude Code tools.** Third-party or future MCP tools ccvet has no rule for are deferred to Claude Code's own normal permission flow rather than auto-approved, but they are not actively classified by ccvet either.

Fixed during hardening and worth naming, since they illustrate the kind of bug this project watches for:

- Compound shell constructs (`{ ...; }`, `(...)`, `if`/`while`/`for`), process substitution (`<(...)`/`>(...)`), and the transparent wrappers `eval`/`exec`/`command`/`builtin` all used to let their wrapped command dodge classification entirely and fall through to `allow`.
- **Shell redirections were completely invisible to classification.** A redirect target (the right-hand side of `>`, `>>`, `<`, `<<<`) never appears in a command's argument list, so `curl ... < ~/.aws/credentials` (exfiltrating a credential file via input redirection) or `echo ... >> ~/.bashrc` (a persistence write) had no sensitive path visible anywhere. Redirect targets are now extracted and checked the same way Edit/Write tool paths are.
- Secret/persistence/manifest path matching used a raw substring search on the full resolved path, so `/etc/passwd` matched `/etc/passwd_notes.md`, `.bashrc` matched `my.bashrc_backup.txt`, and so on. Since the credential-path match is a hard, non-overridable deny, a false positive there couldn't even be worked around. Matching is now component-aware against the path's actual segments.
- The catastrophic-target list for `rm -rf`/`chmod -R` was missing several top-level system directories (`/var`, `/opt`, `/Applications`, `/Library`, `/root`, and others), didn't recognize a literal home-directory root (`/Users/<name>`, `/home/<name>`) as catastrophic, didn't catch a bare `*` wildcard, and (for chmod) only recognized octal `777`/`000`, not symbolic-mode grants like `a+rwx` that achieve the same thing.
- The DELETE/UPDATE-without-WHERE check scanned the whole command's text rather than the specific SQL statement, so a genuinely unconditional `DELETE FROM users` paired with an unrelated `WHERE` elsewhere in the same multi-statement command escaped detection.

Found by an external static review of the published package, after the above (which were all found internally):

- **`cat $(ls -d ~/.ssh)/id_rsa` fully bypassed to `allow`.** The secret-path guard's substring check couldn't see `.ssh/id_` in the raw argument text (the closing paren breaks the match), and since `ls` is independently extracted and classified on its own, `cat` being on the allowlist let the whole thing through with no awareness that its argument's real value was unverifiable. Fixed: an auto-approved verdict is now downgraded to `ask` whenever an argument (not just the command name) contains a substitution or variable expansion that isn't a self-contained, independently-classified one (see `Docs/risk-taxonomy.md` for the exact distinction, including why `<(ls -la)` alone is unaffected).
- **`env` with no arguments was on the auto-approve allowlist.** It prints every environment variable, which for an agent session commonly includes active API keys and tokens. The project's own taxonomy document already said this should ask, not auto; the shipped policy file simply disagreed with its own documentation, and nothing had ever tested it specifically. Fixed.
- **`git remote` and `git tag` were treated as blanket read-only, with no check on their mutating sub-forms.** `git remote add`/`remove`/`set-url` (which can silently redirect future pushes to an attacker-controlled remote) and `git tag -d`/`--delete` were all auto-approved. Fixed with the same flag-sensitive handling `push`/`reset`/`clean`/`branch` already had.
- **`.env`, `.netrc`, `.npmrc`, `.pypirc`, and `.envrc` were entirely absent from the credential-path list.** `.env` in particular is arguably the single most common real-world location for secrets in an actual project. Fixed for both Bash commands and Edit/Write/Read tool calls.

All of the above are fixed and covered by regression tests now. If you find a case like this, see "Reporting a vulnerability" below.

## Reporting a vulnerability

If you find a way to make ccvet auto-approve something it clearly should not (a bypass of Layer 0's hard-coded guards in particular), please open an issue describing the command and the expected versus actual decision. If the bypass is severe enough that public disclosure before a fix would be actively harmful, say so in the issue and we'll coordinate privately first.
