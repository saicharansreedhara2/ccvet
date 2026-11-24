# ccvet Implementation Plan

Risk-classifying `PreToolUse` gate for Claude Code. Public repo on https://github.com/saicharansreedhara2 (not mortalapps), published to PyPI as `pip3 install ccvet`. Layer 0/1 (rules + heuristics) must fully work with zero model configured; Layer 2 (LLM) is opt-in for the gray zone only. See `risk-taxonomy.md` for the full command classification that backs Phase 1.

Legend: `[ ]` not started, `[~]` in progress, `[x]` done.

## Phase 0: Repo and packaging scaffold
- [x] Repo layout: `src/ccvet/`, `tests/`, `pyproject.toml`, `README.md`, `LICENSE` (MIT)
- [~] CLI entry point (`ccvet`) with subcommands: `init`, `gate` done; `config`, `policy`, `status`, `check`, `log`, `allow`, `uninstall` still stubs for later phases
- [x] Minimal `pyproject.toml` (build backend, metadata, `entry_points`)
- [x] Keep runtime deps minimal and imports lazy. `gate`/`init` modules are imported inside the CLI dispatch functions, not at module load time; zero runtime dependencies so far.
- [x] `pip install -e .` + `ccvet --version` smoke test (venv at `.venv/`, gitignored)
- [x] Git init, first commit. Staying local, not pushed anywhere until Phase 6 (target: https://github.com/saicharansreedhara2).

## Phase 0.5: Spike, verify the actual Claude Code hook contract
- [x] Confirmed exact `PreToolUse` stdin JSON shape against current docs (`code.claude.com/docs/en/hooks`). See `Docs/hook-contract.md`.
- [x] Confirmed `permissionDecision` has 4 values, not 3: `allow`/`deny`/`ask`/`defer`. `defer` (hand back to normal permission flow) is what ccvet uses for "no opinion yet". `ask` is reserved for an explicit escalation, including ccvet's own crash fallback. `defer`'s behavior depends on the session's `permission_mode`, which is the wrong failure mode for an internal error, so the two are not interchangeable.
- [x] Confirmed hook timeout: 600s default for `PreToolUse` (not 30s), configurable per-handler. On timeout the tool call falls through to normal permission flow rather than being blocked, so Layer 2's budget (Phase 4) has ample room under the 10s handler timeout `ccvet init` sets.
- [x] Hard-coded hook (`ccvet gate` returning `defer`, or `ask` on internal error) wired via `ccvet init` into a scratch project's `.claude/settings.json`, exercised with the documented stdin example piped directly into `ccvet gate`. Output matched the contract exactly. Also verified `ccvet init` is idempotent (second run is a no-op) and preserves pre-existing `PreToolUse` entries rather than clobbering them.
- [ ] Still unverified: how Claude Code reconciles multiple `PreToolUse` hooks running in parallel when their decisions disagree. Not stated in the docs page; flagged in `hook-contract.md` as an open question.

## Phase 1: Layer 0/1 rule engine (no model required), DONE 2026-11-23
- [x] Rule schema (YAML): shipped `data/default_policy.yaml` covers the argument-insensitive program lists (`auto_programs`/`ask_programs`/git auto/ask subcommands). Argument-sensitive rules (rm -rf, chmod -R 777, git push --force, obfuscation, secret/persistence paths) are hard-coded guards in `rules.py` by design. These are the safety floor and aren't meant to be user-overridable (documented at the top of the YAML file and in risk-taxonomy.md).
- [x] Default policy shipped in-package (`src/ccvet/data/default_policy.yaml`), verified it's actually bundled into a built wheel (not just present in the editable install). A real packaging check, not an assumption.
- [x] Tool-type dispatch in `engine.py`: Bash goes to `shellrules`; Read/Grep/Glob/Edit/Write/NotebookEdit go to `fsrules`; WebSearch/WebFetch/Task/Agent are handled directly; an unknown tool returns `defer`.
- [x] Shell tokenization via `bashlex` (verified against real parse trees for lists/pipelines/command-substitution before writing the extraction code). Splits compound commands (`&&`, `;`, `|`, `$(...)`) into sub-commands; a dynamically-constructed command name (e.g. `$(echo rm) -rf /`) is detected and denied outright since it can't be statically classified.
- [x] Obfuscation heuristic: decode (`base64`/`xxd`/`openssl`) or download (`curl`/`wget`) followed anywhere later in the same parse by a shell invocation (`sh`/`bash`/`zsh`/...) is denied. Catches both `curl url | sh` and `echo <b64> | base64 -d | sh`.
- [x] Path-scope checks resolve `realpath` first (`paths.py`), tested specifically against a symlink pointing outside the project root to confirm it can't bypass the boundary.
- [x] Verdict reason-string convention implemented exactly as specified (`verdict.py`): `allow`/`ask`/`deny`/`defer` each produce a consistently prefixed, human-readable reason.
- [x] Unknown/unrecognized tool calls return `defer`, not `ask` (see verdict.py docstring for why these aren't interchangeable). `defer` is correct here since ccvet genuinely has no opinion on a tool it's never heard of, versus Bash/file gray-zone cases where ccvet does have an opinion: "ask a human".
- [x] 105 unit tests passing: `test_shell.py` (parser/extraction), `test_bash_rules.py` (taxonomy-row table: AUTO/ASK/BLOCK cases across every category), `test_fs_rules.py` (path scoping, symlink traversal, persistence/secret/manifest files), `test_engine_dispatch.py`, `test_gate.py` (end-to-end and crash safety), `test_init.py`.
- [x] Two real bugs caught and fixed by the test suite itself: `"/".rstrip("/")` collapsing to `""` and silently escaping the catastrophic rm/chmod root-path check; `npm list`/`pip show` misclassified as ASK instead of AUTO (fixed by adding subcommand-aware classifiers for npm/pip, same pattern as git).

## Phase 2: Hook integration, DONE 2026-11-23
- [x] `ccvet gate`: reads `PreToolUse` JSON from stdin, runs the engine, emits `hookSpecificOutput` JSON (`permissionDecision`, `permissionDecisionReason`)
- [x] Top-level crash safety: any uncaught exception inside `ccvet gate` must still emit a valid `ask` decision, not `defer` (see Phase 0.5), and never a raw traceback on stdout. Implemented and tested in the Phase 0.5 spike (`gate.py`/`test_gate.py`); carries forward unchanged once the real rule engine replaces the placeholder logic.
- [x] `ccvet init`: project-local by default, `--global` writes `~/.claude/settings.json`; merges into existing hooks (never overwrites), shows a diff, asks for confirmation before writing
- [x] `ccvet uninstall`: cleanly removes just ccvet's hook entry, leaving any other configured hooks untouched (and drops the `hooks` top-level key entirely if nothing's left). Round-tripped against a real scratch project, not just unit-tested.
- [x] Audit log (JSONL) at `~/.ccvet/audit.jsonl` (one consolidated log across all projects, each entry carries `cwd`), concurrency-safe via `fcntl.flock` around each append. Tested with 50 concurrent threads writing simultaneously, no corrupted or merged lines. File created with `0600` permissions (verified, not assumed) since it can contain raw Bash command text. Write-tool content is hashed (`content_sha256` plus `content_length`), never stored verbatim, to avoid persisting secrets into the log.
- [x] `ccvet gate --dry-run`: evaluates and prints the decision but skips the audit-log write. Verified via a real end-to-end smoke test (dangerous command denied, dry-run confirmed absent from the log; a non-dry-run safe command confirmed present).
- [x] A failure inside `audit.log()` is swallowed, never allowed to affect the already-emitted decision or crash the hook (tested by injecting a forced `OSError`)

## Phase 3: Config and status, mostly DONE 2026-11-23
- [x] `ccvet config get/set`: dotted-key YAML store at `~/.ccvet/config.yaml` (`config.py`). Nothing consumes it yet; Phase 4's classifier settings will be the first real reader, but the plumbing is built and tested now.
- [x] `ccvet status`: reports project/global hook-wiring state, project/global policy rule counts, Layer 2 config presence, and audit log entry count. Smoke-tested end to end in an isolated scratch project, not just unit-tested.
- [x] `ccvet policy edit`: opens the active `.ccvet/policy.yaml` (project by default, `--global` for the user's global one, **not** the shipped built-in `data/default_policy.yaml`, which stays code-managed) in `$EDITOR`, creating an empty `rules: []` file first if none exists
- [x] `ccvet check "<command>"` (and `--tool`/`--path`/`--url` for non-Bash tool calls): dry-runs through the real engine and prints decision, reason, and overridable status
- [x] `ccvet log --tail N`: human-readable view of the audit log (defaults to last 20 entries, `--tail 0` for all)
- [x] `ccvet allow "<pattern>"`: writes a rule to the project (or `--global`) policy.yaml. Literal by default (regex-escaped); `--regex` passes a pattern through verbatim; `--verdict ask|deny` is also supported for the "add my own stricter rule" case, not just promote-to-allow.
- [x] User policy precedence implemented in `userpolicy.py`: project `.ccvet/policy.yaml` rules are checked before global `~/.ccvet/policy.yaml` ones, first match wins. Tested, including that a malformed regex in a user rule is skipped rather than fatal.
- [x] **Safety invariant, enforced structurally, not just by convention**: added an `overridable` field to `Verdict` (default `False`). Every named safety-floor guard in `rules.py`/`shell.py`/`sql_guard.py` leaves it at the default; only the generic program-list/gray-zone fallbacks set it `True`. A user policy rule can only take effect where the built-in verdict was already `overridable=True`, verified end-to-end that a `ccvet allow "rm -rf /"` rule is silently ignored and the command still gets denied. `most_severe()` was also fixed to prefer the non-overridable verdict on a rank tie, so a compound command mixing an overridable ask with a non-overridable one can't be bypassed either.
- [ ] Policy presets at `ccvet init` time (`strict`/`default`/`permissive`), not done this pass, deferred (low value until there's real usage to calibrate presets against)

**Bug caught by integration testing, not unit testing**: the `check` subcommand's positional argument was named `command`, colliding with the top-level `argparse` subparsers' `dest="command"`. Both write into the same flat `Namespace`, so `ccvet check "docker build ."` silently set `args.command` to the command text instead of `"check"`, and the whole dispatch fell through to the help text. The `test_commands.py` tests didn't catch this because they hand-built `argparse.Namespace` objects directly, bypassing real parsing. Fixed by renaming the positional to `shell_command`, and added `test_cli.py` to parse real argv for every subcommand going forward.

## Phase 4: Layer 2, optional LLM gray-zone classifier, DONE 2026-11-24
- [x] OpenAI-compatible client (`classifier.py`), configurable `classifier.base_url`/`model`/`api_key`/`timeout_seconds` via `ccvet config`. Covers Ollama/LM Studio/vLLM/mtplx uniformly since they all speak the same `/chat/completions` shape. Uses stdlib `urllib`, not an SDK, so there's zero added dependency for people who never enable Layer 2.
- [x] Forced structured JSON output (`risk`/`reversible`/`blast_radius`/`rationale`) via `response_format: json_object` plus a tolerant regex fallback extraction, with field-value validation (invalid enum values, non-bool `reversible`, etc. all treated as failure)
- [x] Explicit timeout (`classifier.timeout_seconds`, default 8s). Bumped the hook's own handler timeout from 10s to 20s (`HOOK_TIMEOUT_SECONDS` in `init.py`) to leave real room for a slow local model, since the Phase 0.5 finding was that a hook timeout fails open to normal permission flow rather than blocking. A generous ceiling costs nothing on the fast (Layer 0/1-only) path and only helps the slow path.
- [x] Prompt hardening: the command is fenced under an explicit "COMMAND TO EVALUATE" heading with instructions to treat it as data, not instructions, even if its text tries to address the model directly. Tested with an actual prompt-injection-shaped string.
- [x] `ccvet init` auto-detects a running local server (Ollama `:11434`, LM Studio `:1234`) via a 0.5s-timeout probe and offers to wire it in as `classifier.base_url`. Skips the prompt if already configured, silent no-op if nothing's running (verified in this sandbox, which has neither server running, that `ccvet init` doesn't error or hang).
- [x] **Deliberate asymmetry, matching the `overridable` invariant from Phase 3**: the classifier can only turn an `ask` into an `allow`, never into a `deny`. Layer 0's hard-coded guards keep exclusive denial authority, so a hallucinating or misbehaving local model can't unilaterally block the agent. Verified end-to-end that Layer 2 is never even consulted for a non-overridable verdict (`rm -rf /` stays denied regardless of classifier config).
- [x] Any failure path (disabled, timeout, transport error, malformed/invalid JSON) returns `None` from `classify()`, meaning "no opinion". The caller falls back to the original gray-zone `ask`, never defaults to `allow` on uncertainty.
- [x] Verified end-to-end with a real (unreachable) `classifier.base_url` configured: `ccvet gate` degrades to `ask` quickly (connection refused, no hang) rather than timing out or crashing
- [x] 20 new tests (`test_classifier.py`, `test_shellrules_layer2.py`, `test_init_layer2.py`), 150 total passing

## Phase 5: Testing and hardening, DONE 2026-11-24

### Critical finding: compound shell constructs bypassed classification entirely
While adding edge-case tests, found that **`{ rm -rf /; }`, `(rm -rf /)`, `if true; then rm -rf /; fi`, `while`, and `for` loops all evaluated to `allow`** instead of being classified at all. Root cause: bashlex represents brace groups, subshells, and the wrapper around if/while/for/until as a `CompoundNode` exposing its children through a `.list` attribute. Every other node kind uses `.parts`, which is the only attribute `shell.py`'s extraction walker checked. The compound wrapper's children were silently never visited, `extract_simple_commands()` returned an empty list, and `shellrules.evaluate()`'s "no commands found" fallback is `allow("empty command")`. That turned "nothing to classify" into "nothing dangerous found" for an entire class of shell syntax. This was a real classification bypass, not a cosmetic gap, and a determined adversary (or just an agent wrapping a command in `{ ...; }` for unrelated reasons) could have walked straight through Layer 0's hard-coded guards.

Fixed in `shell.py` (`_children()` now checks both `.parts` and `.list`). Verified against all five constructs plus confirmed a benign brace group (`{ ls -la; }`) still correctly allows. Permanent regression tests added at both the extraction level (`test_shell.py`) and the full end-to-end taxonomy table (`test_bash_rules.py`'s `BLOCK_CASES`), so this can't silently regress. `case` statements remain unparseable by bashlex entirely (a bashlex limitation, not fixable here) and fall to `ask`, not `allow`. Safe, just not actively classified; documented as a known gap rather than silently missing.

**This is exactly the kind of bug a hardening pass exists to find.** Worth flagging to the user prominently, not just logging in this file.

### Rest of the pass
- [x] Golden test suite: full taxonomy table mapped to its expected verdict (was already built in Phase 1, extended here with the compound-construct cases above)
- [x] Edge-case tests: compound safe-then-dangerous and dangerous-then-safe (`ls -la && rm -rf /`, `sudo rm -rf /var && git status`; `most_severe` correctly picks the dangerous half either way); relative `../`-traversal into a credential path and outside the project root (distinct from the symlink case already covered in Phase 1)
- [x] Confirmed BLOCK tier is unoverridable by Layer 2 two ways: the existing decision-level check, plus a new spy-based test (`test_layer2_is_never_even_called_for_a_non_overridable_verdict`) proving the classifier function is structurally never invoked at all for `rm -rf /`, `sudo`, `git push --force`, `terraform destroy`. Stronger than checking the final answer, since it also rules out "got asked and got ignored by luck".
- [x] Crash-safety tests: truncated JSON, `tool_input` as the wrong type (string/null), top-level JSON array instead of object, missing `cwd` entirely. All degrade to `ask` (or a sane default), never raise.
- [x] Concurrency: in addition to the existing 50-thread same-process test (Phase 2), added a real **20-subprocess** test. Actual separate `ccvet gate` OS processes, not threads, each with its own isolated `HOME`, all appending to the same audit log file concurrently. No corruption.
- [x] Ran a full coverage pass (`pytest-cov`) and closed every gap worth closing: CLI dispatch for every subcommand via real `argparse` parsing (not just hand-built `Namespace` objects), `init.py`'s interactive decline paths and local-server probe branches, `userpolicy.py`'s malformed-rule and invalid-verdict-name paths, `fsrules.py`'s no-recognizable-path case, `commands.py`'s remaining branches (status with populated policy/audit data, log viewer skipping a malformed line, `policy edit`), `classifier.py`'s remaining validation branches. Ended at **99% line coverage, 212 tests**. The few lines left uncovered are deliberate (the real network call body in `classifier.py`, dead code after an intentional `SystemExit` in `cli.py`) or now-unreachable dead code made safe-but-moot by the compound-construct fix above.
- [x] Verified the wheel still builds cleanly after all changes

## Phase 6: Docs and release
- [x] README: install, quickstart, policy customization, Layer 2 setup, what each verdict tier means, and a clear opening description aimed at discoverability
- [x] SECURITY.md: explicit threat model and limitations. ccvet is a heuristic plus optional-LLM advisory gate, not a sandbox; it reduces risk, it doesn't replace least-privilege or container isolation. Said plainly so nobody over-trusts it.
- [x] CONTRIBUTING.md: how the community proposes new taxonomy rules (issue/PR flow: command and current decision, via `ccvet check`, then the proposed verdict and rationale)
- [x] LICENSE: MIT
- [x] No em dashes anywhere in user-facing text: README, SECURITY.md, CONTRIBUTING.md, the Docs/ folder, CLI help strings, and every `Verdict` reason string. Docstrings and inline code comments are exempt by the project's own standing style rule.
- [x] pyproject.toml polished for PyPI discoverability: expanded description, a `keywords` list (claude-code, pretooluse, permission-hook, auto-approve, risk-classifier, security, guardrails, ollama, lm-studio, and so on), added Topic/Intended Audience classifiers, and Repository/Issues URLs
- [ ] Supply-chain hygiene for ccvet's own release: pinned dependencies, PyPI trusted publishing from GitHub Actions (no long-lived PyPI tokens sitting in repo secrets)
- [ ] Push repo to https://github.com/saicharansreedhara2/ccvet (and set the GitHub repo's own description/topics for discoverability there too)
- [ ] PyPI packaging and first publish (`ccvet`; process reference only from nrchd's release setup, no shared code)
- [ ] Release automation (version bump plus a GitHub Action to publish on tag, if nrchd's workflow pattern fits)

## Phase 7: Stretch goals (post-v1, not blocking initial release)
- [ ] Persistent local daemon mode so the hook script becomes a thin client call instead of a fresh Python process per tool call, cutting per-invocation startup latency
- [ ] Windows/PowerShell taxonomy coverage (explicitly deferred in v1, see Scope notes in risk-taxonomy.md)

## Open decisions (not blocking Phase 0-1)
- ~~Exact repo name/account on GitHub~~ resolved: https://github.com/saicharansreedhara2/ccvet (2026-11-24)
- Whether `ask` prompts render inline in Claude Code's own permission UI or need a separate TTY prompt: resolved by the Phase 0.5 spike, not assumed
