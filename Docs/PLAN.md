# ccvet — Implementation Plan

Risk-classifying `PreToolUse` gate for Claude Code. Public repo on a separate (non-mortalapps) GitHub account — TBD, user will share which one — published to PyPI as `pip3 install ccvet`. Layer 0/1 (rules + heuristics) must fully work with zero model configured; Layer 2 (LLM) is opt-in for the gray zone only. See `risk-taxonomy.md` for the full command classification that backs Phase 1.

Legend: `[ ]` not started · `[~]` in progress · `[x]` done

## Phase 0 — Repo & packaging scaffold
- [x] Repo layout: `src/ccvet/`, `tests/`, `pyproject.toml`, `README.md`, `LICENSE` (MIT)
- [~] CLI entry point (`ccvet`) with subcommands: `init`, `gate` done; `config`, `policy`, `status`, `check`, `log`, `allow`, `uninstall` still stubs for later phases
- [x] Minimal `pyproject.toml` (build backend, metadata, `entry_points`)
- [x] Keep runtime deps minimal and imports lazy — `gate`/`init` modules are imported inside the CLI dispatch functions, not at module load time; zero runtime dependencies so far
- [x] `pip install -e .` + `ccvet --version` smoke test (venv at `.venv/`, gitignored)
- [x] Git init, first commit — staying local, not pushed anywhere until Phase 6 (target GitHub account TBD, not mortalapps — user will share which account to use)

## Phase 0.5 — Spike: verify the actual Claude Code hook contract
- [x] Confirmed exact `PreToolUse` stdin JSON shape against current docs (`code.claude.com/docs/en/hooks`) — see `Docs/hook-contract.md`
- [x] Confirmed `permissionDecision` has 4 values, not 3: `allow`/`deny`/`ask`/`defer`. `defer` (hand back to normal permission flow) is what ccvet uses for "no opinion yet"; `ask` is reserved for an explicit escalation, including ccvet's own crash fallback — `defer`'s behavior depends on the session's `permission_mode`, which is the wrong failure mode for an internal error, so the two are not interchangeable
- [x] Confirmed hook timeout: 600s default for `PreToolUse` (not 30s), configurable per-handler; on timeout the tool call falls through to normal permission flow rather than being blocked — Layer 2's budget (Phase 4) has ample room under the 10s handler timeout `ccvet init` sets
- [x] Hard-coded hook (`ccvet gate` returning `defer`, or `ask` on internal error) wired via `ccvet init` into a scratch project's `.claude/settings.json`, exercised with the documented stdin example piped directly into `ccvet gate` — output matched the contract exactly. Also verified `ccvet init` is idempotent (second run is a no-op) and preserves pre-existing `PreToolUse` entries rather than clobbering them.
- [ ] Still unverified: how Claude Code reconciles multiple `PreToolUse` hooks running in parallel when their decisions disagree — not stated in the docs page, flagged in `hook-contract.md` as an open question

## Phase 1 — Layer 0/1 rule engine (no model required) — DONE 2026-11-23
- [x] Rule schema (YAML): shipped `data/default_policy.yaml` covers the argument-insensitive program lists (`auto_programs`/`ask_programs`/git auto/ask subcommands). Argument-sensitive rules (rm -rf, chmod -R 777, git push --force, obfuscation, secret/persistence paths) are hard-coded guards in `rules.py` by design — these are the safety floor and aren't meant to be user-overridable (documented at the top of the YAML file and in risk-taxonomy.md).
- [x] Default policy shipped in-package (`src/ccvet/data/default_policy.yaml`), verified it's actually bundled into a built wheel (not just present in the editable install) — a real packaging check, not an assumption
- [x] Tool-type dispatch in `engine.py`: Bash → `shellrules`, Read/Grep/Glob/Edit/Write/NotebookEdit → `fsrules`, WebSearch/WebFetch/Task/Agent handled directly, unknown tool → `defer`
- [x] Shell tokenization via `bashlex` (verified against real parse trees for lists/pipelines/command-substitution before writing the extraction code) — splits compound commands (`&&`, `;`, `|`, `$(...)`) into sub-commands; a dynamically-constructed command name (e.g. `$(echo rm) -rf /`) is detected and denied outright since it can't be statically classified
- [x] Obfuscation heuristic: decode (`base64`/`xxd`/`openssl`) or download (`curl`/`wget`) followed anywhere later in the same parse by a shell invocation (`sh`/`bash`/`zsh`/...) is denied — catches both `curl url | sh` and `echo <b64> | base64 -d | sh`
- [x] Path-scope checks resolve `realpath` first (`paths.py`) — tested specifically against a symlink pointing outside the project root to confirm it can't bypass the boundary
- [x] Verdict reason-string convention implemented exactly as specified (`verdict.py`) — `allow`/`ask`/`deny`/`defer` each produce a consistently prefixed, human-readable reason
- [x] Unknown/unrecognized tool calls → `defer` (not `ask` — see verdict.py docstring for why these aren't interchangeable; `defer` is correct here since ccvet genuinely has no opinion on a tool it's never heard of, vs. Bash/file gray-zone cases where ccvet does have an opinion: "ask a human")
- [x] 105 unit tests passing: `test_shell.py` (parser/extraction), `test_bash_rules.py` (taxonomy-row table: AUTO/ASK/BLOCK cases across every category), `test_fs_rules.py` (path scoping, symlink traversal, persistence/secret/manifest files), `test_engine_dispatch.py`, `test_gate.py` (end-to-end + crash safety), `test_init.py`
- [x] Two real bugs caught and fixed by the test suite itself: `"/".rstrip("/")` collapsing to `""` and silently escaping the catastrophic-rm/chmod root-path check; `npm list`/`pip show` misclassified as ASK instead of AUTO (fixed by adding subcommand-aware classifiers for npm/pip, same pattern as git)

## Phase 2 — Hook integration — DONE 2026-11-23
- [x] `ccvet gate`: reads `PreToolUse` JSON from stdin, runs the engine, emits `hookSpecificOutput` JSON (`permissionDecision`, `permissionDecisionReason`)
- [x] Top-level crash safety: any uncaught exception inside `ccvet gate` must still emit a valid `ask` decision (not `defer` — see Phase 0.5), never a raw traceback on stdout. Implemented and tested in the Phase 0.5 spike (`gate.py`/`test_gate.py`); carries forward unchanged once the real rule engine replaces the placeholder logic.
- [x] `ccvet init`: project-local by default, `--global` writes `~/.claude/settings.json`; merges into existing hooks (never overwrites), shows a diff, asks for confirmation before writing
- [x] `ccvet uninstall`: cleanly removes just ccvet's hook entry, leaving any other configured hooks untouched (and drops the `hooks`/top-level key entirely if nothing's left) — round-tripped against a real scratch project, not just unit-tested
- [x] Audit log (JSONL) at `~/.ccvet/audit.jsonl` (one consolidated log across all projects, each entry carries `cwd`), concurrency-safe via `fcntl.flock` around each append — tested with 50 concurrent threads writing simultaneously, no corrupted/merged lines. File created with `0600` permissions (verified, not assumed) since it can contain raw Bash command text. Write-tool content is hashed (`content_sha256`+`content_length`), never stored verbatim, to avoid persisting secrets into the log.
- [x] `ccvet gate --dry-run`: evaluates and prints the decision but skips the audit-log write — verified via a real end-to-end smoke test (dangerous command denied, dry-run confirmed absent from the log; a non-dry-run safe command confirmed present)
- [x] A failure inside `audit.log()` is swallowed, never allowed to affect the already-emitted decision or crash the hook (tested by injecting a forced `OSError`)

## Phase 3 — Config & status — mostly DONE 2026-11-23
- [x] `ccvet config get/set`: dotted-key YAML store at `~/.ccvet/config.yaml` (`config.py`). Nothing consumes it yet — Phase 4's classifier settings will be the first real reader — but the plumbing is built and tested now.
- [x] `ccvet status`: reports project/global hook-wiring state, project/global policy rule counts, Layer 2 config presence, and audit log entry count. Smoke-tested end to end in an isolated scratch project, not just unit-tested.
- [x] `ccvet policy edit`: opens the active `.ccvet/policy.yaml` (project by default, `--global` for the user's global one — **not** the shipped built-in `data/default_policy.yaml`, which stays code-managed) in `$EDITOR`, creating an empty `rules: []` file first if none exists
- [x] `ccvet check "<command>"` (and `--tool`/`--path`/`--url` for non-Bash tool calls): dry-runs through the real engine and prints decision/reason/overridable
- [x] `ccvet log --tail N`: human-readable view of the audit log (defaults to last 20 entries, `--tail 0` for all)
- [x] `ccvet allow "<pattern>"`: writes a rule to the project (or `--global`) policy.yaml; literal by default (regex-escaped), `--regex` to pass a pattern through verbatim; `--verdict ask|deny` also supported for the "add my own stricter rule" case, not just promote-to-allow
- [x] User policy precedence implemented in `userpolicy.py`: project `.ccvet/policy.yaml` rules are checked before global `~/.ccvet/policy.yaml` ones, first match wins — tested, including that a malformed regex in a user rule is skipped rather than fatal
- [x] **Safety invariant, enforced structurally, not just by convention**: added an `overridable` field to `Verdict` (default `False`). Every named safety-floor guard in `rules.py`/`shell.py`/`sql_guard.py` leaves it at the default; only the generic program-list/gray-zone fallbacks set it `True`. A user policy rule can only take effect where the built-in verdict was already `overridable=True` — verified end-to-end that an `ccvet allow "rm -rf /"` rule is silently ignored and the command still gets denied. `most_severe()` was also fixed to prefer the non-overridable verdict on a rank tie, so a compound command mixing an overridable ask with a non-overridable one can't be bypassed either.
- [ ] Policy presets at `ccvet init` time (`strict`/`default`/`permissive`) — not done this pass, deferred (low value until there's real usage to calibrate presets against)

**Bug caught by integration testing, not unit testing**: the `check` subcommand's positional argument was named `command`, colliding with the top-level `argparse` subparsers' `dest="command"` — both write into the same flat `Namespace`, so `ccvet check "docker build ."` silently set `args.command` to the command text instead of `"check"`, and the whole dispatch fell through to the help text. The `test_commands.py` tests didn't catch this because they hand-built `argparse.Namespace` objects directly, bypassing real parsing. Fixed by renaming the positional to `shell_command`, and added `test_cli.py` to parse real argv for every subcommand going forward.

## Phase 4 — Layer 2 (optional LLM gray-zone classifier)
- [ ] OpenAI-compatible client, configurable `base_url`/`model`/`api_key` — covers Ollama/LM Studio/vLLM/mtplx uniformly
- [ ] Forced structured JSON output (`risk`, `reversible`, `blast_radius`, `rationale`) with schema validation
- [ ] Explicit timeout budget (e.g. 5s, comfortably under the hook timeout confirmed in Phase 0.5) — timeout/error/malformed-output all fail safe to `ask`, never `allow`
- [ ] Prompt hardening: tool input fenced explicitly as data, not instructions (anti prompt-injection)
- [ ] `ccvet init` auto-detects a running local server (Ollama `:11434`, LM Studio `:1234`) and offers to wire it in

## Phase 5 — Testing & hardening
- [ ] Golden test suite: full taxonomy table → expected verdict, run in CI
- [ ] Edge-case tests: obfuscated destructive commands, compound commands (`safe_cmd && dangerous_cmd`), path traversal into `~/.ssh` via relative paths and symlinks
- [ ] Confirm BLOCK tier is truly unoverridable by a Layer 2 verdict (test a mocked LLM that returns "low risk" for a BLOCK-listed command — must still block)
- [ ] Crash-safety tests: feed the engine malformed/truncated hook JSON, confirm it still degrades to `ask` rather than raising
- [ ] Concurrency test: two simultaneous `ccvet gate` invocations writing to the same audit log don't corrupt it

## Phase 6 — Docs & release
- [ ] README: install, quickstart, policy customization, Layer 2 setup, what each verdict tier means
- [ ] SECURITY.md: explicit threat model and limitations — ccvet is a heuristic + LLM advisory gate, not a sandbox; it reduces risk, it doesn't replace least-privilege or container isolation. Say this plainly so nobody over-trusts it.
- [ ] CONTRIBUTING.md: how the community proposes new taxonomy rules (PR template: command/pattern → proposed verdict → rationale)
- [ ] LICENSE: MIT
- [ ] Supply-chain hygiene for ccvet's own release: pinned dependencies, PyPI trusted publishing from GitHub Actions (no long-lived PyPI tokens sitting in repo secrets)
- [ ] Push repo to GitHub — account TBD (not mortalapps; user will share the account to use)
- [ ] PyPI packaging + first publish (`ccvet` — process reference only from nrchd's release setup, no shared code)
- [ ] Release automation (version bump + GitHub Action to publish on tag, if nrchd's workflow pattern fits)

## Phase 7 — Stretch goals (post-v1, not blocking initial release)
- [ ] Persistent local daemon mode so the hook script becomes a thin client call instead of a fresh Python process per tool call, cutting per-invocation startup latency
- [ ] Windows/PowerShell taxonomy coverage (explicitly deferred in v1 — see Scope notes in risk-taxonomy.md)

## Open decisions (not blocking Phase 0-1)
- Exact repo name on GitHub (`ccvet` vs `ccvet-gate` etc.) — confirm before creating the GitHub repo
- Whether `ask` prompts render inline in Claude Code's own permission UI or need a separate TTY prompt — resolved by the Phase 0.5 spike, not assumed
