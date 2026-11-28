"""Per-sub-command classification for Bash. Order of checks matters: the
hard-coded guards below are the safety floor (BLOCK tier, not meant to be
user-overridable) and run before falling back to the YAML-configurable
AUTO/ASK program lists.
"""

import re

from . import paths, policy

_POLICY = policy.load_default()
AUTO_PROGRAMS = set(_POLICY["auto_programs"])
ASK_PROGRAMS = set(_POLICY["ask_programs"])
GIT_AUTO_SUBCOMMANDS = set(_POLICY["git"]["auto_subcommands"])
GIT_ASK_SUBCOMMANDS = set(_POLICY["git"]["ask_subcommands"])

SPECIFIC_SECRET_PATH_PATTERNS = (
    ".ssh/id_", ".ssh/authorized_keys", ".aws/credentials", ".aws/config",
    ".config/gcloud", "/etc/passwd", "/etc/shadow",
    # .netrc/.npmrc/.pypirc/.envrc all routinely carry auth tokens too.
    # .env is handled separately (paths.is_dangerous_env_path_text), not
    # listed here, since it needs to catch .env.local/.env.production
    # (real secrets, by convention) while not catching .env.example/
    # .env.sample (equally conventional, safe documentation variants) -
    # a plain pattern can't make that distinction.
    ".netrc", ".npmrc", ".pypirc", ".envrc",
    # Same four found by external review as paths.SECRET_PATTERNS, kept
    # in sync with it - see the comment there for why .gitconfig is
    # deliberately not included.
    ".git-credentials", ".config/gh/hosts.yml", ".docker/config.json", ".aws/sso/cache",
)
GENERIC_SECRET_NAME_PATTERNS = ("token", "secret", "credential")
NETWORK_PROGRAMS = {"curl", "wget", "nc", "netcat", "ssh", "scp", "rsync", "ftp"}

NPM_AUTO_SUBCOMMANDS = {"list", "ls", "view", "show", "ping", "whoami", "outdated", "audit"}
PIP_AUTO_SUBCOMMANDS = {"show", "list", "freeze", "check"}
# Found by a deep search for common read-only commands: "go"/"brew"
# used to be blanket ask_programs entries, asking about even their
# read-only subcommands the same way npm/pip would have without their
# own dedicated classifier. "go build"/"run"/"install"/"get"/"mod
# tidy" etc. and "brew install"/"upgrade"/"uninstall" are all still
# unrecognized by these sets and fall to the generic ask fallback.
GO_AUTO_SUBCOMMANDS = {"list", "env", "version", "doc", "vet"}
BREW_AUTO_SUBCOMMANDS = {"list", "info", "outdated", "deps", "doctor", "config"}
# A program invoked with *only* one of these, nothing else, can't do
# anything but print information and exit - true regardless of which
# program it is, which is what makes this a generic fallback rather
# than a per-program list. Deliberately requires the flag to be the
# *entire* argument list: `rm -v somefile` (verbose rm, a real
# operand) must not be swept into this, only `rm -v` alone (which,
# like every other program here, does nothing without an operand).
# Not hoisted above the per-program guards earlier in _classify_argv -
# sudo/doas's "-v" specifically means "refresh the cached credential
# timestamp", not "print version", so this must never run before
# sudo's own unconditional deny, and mkfs's name-based blanket deny
# is left untouched on purpose rather than carving out an edge case
# nobody asked for.
#
# Found by external review, a real regression: short forms (-v, -V,
# -h) were originally included too, on the assumption that they're
# "true regardless of which program it is" - false for shell
# interpreters specifically. Confirmed by execution, not just reading
# docs: `echo 'echo PWNED' | bash -v` and `| sh -v` both run the piped
# command (-v is bash/sh/zsh's verbose flag, not version; with no
# script argument the shell still reads and executes from stdin), so
# `cat script.sh | bash -v` was a full, silent bypass of the exact
# obfuscation-piped-to-shell pattern shell.pipeline_risk exists to
# catch - a single-letter flag collision this project has been bitten
# by before (sudo -v, grep -v). Long forms don't have this problem:
# confirmed `bash --version`/`--help` and `sh`/`zsh` equivalents all
# print and exit without touching stdin. Only the long forms, which
# are a near-universal GNU-style convention with no competing letter-
# flag meaning, are kept.
_BARE_INFO_FLAGS = {"--version", "--help"}

# Found by external review, a real bug: the previous `git branch`
# list-detection logic inferred safety from "every remaining argument
# starts with a dash", which incorrectly allowed `--unset-upstream`
# (removes the branch's upstream tracking, confirmed by execution -
# branch.b2.merge went from set to removed in a scratch repo) and
# `--edit-description` (spawns an editor) - both are zero-operand
# flags that still mutate. An explicit allowlist of the actual listing
# flags, rather than inferring safety from "no non-flag operand",
# can't make that mistake: anything not in this set, including an
# unrecognized flag, falls through to the ask fallback instead of
# being assumed safe.
GIT_BRANCH_LIST_FLAGS = {"-a", "-r", "-v", "-vv", "--list", "--all", "--remotes", "--show-current", "--color", "--no-color"}
# Writing to these has no effect at all, by design - not "a file
# outside the project root" the way an arbitrary /dev/sdX block
# device would be. "/dev/null" is the one that actually bit a real
# session: `2>/dev/null` (suppressing stderr, an extremely common,
# totally inert idiom) was being denied by redirect_target_root_guard
# as "outside the project root", true of the literal path but not of
# any real consequence.
SAFE_DISCARD_REDIRECT_TARGETS = {"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty"}
PROTECTED_BRANCHES = {"main", "master"}
# Top-level system directories plus bare wildcards. Originally much
# narrower (missing /var, /opt, /Applications, /Library, /root, /sbin,
# /boot, /private, and a bare "*"), which meant e.g. `rm -rf /var` or
# `rm -rf *` (wipe everything in the current directory) weren't
# recognized as catastrophic at all.
CATASTROPHIC_RM_TARGETS = {
    "/", "~", "$home", "/*", "*", ".*",
    "/etc", "/usr", "/bin", "/sbin", "/system", "/users", "/home",
    "/var", "/opt", "/applications", "/library", "/root", "/boot", "/private",
}
CATASTROPHIC_CHMOD_TARGETS = {
    "/", "~",
    "/etc", "/usr", "/bin", "/sbin", "/system", "/users", "/home",
    "/var", "/opt", "/applications", "/library", "/root", "/boot", "/private",
}

_SYMBOLIC_CHMOD_GRANT_RE = re.compile(r"^[ugoa]*([+=])([rwxst]+)$")


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1] if path else path


def _find_secret_arg(all_argvs, specific: bool):
    """Returns the specific matching argument, or None - not just a
    bool. Found by external review: secret_path_guard's deny reason
    named the general category ("~/.ssh, ~/.aws, /etc/passwd, etc.")
    but never which one actually matched (`cat .env` and `cat
    ~/.ssh/id_rsa` produced the identical generic message), costing a
    few seconds of "which rule was that" on every hit. Every other
    guard in this file that can name the specific thing it matched
    already does (redirect_target_guard's message includes the actual
    target, for instance); this one was the exception.
    """
    if specific:
        # Component-aware, like paths.py's matcher for Edit/Write/
        # redirect targets - a raw substring check here meant ".env"
        # matched ".env.example"/".env.local" too (common, safe
        # conventions for documenting required variables, not real
        # secrets), denying something that was never dangerous.
        for argv in all_argvs:
            for arg in argv[1:]:
                if paths.path_text_matches_any(arg, SPECIFIC_SECRET_PATH_PATTERNS):
                    return arg
                if paths.is_dangerous_env_path_text(arg):
                    return arg
        return None
    for argv in all_argvs:
        for arg in argv[1:]:
            low = arg.lower()
            if any(p in low for p in GENERIC_SECRET_NAME_PATTERNS):
                return arg
    return None


def _any_network_program(all_argvs) -> bool:
    return any(argv and _basename(argv[0]) in NETWORK_PROGRAMS for argv in all_argvs)


def secret_path_guard(all_argvs):
    """Checked once per whole command (not per sub-command): specific
    credential paths are always blocked and non-overridable (the exact
    path match is precise enough to trust). The generic token/secret/
    credential *name* heuristic, by contrast, is overridable: it's a
    fuzzy name-based match (paired with a network call to narrow it down)
    that can false-positive on two unrelated sub-commands that happen to
    share a compound statement, so a user must be able to promote past it
    once they've actually reviewed a specific case.
    """
    from .verdict import Verdict

    # The generic token/secret/credential-NAME hit is the argument text
    # that matched, which can genuinely BE a raw secret value (confirmed:
    # curl --header "Authorization: token=<live token>" put the token
    # straight into this message). No manual redact.redact() call
    # needed here, or anywhere else a Verdict reason is built - every
    # Verdict factory (verdict.py) redacts its reason centrally, since
    # permissionDecisionReason isn't just an internal detail: it's also
    # the hook message Claude Code displays live and records in the
    # session transcript, a second durable store ccvet doesn't own and
    # can't redact after the fact. Patching individual f-strings like
    # this one, instead of redacting once at that single choke point,
    # is exactly what let the same leak shape go unfixed in the much
    # more common ASK_PROGRAMS fallback below - see verdict.py.
    specific_hit = _find_secret_arg(all_argvs, specific=True)
    if specific_hit is not None:
        return Verdict.deny(f"command references a credential file path ({specific_hit})")
    generic_hit = _find_secret_arg(all_argvs, specific=False)
    if generic_hit is not None and _any_network_program(all_argvs):
        return Verdict.deny(
            f"command references something named token/secret/credential ({generic_hit}) alongside a network call",
            overridable=True,
        )
    return None


def redirect_target_guard(redirect_targets):
    """Shell redirections (`>`, `>>`, `<`, `<<<`, ...) are invisible to
    the per-argv checks above, since a redirect target never appears in
    argv. Without this, `curl ... < ~/.aws/credentials` (exfiltrating a
    credential file via input redirection) and `echo ... >> ~/.bashrc`
    (a persistence write) were both classified with no awareness of the
    sensitive path at all.

    A dynamic target (one containing a substitution or variable
    expansion) catches a second bypass of the same shape: `cat myfile >
    $(echo ~/.bashrc)` extracts to the raw, unexpanded text, which
    doesn't match any literal pattern, and there's no inner-command
    classification that can tell us what a *destination* path resolves to
    the way there is for a data *source* (contrast with `<(ls -la)` in
    classify_argv). A target that's *purely* one dynamic token with
    nothing concatenated around it (`$(mktemp)`, or a bare variable like
    `$OUT`) is a common, usually-benign shape, so it's asked rather than
    denied outright, and marked overridable; literal text glued around a
    dynamic part (`$(ls -d ~/.ssh)/id_rsa`, `${OUT}.bak`) is denied
    outright with no override, matching the "can't verify the command
    name -> deny" precedent in shell.pipeline_risk.
    """
    from .verdict import Verdict

    for target, severity in redirect_targets:
        if severity == "deny":
            return Verdict.deny(
                f"command redirects to/from a dynamically constructed target ({target}), "
                "cannot verify it doesn't resolve to a sensitive path"
            )
        if severity == "ask":
            return Verdict.ask(
                f"command redirects to/from a dynamically constructed target ({target}), "
                "e.g. a $(mktemp)-style idiom or a plain variable like $OUT; cannot verify it "
                "doesn't resolve to a sensitive path, but this is common enough to let you "
                "review and allow it",
                overridable=True,
            )
        if paths.path_text_matches_any(target, paths.SECRET_PATTERNS) or paths.is_dangerous_env_path_text(target):
            return Verdict.deny(f"command redirects to/from a credential file path ({target})")
        if paths.path_text_matches_any(target, paths.PERSISTENCE_PATTERNS):
            return Verdict.deny(f"command redirects to a persistence vector ({target})")
    return None


def redirect_target_root_guard(output_redirect_targets, cwd):
    """Found by external review, a real gap: `> /etc/hosts` or `>
    /Users/charan/outside.txt` (a redirect with no command before it
    at all, or any other command whose only side effect is the
    redirect) classified as a plain allow - the empty argv a bare
    redirect extracts to is correctly a no-op in `classify_argv`'s
    eyes (the same shape a bare variable assignment produces), but the
    redirect itself still truncates/creates the target file. That
    target was only ever checked against the secret/persistence
    pattern lists above, never against the project-root boundary the
    way an equivalent Write tool call is in `fsrules.py` - a Bash
    redirect to an arbitrary location outside the project silently
    bypassed a protection the Write tool already enforced for the
    identical path. Deliberately separate from redirect_target_guard
    above: this only needs to run on *static* targets (severity
    "none") - a dynamic one is already handled by that function
    instead, at whichever severity it resolved to (a "pure" token like
    `$OUT`/`$(mktemp)` asks, overridable; literal text glued around
    one denies outright) - so this function doesn't need to, and
    can't usefully, second-guess a target it can't even resolve to a
    concrete path. Also only on output redirects, via
    `shell.extract_output_redirect_targets`, since reading from an
    arbitrary path outside the project is already unrestricted for the
    Read tool too.
    """
    import os
    from pathlib import Path

    from .verdict import Verdict

    project_root = Path(os.path.realpath(cwd))
    for target, severity in output_redirect_targets:
        if severity != "none":
            continue
        if target in SAFE_DISCARD_REDIRECT_TARGETS:
            # Found by live use right after this check shipped: `2>
            # /dev/null` (suppressing stderr, an extremely common,
            # completely inert idiom) was being denied as "outside the
            # project root" - true of the path, but `/dev/null` isn't
            # a real file with real content to overwrite; writing to
            # it has no effect at all, by design. Checked against the
            # raw target text, before resolving, since these are
            # well-known fixed paths, not something that needs
            # realpath's symlink/relative-path handling to recognize.
            # Deliberately a short, explicit list, not "skip anything
            # under /dev" - /dev/sda1 and friends are real block
            # devices, and a redirect straight to one is exactly the
            # kind of write this check exists to catch (the same
            # concern `dd ... of=/dev/*` is denied for elsewhere).
            continue
        resolved = paths.resolve(target, cwd)
        if not paths.is_within(resolved, project_root):
            return Verdict.deny(f"command redirects outside the project root ({resolved})")
    return None


def _normalize_target(t: str) -> str:
    # "/".rstrip("/") would otherwise collapse to "" and silently escape
    # the catastrophic-targets check entirely.
    return t.lower() if t == "/" else t.rstrip("/").lower()


def _looks_like_home_directory_root(normalized_target: str) -> bool:
    # Catches `rm -rf /Users/charan` or `/home/alice`: just as
    # catastrophic as `rm -rf /` for that user, but the literal path
    # isn't knowable in advance the way "/etc" or "/usr" is, so a fixed
    # target list alone can never cover it.
    parts = [p for p in normalized_target.split("/") if p]
    return len(parts) == 2 and parts[0] in {"users", "home"}


def _is_catastrophic_target(t: str, catastrophic_set) -> bool:
    # Takes the target set as a parameter rather than hardcoding
    # CATASTROPHIC_RM_TARGETS: found by external review that chmod's own
    # catastrophic-target check used to skip this function entirely (a
    # plain `_normalize_target(t) in CATASTROPHIC_CHMOD_TARGETS` set
    # check, no home-directory-root heuristic), so `chmod -R 777
    # /Users/charan` (the spelled-out home path, the more likely form a
    # model actually emits) only asked, while `rm -rf /Users/charan`
    # already denied. The rm-side fix was never carried over to chmod,
    # despite being just as catastrophic there (a world-writable home
    # directory). A shared parameterized function, rather than reusing
    # CATASTROPHIC_RM_TARGETS directly for chmod too, keeps rm's and
    # chmod's target lists independent (chmod's deliberately omits rm's
    # bare-wildcard entries like "*"/"/*"/".*", which are specific to a
    # recursive delete, not a permission change).
    normalized = _normalize_target(t)
    return normalized in catastrophic_set or _looks_like_home_directory_root(normalized)


def _is_catastrophic_rm(args) -> bool:
    has_recursive = any(a.startswith("-") and "r" in a.lower() for a in args)
    has_force = any(a.startswith("-") and "f" in a.lower() for a in args)
    targets = [a for a in args if not a.startswith("-")]
    hits_catastrophic = any(_is_catastrophic_target(t, CATASTROPHIC_RM_TARGETS) for t in targets)
    return has_recursive and has_force and (hits_catastrophic or not targets)


def _is_full_permission_grant(mode: str) -> bool:
    if mode in {"777", "000"}:
        return True
    match = _SYMBOLIC_CHMOD_GRANT_RE.match(mode)
    if not match:
        return False
    op, perms = match.group(1), set(match.group(2))
    return op in {"+", "="} and {"r", "w", "x"} <= perms


def _is_catastrophic_chmod(args) -> bool:
    has_recursive = any(a in {"-R", "--recursive"} for a in args)
    non_flag_args = [a for a in args if not a.startswith("-")]
    mode_hit = any(_is_full_permission_grant(a) for a in non_flag_args)
    targets = [a for a in non_flag_args if not _is_full_permission_grant(a)]
    hits_catastrophic = any(_is_catastrophic_target(t, CATASTROPHIC_CHMOD_TARGETS) for t in targets)
    return has_recursive and mode_hit and hits_catastrophic


def _classify_git(args):
    from .verdict import Verdict

    if not args:
        return Verdict.ask("bare `git` call with no subcommand", overridable=True)
    # "git" dispatches here unconditionally (see classify_argv), so the
    # generic bare-version/help-flag fallback near the end of
    # _classify_argv never gets a chance to run for it - handled
    # locally instead. git has no short "-v" for version (unlike most
    # other tools), so only "--version" is recognized.
    if args == ["--version"]:
        return Verdict.allow("git --version only prints version info", overridable=True)

    sub, rest = args[0], args[1:]

    if sub == "push":
        if any(f in rest for f in ("--force", "-f", "--force-with-lease")):
            return Verdict.deny("git push --force (or -f) can destroy remote history")
        return Verdict.ask("git push", overridable=True)
    if sub == "reset" and "--hard" in rest:
        return Verdict.deny("git reset --hard destroys uncommitted work")
    if sub == "clean" and any(f.lstrip("-").find("f") != -1 for f in rest if f.startswith("-")):
        return Verdict.deny("git clean -f* permanently deletes untracked files")
    if sub == "branch":
        if any(f in rest for f in ("-D", "-d", "--delete")):
            target = next((a for a in rest if not a.startswith("-")), "")
            if target.lower() in PROTECTED_BRANCHES:
                return Verdict.deny(f"git branch -D on protected branch {target!r}")
            return Verdict.ask(f"git branch -D {target}".strip(), overridable=True)
        # Found by a deep search for common read-only commands: a bare
        # `git branch` (or with only listing flags like -a/-r/-v/
        # --list, none of which take a value) just lists branches and
        # mutates nothing, but fell to the generic "unrecognized
        # subcommand" ask fallback since "branch" was never in
        # GIT_AUTO_SUBCOMMANDS (it can't be - most of its other forms
        # do mutate). Everything else - creating/renaming a branch
        # (`<name>`/`-m old new`), or a zero-operand mutating flag not
        # in GIT_BRANCH_LIST_FLAGS (`--unset-upstream`,
        # `--edit-description`) - deliberately falls through to the
        # ask fallback below instead of being assumed safe.
        if all(a in GIT_BRANCH_LIST_FLAGS for a in rest):
            return Verdict.allow("git branch (list) is read-only", overridable=True)
    if sub == "filter-branch":
        return Verdict.deny("git filter-branch rewrites history")
    if sub == "stash":
        if not rest or rest[0] in {"list", "show"}:
            return Verdict.allow(f"git stash {' '.join(rest)}".strip() + " is read-only", overridable=True)
        return Verdict.ask(f"git stash {' '.join(rest)}".strip(), overridable=True)
    # "remote" and "tag" were in GIT_AUTO_SUBCOMMANDS as if every
    # invocation were as harmless as `git remote -v`/`git tag -l`, with
    # no check for their mutating forms: `git remote remove origin` (or
    # set-url, to redirect future pushes anywhere), and `git tag -d`/
    # `--delete` were both silently auto-approved.
    if sub == "remote":
        if rest and rest[0] in {"add", "remove", "rm", "set-url", "rename", "set-head", "set-branches", "prune"}:
            return Verdict.ask(f"git remote {' '.join(rest)}".strip(), overridable=True)
        return Verdict.allow("git remote (list/show) is read-only", overridable=True)
    if sub == "tag":
        if any(f in rest for f in ("-d", "--delete")):
            return Verdict.ask(f"git tag {' '.join(rest)}".strip(), overridable=True)
        return Verdict.allow("git tag (list/create) is read-only-ish", overridable=True)
    # Found by the same deep search: `git worktree list` is as
    # read-only as `git branch`/`git remote` with no args, but
    # `worktree add`/`remove`/`prune`/`move`/`lock`/`unlock` all mutate
    # the working tree layout, so this needs the exact same
    # list-form-only split as remote/tag/stash above.
    if sub == "worktree":
        if rest and rest[0] == "list":
            return Verdict.allow("git worktree list is read-only", overridable=True)
        return Verdict.ask(f"git worktree {' '.join(rest)}".strip(), overridable=True)
    # `git config` without a value to set is read-only (-l/--list,
    # --get/--get-all <key>); `git config <key> <value>` (or --add/
    # --unset/--replace-all) mutates .git/config or ~/.gitconfig.
    if sub == "config":
        if rest and (rest[0] in {"-l", "--list"} or rest[0] in {"--get", "--get-all"}):
            return Verdict.allow(f"git config {' '.join(rest)}".strip() + " is read-only", overridable=True)
        return Verdict.ask(f"git config {' '.join(rest)}".strip(), overridable=True)
    if sub in GIT_AUTO_SUBCOMMANDS:
        return Verdict.allow(f"git {sub} is read-only", overridable=True)
    if sub in GIT_ASK_SUBCOMMANDS:
        return Verdict.ask(f"git {sub}", overridable=True)
    return Verdict.ask(f"git {sub} (unrecognized subcommand)", overridable=True)


def classify_argv(argv, has_dynamic_arg=False):
    """`has_dynamic_arg` means some word in argv (not necessarily the
    command name) came from a `$(...)`/`<(...)` substitution, so its real
    value can't be known statically. `cat $(ls -d ~/.ssh)/id_rsa` has a
    perfectly ordinary, recognized command name ("cat"), but the raw text
    "$(ls -d ~/.ssh)/id_rsa" doesn't contain ".ssh/id_" as a contiguous
    substring (the closing paren breaks it), so the secret-path guard
    never saw it, and "cat" being auto-approved classified the whole
    thing straight to allow. An otherwise-auto-approved verdict is
    downgraded to ask here instead, since we genuinely cannot verify
    what the argument resolves to.
    """
    verdict = _classify_argv(argv)
    if has_dynamic_arg and verdict.decision == "allow":
        from .verdict import Verdict

        program = _basename(argv[0]) if argv else ""
        return Verdict.ask(
            f"an argument to `{program}` is dynamically constructed (e.g. from $(...) or <(...)), "
            "cannot verify it doesn't resolve to a sensitive path",
            overridable=True,
        )
    return verdict


def _classify_argv(argv):
    from .verdict import Verdict

    if not argv:
        return Verdict.allow("no-op (empty command, e.g. a bare variable assignment)")

    program = _basename(argv[0])
    args = argv[1:]

    if program in {"sudo", "doas"}:
        return Verdict.deny(f"{program} escalates privileges")

    if program == "env" and not args:
        return Verdict.ask(
            "env with no arguments prints every environment variable, which commonly includes "
            "active API keys/tokens for the current session",
            overridable=True,
        )

    # `exec`/`command`/`builtin` pass their remaining words straight
    # through as the real command (bashlex has already split them into
    # argv), so just reclassify the rest directly: `exec rm -rf /` must
    # not be treated as a harmless, unrecognized `exec` call.
    if program in {"exec", "command", "builtin"} and args:
        return classify_argv(args)

    # `eval` is different: it concatenates its own arguments into a
    # single string and re-interprets *that* as shell syntax, so the
    # inner command needs to go back through the real parser, not just
    # be sliced off like exec/command/builtin above. Without this,
    # `eval "rm -rf /"` fell to "unrecognized command `eval`", an ask,
    # instead of being recognized as equivalent to running the command
    # directly.
    if program == "eval" and args:
        from . import shell

        joined = " ".join(args)
        inner_commands = shell.extract_simple_commands(joined)
        inner_verdicts = [
            classify_argv(a, has_dynamic_arg=has_dyn)
            for a, _dynamic_name, has_dyn in (inner_commands or [])
            if a
        ]
        if inner_verdicts:
            from .verdict import most_severe

            return most_severe(inner_verdicts)
        return Verdict.ask(f"eval with unparseable or empty content: {joined!r}")

    if program == "rm" and _is_catastrophic_rm(args):
        return Verdict.deny(f"rm with recursive+force flags targeting {args!r} is catastrophic")

    if program == "chmod" and _is_catastrophic_chmod(args):
        return Verdict.deny(f"chmod -R 777/000 on a system path ({args!r}) is catastrophic")

    if program == "dd" and any(a.startswith("of=/dev/") for a in args):
        return Verdict.deny("dd writing directly to a device file can destroy a disk")

    if program.startswith("mkfs"):
        return Verdict.deny(f"{program} formats a filesystem, destroying existing data")

    if program == "diskutil" and args and args[0] in {"eraseDisk", "eraseVolume", "zeroDisk"}:
        return Verdict.deny(f"diskutil {args[0]} is destructive")

    if program == "git":
        return _classify_git(args)

    if program == "npm" and "publish" in args:
        return Verdict.deny("npm publish pushes a package to the public registry")

    if program == "npm":
        # npm/pip dispatch here unconditionally, same as git above, so
        # they need their own local version-flag carve-out too - the
        # generic one near the end of this function never gets reached
        # for them.
        if len(args) == 1 and args[0] in _BARE_INFO_FLAGS:
            return Verdict.allow(f"npm {args[0]} only prints version/help info", overridable=True)
        # Found by external review, a pre-existing bug this round's
        # generalization to go/brew made more consequential: checking
        # only args[0] against NPM_AUTO_SUBCOMMANDS let "npm audit fix"
        # through on the strength of "audit" alone - npm's own docs
        # describe "audit fix" as automatically installing changes,
        # not read-only the way a bare "npm audit" is.
        if args and args[0] == "audit" and "fix" in args[1:]:
            return Verdict.ask("npm audit fix can automatically install dependency changes", overridable=True)
        if args and args[0] in NPM_AUTO_SUBCOMMANDS:
            return Verdict.allow(f"npm {args[0]} is read-only", overridable=True)
        return Verdict.ask(f"npm {' '.join(args)}".strip(), overridable=True)

    if program in {"pip", "pip3"}:
        if len(args) == 1 and args[0] in _BARE_INFO_FLAGS:
            return Verdict.allow(f"{program} {args[0]} only prints version/help info", overridable=True)
        if args and args[0] in PIP_AUTO_SUBCOMMANDS:
            return Verdict.allow(f"{program} {args[0]} is read-only", overridable=True)
        return Verdict.ask(f"{program} {' '.join(args)}".strip(), overridable=True)

    if program == "go":
        # Found by external review: checking only args[0] against
        # GO_AUTO_SUBCOMMANDS let "go env -w ..." through on the
        # strength of "env" alone - documented Go behavior is that
        # "-w" writes the change persistently to the GOENV config
        # file, unlike a bare "go env" (prints current values only).
        if args and args[0] == "env" and "-w" in args[1:]:
            return Verdict.ask(f"go env {' '.join(args[1:])}".strip() + " writes the persistent GOENV config", overridable=True)
        if args and args[0] in GO_AUTO_SUBCOMMANDS:
            return Verdict.allow(f"go {args[0]} is read-only", overridable=True)
        return Verdict.ask(f"go {' '.join(args)}".strip(), overridable=True)

    if program == "brew":
        if args and args[0] in BREW_AUTO_SUBCOMMANDS:
            return Verdict.allow(f"brew {args[0]} is read-only", overridable=True)
        return Verdict.ask(f"brew {' '.join(args)}".strip(), overridable=True)

    # Unlike the text/system-inspection additions in default_policy.yaml,
    # "hostname" can also *set* the hostname when given an argument
    # (typically requires root, but the attempt itself shouldn't be
    # silently auto-approved) - needs this dedicated zero-args-only
    # check rather than a blanket YAML entry.
    if program == "hostname" and not args:
        return Verdict.allow("hostname with no arguments only prints the current hostname", overridable=True)

    if program == "twine" and "upload" in args:
        return Verdict.deny("twine upload pushes a package to the public registry")

    if program == "crontab" and "-r" in args:
        return Verdict.deny("crontab -r removes all scheduled jobs")

    if program == "kill" and "1" in args and any(f in args for f in ("-9", "-KILL")):
        return Verdict.deny("kill -9 1 would kill the init process")

    if program == "pkill" and any(a in {".", "*", ".*"} for a in args):
        return Verdict.deny("pkill with a catch-all pattern can kill unrelated/critical processes")

    if program == "terraform" and "destroy" in args:
        return Verdict.deny("terraform destroy tears down provisioned infrastructure")

    if program == "aws" and len(args) >= 2 and args[0] == "s3" and args[1] == "rm" and "--recursive" in args:
        return Verdict.deny("aws s3 rm --recursive can delete an entire bucket's contents")

    if program == "kubectl" and args and args[0] == "delete" and any(
        a in {"--all", "namespace", "namespaces", "ns"} for a in args
    ):
        return Verdict.deny("kubectl delete --all/namespace is broad and destructive")

    if program == "find":
        if any(a in {"-delete", "-exec", "-execdir", "-ok", "-okdir"} for a in args):
            return Verdict.ask(f"find with -delete/-exec/-execdir/-ok/-okdir can modify or remove files ({args!r})", overridable=True)
        return Verdict.allow("find without -delete/-exec/-execdir/-ok/-okdir is read-only", overridable=True)

    # Found by external review (flagged as unverified on macOS, but
    # documented Linux behavior): "lsblk" is otherwise blanket-safe
    # (added to AUTO_PROGRAMS above), but "--fstrim" discards unused
    # blocks on the listed devices - a real effect on the device, not
    # a pure read, so it needs excluding before the blanket check
    # below rather than being swept in with the rest of lsblk's
    # ordinary, genuinely read-only usage.
    if program == "lsblk" and "--fstrim" in args:
        return Verdict.ask("lsblk --fstrim discards unused blocks on the listed devices, not a pure read", overridable=True)

    if program in AUTO_PROGRAMS:
        return Verdict.allow(f"{program} is on the read-only allowlist", overridable=True)

    if program in ASK_PROGRAMS:
        return Verdict.ask(f"{program} {' '.join(args)}".strip(), overridable=True)

    # Generic fallback for any program not already handled above,
    # found by a deep search for common read-only commands: a bare
    # --version/-v/-V/--help/-h with *nothing else* can't do anything
    # but print information and exit, regardless of which program it
    # is - this is what makes it a program-agnostic rule rather than
    # another name to add to a list, covering node/python3/rustc/
    # cargo/ruby/php/etc. uniformly, present or future. See the
    # _BARE_INFO_FLAGS definition above for why this isn't hoisted
    # earlier in this function.
    if len(args) == 1 and args[0] in _BARE_INFO_FLAGS:
        return Verdict.allow(f"{program} {args[0]} only prints version/help info, no side effects", overridable=True)

    return Verdict.ask(f"unrecognized command `{program}`, no rule matched", overridable=True)
