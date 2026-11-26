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
    # .env is arguably the single most common place real secrets live in
    # an actual project; .netrc/.npmrc/.pypirc/.envrc all routinely carry
    # auth tokens too. All missing here before, despite being more common
    # in practice than most of the entries above.
    ".env", ".netrc", ".npmrc", ".pypirc", ".envrc",
)
GENERIC_SECRET_NAME_PATTERNS = ("token", "secret", "credential")
NETWORK_PROGRAMS = {"curl", "wget", "nc", "netcat", "ssh", "scp", "rsync", "ftp"}

NPM_AUTO_SUBCOMMANDS = {"list", "ls", "view", "show", "ping", "whoami", "outdated", "audit"}
PIP_AUTO_SUBCOMMANDS = {"show", "list", "freeze", "check"}

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


def _any_secret_arg(all_argvs, specific: bool) -> bool:
    patterns = SPECIFIC_SECRET_PATH_PATTERNS if specific else GENERIC_SECRET_NAME_PATTERNS
    for argv in all_argvs:
        for arg in argv[1:]:
            low = arg.lower()
            if any(p in low for p in patterns):
                return True
    return False


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

    if _any_secret_arg(all_argvs, specific=True):
        return Verdict.deny("command references a credential file path (~/.ssh, ~/.aws, /etc/passwd, etc.)")
    if _any_secret_arg(all_argvs, specific=False) and _any_network_program(all_argvs):
        return Verdict.deny(
            "command references something named token/secret/credential alongside a network call",
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
    """
    from .verdict import Verdict

    for target in redirect_targets:
        if paths.path_text_matches_any(target, paths.SECRET_PATTERNS):
            return Verdict.deny(f"command redirects to/from a credential file path ({target})")
        if paths.path_text_matches_any(target, paths.PERSISTENCE_PATTERNS):
            return Verdict.deny(f"command redirects to a persistence vector ({target})")
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


def _is_catastrophic_target(t: str) -> bool:
    normalized = _normalize_target(t)
    return normalized in CATASTROPHIC_RM_TARGETS or _looks_like_home_directory_root(normalized)


def _is_catastrophic_rm(args) -> bool:
    has_recursive = any(a.startswith("-") and "r" in a.lower() for a in args)
    has_force = any(a.startswith("-") and "f" in a.lower() for a in args)
    targets = [a for a in args if not a.startswith("-")]
    hits_catastrophic = any(_is_catastrophic_target(t) for t in targets)
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
    hits_catastrophic = any(_normalize_target(t) in CATASTROPHIC_CHMOD_TARGETS for t in targets)
    return has_recursive and mode_hit and hits_catastrophic


def _classify_git(args):
    from .verdict import Verdict

    if not args:
        return Verdict.ask("bare `git` call with no subcommand", overridable=True)

    sub, rest = args[0], args[1:]

    if sub == "push":
        if any(f in rest for f in ("--force", "-f", "--force-with-lease")):
            return Verdict.deny("git push --force (or -f) can destroy remote history")
        return Verdict.ask("git push", overridable=True)
    if sub == "reset" and "--hard" in rest:
        return Verdict.deny("git reset --hard destroys uncommitted work")
    if sub == "clean" and any(f.lstrip("-").find("f") != -1 for f in rest if f.startswith("-")):
        return Verdict.deny("git clean -f* permanently deletes untracked files")
    if sub == "branch" and any(f in rest for f in ("-D", "-d", "--delete")):
        target = next((a for a in rest if not a.startswith("-")), "")
        if target.lower() in PROTECTED_BRANCHES:
            return Verdict.deny(f"git branch -D on protected branch {target!r}")
        return Verdict.ask(f"git branch -D {target}".strip(), overridable=True)
    if sub == "filter-branch":
        return Verdict.deny("git filter-branch rewrites history")
    if sub == "stash":
        if not rest or rest[0] == "list":
            return Verdict.allow("git stash list is read-only", overridable=True)
        return Verdict.ask(f"git stash {' '.join(rest)}".strip(), overridable=True)
    # "remote" and "tag" were in GIT_AUTO_SUBCOMMANDS as if every
    # invocation were as harmless as `git remote -v`/`git tag -l`, with
    # no check for their mutating forms: `git remote remove origin` (or
    # set-url, to redirect future pushes anywhere), and `git tag -d`/
    # `--delete` were both silently auto-approved.
    if sub == "remote":
        if rest and rest[0] in {"add", "remove", "rm", "set-url", "rename", "set-head", "set-branches"}:
            return Verdict.ask(f"git remote {' '.join(rest)}".strip(), overridable=True)
        return Verdict.allow("git remote (list/show) is read-only", overridable=True)
    if sub == "tag":
        if any(f in rest for f in ("-d", "--delete")):
            return Verdict.ask(f"git tag {' '.join(rest)}".strip(), overridable=True)
        return Verdict.allow("git tag (list/create) is read-only-ish", overridable=True)
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
        if args and args[0] in NPM_AUTO_SUBCOMMANDS:
            return Verdict.allow(f"npm {args[0]} is read-only", overridable=True)
        return Verdict.ask(f"npm {' '.join(args)}".strip(), overridable=True)

    if program in {"pip", "pip3"}:
        if args and args[0] in PIP_AUTO_SUBCOMMANDS:
            return Verdict.allow(f"{program} {args[0]} is read-only", overridable=True)
        return Verdict.ask(f"{program} {' '.join(args)}".strip(), overridable=True)

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

    if program in AUTO_PROGRAMS:
        return Verdict.allow(f"{program} is on the read-only allowlist", overridable=True)

    if program in ASK_PROGRAMS:
        return Verdict.ask(f"{program} {' '.join(args)}".strip(), overridable=True)

    return Verdict.ask(f"unrecognized command `{program}`, no rule matched", overridable=True)
