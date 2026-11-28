"""Bash command parsing: splits compound commands into sub-commands using a
real shell parser (bashlex) instead of regex on the raw text, since naive
string matching is trivially bypassed by `&&`/`;`/`|`/`$(...)`.
"""

import bashlex

from .verdict import Verdict

DECODE_PROGRAMS = {"base64", "xxd", "openssl"}
DOWNLOAD_PROGRAMS = {"curl", "wget"}
SHELL_PROGRAMS = {"sh", "bash", "zsh", "dash", "ksh"}


def _children(node):
    # CompoundNode (brace groups `{ ...; }`, subshells `(...)`, and the
    # outer wrapper around if/while/for/until/select) exposes its children
    # under `.list`, not `.parts`, like every other node kind. Missing
    # this meant `{ rm -rf /; }`, `(rm -rf /)`, `if ...; then rm -rf /; fi`
    # etc. all extracted to zero commands and silently fell through to
    # "allow" - a real classification bypass, not just a coverage gap.
    children = list(getattr(node, "parts", None) or [])
    children += list(getattr(node, "list", None) or [])
    return children


# Tilde expansion (~) is represented as its own node kind in a word's
# `.parts`, but it's entirely predictable (always "the home directory"),
# not something that could be hiding an unknown or attacker-influenced
# value the way a substitution or variable expansion could. It must not
# count toward "this argument can't be statically verified" - otherwise
# every single `~/...`-prefixed path (an extremely common, ordinary
# shape) would be flagged.
_UNTRUSTED_PART_KINDS = {"commandsubstitution", "processsubstitution", "parameter"}


def _has_untrusted_dynamic_content(word) -> bool:
    """True if `word` contains a command/process substitution or a
    variable expansion whose resolved value can't be known statically,
    UNLESS the word is *entirely* one command/process substitution (e.g.
    `<(ls -la)` as a whole argument, nothing glued onto it) - in that
    case the inner command gets independently extracted and classified
    elsewhere, so there's nothing left to distrust about the word itself.

    A parameter expansion (`$SECRET_FILE`) is always untrusted, pure or
    not: unlike a substitution, there's no inner command to independently
    verify, so the value is simply unknown. Literal text glued around a
    substitution, e.g. `$(ls -d ~/.ssh)/id_rsa`, is also untrusted: the
    word's own span is wider than the substitution's span (bashlex
    positions make the concatenation detectable - the substitution's
    `.pos` only covers the `$(...)` portion, not the trailing text).
    """
    parts = getattr(word, "parts", None) or []
    risky_parts = [p for p in parts if getattr(p, "kind", None) in _UNTRUSTED_PART_KINDS]
    if not risky_parts:
        return False
    if len(parts) == 1 and len(risky_parts) == 1:
        only = risky_parts[0]
        if only.kind in ("commandsubstitution", "processsubstitution"):
            if getattr(only, "pos", None) == getattr(word, "pos", None):
                return False
    return True


def _collect(node, out):
    kind = getattr(node, "kind", None)
    if kind in ("commandsubstitution", "processsubstitution"):
        # $(...) and <(...)/>(...) both expose the embedded command via
        # `.command`, not `.parts`. `cat <(rm -rf /)` was extracting to
        # just `cat` with the process substitution as a literal, unparsed
        # string in its argv, allowing straight through on `cat`'s
        # allowlist entry without the embedded `rm -rf /` ever being seen.
        _collect(node.command, out)
        return
    if kind == "command":
        words = [p for p in node.parts if p.kind == "word"]
        argv = [w.word for w in words]
        dynamic_name = bool(words) and bool(getattr(words[0], "parts", None))
        # Not just the command name: `cat $(ls -d ~/.ssh)/id_rsa` has a
        # perfectly static, recognized command name ("cat") but an
        # argument that's partly substituted. The substring-based secret-
        # path check can't see ".ssh/id_" in the raw text "$(ls -d
        # ~/.ssh)/id_rsa" (the closing paren breaks the match), and since
        # "ls" is independently extracted and is itself auto-approved,
        # this classified straight to "allow" with no awareness that the
        # argument's real value can't be statically verified at all.
        # `<(ls -la)` alone is NOT flagged: see _has_untrusted_dynamic_content.
        has_dynamic_arg = any(_has_untrusted_dynamic_content(w) for w in words)
        out.append((argv, dynamic_name, has_dynamic_arg))
    for part in _children(node):
        _collect(part, out)


def extract_simple_commands(command: str):
    """Returns a flat, left-to-right list of (argv, dynamic_name,
    has_dynamic_arg) for every simple command found anywhere in the parse
    tree, including inside pipelines, lists, and command substitutions,
    or None if the text can't be parsed as shell at all (caller should
    treat that as gray-zone, not as safe). `dynamic_name` means the
    command name itself (argv[0]) is dynamically constructed;
    `has_dynamic_arg` means any word in argv is, which matters for
    deciding whether an otherwise-safe, recognized command can still be
    auto-approved when one of its arguments can't be statically verified.
    """
    try:
        trees = bashlex.parse(command)
    except Exception:
        return None
    out = []
    for tree in trees:
        _collect(tree, out)
    return out


def _redirect_target_severity(word) -> str:
    """Returns "none" (static text, or only a predictable tilde - nothing
    to flag), "ask" (the whole target is *purely* one dynamic token with
    nothing concatenated around it - a self-contained substitution like
    `$(mktemp)`, or a bare variable like `$OUT` - a common, usually-
    benign shape for a redirect target; still unverifiable, so it's
    escalated rather than trusted, but a user-reviewed `ccvet allow` can
    promote it), or "deny" (literal text concatenated around a dynamic
    part, e.g. `$(ls -d ~/.ssh)/id_rsa` or `${OUT}.bak` - the more
    clearly obfuscation-shaped case, with no override available).

    A bare variable gets the same "ask" treatment as a pure substitution,
    not a stricter one: `OUT=report.txt; cmd > $OUT` is an entirely
    ordinary shell idiom, and like `$(mktemp)`, the destination still
    can't be statically verified either way - the risk profile of "one
    clean, unverifiable token" doesn't depend on whether that token is a
    substitution or a variable. What makes a target obfuscation-shaped
    enough to deny outright is specifically literal text glued onto a
    dynamic part, which bashlex's position spans make detectable: the
    word's own span is wider than its single dynamic child's span exactly
    when something is concatenated.

    Unlike an argv data source, where classifying the inner command of a
    pure substitution tells us exactly what's being read (`<(ls -la)`
    reads exactly `ls -la`'s output), a redirect *target*'s dynamic
    content becomes a *destination* path, which there's no way to verify
    without actually running/resolving it - so even "ask" here is a
    concession to a known-common shape, not a claim that it's been
    verified safe the way a pure argv substitution is treated.
    """
    parts = getattr(word, "parts", None) or []
    risky_parts = [p for p in parts if getattr(p, "kind", None) in _UNTRUSTED_PART_KINDS]
    if not risky_parts:
        return "none"
    if len(parts) == 1 and len(risky_parts) == 1:
        only = risky_parts[0]
        if getattr(only, "pos", None) == getattr(word, "pos", None):
            return "ask"
    return "deny"


_WRITE_REDIRECT_TYPES = {">", ">>"}


def _collect_redirect_targets(node, out, only_types=None):
    kind = getattr(node, "kind", None)
    if kind in ("commandsubstitution", "processsubstitution"):
        _collect_redirect_targets(node.command, out, only_types)
        return
    if kind == "command":
        for part in node.parts:
            if getattr(part, "kind", None) != "redirect":
                continue
            if only_types is not None and getattr(part, "type", None) not in only_types:
                continue
            target = getattr(part, "output", None)
            if getattr(target, "kind", None) == "word":
                # A redirect target's own `.word` is the raw, unexpanded
                # text, e.g. "$(echo ~/.bashrc)" - a substitution inside
                # a redirect target was never being recursed into at
                # all (no check of `target.parts` here), so neither the
                # secret/persistence pattern match (looking for a
                # literal ".bashrc" substring broken up by the
                # surrounding "$(...)") nor any other check ever saw it.
                # `cat myfile > $(echo ~/.bashrc)` classified as a plain
                # allow with zero awareness the destination was
                # unverifiable.
                out.append((target.word, _redirect_target_severity(target)))
    for part in _children(node):
        _collect_redirect_targets(part, out, only_types)


def extract_redirect_targets(command: str):
    """Returns a flat list of (target_text, severity) for every
    redirection target (the right-hand side of `>`, `>>`, `<`, `<<<`,
    ...) found anywhere in the parse tree, or None if the text can't be
    parsed. `severity` is "none"/"ask"/"deny" - see
    _redirect_target_severity for what each means.

    Separate from extract_simple_commands() because redirect targets
    aren't arguments to classify per-program; they matter only for the
    secret/persistence path checks. Without this, `curl ... < ~/.aws/
    credentials` (exfiltrating a credential file via input redirection)
    and `echo ... >> ~/.bashrc` (a persistence write) were both
    completely invisible to classification, since only argv words were
    ever scanned and a redirect target never appears in argv.
    """
    try:
        trees = bashlex.parse(command)
    except Exception:
        return None
    out = []
    for tree in trees:
        _collect_redirect_targets(tree, out)
    return out


def extract_output_redirect_targets(command: str):
    """Like extract_redirect_targets() above, but only for *output*
    redirects (">"/">>" - truncate or append), never input ones
    ("<"/"<<<"/heredocs). Used specifically for the project-root
    boundary check (rules.redirect_target_root_guard): found by
    external review, a redirect-only command (no command word before
    the redirect at all, e.g. `> /etc/hosts` or `>
    /Users/charan/outside.txt`) classified as a plain allow - the
    empty argv it extracts to is correctly treated as a no-op by
    classify_argv (the same shape a bare variable assignment produces),
    but the redirect itself still truncates/creates the target file,
    and that target was only ever checked against the secret/
    persistence pattern lists (extract_redirect_targets, above), never
    against the project-root boundary the way an equivalent Write tool
    call would be. An input redirect doesn't need this: reading from an
    arbitrary path outside the project is already unrestricted for the
    Read tool too, so only directionality that writes needs the check.
    """
    try:
        trees = bashlex.parse(command)
    except Exception:
        return None
    out = []
    for tree in trees:
        _collect_redirect_targets(tree, out, only_types=_WRITE_REDIRECT_TYPES)
    return out


def pipeline_risk(commands):
    """Catches the two obfuscation/exfil shapes that a per-command check
    alone would miss: decoded-or-downloaded content piped into a shell, and
    a command whose own name is dynamically constructed (so it can't be
    statically classified at all). Returns a Verdict or None.
    """
    seen_decode_or_download = False
    for argv, dynamic_name, _has_dynamic_arg in commands:
        if not argv:
            continue
        if dynamic_name:
            return Verdict.deny(
                f"command name `{argv[0]}` is dynamically constructed (e.g. from $(...)), "
                "cannot statically verify safety"
            )
        program = _basename(argv[0])
        if program in DECODE_PROGRAMS or program in DOWNLOAD_PROGRAMS:
            seen_decode_or_download = True
        elif program in SHELL_PROGRAMS and seen_decode_or_download:
            return Verdict.deny(
                f"decoded or downloaded content piped into a shell ({program}), "
                "a classic payload-execution pattern"
            )
    return None


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1] if path else path
