"""Bash command parsing: splits compound commands into sub-commands using a
real shell parser (bashlex) instead of regex on the raw text, since naive
string matching is trivially bypassed by `&&`/`;`/`|`/`$(...)`.
"""

import bashlex

from .verdict import Verdict

DECODE_PROGRAMS = {"base64", "xxd", "openssl"}
DOWNLOAD_PROGRAMS = {"curl", "wget"}
SHELL_PROGRAMS = {"sh", "bash", "zsh", "dash", "ksh"}


def _collect(node, out):
    kind = getattr(node, "kind", None)
    if kind == "commandsubstitution":
        _collect(node.command, out)
        return
    if kind == "command":
        words = [p for p in node.parts if p.kind == "word"]
        argv = [w.word for w in words]
        dynamic_name = bool(words) and bool(getattr(words[0], "parts", None))
        out.append((argv, dynamic_name))
    for part in getattr(node, "parts", []):
        _collect(part, out)


def extract_simple_commands(command: str):
    """Returns a flat, left-to-right list of (argv, dynamic_name) for every
    simple command found anywhere in the parse tree — including inside
    pipelines, lists, and command substitutions — or None if the text
    can't be parsed as shell at all (caller should treat that as gray-zone,
    not as safe).
    """
    try:
        trees = bashlex.parse(command)
    except Exception:
        return None
    out = []
    for tree in trees:
        _collect(tree, out)
    return out


def pipeline_risk(commands):
    """Catches the two obfuscation/exfil shapes that a per-command check
    alone would miss: decoded-or-downloaded content piped into a shell, and
    a command whose own name is dynamically constructed (so it can't be
    statically classified at all). Returns a Verdict or None.
    """
    seen_decode_or_download = False
    for argv, dynamic_name in commands:
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
                f"decoded or downloaded content piped into a shell ({program}) — "
                "classic payload-execution pattern"
            )
    return None


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1] if path else path
