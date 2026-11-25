"""Path resolution and classification for file-based tool calls (and, via
shell.py's redirect-target extraction, for Bash redirections too).

Always resolves through realpath before any scope/pattern check — a
symlink or `../../` traversal must not be able to dodge the project-root
boundary or the persistence/secret-path rules.

Patterns are matched component-by-component against the resolved path's
parts, not as a raw substring search on the joined path string. Substring
matching was a real bug: "/etc/passwd" matched "/etc/passwd_notes.md",
".bashrc" matched "my.bashrc_backup.txt", "package.json" matched
"mypackage.json", and so on. Since the SECRET_PATTERNS match is a hard,
non-overridable deny, a false positive there couldn't even be worked
around by the user. A pattern component ending in "_" (e.g. "id_") still
matches as a prefix, so ".ssh/id_" continues to catch id_rsa, id_ed25519,
etc. Every other component must match exactly (case-insensitive).
"""

import os
from pathlib import Path

PERSISTENCE_PATTERNS = (
    ".git/hooks", ".bashrc", ".zshrc", ".profile", ".bash_profile",
    "crontab", "crontabs", "library/launchagents", ".config/systemd/user",
)

SECRET_PATTERNS = (
    ".ssh/id_", ".ssh/authorized_keys", ".aws/credentials", ".aws/config",
    ".config/gcloud", "etc/passwd", "etc/shadow",
)

MANIFEST_PATTERNS = (
    "package.json", ".npmrc", "pyproject.toml", "pipfile",
    ".github/workflows", ".gitlab-ci.yml", "jenkinsfile", "dockerfile",
)


def resolve(path_str: str, cwd: str) -> Path:
    p = Path(path_str).expanduser()
    if not p.is_absolute():
        p = Path(cwd) / p
    return Path(os.path.realpath(p))


def is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _component_sequence_matches(path_parts_lower: tuple, pattern: str) -> bool:
    components = tuple(c.lower() for c in pattern.strip("/").split("/"))
    n = len(components)
    if n == 0 or len(path_parts_lower) < n:
        return False
    prefix_last = components[-1].endswith("_")
    for i in range(len(path_parts_lower) - n + 1):
        window = path_parts_lower[i:i + n]
        if not all(window[j] == components[j] for j in range(n - 1)):
            continue
        if prefix_last:
            if window[-1].startswith(components[-1]):
                return True
        elif window[-1] == components[-1]:
            return True
    return False


def matches_any(path: Path, patterns) -> bool:
    path_parts_lower = tuple(p.lower() for p in path.parts)
    return any(_component_sequence_matches(path_parts_lower, pat) for pat in patterns)


def path_text_matches_any(path_str: str, patterns) -> bool:
    """Same component-aware matching as matches_any, but for a raw path
    string that hasn't been (and shouldn't be) resolved through realpath -
    used for Bash redirect targets, where resolving relative to cwd could
    be misleading (the target may not exist yet, may be on a different
    host inside a container, etc.) and all we actually need is to catch
    the same literal patterns, consistently with the Edit/Write tool checks.
    """
    parts = tuple(seg.lower() for seg in path_str.replace("\\", "/").split("/") if seg)
    return any(_component_sequence_matches(parts, pat) for pat in patterns)
