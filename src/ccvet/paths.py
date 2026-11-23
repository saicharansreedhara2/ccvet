"""Path resolution and classification for file-based tool calls.

Always resolves through realpath before any scope/pattern check — a
symlink or `../../` traversal must not be able to dodge the project-root
boundary or the persistence/secret-path rules.
"""

import os
from pathlib import Path

PERSISTENCE_PATTERNS = (
    ".git/hooks/", ".bashrc", ".zshrc", ".profile", ".bash_profile",
    "crontab", "library/launchagents/", ".config/systemd/user/",
)

SECRET_PATTERNS = (
    ".ssh/id_", ".ssh/authorized_keys", ".aws/credentials", ".aws/config",
    ".config/gcloud/", "/etc/passwd", "/etc/shadow",
)

MANIFEST_PATTERNS = (
    "package.json", ".npmrc", "pyproject.toml", "pipfile",
    ".github/workflows/", ".gitlab-ci.yml", "jenkinsfile", "dockerfile",
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


def matches_any(path: Path, patterns) -> bool:
    text = str(path).lower()
    return any(pat in text for pat in patterns)
