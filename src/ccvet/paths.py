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
    # Claude Code's own config: the files that define its permissions,
    # hooks, and MCP servers. Found by external review: `cat evil >
    # .claude/settings.json` (or the global `~/.claude/settings.json`,
    # or `.mcp.json`) classified as a plain allow, since none of these
    # were in this list at all. This is exactly the "agent quietly makes
    # itself persistent / rewrites its own rules" class the rest of this
    # list exists to stop, and a rewritten settings file can silently
    # drop ccvet's own hook in the next session. The asymmetry was
    # telling: the Edit tool path for the identical file already asked
    # (project-local) or denied (outside the project root via the
    # root-boundary check) - only the Bash/redirect path was missing it.
    ".claude/settings.json", ".claude/settings.local.json", ".mcp.json",
    ".claude/commands", ".claude/agents",
)

# .env is arguably the single most common place real secrets live in an
# actual project, but it needs smarter handling than a plain pattern:
# .env.local/.env.production/.env.development (the conventional
# real-secret-bearing variants, e.g. Next.js's env file loading order)
# must be caught, while .env.example/.env.sample/.env.template (the
# equally conventional, safe, usually-committed documentation variants)
# must not be. See is_dangerous_env_filename below. .netrc/.npmrc/
# .pypirc/.envrc all routinely carry auth tokens too and don't have this
# safe-variant ambiguity, so they stay plain exact-match entries.
_ENV_SAFE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".defaults")


def is_dangerous_env_filename(name: str) -> bool:
    name = name.lower()
    if not (name == ".env" or name.startswith(".env.")):
        return False
    return not any(name.endswith(suffix) for suffix in _ENV_SAFE_SUFFIXES)


def is_dangerous_env_path(path: Path) -> bool:
    return is_dangerous_env_filename(path.name)


def is_dangerous_env_path_text(path_str: str) -> bool:
    basename = path_str.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    return is_dangerous_env_filename(basename)


SECRET_PATTERNS = (
    ".ssh/id_", ".ssh/authorized_keys", ".aws/credentials", ".aws/config",
    ".config/gcloud", "etc/passwd", "etc/shadow",
    # Write to .npmrc is a hard deny too, not just the "ask, it's a
    # manifest file" treatment below - consistent with every other
    # exact-path secret match being unconditional regardless of read vs
    # write, and the more defensible default for something that often
    # carries a registry auth token. .env is handled separately above
    # (is_dangerous_env_filename), not listed here.
    ".netrc", ".npmrc", ".pypirc", ".envrc",
)

MANIFEST_PATTERNS = (
    # .npmrc deliberately not repeated here - it's in SECRET_PATTERNS
    # above, which is checked first and would make this entry dead code.
    "package.json", "pyproject.toml", "pipfile",
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
