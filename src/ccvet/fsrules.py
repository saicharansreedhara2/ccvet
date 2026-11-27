import os
from pathlib import Path

from . import paths
from .verdict import Verdict

READ_ONLY_TOOLS = {"Read", "Grep", "Glob"}
WRITE_TOOLS = {"Edit", "Write", "NotebookEdit"}

# "pattern" deliberately excluded: found by external review, it used to
# be in here as a fallback path field, but for Grep/Glob it's a search
# term (what to look for), not a filesystem path (where to look) - a
# Grep for the literal text ".env.production", or a Glob for
# "**/.ssh/id_*", is an ordinary, harmless search, not a read of that
# path. Running it through paths.resolve() and the secret-path check
# produced false denies on totally ordinary searches (and, worse, an
# inconsistent false allow whenever a benign "path" happened to be
# present alongside a dangerous-looking "pattern", since "path" was
# checked first and "pattern" was never looked at once that short-
# circuited). Grep/Glob's real scoping field is "path", same as every
# other tool here.
_PATH_KEYS = ("file_path", "path", "notebook_path")


def _path_from_input(tool_input: dict):
    for key in _PATH_KEYS:
        if tool_input.get(key):
            return tool_input[key]
    return None


def evaluate(tool_name: str, tool_input: dict, cwd: str) -> Verdict:
    raw_path = _path_from_input(tool_input)
    if raw_path is None:
        if tool_name in READ_ONLY_TOOLS:
            # Grep/Glob commonly run with no scoping path at all (search
            # the whole cwd) - read-only by construction (Docs/risk-
            # taxonomy.md), with no path to even check against the
            # secret-path list, so this is an ordinary case, not a
            # gray-zone one to escalate.
            return Verdict.allow(f"{tool_name} is read-only with no specific path given")
        return Verdict.ask(f"{tool_name} call with no recognizable path field, reviewing manually")

    resolved = paths.resolve(raw_path, cwd)

    if paths.matches_any(resolved, paths.SECRET_PATTERNS) or paths.is_dangerous_env_path(resolved):
        return Verdict.deny(f"{tool_name} touches a credential path ({resolved})")

    if tool_name in READ_ONLY_TOOLS:
        return Verdict.allow(f"{tool_name} is read-only ({resolved})")

    if paths.matches_any(resolved, paths.PERSISTENCE_PATTERNS):
        return Verdict.deny(f"{tool_name} targets a persistence vector ({resolved})")

    project_root = Path(os.path.realpath(cwd))
    if not paths.is_within(resolved, project_root):
        return Verdict.deny(f"{tool_name} writes outside the project root ({resolved})")

    if paths.matches_any(resolved, paths.MANIFEST_PATTERNS):
        return Verdict.ask(f"{tool_name} touches a build/CI/package manifest file ({resolved}), review before approving")

    return Verdict.ask(f"{tool_name} writes to {resolved}")
