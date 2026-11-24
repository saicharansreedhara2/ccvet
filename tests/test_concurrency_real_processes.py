"""The real scenario the audit log's locking is meant to survive: multiple
Claude Code sessions, each running `ccvet gate` as its own OS process, all
appending to the same log file at once. test_audit.py already proved this
for threads within one process; this proves it across real subprocesses.
"""

import concurrent.futures
import json
import os
import shutil
import subprocess
import sys


def _ccvet_binary():
    found = shutil.which("ccvet")
    if found:
        return found
    candidate = os.path.join(os.path.dirname(sys.executable), "ccvet")
    assert os.path.exists(candidate), "ccvet console script not found on PATH or next to sys.executable"
    return candidate


def _run_one(binary, home, i):
    payload = json.dumps({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": f"ls -la /tmp/nonexistent-marker-{i}"},
        "cwd": "/tmp",
    })
    env = dict(os.environ, HOME=home)
    result = subprocess.run([binary, "gate"], input=payload, capture_output=True, text=True, env=env, timeout=10)
    return result.returncode, result.stdout


def test_concurrent_real_subprocesses_do_not_corrupt_the_audit_log(tmp_path):
    binary = _ccvet_binary()
    home = str(tmp_path)
    n = 20

    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(lambda i: _run_one(binary, home, i), range(n)))

    for returncode, stdout in results:
        assert returncode == 0
        decision = json.loads(stdout)["hookSpecificOutput"]["permissionDecision"]
        assert decision == "allow"

    log_path = tmp_path / ".ccvet" / "audit.jsonl"
    lines = log_path.read_text().strip().splitlines()
    assert len(lines) == n
    for line in lines:
        json.loads(line)  # every line independently parseable - none merged or truncated
