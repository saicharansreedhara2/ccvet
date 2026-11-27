# Claude Code PreToolUse Hook Contract (verified 2026-11-23)

Source: https://code.claude.com/docs/en/hooks. Captured here because the whole tool is built on this contract. Re-verify against this page if Claude Code's hook format ever changes.

## stdin (what `ccvet gate` receives)
```json
{
  "session_id": "abc123",
  "prompt_id": "550e8400-e29b-41d4-a716-446655440000",
  "transcript_path": "/home/user/.claude/projects/.../transcript.jsonl",
  "cwd": "/home/user/my-project",
  "scratchpad_dir": "/tmp/claude-1000/-home-user-my-project/abc123/scratchpad",
  "permission_mode": "default",
  "hook_event_name": "PreToolUse",
  "tool_name": "Bash",
  "tool_input": { "command": "npm test", "description": "Run test suite", "timeout": 120000, "run_in_background": false },
  "tool_use_id": "toolu_01ABC123..."
}
```

## stdout (what `ccvet gate` must print, exit 0)
```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "Destructive command blocked by hook"
  }
}
```

`permissionDecision` values:
| Value | Behavior |
|---|---|
| `allow` | Permit the tool call |
| `deny` | Block the tool call |
| `ask` | Escalate to the user |
| `defer` | Documented upstream as "passes to the next configured hook or permission system" (re-confirmed by fetching the live docs page on 2026-11-27, past the original 2026-11-23 verification date, since a previous question raised whether this value was real or ccvet's own invention: it's real). **This is ccvet's internal fallback when it has no opinion**, not `ask`, since `ask` and `defer` are different things on the wire even though both end up asking the user in most permission modes. |

A hook can also rewrite the call instead of just approving or denying it: `{"hookSpecificOutput": {"allow": true, "updatedInput": {...}}}`. Not used by ccvet v1, but worth knowing it exists.

## Exit codes
- `0`: success. stdout JSON (if any) is applied, otherwise normal permission flow runs.
- `2`: blocking error. Tool call is blocked regardless of any JSON printed; stderr becomes the shown reason.
- other: non-blocking error (unless `onFailure: "block"`). Tool call proceeds, stderr shown as a hook error notice.

**ccvet always exits 0 and communicates via the JSON `permissionDecision` field.** Exit code 2 is a blunter instrument (it ignores our JSON) that we don't need.

## Timeout
Default for `PreToolUse` command/http/mcp_tool hooks: **600 seconds** (the 30s default only applies to `UserPromptSubmit`/`PreModelSwitch`/`PostModelSwitch`, not us). Configurable per-handler via `"timeout"` (seconds) in settings.json.

**On timeout**: the hook is cancelled, its output discarded, and critically, *the tool call is NOT blocked by default*. It falls through to normal permission flow unless `onFailure: "block"` is set on that handler. This is actually the right default for ccvet: if Layer 2 hangs, the user still gets a normal prompt rather than the agent silently proceeding.

`ccvet init` sets the handler timeout to **20 seconds** (`HOOK_TIMEOUT_SECONDS` in `init.py`), generous relative to Layer 0/1's sub-millisecond cost, to leave real room for a slow local model on the Layer 2 path. Layer 2's own internal LLM-call timeout (`classifier.timeout_seconds`, default **8 seconds**) is set well under that handler timeout, so it has room to emit its own `ask` fallback before Claude Code's cancellation kicks in.

## settings.json shape
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          { "type": "command", "command": "ccvet gate", "timeout": 20 }
        ]
      }
    ]
  }
}
```
`command` is shown here as the bare `"ccvet gate"` for readability, but `ccvet init` actually writes the running interpreter's absolute path (e.g. `/path/to/venv/bin/ccvet gate`), not the bare name. Found by external review: Claude Code spawns the hook command in its own shell, which isn't guaranteed to carry the same `PATH` the interactive shell `ccvet init` ran from, a venv install being the common case where it doesn't; a bare name then resolves to nothing, fails open to normal permissions per the timeout behavior below, with no error shown anywhere. See `init._hook_binary()`.
- `matcher` filters by tool name pattern (`"Bash"`, `"Edit|Write"`, regex, or `"*"` for all). ccvet installs itself with `"*"` since it wants to see every tool call and apply its own internal dispatch (Read/Grep/Glob versus Bash versus Edit/Write versus everything else) rather than relying on the matcher to pre-filter.
- Multiple matcher groups can coexist for the same event, and **hooks run in parallel when an event fires**. If the user has other `PreToolUse` hooks installed, ours runs alongside them, not before or after. `ccvet init` must merge into the `PreToolUse` array, never replace it.
- Handler `type` can be `command`, `http`, `mcp_tool`, `prompt`, or `agent`. ccvet uses `command`.

## Visibility of `permissionDecisionReason` (verified 2026-11-23)
- **`deny`**: reason is shown to the user as a hook-error notice in the transcript.
- **`ask`/`defer`**: reason is shown as part of the permission escalation itself.
- **`allow`**: **not shown.** The docs are explicit that "Claude never sees stderr from a hook that exits 0". The same silence applies to the JSON reason field for `allow`. There's no transcript mode that lists every hook decision inline, only a debug-log flag (`claude --debug`) and a `/hooks` menu that shows *configured* hooks, not runtime decisions.

**Decision**: ccvet still populates `permissionDecisionReason` on every decision, including `allow`. It's free, and it's exactly what shows up under `claude --debug`. The real user-facing record of allow decisions is ccvet's own audit log (`ccvet log`), not the live chat transcript. The README documents `claude --debug` as the way to see allow reasons in real time for anyone who wants that during setup or testing.

## Open question not yet resolved by the docs page
How Claude Code reconciles multiple hooks' decisions when they run in parallel and disagree (for example, one says `allow`, another says `ask`) isn't stated on this page. Treat as unknown. Don't assume ccvet's `deny` is guaranteed to win over another hook's `allow` until verified against real behavior.

`defer`'s own documented wording ("passes to the next configured hook or permission system") hints that hooks aren't purely independent-and-merged, there's some notion of "the next" one, at least for a `defer` result specifically. That's a hint, not a resolution: it doesn't say what happens when two hooks give actively conflicting allow/deny verdicts rather than one of them deferring. Still treat the conflicting-verdicts case as unknown.
