from . import fsrules, shellrules
from .verdict import Verdict


def evaluate(tool_name: str, tool_input: dict, cwd: str) -> Verdict:
    if tool_name == "Bash":
        return shellrules.evaluate(tool_input.get("command", ""))

    if tool_name in fsrules.READ_ONLY_TOOLS or tool_name in fsrules.WRITE_TOOLS:
        return fsrules.evaluate(tool_name, tool_input, cwd)

    if tool_name == "WebSearch":
        return Verdict.allow("WebSearch doesn't fetch page content")

    if tool_name == "WebFetch":
        return Verdict.ask(f"WebFetch of {tool_input.get('url', '<unknown url>')}")

    if tool_name in {"Task", "Agent"}:
        return Verdict.ask(f"{tool_name} spawns autonomous work that makes its own further tool calls")

    return Verdict.defer(f"no rule for tool {tool_name!r}, deferring to normal permission flow")
