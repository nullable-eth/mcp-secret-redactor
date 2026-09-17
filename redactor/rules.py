"""Request rules: refuse a tools/call by tool name and argument value.

agentgateway's mcpAuthorization CEL can allow or deny a tool by name and
target, but cannot see its arguments. Some limits are about arguments:
"the git tools may write to any branch except the default one" keeps an
agent's repository access to pull requests, which a token's permissions cannot
express.

Rules file (YAML or JSON), path in RULES_FILE:

    deny:
      - target: github              # optional regex on the MCP target name
        tool: create_or_update_file|push_files|delete_file   # regex, full match
        argument: branch            # dotted path into the call's arguments
        matches: main|master        # regex, full match on the value as text
        missing: true               # also deny when the argument is absent
        reason: commit to a branch and open a pull request instead

A rule with no `argument` denies the tool outright. Rules are matched in order;
the first match refuses the call with its reason.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass

_UNSET = object()


def _get(obj, path: str):
    for part in path.split("."):
        if not isinstance(obj, dict) or part not in obj:
            return _UNSET
        obj = obj[part]
    return obj


@dataclass
class Rule:
    tool: re.Pattern
    target: re.Pattern | None = None
    argument: str = ""
    matches: re.Pattern | None = None
    missing: bool = False
    reason: str = "refused by policy"

    @classmethod
    def parse(cls, d: dict) -> "Rule":
        full = lambda p: re.compile(f"(?:{p})\\Z")  # noqa: E731
        return cls(tool=full(d["tool"]),
                   target=full(d["target"]) if d.get("target") else None,
                   argument=d.get("argument", ""),
                   matches=full(d["matches"]) if d.get("matches") is not None else None,
                   missing=bool(d.get("missing", False)),
                   reason=d.get("reason") or "refused by policy")

    def denies(self, targets: list[str], tool: str, args: dict) -> bool:
        if not self.tool.match(tool):
            return False
        if self.target and not any(self.target.match(t) for t in targets):
            return False
        if not self.argument:
            return True
        value = _get(args, self.argument)
        if value is _UNSET or value is None:
            return self.missing
        if self.matches is None:
            return True
        text = value if isinstance(value, str) else json.dumps(value)
        return bool(self.matches.match(text))


def load(text: str) -> list[Rule]:
    text = text.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except ValueError:
        import yaml
        data = yaml.safe_load(text)
    return [Rule.parse(r) for r in (data or {}).get("deny", [])]


def from_env() -> list[Rule]:
    path = os.environ.get("RULES_FILE", "")
    if not path or not os.path.exists(path):
        return []
    with open(path) as f:
        return load(f.read())


def check(rules: list[Rule], targets: list[str], params: dict) -> str | None:
    """The reason the call is refused, or None."""
    tool = str(params.get("name") or "")
    args = params.get("arguments") or {}
    for r in rules:
        if r.denies(targets, tool, args if isinstance(args, dict) else {}):
            return f"{tool}: {r.reason}"
    return None
