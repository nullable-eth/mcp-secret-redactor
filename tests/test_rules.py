"""Request rules: tool + argument denial."""
import json

from redactor import ext_mcp_pb2 as pb
from redactor import rules
from redactor.server import ExtMcp
from redactor.engine import Redactor

RULES = rules.load("""
deny:
  - target: github
    tool: create_or_update_file|push_files|delete_file
    argument: branch
    matches: main|master
    missing: true
    reason: commit to a branch and open a pull request instead
  - tool: merge_pull_request
    reason: a human merges
""")


def req(server, tool, args, target="github"):
    return server.CheckRequest(pb.McpRequest(
        method="tools/call", service_names=[target],
        mcp_request=json.dumps({"name": tool, "arguments": args}).encode()), None)


def server():
    return ExtMcp(Redactor(), None, RULES)


def test_default_branch_write_is_refused():
    r = req(server(), "push_files", {"owner": "o", "repo": "r", "branch": "main"})
    assert r.WhichOneof("result") == "error"
    assert "pull request" in r.error.reason


def test_missing_branch_is_refused():
    assert req(server(), "create_or_update_file", {"path": "x"}).WhichOneof("result") == "error"


def test_feature_branch_write_passes():
    r = req(server(), "push_files", {"branch": "agent/fix-dns"})
    assert r.WhichOneof("result") == "pass"


def test_full_match_only():
    assert req(server(), "push_files", {"branch": "main-fix"}).WhichOneof("result") == "pass"


def test_other_target_is_not_matched():
    r = req(server(), "push_files", {"branch": "main"}, target="gitea")
    assert r.WhichOneof("result") == "pass"


def test_tool_denied_outright():
    assert req(server(), "merge_pull_request", {}).WhichOneof("result") == "error"


def test_reads_pass():
    assert req(server(), "get_file_contents", {"branch": "main"}).WhichOneof("result") == "pass"


def test_non_call_methods_pass():
    r = server().CheckRequest(pb.McpRequest(method="tools/list"), None)
    assert r.WhichOneof("result") == "pass"


def test_empty_rules():
    assert rules.load("") == []
    assert rules.load('{"deny": []}') == []
