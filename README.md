# mcp-secret-redactor

An [agentgateway](https://agentgateway.dev) MCP guardrail (ExtMcp gRPC) that
removes Kubernetes Secret values from MCP tool results before a model sees them.

Any tool that can read files, exec into pods or read logs can surface a
credential. This service keeps the exact credential values from the cluster's
own Secrets and replaces them wherever they appear, in raw, base64, URL- and
JSON-escaped form, with `[REDACTED:<namespace>/<secret>.<key>]`. A pattern pass
(private keys, URL userinfo, bearer/basic tokens, `*_password=`, GitHub PATs,
JWTs, AWS keys) catches credentials that were never put in a Secret.

It is a second layer: the agent's own ServiceAccount should not be able to read
Secrets at all. The redactor has its own ServiceAccount with `get/list` on
Secrets; its values never leave the process (only labels are logged).

## Behaviour

- Only `tools/call` results are inspected (`methods: {"tools/call": response}`).
- A changed result is returned as `mutated`, an unchanged one as `pass`.
- **Fail closed:** if the Secret set has not refreshed for 5 × `REFRESH_SECONDS`
  the result is refused. Use `failureMode: failClosed` on the processor so an
  unreachable redactor also refuses.
- Secret values that are ordinary (short values, host names, paths, e-mail
  addresses, URLs without credentials) are not masked unless their key names a
  credential.
- JSON-RPC error responses do not pass through ExtMcp hooks.

## Request rules

agentgateway's `mcpAuthorization` CEL allows or denies tools by name and target
but cannot see arguments. `RULES_FILE` adds argument rules on `tools/call`
(the processor needs `tools/call: full` to see requests):

```yaml
deny:
  - target: github                      # optional, regex on the MCP target
    tool: create_or_update_file|push_files|delete_file
    argument: branch                    # dotted path into arguments
    matches: main|master                # full-match regex on the value
    missing: true                       # also deny when absent
    reason: commit to a branch and open a pull request instead
  - tool: merge_pull_request            # no argument: deny the tool
    reason: a human merges
```

## Configuration

| env | default | |
|---|---|---|
| `PORT` | `4445` | gRPC (h2c) |
| `REFRESH_SECONDS` | `60` | Secret reload interval |
| `SECRET_NAMESPACES` | all | comma-separated list to restrict the source |
| `WORKERS` | `8` | gRPC threads |
| `RULES_FILE` | unset | request rules (YAML/JSON) |

agentgateway (standalone config):

```yaml
backends:
- mcp:
    targets: [...]
  policies:
    mcpGuardrails:
      processors:
      - kind: remote
        host: mcp-secret-redactor.<ns>.svc.cluster.local
        port: 4445
        failureMode: failClosed
        methods:
          tools/call: full       # `response` if no request rules
```

## Development

```sh
uv run --no-project --python 3.12 --with-requirements requirements.txt \
  --with 'grpcio-tools==1.*' --with pytest sh -c './gen.sh && python -m pytest -q tests'
```

`proto/ext_mcp.proto` is copied from agentgateway
(`crates/protos/proto/ext_mcp.proto`).
