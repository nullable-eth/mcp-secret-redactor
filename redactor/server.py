"""agentgateway ExtMcp server: redacts secrets from MCP tool results.

agentgateway calls CheckResponse with each tools/call result (configure the
processor with `methods: {"tools/call": response}`). The result JSON is
walked and every string is redacted (engine.py); a changed result is returned
as `mutated`, an unchanged one as `pass`. Requests are passed through.

Fail closed: if the Secret set has not been refreshed for a while, results
are refused rather than returned unredacted.
"""
from __future__ import annotations

import json
import logging
import os
import signal
from concurrent import futures

import grpc
from grpc_health.v1 import health, health_pb2, health_pb2_grpc

from . import rules
from . import ext_mcp_pb2 as pb
from . import ext_mcp_pb2_grpc as pbg
from .engine import Redactor, Stats
from .secrets import from_env

log = logging.getLogger("redactor")


class ExtMcp(pbg.ExtMcpServicer):
    def __init__(self, redactor: Redactor, source, request_rules=None):
        self.redactor, self.source = redactor, source
        self.rules = request_rules or []

    def CheckRequest(self, request, context):
        if self.rules and request.method == "tools/call":
            try:
                params = json.loads(request.mcp_request or b"{}")
            except ValueError:
                params = {}
            reason = rules.check(self.rules, list(request.service_names),
                                 params if isinstance(params, dict) else {})
            if reason:
                log.info("refused %s on %s: %s", request.method,
                         ",".join(request.service_names) or "-", reason)
                return pb.McpRequestResult(error=pb.AuthorizationError(
                    code=pb.AuthorizationError.Code.PERMISSION_DENIED, reason=reason))
        return pb.McpRequestResult(**{"pass": pb.Pass()})

    def CheckResponse(self, request, context):
        if self.source is not None and not self.source.fresh():
            log.error("secret set is stale; refusing %s", request.method)
            return pb.McpResponseResult(error=pb.AuthorizationError(
                code=pb.AuthorizationError.Code.RESOURCE_EXHAUSTED,
                reason="redactor cannot vouch for this result: secret list is stale"))
        try:
            result = json.loads(request.mcp_response or b"null")
        except ValueError:
            return pb.McpResponseResult(error=pb.AuthorizationError(
                code=pb.AuthorizationError.Code.INVALID, reason="result is not JSON"))
        stats = Stats()
        redacted = self.redactor.value(result, stats)
        if not (stats.exact or stats.pattern):
            return pb.McpResponseResult(**{"pass": pb.Pass()})
        log.info("redacted %s from %s: %d exact, %d pattern", request.method,
                 ",".join(request.service_names) or "-", stats.exact, stats.pattern)
        return pb.McpResponseResult(mutated=json.dumps(redacted).encode())


def serve() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    redactor = Redactor()
    source = from_env(redactor)
    source.start()
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=int(os.environ.get("WORKERS", "8"))))
    request_rules = rules.from_env()
    log.info("%d request rule(s) loaded", len(request_rules))
    pbg.add_ExtMcpServicer_to_server(ExtMcp(redactor, source, request_rules), server)
    health_servicer = health.HealthServicer()
    health_servicer.set("", health_pb2.HealthCheckResponse.SERVING)
    health_pb2_grpc.add_HealthServicer_to_server(health_servicer, server)
    port = os.environ.get("PORT", "4445")
    server.add_insecure_port(f"[::]:{port}")          # h2c, as agentgateway expects
    server.start()
    log.info("listening on :%s", port)
    signal.signal(signal.SIGTERM, lambda *_: server.stop(5))
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
