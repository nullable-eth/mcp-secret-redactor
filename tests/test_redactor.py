"""Tests: engine, secret collection, and the gRPC service end to end.

    ./gen.sh && python -m pytest -q tests
"""
import base64
import json
import time
import types
from concurrent import futures

import grpc
import pytest

from redactor import ext_mcp_pb2 as pb
from redactor import ext_mcp_pb2_grpc as pbg
from redactor.engine import Redactor, Stats, looks_secret
from redactor.secrets import collect
from redactor.server import ExtMcp

DB_PASS = "S3cr3t-Pg-Passw0rd-xyz"
API_KEY = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"


def secret(ns, name, data, type_="Opaque"):
    return types.SimpleNamespace(
        type=type_, metadata=types.SimpleNamespace(namespace=ns, name=name),
        data={k: base64.b64encode(v.encode()).decode() for k, v in data.items()})


SECRETS = [
    secret("databases", "shared-pg-app", {
        "username": "sonarr", "host": "shared-pg-rw.databases.svc", "port": "5432",
        "password": DB_PASS,
        "uri": f"postgresql://sonarr:{DB_PASS}@shared-pg-rw.databases.svc:5432/sonarr"}),
    secret("media", "arr-api-keys", {"SONARR_API_KEY": API_KEY}),
    secret("ai", "registry", {".dockerconfigjson": json.dumps(
        {"auths": {"ghcr.io": {"username": "bot", "password": "ghcr-registry-pw-123"}}})},
        type_="kubernetes.io/dockerconfigjson"),
    secret("default", "sh.helm.release.v1.x.v1", {"release": "H4sIAAAA" * 10}, type_="helm.sh/release.v1"),
]


@pytest.fixture
def red():
    r = Redactor()
    r.load(collect(SECRETS))
    return r


def run(r, text):
    s = Stats()
    return r.text(text, s), s


def test_ordinary_values_are_not_masked(red):
    out, _ = run(red, "connect to shared-pg-rw.databases.svc:5432 as sonarr")
    assert out == "connect to shared-pg-rw.databases.svc:5432 as sonarr"


def test_exact_value_in_env_output(red):
    out, s = run(red, f"PGPASSWORD={DB_PASS}\nHOME=/root")
    assert DB_PASS not in out and "databases/shared-pg-app.password" in out and s.exact >= 1
    assert "HOME=/root" in out


def test_api_key_inside_an_app_config_file(red):
    xml = f"<Config><ApiKey>{API_KEY}</ApiKey><Port>8989</Port></Config>"
    out, _ = run(red, xml)
    assert API_KEY not in out and "<Port>8989</Port>" in out


def test_encoded_forms(red):
    for form in (base64.b64encode(DB_PASS.encode()).decode(), json.dumps(DB_PASS)[1:-1]):
        out, _ = run(red, f"value: {form}")
        assert form not in out


def test_dockerconfigjson_inner_password(red):
    out, _ = run(red, "login with ghcr-registry-pw-123")
    assert "ghcr-registry-pw-123" not in out


def test_helm_release_blobs_are_skipped():
    assert not any("helm" in label for label in collect(SECRETS).values())


def test_patterns_for_values_not_in_secrets(red):
    cases = {
        "DATABASE_URL=postgres://app:hunter2hunter@db:5432/x": "hunter2hunter",
        "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123": "abcdefghijklmnopqrstuvwxyz0123",
        'GIT_TOKEN=notInAnySecret99': "notInAnySecret99",
        '{"password": "local-only-pw"}': "local-only-pw",
        "token ghp_" + "A" * 36: "ghp_" + "A" * 36,
    }
    for text, leaked in cases.items():
        out, _ = run(red, text)
        assert leaked not in out, (text, out)


def test_kubernetes_field_names_are_not_mistaken_for_credentials(red):
    for text in ("secretName: grafana-pg-credentials",
                 "secretKeyRef: {name: llm-api-key, key: API_KEY}",
                 "max_tokens=4000 tokens_used: 123456"):
        out, _ = run(red, text)
        assert out == text, out


def test_looks_secret():
    assert looks_secret("password", "short-but-8")
    assert not looks_secret("username", "sonarr-user")
    assert not looks_secret("uri", "http://shared-pg-rw:5432/db")
    assert looks_secret("uri", "postgres://u:p4ssword@h/db")
    assert looks_secret("random", "Zq8#kP2@xL9!mN4$vB7^")


def test_json_structure_including_keys(red):
    s = Stats()
    obj = {"content": [{"type": "text", "text": f"pw is {DB_PASS}"}], "isError": False}
    out = red.value(obj, s)
    assert DB_PASS not in json.dumps(out) and out["isError"] is False


# --- gRPC end to end ---------------------------------------------------------
class Fresh:
    def __init__(self, ok=True):
        self.ok = ok

    def fresh(self):
        return self.ok


@pytest.fixture
def stub(red):
    source = Fresh()
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
    pbg.add_ExtMcpServicer_to_server(ExtMcp(red, source), server)
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    channel = grpc.insecure_channel(f"127.0.0.1:{port}")
    yield pbg.ExtMcpStub(channel), source
    server.stop(0)


def call(stub, result):
    return stub.CheckResponse(pb.McpResponse(
        service_names=["kubernetes"], method="tools/call",
        mcp_response=json.dumps(result).encode()))


def test_grpc_mutates_a_result_with_a_secret(stub):
    s, _ = stub
    r = call(s, {"content": [{"type": "text", "text": f"PGPASSWORD={DB_PASS}"}]})
    assert r.WhichOneof("result") == "mutated"
    assert DB_PASS not in r.mutated.decode()
    json.loads(r.mutated)


def test_grpc_passes_a_clean_result(stub):
    s, _ = stub
    r = call(s, {"content": [{"type": "text", "text": "3 pods running"}]})
    assert r.WhichOneof("result") == "pass"


def test_grpc_fails_closed_when_the_secret_list_is_stale(stub):
    s, source = stub
    source.ok = False
    r = call(s, {"content": [{"type": "text", "text": "anything"}]})
    assert r.WhichOneof("result") == "error"


def test_grpc_requests_pass(stub):
    s, _ = stub
    r = s.CheckRequest(pb.McpRequest(method="tools/call"))
    assert r.WhichOneof("result") == "pass"
