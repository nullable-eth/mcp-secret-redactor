#!/bin/sh
# Generates the gRPC bindings for agentgateway's ExtMcp protocol
# (proto/ext_mcp.proto, copied from agentgateway/agentgateway
# crates/protos/proto/ext_mcp.proto).
set -eu
python -m grpc_tools.protoc -I proto --python_out=redactor --grpc_python_out=redactor proto/ext_mcp.proto
sed -i 's/^import ext_mcp_pb2 as/from . import ext_mcp_pb2 as/' redactor/ext_mcp_pb2_grpc.py
