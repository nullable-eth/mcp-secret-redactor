FROM python:3.13-slim AS build
WORKDIR /src
COPY requirements.txt .
# Resolve the runtime and the code generator TOGETHER, then install the runtime
# at exactly those versions: generated code must not be newer than the
# protobuf runtime that loads it.
RUN pip install --no-cache-dir -r requirements.txt 'grpcio-tools==1.*' \
 && pip freeze > /tmp/constraints.txt \
 && pip install --no-cache-dir --prefix=/install -r requirements.txt -c /tmp/constraints.txt
COPY proto/ proto/
COPY redactor/ redactor/
COPY gen.sh .
RUN ./gen.sh \
 && PYTHONPATH=/install/lib/python3.13/site-packages python -c "import redactor.ext_mcp_pb2"

FROM python:3.13-slim
WORKDIR /srv
COPY --from=build /install /usr/local
COPY --from=build /src/redactor/ redactor/
USER 65534
EXPOSE 4445
CMD ["python", "-m", "redactor.server"]
