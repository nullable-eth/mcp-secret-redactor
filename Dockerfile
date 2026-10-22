FROM python:3.13-slim AS build
WORKDIR /src
COPY requirements.txt .
# Resolve the runtime and the code generator TOGETHER, then install the runtime
# at exactly those versions: generated code must not be newer than the
# protobuf runtime that loads it.
RUN pip install --no-cache-dir -r requirements.txt 'grpcio-tools==1.*' \
 && pip freeze > /tmp/constraints.txt \
 && pip install --no-cache-dir --ignore-installed --prefix=/install -r requirements.txt -c /tmp/constraints.txt
COPY proto/ proto/
COPY redactor/ redactor/
COPY gen.sh .
RUN ./gen.sh \
 && PYTHONPATH=/install/lib/python3.13/site-packages python -c "import redactor.ext_mcp_pb2"

FROM python:3.13-slim
# eMudhra CA compromise (20 Oct 26): eight eMudhra intermediate keys are
# derivable from their certificates. Take the distro's fixed ca-certificates
# even when the base image predates it.
RUN apt-get update && apt-get install -y --no-install-recommends --only-upgrade ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /srv
COPY --from=build /install /usr/local
COPY --from=build /src/redactor/ redactor/
# certifi >= 2026.10.19 drops the compromised roots; requests/httpx use it,
# not the OS store.
RUN pip install --no-cache-dir -U "certifi>=2026.10.19"

USER 65534
EXPOSE 4445
CMD ["python", "-m", "redactor.server"]
