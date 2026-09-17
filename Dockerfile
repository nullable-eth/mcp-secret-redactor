FROM python:3.13-slim AS build
WORKDIR /src
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt \
 && pip install --no-cache-dir grpcio-tools==1.*
COPY proto/ proto/
COPY redactor/ redactor/
COPY gen.sh .
RUN ./gen.sh

FROM python:3.13-slim
WORKDIR /srv
COPY --from=build /install /usr/local
COPY --from=build /src/redactor/ redactor/
USER 65534
EXPOSE 4445
CMD ["python", "-m", "redactor.server"]
