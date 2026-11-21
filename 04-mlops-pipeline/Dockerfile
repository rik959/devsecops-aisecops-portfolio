# syntax=docker/dockerfile:1.7
# Training runs in CI and produces artifacts/; this image only serves a model
# whose checksum matches its model card.
FROM python:3.15-slim AS builder
ENV PIP_NO_CACHE_DIR=1
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY requirements.txt .
RUN pip install -r requirements.txt

FROM python:3.15-slim
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" PYTHONUNBUFFERED=1 MODEL_DIR=/app/artifacts
WORKDIR /app
COPY src ./src
COPY artifacts ./artifacts
USER 10001
EXPOSE 8080
HEALTHCHECK CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/healthz')"
CMD ["uvicorn", "src.serve:app", "--host", "0.0.0.0", "--port", "8080"]
