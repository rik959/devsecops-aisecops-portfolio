# syntax=docker/dockerfile:1.7
# Multi-stage build: dependencies are installed in a builder that matches the
# runtime's Python minor version (distroless debian12 ships Python 3.11), and only
# site-packages + app code are copied into a distroless, non-root runtime image
# with no shell or package manager.

FROM python:3.11-slim-bookworm AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY requirements.txt .
RUN pip install --target /deps -r requirements.txt
COPY app ./app

FROM gcr.io/distroless/python3-debian12:nonroot
LABEL org.opencontainers.image.title="llm-security-gateway" \
      org.opencontainers.image.source="https://github.com/rik959/devsecops-aisecops-portfolio" \
      org.opencontainers.image.licenses="MIT"
WORKDIR /app
COPY --from=builder /deps /deps
COPY --from=builder /build/app ./app
ENV PYTHONPATH=/deps PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER nonroot
EXPOSE 8080
# No shell in distroless, so the healthcheck is exec-form Python.
HEALTHCHECK --interval=30s --timeout=3s \
  CMD ["python3", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2)"]
ENTRYPOINT ["python3", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-server-header"]
