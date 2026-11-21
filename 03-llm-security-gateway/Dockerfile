# syntax=docker/dockerfile:1.7
# Runtime: distroless cc-debian13 (glibc + libssl, no shell, no package manager)
# plus a current standalone CPython from uv. Distroless has no debian13 Python
# image yet, and python3-debian12 lags on OS patches (45 fixable HIGH CVEs when
# this was switched), so the interpreter is supplied explicitly instead.

FROM python:3.13-slim-trixie AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    UV_PYTHON_INSTALL_DIR=/python UV_PYTHON_PREFERENCE=only-managed UV_LINK_MODE=copy
RUN pip install uv==0.13.9
RUN uv python install 3.13 && uv venv /opt/venv --python 3.13
COPY requirements.txt .
RUN uv pip install --python /opt/venv/bin/python --no-cache -r requirements.txt
COPY app /app/app

FROM gcr.io/distroless/cc-debian13:nonroot
LABEL org.opencontainers.image.title="llm-security-gateway" \
      org.opencontainers.image.source="https://github.com/rik959/devsecops-aisecops-portfolio" \
      org.opencontainers.image.licenses="MIT"
# The venv's interpreter symlinks into /python, so both keep the same paths.
COPY --from=builder /python /python
COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /app /app
WORKDIR /app
ENV PATH=/opt/venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER nonroot
EXPOSE 8080
# No shell in distroless, so the healthcheck is exec-form Python.
HEALTHCHECK --interval=30s --timeout=3s \
  CMD ["/opt/venv/bin/python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2)"]
ENTRYPOINT ["/opt/venv/bin/python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-server-header"]
