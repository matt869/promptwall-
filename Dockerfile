# syntax=docker/dockerfile:1

# --- build ------------------------------------------------------------------
FROM python:3.12-slim AS builder

WORKDIR /build

# Wheels are built in this stage so the runtime image needs no compiler.
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --upgrade pip build

COPY pyproject.toml README.md LICENSE ./
COPY promptwall ./promptwall

RUN --mount=type=cache,target=/root/.cache/pip \
    pip wheel --no-deps --wheel-dir /wheels . \
 && pip wheel --wheel-dir /wheels \
      "fastapi>=0.110" "uvicorn[standard]>=0.27" "pydantic>=2.6" \
      "pyyaml>=6.0" "httpx>=0.27" "prometheus-client>=0.20" "regex>=2023.12"

# --- runtime ----------------------------------------------------------------
FROM python:3.12-slim AS runtime

# Non-root. A gateway that terminates auth and holds the provider credential
# has no business running as root.
RUN groupadd --gid 10001 promptwall \
 && useradd --uid 10001 --gid promptwall --create-home --shell /usr/sbin/nologin promptwall

WORKDIR /app

RUN --mount=type=bind,from=builder,source=/wheels,target=/wheels \
    pip install --no-cache-dir --no-index --find-links=/wheels promptwall \
 && rm -rf /root/.cache

# Policy is copied separately so it can be overridden by a mount without
# rebuilding, which is how you ship a rule change without a release.
COPY --chown=promptwall:promptwall promptwall/policy/rules /app/policy/rules

USER promptwall

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PW_HOST=0.0.0.0 \
    PW_PORT=8080 \
    PW_POLICY_DIR=/app/policy/rules \
    PW_LOG_FORMAT=json \
    PW_MODE=monitor

EXPOSE 8080

# Liveness only. /readyz depends on layer state and is the orchestrator's job
# to poll, not the container runtime's -- a degraded gateway should be pulled
# from rotation, not restarted in a loop.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4).status == 200 else 1)"

ENTRYPOINT ["python", "-m", "uvicorn", "promptwall.main:app"]
CMD ["--host", "0.0.0.0", "--port", "8080", "--log-config", "/dev/null", "--no-access-log"]
