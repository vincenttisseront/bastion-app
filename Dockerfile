# Multi-stage bastion-app (FastAPI) — Docker Hardened Images (DHI)
# Migrations: service one-shot bastion-app-migrate (target: migrate; never in runtime CMD).
#
# Runtime image has no shell / apt (DHI minimal). Builder + migrate use *-dev.
# Override bases: docker build --build-arg PYTHON_RUNTIME=dhi.io/python:3.12-debian13@sha256:…

ARG PYTHON_RUNTIME=dhi.io/python:3.12-debian13
ARG PYTHON_BUILDER=dhi.io/python:3.12-debian13-dev

# ---------------------------------------------------------------------------
# Builder — install app into a venv (wheels; gcc available on -dev if needed)
# ---------------------------------------------------------------------------
FROM ${PYTHON_BUILDER} AS builder

ENV LANG=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

WORKDIR /src
COPY pyproject.toml README.md ./
COPY app ./app
RUN python -m venv /opt/venv \
    && pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir .

# ---------------------------------------------------------------------------
# Runtime — minimal DHI (no shell). UID 65532 = DHI nonroot.
# ---------------------------------------------------------------------------
FROM ${PYTHON_RUNTIME} AS runtime

ENV LANG=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    BASTION_MANIFEST_ROOT=/app \
    TZ=UTC

WORKDIR /app

COPY --from=builder --chown=65532:65532 /opt/venv /opt/venv
COPY --chown=65532:65532 alembic.ini /app/alembic.ini
COPY --chown=65532:65532 migrations /app/migrations
COPY --chown=65532:65532 scripts /app/scripts
# Manifests for Admin → Dépendances inventory (not shipped via site-packages).
COPY --chown=65532:65532 pyproject.toml package.json package-lock.json /app/

USER 65532
EXPOSE 8000

# No curl/shell in DHI runtime — probe with stdlib only (exec form).
HEALTHCHECK --interval=30s --timeout=5s --start-period=25s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4)"]

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

# ---------------------------------------------------------------------------
# Migrate — one-shot job needs shell + root for chown of data volumes
# ---------------------------------------------------------------------------
FROM ${PYTHON_BUILDER} AS migrate

ENV LANG=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    BASTION_MANIFEST_ROOT=/app \
    TZ=UTC

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
COPY alembic.ini /app/alembic.ini
COPY migrations /app/migrations
COPY scripts /app/scripts
COPY pyproject.toml package.json package-lock.json /app/

USER root
# Default command overridden by compose (encrypt DB, alembic, chown).
CMD ["alembic", "upgrade", "head"]
