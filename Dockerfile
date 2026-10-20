# Nasi Lemak gateway image.
#
# Build context is this repository root, but only the project metadata and the
# ``nasi_lemak`` package are copied.  Runtime dependencies are installed from
# the exact pins in ``pyproject.toml`` (the ``server`` extra); no requirements
# lock file is generated here.
#
# Image tag notes: ``3.12-slim-bookworm`` matches the tested Python 3.12 series
# (the workspace virtualenv is 3.12.14).  Tags are versioned rather than
# ``latest``, but they are mutable.  Immutable digest pinning and registry
# signature verification remain a release/security-review task.
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# Fixed non-root runtime identity (arbitrary but stable for volume/secret ACLs).
RUN groupadd --system --gid 10001 nasi \
    && useradd --system --uid 10001 --gid nasi --home-dir /app \
       --no-create-home --shell /usr/sbin/nologin nasi

WORKDIR /app

# Explicit, minimal copies.  Never copy the whole workspace (tests, docs,
# routing state, virtualenv, local secrets or database files).
COPY --chown=10001:10001 pyproject.toml ./
COPY --chown=10001:10001 nasi_lemak ./nasi_lemak

RUN python -m pip install --no-cache-dir --no-compile ".[server]"

USER 10001:10001

EXPOSE 8000

# Exec form, no shell, no reload/debug worker.  Access logs are disabled; the
# application itself maps unexpected exceptions to generic 503 responses and
# never logs raw request bodies, credentials or DSNs.
ENTRYPOINT ["uvicorn", "nasi_lemak.server:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--no-access-log"]
