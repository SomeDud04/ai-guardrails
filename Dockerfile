# Nasi Lemak gateway image (multi-stage).
#
# Stage graph:
#   base         the tested ``server`` extra against a stub package, fixed
#                non-root identity 10001:10001
#   guards-deps  adds only the existing pinned ``guards`` extra (needs root pip)
#   guards       opt-in guard-enabled runtime image with the real package;
#                selected explicitly with ``docker build --target guards`` or
#                the pilot Compose overlay
#   server       default final stage: server extra and the real package, no ML
#                dependencies
#
# The real ``nasi_lemak`` source is copied only into the two final stages.  A
# code change therefore keeps every dependency layer, and only a change to
# ``pyproject.toml`` downloads the wheels again.
#
# A plain ``docker build .`` or the default ``compose.yaml`` builds only the
# final ``server`` stage.  The optional ML wheels are therefore not downloaded
# for the lightweight image, and no model weights are ever copied into any
# stage.  Model artifacts are operator-supplied read-only runtime mounts.
#
# Build context is the repository root, but only the project metadata and the
# ``nasi_lemak`` package are copied.  Dependencies come from the exact pins in
# ``pyproject.toml``; no requirements lock file is generated here.
#
# Image tag notes: ``3.12-slim-bookworm`` matches the tested Python 3.12 series
# (the workspace virtualenv is 3.12.14).  Tags are versioned rather than
# ``latest``, but they are mutable.  Immutable digest pinning and registry
# signature verification remain a release/security-review task.
FROM python:3.12-slim-bookworm AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DEFAULT_TIMEOUT=120 \
    HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1 \
    HF_DATASETS_OFFLINE=1

# Fixed non-root runtime identity (arbitrary but stable for volume/secret ACLs).
RUN groupadd --system --gid 10001 nasi \
    && useradd --system --uid 10001 --gid nasi --home-dir /app \
       --no-create-home --shell /usr/sbin/nologin nasi

WORKDIR /app

# Explicit, minimal copies.  Never copy the whole workspace (tests, docs,
# routing state, virtualenv, local secrets or database files).
COPY --chown=10001:10001 pyproject.toml ./

# Installed while the base build stage is still root; the runtime stages below
# drop back to UID/GID 10001.  The stub is only there so pip can resolve the
# extras from pyproject.toml; each final stage replaces it with the real source.
RUN mkdir nasi_lemak && touch nasi_lemak/__init__.py && \
    python -m pip install --no-cache-dir --no-compile ".[server]"

# Runtime stages inherit this non-root identity.  Do not run application
# processes as root.
USER 10001:10001

# Optional ML dependency stage.  The inherited USER is deliberately overridden
# only for the pip install; the final guard runtime stage drops to 10001 again.
# No model is downloaded: these are Python packages only, and the offline flags
# above keep Transformers/Hugging Face from resolving a Hub model.
#
# torch is installed FIRST from the official CPU-only wheel index.  The default
# PyPI Linux wheel for the pinned version is the ~2.5 GB CUDA build, which is
# useless on this CPU-only guard VM.  The extra is installed afterwards from
# the default index so its exact pins (transformers, jinja2) are unchanged.  The
# two installs are separate layers so a failed second download keeps torch.
FROM base AS guards-deps

USER root

RUN python -m pip install --no-cache-dir --no-compile \
        torch==2.14.1 --index-url https://download.pytorch.org/whl/cpu

RUN python -m pip install --no-cache-dir --no-compile ".[guards]"

FROM guards-deps AS guards

# ``build`` must go first: it holds the stub, whose later timestamp would stop
# setuptools copying the real ``__init__.py`` over it.
COPY --chown=10001:10001 nasi_lemak ./nasi_lemak
RUN rm -rf build ./*.egg-info && \
    python -m pip install --no-cache-dir --no-compile --no-deps --force-reinstall .

USER 10001:10001

EXPOSE 8000

# Exec form, no shell, no reload/debug worker.  Access logs are disabled; the
# application itself maps unexpected exceptions to generic 503 responses and
# never logs raw request bodies, credentials or DSNs.
ENTRYPOINT ["uvicorn", "nasi_lemak.server:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--no-access-log"]

# Default final stage.  Keeping ``server`` last means a plain build (and the
# default Compose file) never pulls the optional ML dependencies.
FROM base AS server

USER root

COPY --chown=10001:10001 nasi_lemak ./nasi_lemak
RUN rm -rf build ./*.egg-info && \
    python -m pip install --no-cache-dir --no-compile --no-deps --force-reinstall .

USER 10001:10001

EXPOSE 8000

ENTRYPOINT ["uvicorn", "nasi_lemak.server:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--no-access-log"]
