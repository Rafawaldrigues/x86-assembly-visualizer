# syntax=docker/dockerfile:1

FROM python:3.11-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

COPY pyproject.toml README.md asmx.py ./
COPY asmx/ ./asmx/

RUN python -m pip install --upgrade pip build \
    && python -m build --wheel --outdir /dist

FROM python:3.11-slim AS runtime

LABEL org.opencontainers.image.title="ASM X" \
      org.opencontainers.image.description="Desktop environment to study, validate and debug x86-64 assembly, without external dependency" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/Rafawaldrigues/x86-assembly-visualizer" \
      org.opencontainers.image.url="https://github.com/Rafawaldrigues/x86-assembly-visualizer" \
      org.opencontainers.image.documentation="https://github.com/Rafawaldrigues/x86-assembly-visualizer/blob/main/docs/GUIDE.md"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    LOG_LEVEL=INFO \
    ASMX_LOG_JSON=0

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3-tk \
        xvfb \
        xauth \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 1000 --shell /bin/bash analyst

WORKDIR /app

COPY --from=builder /dist/*.whl /tmp/wheels/
COPY requirements.txt requirements-dev.txt ./
RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir /tmp/wheels/*.whl \
    # Dev tooling (coverage, flake8, mypy, ...) so `test` and `quality` work
    # inside the container.  It is never needed to *run* ASM X.
    && python -m pip install --no-cache-dir -r requirements-dev.txt \
    && rm -rf /tmp/wheels

COPY --chown=analyst:analyst asmx/ ./asmx/
COPY --chown=analyst:analyst tests/ ./tests/
COPY --chown=analyst:analyst tools/ ./tools/
COPY --chown=analyst:analyst examples/ ./examples/
COPY --chown=analyst:analyst docs/ ./docs/
COPY --chown=analyst:analyst pyproject.toml README.md CITATION.cff asmx.py ./
COPY --chown=analyst:analyst docker/ ./docker/
RUN chmod +x /app/docker/entrypoint.sh \
    && mkdir -p /app/samples /app/results \
    # /app itself must be writable by the non-root user: coverage writes
    # .coverage there, and tools create caches next to the sources.
    && chown -R analyst:analyst /app

USER analyst

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -m asmx info --json > /dev/null || exit 1

ENTRYPOINT ["/app/docker/entrypoint.sh"]
CMD ["--help"]
