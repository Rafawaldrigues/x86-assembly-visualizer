# syntax=docker/dockerfile:1
#
# ===========================================================================
# ASM X — container image
# ===========================================================================
#
# The image is built in two stages: a throwaway builder produces the wheel
# from source, and the runtime stage installs only that wheel plus the system
# packages ASM X needs (tkinter for the GUI, xvfb for headless GUI tests).
#
# ---------------------------------- GUI mode -------------------------------
# Tkinter needs an X server.  On a Linux host, share the X11 socket and the
# DISPLAY variable with the container:
#
#     xhost +local:docker                       # allow local containers
#     docker run --rm -it \
#         -v /tmp/.X11-unix:/tmp/.X11-unix \
#         -e DISPLAY=$DISPLAY \
#         asmx gui
#
# The same two flags are what docker-compose needs for GUI mode:
#
#     volumes:
#       - /tmp/.X11-unix:/tmp/.X11-unix
#     environment:
#       DISPLAY: "${DISPLAY}"
#
# Without an X display the `gui` command exits 1 with a hint; use `check`,
# `run`, `explain`, `info`, `examples`, `test` or `quality` for headless work.
# On macOS/Windows the X11 socket does not exist — run the GUI natively with
# `python3 asmx.py` instead.
# ---------------------------------------------------------------------------
#
# Typical headless usage:
#     docker run --rm -v "$PWD/samples:/app/samples:ro" asmx check /app/samples/hello.asm
#     docker run --rm asmx test          # full unittest suite under xvfb
#     docker run --rm asmx quality       # coverage + flake8 + mypy
#     docker run --rm asmx shell         # interactive shell
#
# ===========================================================================

# ---------------------------------------------------------------------------
# Stage 1 — build the distribution from source
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

# Only what the build backend needs: ASM X has no runtime dependencies, so
# there is no requirements.txt to install here.  `asmx.py` is copied too so
# the build sees exactly the same flat layout as the repository (it shadows
# nothing at build time, but keeps `python -m build` honest).
COPY pyproject.toml README.md asmx.py ./
COPY asmx/ ./asmx/

RUN python -m pip install --upgrade pip build \
    && python -m build --wheel --outdir /dist

# ---------------------------------------------------------------------------
# Stage 2 — runtime image
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS runtime

LABEL org.opencontainers.image.title="ASM X" \
      org.opencontainers.image.description="Desktop environment to study, validate and debug x86-64 assembly" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/rafawaldrigues/asmx"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    LOG_LEVEL=INFO \
    ASMX_LOG_JSON=0

# python3-tk -> Tkinter bindings used by the GUI
# xvfb       -> virtual X server so the GUI test suite can run headless
# xauth      -> required by xvfb-run (without it it aborts with
#               "xvfb-run: error: xauth command not found")
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3-tk \
        xvfb \
        xauth \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime user (uid 1000 keeps bind mounts writable on Linux hosts).
RUN useradd --create-home --uid 1000 --shell /bin/bash analyst

WORKDIR /app

# The wheel built above is the single source of truth for the installed package.
COPY --from=builder /dist/*.whl /tmp/wheels/
COPY requirements.txt requirements-dev.txt ./
RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir /tmp/wheels/*.whl \
    # Dev tooling (coverage, flake8, mypy, ...) so `test` and `quality` work
    # inside the container.  It is never needed to *run* ASM X.
    && python -m pip install --no-cache-dir -r requirements-dev.txt \
    && rm -rf /tmp/wheels

# Source, tests, tools and examples are copied as well: `quality` lints
# /app/asmx and runs the quality gates, coverage measures the package, and
# `check examples/linux-hello.asm` needs the sample programs.  The installed
# wheel still provides the `asmx` / `asmx-gui` console scripts.
COPY --chown=analyst:analyst asmx/ ./asmx/
COPY --chown=analyst:analyst tests/ ./tests/
COPY --chown=analyst:analyst tools/ ./tools/
COPY --chown=analyst:analyst examples/ ./examples/
COPY --chown=analyst:analyst pyproject.toml README.md asmx.py ./
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
