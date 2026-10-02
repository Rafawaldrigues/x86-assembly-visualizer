#!/usr/bin/env bash

set -euo pipefail

PYTHON="${PYTHON:-python}"

usage() {
    cat <<'EOF'
ASM X container

usage: docker run --rm [-it] asmx <command> [arguments...]

commands:
  check FILE.asm [--json] [--min-severity error|warning|info]
                        run the static validator on a source file
  run FILE.asm [...]    emulate the program step by step
  explain FILE.asm --line N | --mnemonic mov
                        explain one line or one instruction
  info [--json]         environment and build information
  version               print the ASM X version
  examples [--list|--show NAME]
                        list or print the bundled examples
  gui                   open the Tkinter GUI (needs $DISPLAY + X11 socket)
  test                  run the unittest suite under xvfb-run
  quality               coverage (fail under 94%) + flake8 + mypy
  shell                 open an interactive bash shell
  help                  show this message

Anything else is forwarded to `python -m asmx` (so `--help` prints the CLI
help, and `--version` works as well).

GUI mode (Linux hosts only):
  xhost +local:docker
  docker run --rm -it \
      -v /tmp/.X11-unix:/tmp/.X11-unix \
      -e DISPLAY=$DISPLAY \
      asmx gui
EOF
}

with_display() {
    if command -v xvfb-run >/dev/null 2>&1; then
        xvfb-run -a "$@"
    else
        echo "entrypoint: xvfb-run not found — GUI tests will be skipped" >&2
        "$@"
    fi
}

main() {
    local command="${1:-help}"

    case "${command}" in
        check|run|explain|info|version|examples)
            exec "${PYTHON}" -m asmx "$@"
            ;;

        test)
            echo "== ASM X test suite =="
            # not exec'd: with_display may fall back to a plain interpreter
            with_display "${PYTHON}" -m unittest discover -s tests -v
            ;;

        quality)
            echo "== ASM X quality gate: coverage + flake8 + mypy =="
            with_display "${PYTHON}" -m coverage run --source=asmx \
                -m unittest discover -s tests
            "${PYTHON}" -m coverage report --fail-under=94 --show-missing
            "${PYTHON}" -m flake8 asmx/ tests/ tools/ asmx.py \
                --max-line-length=100 --extend-ignore=E203,W503
            "${PYTHON}" -m mypy asmx/
            "${PYTHON}" tools/quality_gates.py
            "${PYTHON}" tools/export_examples.py --check
            "${PYTHON}" tools/build_reference.py --check
            echo "== quality gate passed =="
            ;;

        gui)
            if [ -z "${DISPLAY:-}" ]; then
                cat >&2 <<'EOF'
entrypoint: no X display available ($DISPLAY is empty).

The GUI needs an X server.  On a Linux host, share the X11 socket:

    xhost +local:docker
    docker run --rm -it \
        -v /tmp/.X11-unix:/tmp/.X11-unix \
        -e DISPLAY=$DISPLAY \
        asmx gui

Headless alternatives: check, run, explain, info, examples, test, quality.
On macOS/Windows run the GUI natively with `python3 asmx.py`.
EOF
                exit 1
            fi
            exec "${PYTHON}" -m asmx
            ;;

        shell)
            exec /bin/bash
            ;;

        help)
            usage
            ;;

        *)
            exec "${PYTHON}" -m asmx "$@"
            ;;
    esac
}

main "$@"
