#!/usr/bin/env python3
"""Writes the built-in examples as real ``.asm`` files.

The example collection lives in :mod:`asmx.examples` so the interface and the
command line can open it without touching the disk. This utility materializes the same
texts in ``examples/*.asm``, for whoever wants to assemble with real
``nasm``/``ld`` or open them in an editor without going through ASM X.

The content written is byte for byte the same as :data:`asmx.examples.EXAMPLES`
(plus the final newline), so there is a test that compares both and complains
when someone edits only one side.

Usage:
    python3 tools/export_examples.py [DIRECTORY]
    python3 tools/export_examples.py --check      # check only, does not write

Exit codes:
    0  examples written (or checked) successfully
    1  divergence found in ``--check`` mode
"""

from __future__ import annotations

import os
import sys
from typing import List

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from asmx.examples import EXAMPLES, render  # noqa: E402  (sys.path comes first)

#: Default output directory, relative to the project root.
DEFAULT_OUTPUT = os.path.join(ROOT, "examples")


def export(destination: str = DEFAULT_OUTPUT) -> List[str]:
    """Writes every example as ``.asm``.

    Args:
        destination: Output directory (created when it does not exist).

    Returns:
        List of the written paths, in alphabetical order.
    """
    os.makedirs(destination, exist_ok=True)
    paths = []
    for item_name in sorted(EXAMPLES):
        file_path = os.path.join(destination, "%s.asm" % item_name)
        with open(file_path, "w", encoding="utf-8") as source_file:
            source_file.write(render(item_name))
        paths.append(file_path)
    return paths


def check(destination: str = DEFAULT_OUTPUT) -> List[str]:
    """Compares the files on disk with the built-in examples.

    Args:
        destination: Directory where the files should be.

    Returns:
        List of problems found (empty when everything matches).
    """
    problems = []
    for item_name in sorted(EXAMPLES):
        file_path = os.path.join(destination, "%s.asm" % item_name)
        if not os.path.exists(file_path):
            problems.append("missing file %s" % file_path)
            continue
        with open(file_path, encoding="utf-8") as source_file:
            current_value = source_file.read()
        if current_value != render(item_name):
            problems.append("%s differs from asmx/examples.py" % file_path)
    extras = {f for f in os.listdir(destination) if f.endswith(".asm")} - {
        "%s.asm" % n for n in EXAMPLES
    }
    for extra in sorted(extras):
        problems.append("file without a matching example: %s" % extra)
    return problems


def main(argv: List[str]) -> int:
    """Entry point of the utility.

    Args:
        argv: Arguments without the program name.

    Returns:
        Exit code described at the top of the module.
    """
    check_only = "--check" in argv
    remaining = [a for a in argv if not a.startswith("-")]
    destination = remaining[0] if remaining else DEFAULT_OUTPUT

    if check_only:
        problems = check(destination)
        for problem_item in problems:
            print(problem_item)
        if problems:
            return 1
        print("the %d examples in %s match the package" % (len(EXAMPLES), destination))
        return 0

    paths = export(destination)
    print("%d examples written to %s" % (len(paths), destination))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
