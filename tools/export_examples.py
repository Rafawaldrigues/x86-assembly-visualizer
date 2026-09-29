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

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, RAIZ)

from asmx.examples import EXAMPLES, render  # noqa: E402  (sys.path comes first)

#: Default output directory, relative to the project root.
DESTINO_PADRAO = os.path.join(RAIZ, "examples")


def export(destino: str = DESTINO_PADRAO) -> List[str]:
    """Writes every example as ``.asm``.

    Args:
        destino: Output directory (created when it does not exist).

    Returns:
        List of the written paths, in alphabetical order.
    """
    os.makedirs(destino, exist_ok=True)
    caminhos = []
    for nome in sorted(EXAMPLES):
        caminho = os.path.join(destino, "%s.asm" % nome)
        with open(caminho, "w", encoding="utf-8") as arquivo:
            arquivo.write(render(nome))
        caminhos.append(caminho)
    return caminhos


def check(destino: str = DESTINO_PADRAO) -> List[str]:
    """Compares the files on disk with the built-in examples.

    Args:
        destino: Directory where the files should be.

    Returns:
        List of problems found (empty when everything matches).
    """
    problemas = []
    for nome in sorted(EXAMPLES):
        caminho = os.path.join(destino, "%s.asm" % nome)
        if not os.path.exists(caminho):
            problemas.append("missing file %s" % caminho)
            continue
        with open(caminho, encoding="utf-8") as arquivo:
            atual = arquivo.read()
        if atual != render(nome):
            problemas.append("%s differs from asmx/examples.py" % caminho)
    extras = {f for f in os.listdir(destino) if f.endswith(".asm")} - {
        "%s.asm" % n for n in EXAMPLES
    }
    for extra in sorted(extras):
        problemas.append("file without a matching example: %s" % extra)
    return problemas


def main(argv: List[str]) -> int:
    """Entry point of the utility.

    Args:
        argv: Arguments without the program name.

    Returns:
        Exit code described at the top of the module.
    """
    conferir = "--check" in argv
    restantes = [a for a in argv if not a.startswith("-")]
    destino = restantes[0] if restantes else DESTINO_PADRAO

    if conferir:
        problemas = check(destino)
        for problema in problemas:
            print(problema)
        if problemas:
            return 1
        print("the %d examples in %s match the package" % (len(EXAMPLES), destino))
        return 0

    caminhos = export(destino)
    print("%d examples written to %s" % (len(caminhos), destino))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
