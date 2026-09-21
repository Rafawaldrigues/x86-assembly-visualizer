#!/usr/bin/env python3
"""Atalho para o ASM X a partir do código-fonte.

``python3 asmx.py`` abre a interface gráfica; ``python3 asmx.py check prog.asm``
usa a linha de comando — os dois caminhos entram pelo mesmo pacote ``asmx``.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from asmx.cli import main  # noqa: E402  (o sys.path precisa vir antes)

if __name__ == "__main__":
    raise SystemExit(main())
