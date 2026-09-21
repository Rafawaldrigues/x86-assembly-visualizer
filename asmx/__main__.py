"""Ponto de entrada do pacote.

``python3 -m asmx`` abre a interface gráfica; qualquer argumento é entregue à
linha de comando (``python3 -m asmx check prog.asm``). A importação da
interface é preguiçosa de propósito: assim a linha de comando continua
funcionando em máquinas sem Tkinter, como um contêiner mínimo.
"""

from __future__ import annotations

import sys


def main() -> int:
    """Despacha entre a interface gráfica e a linha de comando.

    Returns:
        Código de saída do processo: o da linha de comando quando houver
        argumentos, ou ``0`` quando a janela fecha normalmente.
    """
    from .cli import launch_gui, main as cli_main

    if len(sys.argv) > 1:
        return cli_main()
    return launch_gui()


if __name__ == "__main__":
    raise SystemExit(main())
