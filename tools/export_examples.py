#!/usr/bin/env python3
"""Grava os exemplos embutidos como arquivos ``.asm`` de verdade.

O acervo de exemplos vive em :mod:`asmx.examples` para a interface e a linha de
comando abrirem sem tocar no disco. Este utilitário materializa os mesmos
textos em ``examples/*.asm``, para quem quiser montar com ``nasm``/``ld`` de
verdade ou abrir no editor sem passar pelo ASM X.

O conteúdo gravado é byte a byte o mesmo de :data:`asmx.examples.EXAMPLES`
(mais a quebra de linha final), então existe um teste que compara os dois e
acusa quando alguém edita um lado só.

Usage:
    python3 tools/export_examples.py [DIRETÓRIO]
    python3 tools/export_examples.py --check      # só confere, não grava

Exit codes:
    0  exemplos gravados (ou conferidos) com sucesso
    1  divergência encontrada no modo ``--check``
"""

from __future__ import annotations

import os
import sys
from typing import List

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, RAIZ)

from asmx.examples import EXAMPLES, render  # noqa: E402  (o sys.path vem antes)

#: Diretório padrão de saída, relativo à raiz do projeto.
DESTINO_PADRAO = os.path.join(RAIZ, "examples")


def export(destino: str = DESTINO_PADRAO) -> List[str]:
    """Grava todos os exemplos como ``.asm``.

    Args:
        destino: Diretório de saída (criado se não existir).

    Returns:
        Lista dos caminhos gravados, em ordem alfabética.
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
    """Compara os arquivos em disco com os exemplos embutidos.

    Args:
        destino: Diretório onde os arquivos deveriam estar.

    Returns:
        Lista de problemas encontrados (vazia quando está tudo igual).
    """
    problemas = []
    for nome in sorted(EXAMPLES):
        caminho = os.path.join(destino, "%s.asm" % nome)
        if not os.path.exists(caminho):
            problemas.append("falta o arquivo %s" % caminho)
            continue
        with open(caminho, encoding="utf-8") as arquivo:
            atual = arquivo.read()
        if atual != render(nome):
            problemas.append("%s está diferente de asmx/examples.py" % caminho)
    extras = {f for f in os.listdir(destino) if f.endswith(".asm")} - {
        "%s.asm" % n for n in EXAMPLES
    }
    for extra in sorted(extras):
        problemas.append("arquivo sem exemplo correspondente: %s" % extra)
    return problemas


def main(argv: List[str]) -> int:
    """Ponto de entrada do utilitário.

    Args:
        argv: Argumentos sem o nome do programa.

    Returns:
        Código de saída descrito no topo do módulo.
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
        print("os %d exemplos em %s estão iguais aos do pacote" % (len(EXAMPLES), destino))
        return 0

    caminhos = export(destino)
    print("gravados %d exemplos em %s" % (len(caminhos), destino))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
