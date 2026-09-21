"""Leitura de arquivos de código: texto, tamanho, codificação e impressão digital.

Toda entrada de código passa por aqui — a linha de comando, a importação de
``.asm`` do projeto e os testes. Assim existe um único lugar que decide o que
fazer quando o arquivo não existe, quando é um diretório, quando a extensão não
é de assembly e quando os bytes não são UTF-8 (comentário em latin-1 acontece).

Example:
    >>> from asmx.source import read_source         # doctest: +SKIP
    >>> fonte = read_source("examples/hello.asm")   # doctest: +SKIP
    >>> print(fonte.name, fonte.lines, fonte.sha256[:8])  # doctest: +SKIP
"""

from __future__ import annotations

import codecs
import hashlib
import os
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Optional, Tuple

from .errors import ParseError, SourceNotFoundError, SourceReadError, UnsupportedSourceError

__all__ = [
    "SOURCE_SUFFIXES",
    "PROJECT_SUFFIXES",
    "SourceFile",
    "read_source",
    "decode_text",
    "sha256_of",
    "fingerprint",
]

#: Extensões aceitas como código de assembly.
SOURCE_SUFFIXES: Tuple[str, ...] = (
    ".asm",
    ".s",
    ".S",
    ".nasm",
    ".inc",
    ".asm64",
    ".txt",
    ".src",
)

#: Extensões aceitas como projeto do ASM X.
PROJECT_SUFFIXES: Tuple[str, ...] = (".asmproj", ".json")

#: Ordem de tentativa de decodificação: UTF-8 e, como rede, latin-1 (que aceita
#: qualquer byte). O BOM do UTF-8 é tratado antes, em :func:`decode_text`.
ENCODINGS: Tuple[str, ...] = ("utf-8", "latin-1")


def decode_text(data: bytes, encodings: Iterable[str] = ENCODINGS) -> Tuple[str, str]:
    """Decodifica bytes de código tolerando arquivos fora do UTF-8.

    Um BOM de UTF-8 no começo é removido (senão o ``\\ufeff`` ficaria colado no
    primeiro mnemônico e o parser não reconheceria a instrução). Não havendo
    BOM, tenta as codificações na ordem até uma funcionar.

    Args:
        data: Conteúdo bruto do arquivo.
        encodings: Codificações tentadas na ordem (padrão UTF-8 e latin-1).

    Returns:
        Tupla ``(texto, codificação)``. A última codificação da lista sempre
        funciona, então a função não levanta exceção.

    Example:
        >>> decode_text(b"mov rax, 1")
        ('mov rax, 1', 'utf-8')
        >>> decode_text("; ação".encode("latin-1"))[1]
        'latin-1'
        >>> decode_text(b"\\xef\\xbb\\xbfnop")
        ('nop', 'utf-8-sig')
    """
    com_bom = data.startswith(codecs.BOM_UTF8)
    if com_bom:
        data = data[len(codecs.BOM_UTF8) :]
    ultimo = "utf-8"
    for encoding in encodings:
        ultimo = encoding
        try:
            texto = data.decode(encoding)
        except UnicodeDecodeError:
            continue
        return texto, ("utf-8-sig" if com_bom else encoding)
    return data.decode(ultimo, errors="replace"), ultimo


def sha256_of(data: bytes) -> str:
    """Calcula o SHA-256 de um conteúdo.

    Args:
        data: Bytes a resumir.

    Returns:
        Hexadecimal de 64 caracteres.

    Example:
        >>> sha256_of(b"")[:8]
        'e3b0c442'
    """
    return hashlib.sha256(data).hexdigest()


def fingerprint(text: str, size: int = 12) -> str:
    """Cria um identificador curto e estável para um código.

    Serve para nomear relatórios e comparar duas análises sem depender do
    caminho do arquivo. Espaços no fim da linha e quebras de linha sobrando no
    começo e no fim não mudam o resultado — só o código interessa.

    Args:
        text: Código fonte.
        size: Quantidade de caracteres do identificador (padrão 12).

    Returns:
        Prefixo hexadecimal do SHA-256 do texto normalizado.

    Example:
        >>> fingerprint("mov rax, 1", 6)
        '851a74'
    """
    linhas = [linha.rstrip() for linha in text.replace("\r\n", "\n").split("\n")]
    normalizado = "\n".join(linhas).strip("\n")
    return sha256_of(normalizado.encode("utf-8"))[:size]


@dataclass(frozen=True)
class SourceFile:
    """Um arquivo de código já lido e resumido.

    Attributes:
        path: Caminho absoluto do arquivo.
        text: Conteúdo decodificado.
        size: Tamanho em bytes no disco.
        lines: Quantidade de linhas de ``text``.
        sha256: Hash do conteúdo bruto.
        encoding: Codificação que decodificou o arquivo sem erro.
        fingerprint: Identificador curto derivado do texto.
    """

    path: str
    text: str
    size: int
    lines: int
    sha256: str
    encoding: str
    fingerprint: str

    @property
    def name(self) -> str:
        """Nome do arquivo sem diretório.

        Returns:
            O basename do caminho.
        """
        return os.path.basename(self.path)

    @property
    def suffix(self) -> str:
        """Extensão em minúsculas, incluindo o ponto.

        Returns:
            Como ``".asm"``; string vazia quando não há extensão.
        """
        return os.path.splitext(self.path)[1].lower()

    def to_dict(self) -> Dict[str, Any]:
        """Resume o arquivo para relatórios JSON.

        Returns:
            Dicionário com nome, caminho, tamanho, linhas, hashes e codificação.
        """
        return {
            "name": self.name,
            "path": self.path,
            "size": self.size,
            "lines": self.lines,
            "encoding": self.encoding,
            "sha256": self.sha256,
            "fingerprint": self.fingerprint,
        }


def read_source(
    path: str,
    *,
    suffixes: Optional[Iterable[str]] = None,
    max_bytes: Optional[int] = None,
) -> SourceFile:
    """Lê um arquivo de código e devolve o texto com seus metadados.

    Args:
        path: Caminho do arquivo (``~`` é expandido).
        suffixes: Extensões aceitas; ``None`` aceita qualquer arquivo. Arquivos
            sem extensão também passam, o que cobre nomes temporários.
        max_bytes: Tamanho máximo aceito, em bytes (padrão: sem limite).

    Returns:
        O :class:`SourceFile` preenchido.

    Raises:
        SourceNotFoundError: Se o caminho não existe.
        SourceReadError: Se é um diretório ou a leitura falhou.
        UnsupportedSourceError: Se a extensão está fora de ``suffixes``.
        ParseError: Se o conteúdo tem bytes nulos, sinal de arquivo binário.

    Example:
        >>> fonte = read_source("exemplo.asm")     # doctest: +SKIP
        >>> fonte.lines > 0                        # doctest: +SKIP
        True
    """
    caminho = os.path.abspath(os.path.expanduser(str(path)))
    if not os.path.exists(caminho):
        raise SourceNotFoundError(caminho)
    if os.path.isdir(caminho):
        raise SourceReadError(caminho, "é um diretório, não um arquivo")

    if suffixes is not None:
        aceitas = tuple(suffixes)
        extensao = os.path.splitext(caminho)[1]
        if extensao and extensao.lower() not in tuple(s.lower() for s in aceitas):
            raise UnsupportedSourceError(caminho, ", ".join(aceitas))

    try:
        with open(caminho, "rb") as arquivo:
            dados = arquivo.read(max_bytes + 1 if max_bytes else -1)
    except OSError as erro:
        raise SourceReadError(caminho, str(erro)) from erro

    if max_bytes is not None and len(dados) > max_bytes:
        raise SourceReadError(caminho, "maior que o limite de %d bytes" % max_bytes)

    if b"\x00" in dados:
        raise ParseError(
            "%s tem bytes nulos: isso é um arquivo binário, não um fonte de "
            "assembly. O ASM X analisa texto (NASM/Intel, MASM ou GAS/AT&T) e "
            "não faz engenharia reversa de binário." % caminho
        )

    texto, encoding = decode_text(dados)
    return SourceFile(
        path=caminho,
        text=texto,
        size=len(dados),
        lines=texto.count("\n") + (0 if texto.endswith("\n") or not texto else 1),
        sha256=sha256_of(dados),
        encoding=encoding,
        fingerprint=fingerprint(texto),
    )
