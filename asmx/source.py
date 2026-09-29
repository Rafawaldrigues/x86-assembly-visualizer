"""Reading of source files: text, size, encoding and fingerprint.

Every code entry point goes through here — the command line, the ``.asm``
import of the project and the tests. That way there is a single place that
decides what to do when the file does not exist, when it is a directory, when
the extension is not assembly and when the bytes are not UTF-8 (a latin-1
comment happens).

Example:
    >>> from asmx.source import read_source         # doctest: +SKIP
    >>> source = read_source("examples/hello.asm")  # doctest: +SKIP
    >>> print(source.name, source.lines, source.sha256[:8])  # doctest: +SKIP
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

#: Extensions accepted as assembly source.
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

#: Extensions accepted as an ASM X project.
PROJECT_SUFFIXES: Tuple[str, ...] = (".asmproj", ".json")

#: Decoding attempt order: UTF-8 and, as a safety net, latin-1 (which accepts
#: any byte). The UTF-8 BOM is handled before that, in :func:`decode_text`.
ENCODINGS: Tuple[str, ...] = ("utf-8", "latin-1")


def decode_text(data: bytes, encodings: Iterable[str] = ENCODINGS) -> Tuple[str, str]:
    """Decodes source bytes, tolerating files that are not UTF-8.

    A UTF-8 BOM at the start is removed (otherwise the ``\\ufeff`` would stick
    to the first mnemonic and the parser would not recognize the instruction).
    With no BOM, it tries the encodings in order until one works.

    Args:
        data: Raw content of the file.
        encodings: Encodings tried in order (default UTF-8 and latin-1).

    Returns:
        Tuple ``(text, encoding)``. The last encoding of the list always works,
        so the function never raises.

    Example:
        >>> decode_text(b"mov rax, 1")
        ('mov rax, 1', 'utf-8')
        >>> decode_text("; temp: 20\\xb0C".encode("latin-1"))[1]
        'latin-1'
        >>> decode_text(b"\\xef\\xbb\\xbfnop")
        ('nop', 'utf-8-sig')
    """
    with_bom = data.startswith(codecs.BOM_UTF8)
    if with_bom:
        data = data[len(codecs.BOM_UTF8) :]
    last = "utf-8"
    for encoding in encodings:
        last = encoding
        try:
            text = data.decode(encoding)
        except UnicodeDecodeError:
            continue
        return text, ("utf-8-sig" if with_bom else encoding)
    return data.decode(last, errors="replace"), last


def sha256_of(data: bytes) -> str:
    """Computes the SHA-256 of a content.

    Args:
        data: Bytes to digest.

    Returns:
        Hexadecimal string of 64 characters.

    Example:
        >>> sha256_of(b"")[:8]
        'e3b0c442'
    """
    return hashlib.sha256(data).hexdigest()


def fingerprint(text: str, size: int = 12) -> str:
    """Creates a short, stable identifier for a piece of code.

    It is used to name reports and to compare two analyses without depending on
    the file path. Trailing spaces at the end of a line and leftover line
    breaks at the start and at the end do not change the result — only the code
    matters.

    Args:
        text: Assembly source.
        size: Number of characters of the identifier (default 12).

    Returns:
        Hexadecimal prefix of the SHA-256 of the normalized text.

    Example:
        >>> fingerprint("mov rax, 1", 6)
        '851a74'
    """
    lines = [line.rstrip() for line in text.replace("\r\n", "\n").split("\n")]
    normalized = "\n".join(lines).strip("\n")
    return sha256_of(normalized.encode("utf-8"))[:size]


@dataclass(frozen=True)
class SourceFile:
    """A source file already read and summarized.

    Attributes:
        path: Absolute path of the file.
        text: Decoded content.
        size: Size in bytes on disk.
        lines: Number of lines of ``text``.
        sha256: Hash of the raw content.
        encoding: Encoding that decoded the file without error.
        fingerprint: Short identifier derived from the text.
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
        """File name without the directory.

        Returns:
            The basename of the path.
        """
        return os.path.basename(self.path)

    @property
    def suffix(self) -> str:
        """Extension in lowercase, including the dot.

        Returns:
            Such as ``".asm"``; empty string when there is no extension.
        """
        return os.path.splitext(self.path)[1].lower()

    def to_dict(self) -> Dict[str, Any]:
        """Summarizes the file for JSON reports.

        Returns:
            Dictionary with name, path, size, lines, hashes and encoding.
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
    """Reads a source file and returns the text with its metadata.

    Args:
        path: Path of the file (``~`` is expanded).
        suffixes: Accepted extensions; ``None`` accepts any file. Files without
            an extension also pass, which covers temporary names.
        max_bytes: Maximum accepted size, in bytes (default: no limit).

    Returns:
        The filled :class:`SourceFile`.

    Raises:
        SourceNotFoundError: When the path does not exist.
        SourceReadError: When it is a directory or the read failed.
        UnsupportedSourceError: When the extension is outside ``suffixes``.
        ParseError: When the content has null bytes, a sign of a binary file.

    Example:
        >>> source = read_source("example.asm")    # doctest: +SKIP
        >>> source.lines > 0                       # doctest: +SKIP
        True
    """
    full_path = os.path.abspath(os.path.expanduser(str(path)))
    if not os.path.exists(full_path):
        raise SourceNotFoundError(full_path)
    if os.path.isdir(full_path):
        raise SourceReadError(full_path, "is a directory, not a file")

    if suffixes is not None:
        accepted = tuple(suffixes)
        extension = os.path.splitext(full_path)[1]
        if extension and extension.lower() not in tuple(s.lower() for s in accepted):
            raise UnsupportedSourceError(full_path, ", ".join(accepted))

    try:
        with open(full_path, "rb") as file:
            data = file.read(max_bytes + 1 if max_bytes else -1)
    except OSError as error:
        raise SourceReadError(full_path, str(error)) from error

    if max_bytes is not None and len(data) > max_bytes:
        raise SourceReadError(full_path, "bigger than the limit of %d bytes" % max_bytes)

    if b"\x00" in data:
        raise ParseError(
            "%s has null bytes: this is a binary file, not assembly source. "
            "ASM X reads text (NASM/Intel, MASM or GAS/AT&T) and does not "
            "reverse-engineer binaries." % full_path
        )

    text, encoding = decode_text(data)
    return SourceFile(
        path=full_path,
        text=text,
        size=len(data),
        lines=text.count("\n") + (0 if text.endswith("\n") or not text else 1),
        sha256=sha256_of(data),
        encoding=encoding,
        fingerprint=fingerprint(text),
    )
