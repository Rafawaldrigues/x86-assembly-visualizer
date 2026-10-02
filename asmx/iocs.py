"""Indicators of compromise and interesting strings hidden in the source.

The behavior analysis says what the program *does*; this module answers another
question: what is *written* inside it. URLs, IP addresses, domains, paths,
registry keys, commands and keywords are looked for in the data literals
(``db``, ``dq``...) and in the comments of the source — and also in memory,
after the program runs, with :func:`from_memory`.

The starting point is :func:`strings_of`, which returns the strings of each
line; :func:`extract` classifies each one and returns the list of :class:`Ioc`,
already without repetitions. Nothing here raises an exception: an empty, binary
or absurd source returns an empty list.

Example:
    >>> from asmx.iocs import extract, summary
    >>> iocs = extract('msg db "http://example.com/x", 0')
    >>> [(i.kind, i.value) for i in iocs]
    [('url', 'http://example.com/x')]
    >>> summary(iocs)
    '1 indicator(s): 1 URL'
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import partial
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

from .parser import strip_comment

__all__ = [
    "IOC_KINDS",
    "Ioc",
    "strings_of",
    "extract",
    "group",
    "to_dicts",
    "summary",
    "from_memory",
]

#: Label of each indicator kind, as shown in the report.
IOC_KINDS: Dict[str, str] = {
    "url": "URL",
    "ipv4": "IPv4 address",
    "domain": "Domain",
    "email": "Email address",
    "path_unix": "Unix path",
    "path_windows": "Windows path",
    "registry": "Registry key",
    "command": "Command",
    "extension": "Sensitive extension",
    "keyword": "Keyword",
    "string": "String",
}

#: Short names used only in the one-line summary (see :func:`summary`).
_SHORT_LABELS: Dict[str, str] = {
    "url": "URL",
    "ipv4": "IPv4",
    "domain": "domain",
    "email": "email",
    "path_unix": "path",
    "path_windows": "Windows path",
    "registry": "registry",
    "command": "command",
    "extension": "extension",
    "keyword": "keyword",
    "string": "string",
}

#: Kinds recognized by pattern (everything except the generic string).
_PATTERN_KINDS: Tuple[str, ...] = (
    "url",
    "ipv4",
    "domain",
    "email",
    "path_unix",
    "path_windows",
    "registry",
    "command",
    "extension",
    "keyword",
)

#: Position of each kind, so that the output always stays in the same order.
_KIND_ORDER: Dict[str, int] = {kind: index for index, kind in enumerate(IOC_KINDS)}

#: Maximum size of the line excerpt stored in :attr:`Ioc.context`.
_MAX_CONTEXT = 160

#: Extensions that deserve attention when they are cited in the source.
_EXTENSIONS: Tuple[str, ...] = (
    ".exe",
    ".dll",
    ".bat",
    ".ps1",
    ".sh",
    ".so",
    ".zip",
    ".enc",
    ".locked",
    ".key",
)

#: Commands and executables that the report highlights when they are cited.
_COMMANDS: Tuple[str, ...] = (
    "cmd.exe",
    "powershell.exe",
    "powershell",
    "pwsh",
    "cmd",
    "bash.exe",
    "bash",
    "sh.exe",
    "sh",
    "nc.exe",
    "nc",
    "ncat",
    "netcat",
    "curl.exe",
    "curl",
    "wget.exe",
    "wget",
    "chmod",
    "chown",
    "iptables",
    "systemctl",
    "crontab",
)

#: Words of interest (compared without case distinction).
_KEYWORDS: Tuple[str, ...] = (
    "password",
    "senha",
    "token",
    "secret",
    "admin",
    "root",
    "login",
    "bot",
    "keylog",
    "ransom",
    "bitcoin",
    "wallet",
)

#: TLDs considered plausible. The ones that are also a file extension are left
#: out on purpose (``md``, ``pl``, ``rs``, ``py``, ``sh``, ``so``, ``zip``,
#: ``in``, ``it``, ``is``, ``id``): without that, ``README.md`` and
#: ``script.sh`` would show up as a domain.
_TLDS = frozenset("""
    com org net edu gov mil int info biz name pro aero coop museum travel
    io ai app dev xyz online site store tech cloud blog page live news media
    shop club space world today life zone link click email group digital
    top icu monster quest wiki me
    br pt us uk de fr es nl ca au jp cn ru ua se ch be dk no fi gr tr
    mx ar cl co pe ve ec uy bo cr pa gt hn sv ni
    kr tw hk sg th vn ph pk lk np
    za eg ma ng ke il sa ae qa ir cz sk hu ro bg hr si lt lv ee by
    kz uz az ge am tn dz gh ci sn cm ug tz zm zw mu mg ao mz cv na bw
    """.split())

#: Marks the boundaries of a word: it accepts ``_``, ``.`` and ``/`` on the
#: sides, but not a letter or a digit. It is what keeps ``bot`` from matching
#: inside ``bottom``.
_LEFT_BOUNDARY = r"(?<![^\W_])"
_RIGHT_BOUNDARY = r"(?![^\W_])"

#: Command boundary: a file name such as ``script.sh`` is not the command
#: ``sh``, so the dot on the left also blocks the capture.
_COMMAND_LEFT_BOUNDARY = r"(?<![\w.])"

_URL_RE = re.compile(r"https?://[^\s\"',;<>()\[\]{}]+", re.I)
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_DOMAIN_RE = re.compile(
    r"(?<![\w.@/-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+([A-Za-z]{2,24})"
)
_EMAIL_RE = re.compile(
    r"(?<![\w.%+-])[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}(?![^\W_])"
)
_PATH_UNIX_RE = re.compile(r"(?<![\w./-])/(?:[A-Za-z0-9._-]+/)+[A-Za-z0-9._-]*")
_WIN_COMP = r"[A-Za-z0-9_.$-]+(?: [A-Za-z0-9_.$-]+)*"
_WIN_LAST = r"[A-Za-z0-9_.$-]+"
_PATH_WIN_RE = re.compile(
    rf"(?<![A-Za-z0-9_])"
    rf"(?:[A-Za-z]:\\(?:{_WIN_COMP}\\)*{_WIN_LAST}"
    rf"|\\\\{_WIN_COMP}\\{_WIN_LAST}(?:\\{_WIN_COMP})*)"
)
_REGISTRY_RE = re.compile(
    rf"(?:(?:HKEY_[A-Za-z_]+|HKLM|HKCU|HKCR|HKU|HKCC)(?:\\{_WIN_COMP})+"
    rf"|(?:Software|System)(?:\\{_WIN_COMP})+"
    rf"|(?:[A-Za-z0-9_.$-]+)?CurrentVersion\\Run(?:\\{_WIN_COMP})*)",
    re.I,
)
_COMMAND_RE = re.compile(
    _COMMAND_LEFT_BOUNDARY
    + r"(?:"
    + "|".join(re.escape(c) for c in sorted(_COMMANDS, key=len, reverse=True))
    + r")"
    + _RIGHT_BOUNDARY,
    re.I,
)
_EXTENSION_RE = re.compile(r"\.[A-Za-z][A-Za-z0-9]{0,5}" + _RIGHT_BOUNDARY)
_KEYWORD_RE = re.compile(
    _LEFT_BOUNDARY
    + r"(?:"
    + "|".join(re.escape(p) for p in sorted(_KEYWORDS, key=len, reverse=True))
    + r")"
    + r"(?![^\W_\d])",
    re.I,
)
_LITERAL_RE = re.compile(r"\"((?:[^\"\\]|\\.)*)\"|'((?:[^'\\]|\\.)*)'")
_DATA_HEAD_RE = re.compile(
    r"(?:[A-Za-z_.$][\w.$@]*\s+)?(?:db|dw|dd|dq|dt|resb|resw|resd|resq)\b", re.I
)
_ONLY_SEPARATORS = re.compile(r"[,;:.\-_/\\|*+=~^\s]+")

#: Escapes that NASM understands inside a literal and what each one becomes.
_ESCAPES: Dict[str, str] = {
    "n": "\n",
    "t": "\t",
    "r": "\r",
    "\\": "\\",
    '"': '"',
    "'": "'",
}


@dataclass(frozen=True)
class Ioc:
    """An indicator found in the source or in memory.

    Attributes:
        kind: Key of the kind, one of :data:`IOC_KINDS`.
        value: The text of the indicator, as it appeared (extensions in lower
            case).
        line: Line of the source (1-based) or ``0`` when it came from memory.
        context: Excerpt of the line where it appeared, without duplicate
            spaces.
    """

    kind: str
    value: str
    line: int
    context: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert the indicator into a dictionary ready for the report.

        Returns:
            Dictionary with ``kind``, ``value``, ``line``, ``context`` and the
            ``label`` coming from :data:`IOC_KINDS`.
        """
        return {
            "kind": self.kind,
            "value": self.value,
            "line": self.line,
            "context": self.context,
            "label": IOC_KINDS.get(self.kind, self.kind),
        }


@dataclass(frozen=True)
class _Line:
    """A line of the source already split into code and comment.

    Attributes:
        n: Line number (1-based).
        raw: Original line, unchanged.
        body: Part before the comment, without leading or trailing spaces.
        comment: Comment of the line (with the marker), empty when there is
            none.
    """

    n: int
    raw: str
    body: str
    comment: str


# ---------------------------------------------------------------------- lines -


def _scan_lines(text: str) -> List[_Line]:
    """Split the text into lines with code and comment already separated.

    Args:
        text: Complete source.

    Returns:
        One :class:`_Line` per line of the text, in file order.
    """
    lines: List[_Line] = []
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    for index, raw in enumerate(normalized.split("\n")):
        try:
            body, comment = strip_comment(raw)
        except Exception:
            body, comment = raw, ""
        lines.append(_Line(n=index + 1, raw=raw, body=body.strip(), comment=comment))
    return lines


def _unescape(fragment: str) -> str:
    """Translate the usual NASM escapes inside a literal.

    ``\\n``, ``\\t``, ``\\r``, ``\\\\``, ``\\"`` and ``\\'`` become one character;
    an unknown escape stays as it is, with the backslash.

    Args:
        fragment: Content of the literal, still with the escapes.

    Returns:
        The text already decoded.
    """
    if "\\" not in fragment:
        return fragment
    output: List[str] = []
    i = 0
    while i < len(fragment):
        char = fragment[i]
        if char == "\\" and i + 1 < len(fragment) and fragment[i + 1] in _ESCAPES:
            output.append(_ESCAPES[fragment[i + 1]])
            i += 2
            continue
        output.append(char)
        i += 1
    return "".join(output)


def _literals_of(body: str) -> List[str]:
    """Extract the literals of a piece of code.

    Neighboring literals separated only by a comma are concatenated, as the
    assembler would do with ``db "a", "b"``; a number or symbol in the middle
    breaks the concatenation.

    Args:
        body: Code piece of the line, already without the comment.

    Returns:
        The texts found, in the order they appear.
    """
    values: List[str] = []
    pending: Optional[str] = None
    previous_end = -1
    for match in _LITERAL_RE.finditer(body):
        group_name = match.group(1)
        text = _unescape(group_name if group_name is not None else match.group(2) or "")
        between = body[previous_end : match.start()] if previous_end >= 0 else ""
        if pending is not None and between.strip(" \t,") == "":
            pending += text
        else:
            if pending is not None:
                values.append(pending)
            pending = text
        previous_end = match.end()
    if pending is not None:
        values.append(pending)
    return values


def _comment_text(comment: str) -> str:
    """Clean a comment: remove the marker and join the spaces.

    Args:
        comment: Comment as it came out of the parser, with ``;``, ``#`` or
            ``//``.

    Returns:
        The comment text without the marker and without duplicate spaces.
    """
    return " ".join(comment.lstrip(";#/").split())


def _accepted(value: str, min_length: int) -> bool:
    """Tell whether a text deserves to become an indicator.

    Args:
        value: Candidate text.
        min_length: Minimum size, measured without the leading and trailing
            spaces.

    Returns:
        ``True`` when the text is not empty, nor only separators, and reaches
        the minimum size.
    """
    text = value.strip()
    if len(text) < max(1, int(min_length)):
        return False
    return _ONLY_SEPARATORS.fullmatch(text) is None


def _context(raw: str) -> str:
    """Build the line excerpt that accompanies the indicator.

    Args:
        raw: Original line of the source.

    Returns:
        The line without duplicate spaces, cut at :data:`_MAX_CONTEXT`.
    """
    return " ".join(raw.split())[:_MAX_CONTEXT]


# ------------------------------------------------------------------ detectors -


def _urls(text: str) -> List[str]:
    """Look for ``http``/``https`` URLs.

    The capture stops at the first space, quote, comma or closing bracket, and
    the final punctuation of the sentence does not enter.

    Args:
        text: Text to scan.

    Returns:
        The URLs found.
    """
    found: List[str] = []
    for match in _URL_RE.finditer(text):
        value = match.group(0).rstrip(".,;:")
        if len(value) > len("https://"):
            found.append(value)
    return found


def _ips(text: str) -> List[str]:
    """Look for valid IPv4 addresses.

    Each octet has to fit in 0-255 and the address cannot be part of a longer
    sequence of numbers: ``1.2.3.4.5`` and the version ``1.2`` stay out.

    Args:
        text: Text to scan.

    Returns:
        The addresses found.
    """
    found: List[str] = []
    for match in _IPV4_RE.finditer(text):
        value = match.group(0)
        octets = value.split(".")
        if all(octet.isdigit() and int(octet) <= 255 for octet in octets):
            found.append(value)
    return found


def _domains(text: str) -> List[str]:
    """Look for domains with a plausible TLD.

    A domain inside a URL (after ``/``) or an e-mail (after ``@``) does not
    count: the URL and the e-mail already carry the name, and repeating it would
    only add noise. File names (``file.asm``) and section names (``.text``) also
    stay out, because their extension is not a TLD.

    Args:
        text: Text to scan.

    Returns:
        The domains found.
    """
    found: List[str] = []
    for match in _DOMAIN_RE.finditer(text):
        if match.group(1).lower() in _TLDS:
            found.append(match.group(0))
    return found


def _emails(text: str) -> List[str]:
    """Look for e-mail addresses.

    Args:
        text: Text to scan.

    Returns:
        The e-mails found.
    """
    return [match.group(0) for match in _EMAIL_RE.finditer(text)]


def _unix_paths(text: str) -> List[str]:
    """Look for Unix paths with at least one directory.

    Args:
        text: Text to scan.

    Returns:
        The paths found, such as ``/etc/passwd``.
    """
    return [match.group(0) for match in _PATH_UNIX_RE.finditer(text)]


def _windows_paths(text: str) -> List[str]:
    """Look for Windows paths and UNC names.

    It accepts escaped backslashes (``C:\\\\Windows``) and single ones
    (``C:\\Windows``), because the scanned text already comes normalized. The last
    component does not accept a space, which makes the capture stop before the
    prose that follows.

    Args:
        text: Text to scan.

    Returns:
        The paths found.
    """
    return [match.group(0) for match in _PATH_WIN_RE.finditer(text)]


def _registry_keys(text: str) -> List[str]:
    """Look for Windows registry keys.

    Args:
        text: Text to scan.

    Returns:
        The keys found, such as ``HKLM\\Software\\Microsoft``.
    """
    return [match.group(0) for match in _REGISTRY_RE.finditer(text)]


def _commands(text: str) -> List[str]:
    """Look for command and executable names that are cited.

    Args:
        text: Text to scan.

    Returns:
        The commands found, preserving upper and lower case.
    """
    return [match.group(0) for match in _COMMAND_RE.finditer(text)]


def _extensions(text: str) -> List[str]:
    """Look for file extensions that deserve attention.

    Args:
        text: Text to scan.

    Returns:
        The extensions found, always in lower case.
    """
    found: List[str] = []
    for match in _EXTENSION_RE.finditer(text):
        value = match.group(0).lower()
        if value in _EXTENSIONS:
            found.append(value)
    return found


def _keywords(text: str) -> List[str]:
    """Look for words of interest, without case distinction.

    Args:
        text: Text to scan.

    Returns:
        The words found, stored as they appeared in the text.
    """
    return [match.group(0) for match in _KEYWORD_RE.finditer(text)]


#: One detector per pattern kind.
_DETECTORS: Dict[str, Callable[[str], List[str]]] = {
    "url": _urls,
    "ipv4": _ips,
    "domain": _domains,
    "email": _emails,
    "path_unix": _unix_paths,
    "path_windows": _windows_paths,
    "registry": _registry_keys,
    "command": _commands,
    "extension": _extensions,
    "keyword": _keywords,
}


def _classify(value: str) -> List[Tuple[str, str]]:
    """Run every detector over a text.

    Args:
        value: Text to classify, coming from the source or from memory.

    Returns:
        Pairs ``(kind, value)``; when no detector recognizes the text, the
        answer is ``[("string", value)]``.
    """
    found: List[Tuple[str, str]] = []
    for kind in _PATTERN_KINDS:
        for candidate in _DETECTORS[kind](value):
            found.append((kind, candidate))
    return found if found else [("string", value)]


def _fallback_patterns(raw: str) -> List[Tuple[str, str]]:
    """Look for paths and keys in the raw text of a line.

    It is the safety net for when the string is broken into pieces: the doubled
    backslashes of the source become single ones before the search.

    Args:
        raw: Original line of the source.

    Returns:
        Pairs ``(kind, value)`` found.
    """
    normalized = raw.replace("\\\\", "\\")
    found: List[Tuple[str, str]] = [("path_unix", v) for v in _unix_paths(normalized)]
    found += [("path_windows", v) for v in _windows_paths(normalized)]
    found += [("registry", v) for v in _registry_keys(normalized)]
    return found


def _needs_fallback(line: _Line) -> bool:
    """Tell whether the raw line must go through the search for paths and keys.

    Args:
        line: Line already split into code and comment.

    Returns:
        ``True`` for data lines and for lines with a comment.
    """
    if line.comment:
        return True
    return _DATA_HEAD_RE.match(line.body) is not None


def _add_iocs(
    destination: List[Ioc],
    seen: Set[Tuple[str, str]],
    value: str,
    line: int,
    context: str,
) -> None:
    """Classify a text and store the indicators that are still new.

    Args:
        destination: List where the indicators are accumulated.
        seen: Set of ``(kind, value)`` pairs already registered.
        value: Text to classify.
        line: Line where the text appeared.
        context: Excerpt of the line, for the report.
    """
    for kind, candidate in _classify(value):
        if (kind, candidate) in seen:
            continue
        seen.add((kind, candidate))
        destination.append(Ioc(kind=kind, value=candidate, line=line, context=context))


def _order_key(ioc: Ioc) -> Tuple[int, int, str]:
    """Build the sorting key of the indicators.

    Args:
        ioc: Indicator to sort.

    Returns:
        Tuple ``(line, kind, value)``.
    """
    return (ioc.line, _KIND_ORDER.get(ioc.kind, len(_KIND_ORDER)), ioc.value)


def _without_prefixes(iocs: List[Ioc]) -> List[Ioc]:
    """Drop the path that is only a piece of another path of the same line.

    When a literal loses its backslashes to an escape (``db "C:\\Users"``
    written with a single backslash), the decoded reading stops in the middle of
    the path and the rest only appears in the raw text of the line. Of the two,
    the most complete one stays.

    Args:
        iocs: Indicators already without repetition.

    Returns:
        The list without the paths that are a prefix of another one of the same
        line.
    """
    complete_kinds = {"path_unix", "path_windows", "registry"}
    discard: Set[Tuple[str, str]] = set()
    for ioc in iocs:
        if ioc.kind not in complete_kinds:
            continue
        for other in iocs:
            if other.kind != ioc.kind or other.line != ioc.line:
                continue
            if len(other.value) > len(ioc.value) and other.value.startswith(ioc.value):
                discard.add((ioc.kind, ioc.value))
                break
    return [ioc for ioc in iocs if (ioc.kind, ioc.value) not in discard]


# -------------------------------------------------------------------- public -


def strings_of(
    text: str, *, min_length: int = 4, include_comments: bool = True
) -> List[Tuple[int, str]]:
    """List the strings written in the source, with the line of each one.

    It reads the data literals (``db "..."``, ``dq '...'``, including lists
    separated by commas, which are concatenated) and, when
    ``include_comments``, the text of the comments as well. Escapes such as
    ``\\n``, ``\\t``, ``\\\\`` and ``\\"`` are decoded in the literals; in a
    comment the text enters as it is. Empty strings, strings only of separators
    or strings shorter than ``min_length`` stay out.

    Args:
        text: Complete source.
        min_length: Minimum size of a string for it to enter the list.
        include_comments: Whether the comments also count as strings.

    Returns:
        List of ``(line, text)`` in file order; an empty list for an empty,
        binary or absurd input.

    Example:
        >>> strings_of('msg db "Ola", 0', min_length=2)
        [(1, 'Ola')]
    """
    if not isinstance(text, str):
        return []
    found_strings: List[Tuple[int, str]] = []
    try:
        for line in _scan_lines(text):
            for value in _literals_of(line.body):
                if _accepted(value, min_length):
                    found_strings.append((line.n, value))
            if include_comments and line.comment:
                comment_text = _comment_text(line.comment)
                if _accepted(comment_text, min_length):
                    found_strings.append((line.n, comment_text))
    except Exception:
        return found_strings
    return found_strings


def extract(text: str, *, min_length: int = 4, include_comments: bool = True) -> List[Ioc]:
    """Extract the indicators of compromise written in the source.

    It runs every kind over :func:`strings_of` and, as a reinforcement, looks
    for paths and registry keys in the raw text of the data lines and of the
    comments — that is what saves the case of a string broken into pieces. The
    same ``(kind, value)`` pair appears only once, at the first line where it
    showed up, and a string that already fell into some kind does not come back
    as ``string``. If a path of the same line is only a piece of another one,
    the most complete one stays.

    Args:
        text: Complete source.
        min_length: Minimum size of a string for it to be classified.
        include_comments: Whether the comments are also scanned.

    Returns:
        The indicators in line order; an empty list for an empty, binary or
        absurd input.

    Example:
        >>> iocs = extract('msg db "admin password", 0')
        >>> [(i.kind, i.value) for i in iocs]
        [('keyword', 'admin'), ('keyword', 'password')]
    """
    if not isinstance(text, str):
        return []
    found: List[Ioc] = []
    seen: Set[Tuple[str, str]] = set()
    try:
        lines = _scan_lines(text)
        for line in lines:
            context = _context(line.raw)
            for value in _literals_of(line.body):
                if _accepted(value, min_length):
                    _add_iocs(found, seen, value, line.n, context)
            if include_comments and line.comment:
                comment_text = _comment_text(line.comment)
                if _accepted(comment_text, min_length):
                    _add_iocs(found, seen, comment_text, line.n, context)
        for line in lines:
            if not _needs_fallback(line):
                continue
            for kind, value in _fallback_patterns(line.raw):
                if (kind, value) in seen:
                    continue
                seen.add((kind, value))
                found.append(Ioc(kind=kind, value=value, line=line.n, context=_context(line.raw)))
    except Exception:
        return _without_prefixes(sorted(found, key=_order_key))
    return _without_prefixes(sorted(found, key=_order_key))


def group(iocs: Sequence[Ioc]) -> Dict[str, List[Ioc]]:
    """Group the indicators by kind, without repeating a value.

    Args:
        iocs: Indicators to group, in any order.

    Returns:
        Dictionary ``kind -> list``, with the kinds in the order of
        :data:`IOC_KINDS`; of each value the first occurrence stays.
    """
    grouped: Dict[str, List[Ioc]] = {}
    for ioc in iocs:
        items = grouped.setdefault(ioc.kind, [])
        if any(existing.value == ioc.value for existing in items):
            continue
        items.append(ioc)
    order = sorted(grouped, key=lambda kind: _KIND_ORDER.get(kind, len(_KIND_ORDER)))
    return {kind: grouped[kind] for kind in order}


def to_dicts(iocs: Sequence[Ioc]) -> Dict[str, List[Dict[str, Any]]]:
    """Convert the grouped indicators into dictionaries ready for the report.

    Args:
        iocs: Indicators to convert.

    Returns:
        Dictionary ``kind -> list of dictionaries``, in the format of
        :meth:`Ioc.to_dict`.
    """
    return {kind: [ioc.to_dict() for ioc in items] for kind, items in group(iocs).items()}


def summary(iocs: Sequence[Ioc]) -> str:
    """Summarize the indicators in one line, by kind.

    Args:
        iocs: Indicators to summarize.

    Returns:
        Text such as ``"12 indicator(s): 3 URL, 2 IPv4, 1 path"``; when there is
        nothing, ``"0 indicator(s)"``.
    """
    counts: Dict[str, int] = {}
    for ioc in iocs:
        counts[ioc.kind] = counts.get(ioc.kind, 0) + 1
    parts = [
        "%d %s" % (counts[kind], _SHORT_LABELS[kind]) for kind in _KIND_ORDER if kind in counts
    ]
    if not parts:
        return "0 indicator(s)"
    return "%d indicator(s): %s" % (len(iocs), ", ".join(parts))


def _read_with_rd8(rd8: Callable[[int], Any], addr: int) -> int:
    """Read a byte using ``rd8`` from the reader, tolerating a read failure.

    Args:
        rd8: ``rd8`` method of the reader.
        addr: Requested address.

    Returns:
        The byte read, or ``0`` when the read is not possible.
    """
    try:
        value = rd8(addr)
    except Exception:
        return 0
    return value & 0xFF if isinstance(value, int) else 0


def _read_with_mem(read_mem: Callable[[int, int], Any], addr: int) -> int:
    """Read a byte using ``read_mem(addr, 1)``, tolerating a read failure.

    Args:
        read_mem: ``read_mem`` method of the reader.
        addr: Requested address.

    Returns:
        The byte read, or ``0`` when the read is not possible.
    """
    try:
        value = read_mem(addr, 1)
    except Exception:
        return 0
    return value & 0xFF if isinstance(value, int) else 0


def _byte_reader(reader: Any) -> Optional[Callable[[int], int]]:
    """Choose the best byte read offered by the reader.

    Args:
        reader: Object with ``rd8`` or, in its absence, ``read_mem``.

    Returns:
        Function ``address -> byte``, or ``None`` when the reader has neither of
        the two.
    """
    rd8 = getattr(reader, "peek8", None) or getattr(reader, "rd8", None)
    if callable(rd8):
        return partial(_read_with_rd8, rd8)
    read_mem = getattr(reader, "read_mem", None)
    if callable(read_mem):
        return partial(_read_with_mem, read_mem)
    return None


def _printable(byte: int) -> bool:
    """Tell whether a byte is part of a piece of text.

    Args:
        byte: Value from 0 to 255.

    Returns:
        ``True`` for the printable ASCII bytes and for the high bytes used by
        UTF-8 and latin-1.
    """
    return 0x20 <= byte <= 0x7E or byte >= 0x80


def _printable_runs(
    read_byte: Callable[[int], int], start: int, end: int, min_length: int
) -> List[Tuple[int, int]]:
    """Scan the memory looking for runs of printable bytes.

    Args:
        read_byte: Function that returns the byte of an address.
        start: First address of the scan.
        end: Address after the last one (exclusive).
        min_length: Minimum size of a run, in bytes.

    Returns:
        Pairs ``(start, end)`` of each accepted run.
    """
    runs: List[Tuple[int, int]] = []
    i = start
    while i < end:
        try:
            if not _printable(read_byte(i)):
                i += 1
                continue
            j = i + 1
            while j < end and _printable(read_byte(j)):
                j += 1
        except Exception:
            break
        if j - i >= min_length:
            runs.append((i, j))
        i = j
    return runs


def _memory_text(reader: Any, read_byte: Callable[[int], int], start: int, end: int) -> str:
    """Read the text of a run of bytes from memory.

    It uses ``read_cstring`` from the reader and, if it returns nothing, rebuilds
    the text from the bytes already read.

    Args:
        reader: Object with ``read_cstring``.
        read_byte: Function that returns the byte of an address.
        start: First address of the run.
        end: Address after the last one (exclusive).

    Returns:
        The text found, without leading or trailing spaces.
    """
    read_cstring = getattr(reader, "read_cstring", None)
    content = ""
    if callable(read_cstring):
        try:
            read_value = read_cstring(start, end - start)
        except Exception:
            read_value = ""
        if isinstance(read_value, str):
            content = read_value
    if not content:
        pieces: List[str] = []
        for addr in range(start, end):
            pieces.append(chr(read_byte(addr) & 0xFF))
        content = "".join(pieces)
    return content.strip()


def _cstring_runs(
    read_cstring: Callable[..., Any], start: int, end: int, min_length: int
) -> List[str]:
    """Scan the memory using only ``read_cstring`` from the reader.

    It is the path for whoever knows how to read zero-terminated strings but
    does not know how to read byte by byte.

    Args:
        read_cstring: ``read_cstring`` method of the reader.
        start: First address of the scan.
        end: Address after the last one (exclusive).
        min_length: Minimum size of a string, in characters.

    Returns:
        The accepted strings, in address order.
    """
    texts: List[str] = []
    addr = start
    while addr < end:
        try:
            read_value = read_cstring(addr, end - addr)
        except Exception:
            break
        if not isinstance(read_value, str):
            break
        if _accepted(read_value, min_length):
            texts.append(read_value.strip())
        addr += len(read_value) + 1
    return texts


def from_memory(
    reader: Any, *, base: int = 0x00400000, size: int = 0x40000, min_length: int = 4
) -> List[Ioc]:
    """Extract indicators from the strings that only exist in running memory.

    It scans ``size`` bytes from ``base`` looking for runs of printable bytes of
    at least ``min_length`` and classifies each one with the same kinds of
    :func:`extract`. The indicators come out with ``line`` equal to ``0``,
    because they do not come from any line of the source.

    Args:
        reader: Memory reader with ``read_cstring`` (the ``Machine`` of ASM X);
            ``rd8`` or ``read_mem`` speed up the scan.
        base: First address scanned.
        size: Number of bytes scanned.
        min_length: Minimum size of a run, in bytes.

    Returns:
        The indicators found, in address order; an empty list when the reader
        does not know how to read strings or when there is nothing readable in
        the region.
    """
    read_cstring = getattr(reader, "read_cstring", None)
    if not callable(read_cstring):
        return []
    try:
        start = int(base)
        end = start + max(0, int(size))
        minimum = max(1, int(min_length))
    except Exception:
        return []
    found: List[Ioc] = []
    seen: Set[Tuple[str, str]] = set()
    try:
        read_byte = _byte_reader(reader)
        texts: List[str] = []
        if read_byte is not None:
            for run_start, run_end in _printable_runs(read_byte, start, end, minimum):
                texts.append(_memory_text(reader, read_byte, run_start, run_end))
        else:
            texts = _cstring_runs(read_cstring, start, end, minimum)
        for text in texts:
            if _accepted(text, minimum):
                _add_iocs(found, seen, text, 0, text[:_MAX_CONTEXT])
    except Exception:
        return found
    return found
