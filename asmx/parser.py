"""x86-64 assembly parser: NASM/Intel, MASM and GAS/AT&T.

The parser is tolerant on purpose: it never refuses a file. Each line becomes a
:class:`Line` with whatever could be recognized — label, data, directive or
instruction —, and whatever looked strange shows up later in the validator,
with a line number. That way the student sees the explanation of what they
wrote even when the real assembler would complain.

The dialect is detected from the content (:func:`detect_flavor`): ``%rax``/``$10``
mean AT&T, ``.code``/``PROC`` mean MASM, and everything else is treated as
NASM/Intel. In AT&T the operands are swapped on input so that the rest of the
program always works in Intel order (destination first).

Example:
    >>> from asmx.parser import parse
    >>> program = parse("mov rax, 1\\nadd rax, 0x10")
    >>> [i.mnemonic for i in program.instructions]
    ['mov', 'add']
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Match, Optional, Tuple

from .isa import CONTROL_DIRECTIVES, DATA_DIRECTIVES, ISA, REG_INFO, SIZE_KEYWORDS
from .logging_setup import get_logger, log_event

logger = get_logger(__name__)


@dataclass
class Operand:
    """An operand already classified.

    Attributes:
        text: Original text of the operand, as it appeared in the source.
        type: ``reg``, ``imm``, ``mem``, ``sym``, ``expr`` or ``unknown``.
        size: Size in bytes, when declared (``qword`` -> 8) or taken from the
            register.
        reg: Lowercase register name, when it is a register.
        value: Numeric value, when it is an immediate.
        inner: Content inside the brackets, when it is a memory access.
        regs: Registers used in the address computation.
        symbol: Referenced symbol (variable or label).
        is_char: Marks the immediate that came from a character literal.
    """

    text: str
    type: str = "unknown"  # reg | imm | mem | sym | expr | unknown
    size: Optional[int] = None
    reg: Optional[str] = None
    value: Optional[int] = None
    inner: Optional[str] = None
    regs: List[str] = field(default_factory=list)
    symbol: Optional[str] = None
    is_char: bool = False


@dataclass
class Line:
    """One line of the source with everything the parser could extract.

    Attributes:
        n: Line number in the file (1-based).
        raw: Original line, unchanged.
        comment: Comment left over from the line.
        kind: ``empty``, ``label``, ``data``, ``directive`` or ``instruction``.
        label: Label defined on the line, when there is one.
        local_label: Whether the label starts with ``.`` or ``@`` (local scope).
        directive: Assembler directive (``section``, ``db``, ``equ``...).
        args: Arguments of the directive or of the data declaration.
        unit: Unit size of the directive, in bytes.
        reserve: Whether the directive only reserves space (``resb``, ``.space``).
        mnemonic: Instruction mnemonic, in lowercase.
        prefix: Instruction prefix (``rep``, ``lock``).
        operands: Operands already classified.
        known: Whether the mnemonic exists in the catalogue.
        section: Section in force on the line.
        func: Function (previous non-local label) the line is in.
        new_section: Section opened on this very line.
        labels: Labels immediately before the instruction.
        idx: Index among the instructions of the program.
        block: Index of the basic block the instruction belongs to.
        sem: Semantics filled in by the analyzer.
        addr: Simulated address of the data, in the virtual machine.
    """

    n: int
    raw: str
    comment: str = ""
    kind: str = "empty"  # empty | label | data | directive | instruction
    label: Optional[str] = None
    local_label: bool = False
    directive: Optional[str] = None
    args: List[str] = field(default_factory=list)
    unit: int = 1
    reserve: bool = False
    mnemonic: Optional[str] = None
    prefix: Optional[str] = None
    operands: List[Operand] = field(default_factory=list)
    known: bool = True
    section: Optional[str] = None
    func: Optional[str] = None
    new_section: Optional[str] = None
    labels: List[str] = field(default_factory=list)
    idx: Optional[int] = None  # index among the instructions
    block: Optional[int] = None
    sem: Optional[Any] = None
    addr: Optional[int] = None

    @property
    def text(self) -> str:
        """Line without leading or trailing spaces.

        Returns:
            The text of ``raw`` already trimmed.
        """
        return self.raw.strip()


@dataclass
class Program:
    """The whole source, already read.

    Attributes:
        lines: All the lines, in file order.
        symbols: Labels, data and external symbols, by name.
        flavor: Detected dialect: ``intel``, ``masm`` or ``att``.
        source: Original text of the file.
    """

    lines: List[Line]
    symbols: Dict[str, Dict[str, Any]]
    flavor: str
    source: str

    @property
    def instructions(self) -> List[Line]:
        """Only the lines that are machine instructions.

        Returns:
            List of :class:`Line` with ``kind == "instruction"``.
        """
        return [line for line in self.lines if line.kind == "instruction"]


#: Size, in bytes, that the AT&T suffix declares (``movl`` -> 4).
ATT_SIZES: Dict[str, int] = {"b": 1, "w": 2, "l": 4, "q": 8}


LABEL_RE = re.compile(r"^([A-Za-z_.$?@][\w.$@?]*)\s*:\s*(.*)$")
MASM_PROC_RE = re.compile(r"^([A-Za-z_?@][\w?@]*)\s+(proc|endp)\b", re.I)
DATA_DEF_RE = re.compile(
    r"^([A-Za-z_.$][\w.$@]*)\s+(db|dw|dd|dq|dt|resb|resw|resd|resq|equ|times)\b\s*(.*)$", re.I
)
NUM_RE = re.compile(r"^\$?-?(0x[0-9a-f]+|[0-9a-f]+h|[01]+b|0o[0-7]+|\d+)$", re.I)
SYM_RE = re.compile(r"^[A-Za-z_.$][\w.$@]*$")


def strip_comment(line: str) -> Tuple[str, str]:
    """Splits code and comment without breaking what is inside quotes.

    Accepts ``;`` at any position, ``#`` when it is not glued to a word (so as
    not to confuse it with an AT&T immediate) and ``//``.

    Args:
        line: Raw line of the file.

    Returns:
        Tuple ``(code, comment)``; the comment includes the marker and comes
        back empty when there is none.

    Example:
        >>> strip_comment('db "a;b"   ; note')
        ('db "a;b"   ', '; note')
    """
    out, comment, in_str = "", "", None
    i = 0
    while i < len(line):
        ch = line[i]
        if in_str:
            out += ch
            if ch == in_str and (i == 0 or line[i - 1] != "\\"):
                in_str = None
            i += 1
            continue
        if ch in "\"'":
            in_str = ch
            out += ch
            i += 1
            continue
        prev = line[i - 1] if i else ""
        if (
            ch == ";"
            or (ch == "#" and not prev.isalnum())
            or (ch == "/" and line[i : i + 2] == "//")
        ):
            comment = line[i:]
            break
        out += ch
        i += 1
    return out, comment


def split_operands(text: str) -> List[str]:
    """Splits the operands on commas, respecting brackets, parentheses and quotes.

    Args:
        text: Snippet after the mnemonic.

    Returns:
        List of operands already without leading or trailing spaces.

    Example:
        >>> split_operands("rbx + rcx*4, 8")
        ['rbx + rcx*4', '8']
        >>> split_operands("[rbx + 8], 'a,b'")
        ['[rbx + 8]', "'a,b'"]
    """
    parts, depth, cur, in_str = [], 0, "", None
    for i, ch in enumerate(text):
        if in_str:
            cur += ch
            if ch == in_str and (i == 0 or text[i - 1] != "\\"):
                in_str = None
            continue
        if ch in "\"'":
            in_str = ch
            cur += ch
            continue
        if ch in "[(":
            depth += 1
        elif ch in "])":
            depth -= 1
        if ch == "," and depth == 0:
            if cur.strip():
                parts.append(cur.strip())
            cur = ""
            continue
        cur += ch
    if cur.strip():
        parts.append(cur.strip())
    return parts


def parse_number(token: str) -> int:
    """Converts a number written in any of the assembly bases.

    Understands ``0x1f``, ``1fh``, ``1010b``, ``0o17``, decimal, a minus sign
    and the AT&T ``$``. Text that is not a number becomes ``0`` instead of an
    exception, because the parser cannot stop over a symbolic constant.

    Args:
        token: Text of the number.

    Returns:
        The integer value, negative when there was a ``-`` in front.

    Example:
        >>> parse_number("0x10"), parse_number("10h"), parse_number("1010b"), parse_number("-5")
        (16, 16, 10, -5)
    """
    t = str(token).strip().lstrip("$")
    neg = t.startswith("-")
    if neg:
        t = t[1:]
    try:
        if re.fullmatch(r"0x[0-9a-f]+", t, re.I):
            v = int(t, 16)
        elif re.fullmatch(r"[0-9][0-9a-f]*h", t, re.I):
            v = int(t[:-1], 16)
        elif re.fullmatch(r"[01]+b", t, re.I):
            v = int(t[:-1], 2)
        elif re.fullmatch(r"0o[0-7]+", t, re.I):
            v = int(t[2:], 8)
        elif re.fullmatch(r"-?\d+", t):
            v = int(t, 10)
        else:
            v = 0
    except ValueError:
        v = 0
    return -v if neg else v


def classify_operand(text: str) -> Operand:
    """Finds out what kind of operand this text is.

    Recognizes a declared size (``qword ptr [rbx]``), a memory access with
    registers and symbols, a bare register, a numeric immediate, a character
    literal, a symbol and an arithmetic expression.

    Args:
        text: Text of the operand.

    Returns:
        The filled :class:`Operand` (``type == "unknown"`` when nothing matches).

    Example:
        >>> op = classify_operand("qword [rbx + rcx*4 + 8]")
        >>> op.type, op.size, op.regs
        ('mem', 8, ['rbx', 'rcx'])
    """
    t = text.strip()
    op = Operand(text=t)
    if not t:
        return op

    m = re.match(r"^(byte|word|dword|qword|oword|tword|xmmword)\s+(ptr\s+)?", t, re.I)
    if m:
        op.size = SIZE_KEYWORDS[m.group(1).lower()]
        t = t[m.end() :].strip()

    if (t.startswith("[") and t.endswith("]")) or re.match(r"^[\w]*\s*ptr\s*\[", t, re.I):
        op.type = "mem"
        op.inner = re.sub(r"^.*?\[", "", t).rstrip("]").strip()
        op.regs = [
            r.lower() for r in re.findall(r"\b[A-Za-z][\w]*\b", op.inner) if r.lower() in REG_INFO
        ]
        syms = [
            s
            for s in re.findall(r"\b[A-Za-z_.$][\w.$@]*\b", op.inner)
            if s.lower() not in REG_INFO and s.lower() != "rel"
        ]
        op.symbol = syms[0] if syms else None
        return op

    bare = t.lower().lstrip("%")
    if bare in REG_INFO:
        op.type = "reg"
        op.reg = bare
        op.size = REG_INFO[bare]["size"]
        return op
    if NUM_RE.match(t):
        op.type = "imm"
        op.value = parse_number(t)
        return op
    if re.fullmatch(r"'.'", t) or re.fullmatch(r'".+"', t):
        op.type = "imm"
        op.value = ord(t[1])
        op.is_char = True
        return op
    if SYM_RE.match(t):
        op.type = "sym"
        op.symbol = t
        return op
    if re.search(r"[-+*]", t):
        op.type = "expr"
    return op


def detect_flavor(text: str) -> str:
    """Finds out the dialect of the source.

    Args:
        text: Complete code.

    Returns:
        ``"att"`` when there are enough AT&T marks (``%rax``, ``$10``),
        ``"masm"`` when ``.code``/``.model`` or ``PROC``/``ENDP`` show up, and
        ``"intel"`` in the remaining case.

    Example:
        >>> detect_flavor("movq %rsp, %rbp\\nsubq $16, %rsp")
        'att'
        >>> detect_flavor("main PROC\\n ret\\nmain ENDP")
        'masm'
    """
    att = len(re.findall(r"%r[a-z0-9]{1,3}\b", text)) + len(re.findall(r"\$\d", text))
    masm = re.search(r"(^|\n)\s*\.(code|data|model)\b", text, re.I) or re.search(
        r"\bproc\b[\s\S]*\bendp\b", text, re.I
    )
    if att > 2:
        return "att"
    if masm:
        return "masm"
    return "intel"


def _att_memory(expr: str) -> str:
    """Converts an AT&T address to the Intel form.

    ``-8(%rbp)`` becomes ``[rbp-8]`` and ``(%rax,%rcx,4)`` becomes ``[rax+rcx*4]``.

    Args:
        expr: Text of the operand in AT&T.

    Returns:
        The same address written between brackets, in Intel style.
    """

    def repl(m: Match[str]) -> str:
        """Rewrites a ``disp(base,index,scale)`` address between brackets.

        Returns:
            The address in Intel format.
        """
        disp, inner = m.group(1), m.group(2)
        parts = [p.strip() for p in inner.split(",")]
        out = parts[0] if parts else ""
        if len(parts) > 1 and parts[1]:
            out += "+" + parts[1]
            if len(parts) > 2 and parts[2]:
                out += "*" + parts[2]
        if disp and disp not in ("", "0"):
            if not out:
                out = disp
            elif disp.startswith("-"):
                out = out + disp
            else:
                out = out + "+" + disp
        return "[" + out + "]"

    return re.sub(r"(-?\w*)\(([^)]*)\)", repl, expr)


def att_operand_size(mnemonic: str, normalized: str) -> Optional[int]:
    """Reads the size the AT&T suffix declares (``movl`` -> 4 bytes).

    In AT&T it is the mnemonic suffix that tells the width of the memory access,
    not the operand: ``movl $0, -4(%rbp)`` stores 4 bytes, not 8. Without this
    the validator flagged "ambiguous operand size" (MEM001) on correct code and
    the virtual machine read the wrong width.

    Args:
        mnemonic: Mnemonic as it came from the file (``movl``, ``pushq``...).
        normalized: Mnemonic after :func:`normalize_att` (``mov``).

    Returns:
        The size in bytes, or ``None`` when the mnemonic did not carry a size
        suffix (``lea``, ``call``, ``movsb``...).
    """
    original = mnemonic.lower()
    if original == normalized or len(original) < 2:
        return None
    if original[:-1] != normalized:
        return None
    return ATT_SIZES.get(original[-1])


def normalize_att(mnemonic: str, operands: List[str]) -> Tuple[str, List[str]]:
    """Adjusts an AT&T instruction to the canonical Intel form.

    Removes ``%`` and ``$``, converts addresses, drops the size suffix from the
    mnemonic (``movq`` -> ``mov``) and swaps the order of the two operands.

    Args:
        mnemonic: Mnemonic as it came from the file.
        operands: Operands in AT&T.

    Returns:
        Tuple ``(mnemonic, operands)`` in the pattern used by the rest of the code.
    """
    m = mnemonic.lower()
    if m not in ISA and m[:-1] in ISA and m[-1] in "bwlq":
        m = m[:-1]
    ops = []
    for o in operands:
        o = o.replace("%", "").replace("$", "")
        o = _att_memory(o)
        ops.append(o)
    if len(ops) == 2:
        ops = [ops[1], ops[0]]
    return m, ops


def parse(text: str) -> Program:
    """Reads the whole code and returns the classified lines.

    Args:
        text: Source code in NASM/Intel, MASM or GAS/AT&T.

    Returns:
        The :class:`Program` with lines, symbols and detected dialect.

    Example:
        >>> program = parse("section .data\\nx dq 7\\nsection .text\\nf:\\n mov rax, [x]\\n ret")
        >>> program.symbols["x"]["type"], len(program.instructions)
        ('data', 2)
    """
    flavor = detect_flavor(text)
    raw_lines = text.replace("\r\n", "\n").split("\n")
    lines: List[Line] = []
    symbols: Dict[str, Dict[str, Any]] = {}
    section: Optional[str] = None
    func: Optional[str] = None

    for i, raw in enumerate(raw_lines):
        body, comment = strip_comment(raw)
        body = body.strip()
        entry = Line(n=i + 1, raw=raw, comment=comment, section=section, func=func)

        if not body:
            lines.append(entry)
            continue

        m = LABEL_RE.match(body)
        if m and m.group(1).lower() not in SIZE_KEYWORDS:
            entry.kind = "label"
            entry.label = m.group(1)
            entry.local_label = m.group(1)[0] in ".@"
            if not entry.local_label:
                func = m.group(1)
            entry.func = func
            symbols.setdefault(
                m.group(1),
                {
                    "name": m.group(1),
                    "line": i + 1,
                    "type": "label",
                    "section": section,
                    "global": False,
                    "local": entry.local_label,
                },
            )
            lines.append(entry)
            body = m.group(2).strip()
            if not body:
                continue
            entry = Line(n=i + 1, raw=raw, comment="", section=section, func=func)

        tokens = body.split()
        head = tokens[0].lower()

        mp = MASM_PROC_RE.match(body)
        if mp:
            entry.kind = "directive"
            entry.directive = mp.group(2).lower()
            entry.label = mp.group(1)
            if entry.directive == "proc":
                func = mp.group(1)
                entry.func = func
                symbols[mp.group(1)] = {
                    "name": mp.group(1),
                    "line": i + 1,
                    "type": "label",
                    "section": section,
                    "global": True,
                    "local": False,
                }
            lines.append(entry)
            continue

        dd = DATA_DEF_RE.match(body)
        if dd:
            entry.kind = "data"
            entry.label = dd.group(1)
            entry.directive = dd.group(2).lower()
            entry.args = split_operands(dd.group(3))
            entry.unit = DATA_DIRECTIVES.get(entry.directive, 1)
            entry.reserve = entry.directive.startswith("res")
            symbols[dd.group(1)] = {
                "name": dd.group(1),
                "line": i + 1,
                "type": "data",
                "directive": entry.directive,
                "section": section,
                "global": False,
                "local": False,
            }
            lines.append(entry)
            continue

        if head in DATA_DIRECTIVES:
            entry.kind = "data"
            entry.directive = head
            entry.args = split_operands(body[len(tokens[0]) :])
            entry.unit = DATA_DIRECTIVES[head]
            entry.reserve = head.startswith("res") or "space" in head or "zero" in head
            lines.append(entry)
            continue

        if (
            head in CONTROL_DIRECTIVES
            or head.startswith("%")
            or (head.startswith(".") and head[1:] not in ISA)
        ):
            entry.kind = "directive"
            entry.directive = head.lstrip(".")
            entry.args = [a.strip(",:") for a in tokens[1:]]
            if head in ("section", "segment", ".section"):
                section = (entry.args[0] if entry.args else "").lstrip(".").strip('",')
                entry.section = section
                entry.new_section = section
            elif re.fullmatch(r"\.?(text|data|bss|rodata|const|code)", head):
                section = head.lstrip(".")
                entry.section = section
                entry.new_section = section
            if entry.directive in ("global", "globl", "export", "public"):
                for a in entry.args:
                    s = symbols.setdefault(
                        a,
                        {
                            "name": a,
                            "line": i + 1,
                            "type": "label",
                            "section": section,
                            "global": False,
                            "local": False,
                        },
                    )
                    s["global"] = True
            if entry.directive.startswith("extern"):
                for a in entry.args:
                    symbols[a] = {
                        "name": a,
                        "line": i + 1,
                        "type": "extern",
                        "section": section,
                        "global": True,
                        "local": False,
                    }
            lines.append(entry)
            continue

        prefix = None
        if head in ("rep", "repe", "repne", "repz", "repnz", "lock") and len(tokens) > 1:
            prefix = head
            tokens = tokens[1:]
            body = " ".join(tokens)

        mnemonic = tokens[0].lower()
        operand_text = body[len(tokens[0]) :].strip()
        operands = split_operands(operand_text)

        att_size: Optional[int] = None
        if flavor == "att":
            att_size = att_operand_size(mnemonic, normalize_att(mnemonic, [])[0])
            mnemonic, operands = normalize_att(mnemonic, operands)

        entry.kind = "instruction"
        entry.prefix = prefix
        entry.mnemonic = mnemonic
        entry.operands = [classify_operand(o) for o in operands]
        if att_size:
            # In AT&T the width of the access comes from the mnemonic suffix:
            # apply it to the memory operands that did not declare their own
            # size.
            for operand in entry.operands:
                if operand.type == "mem" and operand.size is None:
                    operand.size = att_size
        entry.known = mnemonic in ISA
        lines.append(entry)

    program = Program(lines=lines, symbols=symbols, flavor=flavor, source=text)
    log_event(
        logger,
        "parsed",
        level=10,
        flavor=flavor,
        lines=len(lines),
        instructions=len(program.instructions),
        symbols=len(symbols),
    )
    return program
