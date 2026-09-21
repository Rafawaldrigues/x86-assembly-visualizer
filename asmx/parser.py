"""Parser de assembly x86-64: NASM/Intel, MASM e GAS/AT&T.

O parser é tolerante de propósito: ele nunca recusa um arquivo. Cada linha vira
um :class:`Line` com o que foi possível reconhecer — rótulo, dado, diretiva ou
instrução —, e o que ficou estranho aparece depois no validador, com número de
linha. Assim o estudante vê a explicação do que escreveu mesmo quando o
assembler real reclamaria.

O dialeto é detectado pelo conteúdo (:func:`detect_flavor`): ``%rax``/``$10``
indicam AT&T, ``.code``/``PROC`` indicam MASM, e o resto é tratado como
NASM/Intel. Em AT&T os operandos são invertidos na entrada para que todo o
resto do programa trabalhe sempre na ordem Intel (destino primeiro).

Example:
    >>> from asmx.parser import parse
    >>> programa = parse("mov rax, 1\\nadd rax, 0x10")
    >>> [i.mnemonic for i in programa.instructions]
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
    """Um operando já classificado.

    Attributes:
        text: Texto original do operando, como apareceu no fonte.
        type: ``reg``, ``imm``, ``mem``, ``sym``, ``expr`` ou ``unknown``.
        size: Tamanho em bytes, quando declarado (``qword`` -> 8) ou tirado do
            registrador.
        reg: Nome do registrador em minúsculas, quando é um registrador.
        value: Valor numérico, quando é um imediato.
        inner: Conteúdo de dentro dos colchetes, quando é acesso à memória.
        regs: Registradores usados no cálculo do endereço.
        symbol: Símbolo referenciado (variável ou rótulo).
        is_char: Marca o imediato que veio de um literal de caractere.
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
    """Uma linha do fonte com tudo o que o parser conseguiu extrair.

    Attributes:
        n: Número da linha no arquivo (1-based).
        raw: Linha original, sem alterações.
        comment: Comentário que sobrou da linha.
        kind: ``empty``, ``label``, ``data``, ``directive`` ou ``instruction``.
        label: Rótulo definido na linha, quando houver.
        local_label: Se o rótulo começa com ``.`` ou ``@`` (escopo local).
        directive: Diretiva do montador (``section``, ``db``, ``equ``...).
        args: Argumentos da diretiva ou da declaração de dados.
        unit: Tamanho da unidade da diretiva, em bytes.
        reserve: Se a diretiva só reserva espaço (``resb``, ``.space``).
        mnemonic: Mnemônico da instrução, em minúsculas.
        prefix: Prefixo da instrução (``rep``, ``lock``).
        operands: Operandos já classificados.
        known: Se o mnemônico existe no acervo.
        section: Seção em vigor na linha.
        func: Função (rótulo não local anterior) em que a linha está.
        new_section: Seção aberta nesta própria linha.
        labels: Rótulos imediatamente antes da instrução.
        idx: Índice entre as instruções do programa.
        block: Índice do bloco básico a que a instrução pertence.
        sem: Semântica preenchida pelo analisador.
        addr: Endereço simulado do dado, na máquina virtual.
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
    idx: Optional[int] = None  # índice entre as instruções
    block: Optional[int] = None
    sem: Optional[Any] = None
    addr: Optional[int] = None

    @property
    def text(self) -> str:
        """Linha sem espaços nas pontas.

        Returns:
            O texto de ``raw`` já aparado.
        """
        return self.raw.strip()


@dataclass
class Program:
    """O fonte inteiro já lido.

    Attributes:
        lines: Todas as linhas, na ordem do arquivo.
        symbols: Rótulos, dados e símbolos externos, por nome.
        flavor: Dialeto detectado: ``intel``, ``masm`` ou ``att``.
        source: Texto original do arquivo.
    """

    lines: List[Line]
    symbols: Dict[str, Dict[str, Any]]
    flavor: str
    source: str

    @property
    def instructions(self) -> List[Line]:
        """Somente as linhas que são instruções de máquina.

        Returns:
            Lista de :class:`Line` com ``kind == "instruction"``.
        """
        return [linha for linha in self.lines if linha.kind == "instruction"]


LABEL_RE = re.compile(r"^([A-Za-z_.$?@][\w.$@?]*)\s*:\s*(.*)$")
MASM_PROC_RE = re.compile(r"^([A-Za-z_?@][\w?@]*)\s+(proc|endp)\b", re.I)
DATA_DEF_RE = re.compile(
    r"^([A-Za-z_.$][\w.$@]*)\s+(db|dw|dd|dq|dt|resb|resw|resd|resq|equ|times)\b\s*(.*)$", re.I
)
NUM_RE = re.compile(r"^\$?-?(0x[0-9a-f]+|[0-9a-f]+h|[01]+b|0o[0-7]+|\d+)$", re.I)
SYM_RE = re.compile(r"^[A-Za-z_.$][\w.$@]*$")


def strip_comment(line: str) -> Tuple[str, str]:
    """Separa código e comentário sem estragar o que está entre aspas.

    Aceita ``;`` em qualquer posição, ``#`` quando não colado a uma palavra
    (para não confundir com imediato do AT&T) e ``//``.

    Args:
        line: Linha crua do arquivo.

    Returns:
        Tupla ``(código, comentário)``; o comentário inclui o marcador e vem
        vazio quando não existe.

    Example:
        >>> strip_comment('db "a;b"   ; nota')
        ('db "a;b"   ', '; nota')
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
    """Divide os operandos pela vírgula, respeitando colchetes, parênteses e aspas.

    Args:
        text: Trecho depois do mnemônico.

    Returns:
        Lista de operandos já sem espaços nas pontas.

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
    """Converte um número escrito em qualquer das bases do assembly.

    Entende ``0x1f``, ``1fh``, ``1010b``, ``0o17``, decimal, sinal de menos e o
    ``$`` do AT&T. Texto que não é número vira ``0`` em vez de exceção, porque o
    parser não pode parar por causa de uma constante simbólica.

    Args:
        token: Texto do número.

    Returns:
        O valor inteiro, negativo quando havia ``-`` na frente.

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
    """Descobre que tipo de operando é esse texto.

    Reconhece tamanho declarado (``qword ptr [rbx]``), acesso à memória com
    registradores e símbolos, registrador puro, imediato numérico, literal de
    caractere, símbolo e expressão aritmética.

    Args:
        text: Texto do operando.

    Returns:
        O :class:`Operand` preenchido (``type == "unknown"`` quando nada bate).

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
    """Descobre o dialeto do fonte.

    Args:
        text: Código completo.

    Returns:
        ``"att"`` quando há marcas suficientes de AT&T (``%rax``, ``$10``),
        ``"masm"`` quando aparecem ``.code``/``.model`` ou ``PROC``/``ENDP``,
        e ``"intel"`` no caso restante.

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
    """Converte um endereço do AT&T para a forma Intel.

    ``-8(%rbp)`` vira ``[rbp-8]`` e ``(%rax,%rcx,4)`` vira ``[rax+rcx*4]``.

    Args:
        expr: Texto do operando em AT&T.

    Returns:
        O mesmo endereço escrito entre colchetes, no estilo Intel.
    """

    def repl(m: Match[str]) -> str:
        """Reescreve um endereço ``disp(base,index,escala)`` entre colchetes.

        Returns:
            O endereço no formato Intel.
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


def normalize_att(mnemonic: str, operands: List[str]) -> Tuple[str, List[str]]:
    """Ajusta uma instrução em AT&T para a forma canônica Intel.

    Tira ``%`` e ``$``, converte endereços, remove o sufixo de tamanho do
    mnemônico (``movq`` -> ``mov``) e inverte a ordem dos dois operandos.

    Args:
        mnemonic: Mnemônico como veio do arquivo.
        operands: Operandos em AT&T.

    Returns:
        Tupla ``(mnemônico, operandos)`` no padrão usado pelo resto do código.
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
    """Lê o código inteiro e devolve as linhas classificadas.

    Args:
        text: Código fonte em NASM/Intel, MASM ou GAS/AT&T.

    Returns:
        O :class:`Program` com linhas, símbolos e dialeto detectado.

    Example:
        >>> programa = parse("section .data\\nx dq 7\\nsection .text\\nf:\\n mov rax, [x]\\n ret")
        >>> programa.symbols["x"]["type"], len(programa.instructions)
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

        if flavor == "att":
            mnemonic, operands = normalize_att(mnemonic, operands)

        entry.kind = "instruction"
        entry.prefix = prefix
        entry.mnemonic = mnemonic
        entry.operands = [classify_operand(o) for o in operands]
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
