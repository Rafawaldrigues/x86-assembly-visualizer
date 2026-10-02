"""Static validation: finds what will probably break before running.

Each rule is a function that receives the :class:`~asmx.analyzer.Analysis` and
returns a list of :class:`Problem`; all of them run in :func:`validate`, in the
order of :data:`ALL_CHECKS`. The codes go from STR (strings) and DIV (division)
to SEC (sections) and REG (register read before receiving a value).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from .analyzer import Analysis
from .isa import CALLEE_SAVED_SYSV, CALLEE_SAVED_WIN, REG_INFO, is_cond_jump

ERROR = "error"
WARNING = "warning"
INFO = "info"
SEVERITY_ORDER = {ERROR: 0, WARNING: 1, INFO: 2}


@dataclass
class Problem:
    """An issue found by the static validation.

    Attributes:
        line: Source line where the issue appears.
        severity: ``error``, ``warning`` or ``info``.
        code: Rule code (``DIV001``, ``STR003``...).
        message: What is wrong.
        hint: How to fix it.
    """

    line: int
    severity: str
    code: str
    message: str
    hint: str = ""

    def __str__(self) -> str:
        """Formats the issue into one readable line.

        Returns:
            Text in the ``L12 [error] DIV001: message`` format.
        """
        return "L%d [%s] %s: %s" % (self.line, self.severity, self.code, self.message)

    def to_dict(self) -> Dict[str, Any]:
        """Converts the issue into a dictionary ready for JSON.

        Returns:
            Dictionary with ``line``, ``severity``, ``code``, ``message`` and
            ``hint``.
        """
        return {
            "line": self.line,
            "severity": self.severity,
            "code": self.code,
            "message": self.message,
            "hint": self.hint,
        }


def _base(reg: Optional[str]) -> Optional[str]:
    """Finds the 64-bit register behind a partial name.

    Args:
        reg: Register name, or ``None``.

    Returns:
        The base name (``rax``, ``rsp``...) or ``None`` when it is not a register.
    """
    return REG_INFO[reg]["base"] if reg and reg in REG_INFO else None


def _func_ranges(analysis: Analysis) -> Dict[str, List[Any]]:
    """Groups the instructions by declared function.

    Args:
        analysis: Source analysis.

    Returns:
        Dictionary ``function -> instructions``; code without a label goes in as
        ``<unlabeled>``.
    """
    groups: Dict[str, List[Any]] = {}
    for ins in analysis.instrs:
        groups.setdefault(ins.func or "<unlabeled>", []).append(ins)
    return groups


# --------------------------------------------------------------- strings --
def check_strings(analysis: Analysis) -> List[Problem]:
    """Checks the strings of the data lines.

    Detects unterminated quotes (STR002), non-ASCII characters (STR001), literal
    control characters (STR004) and backslashes that may not be an escape
    (STR005).

    Args:
        analysis: Source analysis.

    Returns:
        The list of issues found, in line order.
    """
    out = []
    for source_line in analysis.program.lines:
        if source_line.kind != "data" or source_line.reserve:
            continue
        # The parser already separated comment from code respecting the quotes,
        # so the code is the beginning of the raw line, without the trailing
        # comment. Cutting at ";" by hand would give a false positive on a
        # string that contains a semicolon (for example a User-Agent
        # "Mozilla/5.0 (compatible; ASMX/1.0)").
        code = (
            source_line.raw[: len(source_line.raw) - len(source_line.comment)]
            if source_line.comment
            else source_line.raw
        )
        quotes = code.count('"')
        simple = code.count("'")
        if quotes % 2 or simple % 2:
            out.append(
                Problem(
                    source_line.n,
                    ERROR,
                    "STR002",
                    "unterminated quotes on this data line",
                    "the assembler will swallow the rest of the line; close the string",
                )
            )
        for arg in source_line.args:
            m = re.fullmatch(r"(['\"])([\s\S]*)\1", arg.strip())
            if not m:
                continue
            source_text = m.group(2)
            outside = [c for c in source_text if ord(c) > 127]
            if outside:
                out.append(
                    Problem(
                        source_line.n,
                        WARNING,
                        "STR001",
                        "the string has a non-ASCII character (%s) — each one becomes "
                        "2 or more bytes in UTF-8" % " ".join(sorted(set(outside))),
                        "the size computed with $ - label will not match the number of "
                        "letters; switch to ASCII or count the real bytes",
                    )
                )
            ctrl = [c for c in source_text if ord(c) < 32 and c not in "\n\t"]
            if ctrl:
                out.append(
                    Problem(
                        source_line.n,
                        WARNING,
                        "STR004",
                        "the string has a literal control character",
                        'prefer writing the numeric code: db "text", 10',
                    )
                )
            if "\\" in source_text and not re.search(r"\\[nt0\\]", source_text):
                out.append(
                    Problem(
                        source_line.n,
                        INFO,
                        "STR005",
                        "the backslash is not an escape in every assembler syntax",
                        "in NASM only double-quoted strings accept escapes; check the byte "
                        "that will really come out",
                    )
                )
    return out


def check_unterminated(analysis: Analysis) -> List[Problem]:
    """Checks data strings without a 0 terminator and without a size computed by equ.

    Detects the STR006 case: the string does not end in 0 and no
    ``label_len equ $ - label`` says where it ends.

    Args:
        analysis: Source analysis.

    Returns:
        The list of STR006 issues found.
    """
    out = []
    sizes = set()
    for source_line in analysis.program.lines:
        if source_line.kind == "data" and source_line.directive == "equ" and source_line.args:
            m = re.search(r"\$\s*-\s*([A-Za-z_.$][\w.$]*)", source_line.args[0])
            if m:
                sizes.add(m.group(1))
    for source_line in analysis.program.lines:
        if (
            source_line.kind != "data"
            or source_line.reserve
            or not source_line.label
            or not source_line.args
        ):
            continue
        has_text = any(re.fullmatch(r"(['\"])[\s\S]*\1", a.strip()) for a in source_line.args)
        if not has_text or source_line.label in sizes:
            continue
        last_item = source_line.args[-1].strip()
        if re.fullmatch(r"-?0+", last_item) or re.fullmatch(r"\d+", last_item):
            continue
        out.append(
            Problem(
                source_line.n,
                WARNING,
                "STR006",
                "the string %s does not end in 0 nor has a computed size" % source_line.label,
                "without a terminator and without '%s_len equ $ - %s' there is no way to know "
                "where it ends; whoever prints it will guess the size"
                % (source_line.label, source_line.label),
            )
        )
    return out


def check_cstrings(analysis: Analysis) -> List[Problem]:
    """Checks strings passed to functions that expect a null terminator.

    Detects the STR003 case: a symbol without a trailing 0 is loaded into a
    register and then handed to ``printf``, ``puts``, ``MessageBox`` and the
    like.

    Args:
        analysis: Source analysis.

    Returns:
        The list of STR003 issues found.
    """
    out = []
    machine_syms = {}
    for source_line in analysis.program.lines:
        if source_line.kind == "data" and source_line.label and not source_line.reserve:
            ends_zero = bool(source_line.args) and re.fullmatch(
                r"-?0+", source_line.args[-1].strip()
            )
            machine_syms[source_line.label] = (source_line.n, ends_zero)

    consumers = re.compile(
        r"printf|puts|strlen|strcpy|MessageBox|CreateFile|LoadLibrary|"
        r"GetProcAddress|OutputDebugString",
        re.I,
    )
    pending = {}
    for ins in analysis.instrs:
        if ins.mnemonic in ("mov", "lea") and len(ins.operands) > 1:
            sym = ins.operands[1].symbol
            if sym in machine_syms:
                pending[_base(ins.operands[0].reg)] = sym
        if ins.mnemonic == "call" and ins.operands:
            target_name = ins.operands[0].symbol or ins.operands[0].text
            if consumers.search(str(target_name)):
                for sym in set(pending.values()):
                    line, ends_zero = machine_syms[sym]
                    if not ends_zero:
                        out.append(
                            Problem(
                                line,
                                ERROR,
                                "STR003",
                                "the string %s is passed to %s but does not end in 0"
                                % (sym, target_name),
                                'add the terminator: %s db "...", 0' % sym,
                            )
                        )
            pending = {}
    return out


# -------------------------------------------------------------- division --
def check_division(analysis: Analysis) -> List[Problem]:
    """Checks the divisions inside each basic block.

    Detects DIV/IDIV without RDX prepared (DIV001), literal division by zero
    (DIV002) and an immediate divisor, which the instruction does not accept
    (DIV003).

    Args:
        analysis: Source analysis.

    Returns:
        The list of issues found.
    """
    out = []
    for b in analysis.blocks:
        prepared = False
        for ins in b.instrs:
            m = ins.mnemonic
            if m in ("cqo", "cdq"):
                prepared = True
            if (
                m == "xor"
                and len(ins.operands) > 1
                and _base(ins.operands[0].reg) == "rdx"
                and _base(ins.operands[1].reg) == "rdx"
            ):
                prepared = True
            if (
                m == "mov"
                and ins.operands
                and _base(ins.operands[0].reg) == "rdx"
                and len(ins.operands) > 1
                and ins.operands[1].type == "imm"
                and ins.operands[1].value == 0
            ):
                prepared = True
            if m in ("div", "idiv"):
                if not prepared:
                    correction = "XOR RDX, RDX" if m == "div" else "CQO"
                    out.append(
                        Problem(
                            ins.n,
                            ERROR,
                            "DIV001",
                            "%s without preparing RDX in this block" % m.upper(),
                            "the CPU divides RDX:RAX; with garbage in RDX the quotient overflows "
                            "and raises an exception. Put %s before it." % correction,
                        )
                    )
                op = ins.operands[0] if ins.operands else None
                if op is not None and op.type == "imm":
                    if op.value == 0:
                        out.append(
                            Problem(
                                ins.n,
                                ERROR,
                                "DIV002",
                                "literal division by zero",
                                "the process dies with a #DE exception",
                            )
                        )
                    else:
                        out.append(
                            Problem(
                                ins.n,
                                ERROR,
                                "DIV003",
                                "DIV/IDIV does not accept an immediate operand",
                                "load the divisor into a register first",
                            )
                        )
                prepared = False
    return out


# ----------------------------------------------------------------- stack --
def check_stack(analysis: Analysis) -> List[Problem]:
    """Checks the stack balance in each function that ends in RET.

    Detects a function that returns with extra values on the stack (STK001) or
    that pops more than it pushed (STK002).

    Args:
        analysis: Source analysis.

    Returns:
        The list of issues found.
    """
    out = []
    for name, instrs in _func_ranges(analysis).items():
        if not any(i.mnemonic.startswith("ret") for i in instrs):
            continue
        balance = 0
        first_item = instrs[0].n
        for ins in instrs:
            if ins.mnemonic == "push":
                balance += 1
            elif ins.mnemonic == "pop":
                balance -= 1
            elif ins.mnemonic == "leave":
                balance = 0
            elif ins.mnemonic.startswith("ret"):
                if balance > 0:
                    out.append(
                        Problem(
                            ins.n,
                            ERROR,
                            "STK001",
                            "%s returns with %d extra value(s) on the stack" % (name, balance),
                            "every PUSH needs its matching POP before the RET, otherwise the RET "
                            "takes the wrong value and jumps to an invalid address",
                        )
                    )
                elif balance < 0:
                    out.append(
                        Problem(
                            ins.n,
                            ERROR,
                            "STK002",
                            "%s pops %d more value(s) than it pushed" % (name, -balance),
                            "the function is consuming the caller stack",
                        )
                    )
                balance = 0
        _ = first_item
    return out


def check_missing_ret(analysis: Analysis) -> List[Problem]:
    """Checks functions called with CALL that have no RET and no exit jump.

    Detects the STK003 case: without RET or JMP, execution slips into the
    following code.

    Args:
        analysis: Source analysis.

    Returns:
        The list of STK003 issues found.
    """
    out = []
    called_functions = {
        (i.operands[0].symbol or i.operands[0].text)
        for i in analysis.instrs
        if i.mnemonic == "call" and i.operands
    }
    for name, instrs in _func_ranges(analysis).items():
        if name not in called_functions:
            continue
        has_exit = any(i.mnemonic.startswith("ret") or i.mnemonic == "jmp" for i in instrs)
        if not has_exit:
            out.append(
                Problem(
                    instrs[0].n,
                    ERROR,
                    "STK003",
                    "%s is called with CALL but has no RET" % name,
                    "execution will slip into the following code",
                )
            )
    return out


# -------------------------------------------------------------------- ABI -
def check_abi(analysis: Analysis) -> List[Problem]:
    """Checks the respect for the ABI of the detected platform.

    Detects a preserved register changed without PUSH/POP (ABI002) and, on
    Windows, a call without the 32 bytes of shadow space (ABI001).

    Args:
        analysis: Source analysis.

    Returns:
        The list of issues found.
    """
    out = []
    win = analysis.platform.os == "windows"
    preserved = CALLEE_SAVED_WIN if win else CALLEE_SAVED_SYSV
    for name, instrs in _func_ranges(analysis).items():
        if not any(i.mnemonic.startswith("ret") for i in instrs):
            continue
        saved_regs = {
            _base(i.operands[0].reg)
            for i in instrs
            if i.mnemonic == "push" and i.operands and i.operands[0].type == "reg"
        }
        for ins in instrs:
            if (
                ins.mnemonic in ("mov", "add", "sub", "xor", "lea", "inc", "dec", "pop")
                and ins.operands
                and ins.operands[0].type == "reg"
            ):
                base = _base(ins.operands[0].reg)
                if base in preserved and base not in saved_regs and base != "rbp":
                    out.append(
                        Problem(
                            ins.n,
                            WARNING,
                            "ABI002",
                            "%s changes %s without saving it first" % (name, base.upper()),
                            "%s must go back intact to the caller (%s). Do a PUSH "
                            "at the start and a POP at the end."
                            % (base.upper(), analysis.platform.abi["name"]),
                        )
                    )
                    saved_regs.add(base)  # warns only once per register
        if win:
            reservation = any(
                i.mnemonic == "sub"
                and i.operands
                and _base(i.operands[0].reg) == "rsp"
                and len(i.operands) > 1
                and i.operands[1].type == "imm"
                and i.operands[1].value >= 32
                for i in instrs
            )
            call_ins = [i for i in instrs if i.mnemonic == "call"]
            if call_ins and not reservation:
                out.append(
                    Problem(
                        call_ins[0].n,
                        ERROR,
                        "ABI001",
                        "call without reserved shadow space",
                        "the Windows ABI requires SUB RSP, 40 (32 of shadow space + alignment) "
                        "before calling any function",
                    )
                )
    return out


# -------------------------------------------------------------- operands --
def check_operands(analysis: Analysis) -> List[Problem]:
    """Checks operands and mnemonics instruction by instruction.

    Detects an unknown mnemonic (UNK001), memory on both sides (MEM002),
    ambiguous memory size (MEM001), an immediate that does not fit in the target
    (IMM001), a 64-bit immediate outside MOV (IMM002) and a shift larger than
    the operand (SHF001).

    Args:
        analysis: Source analysis.

    Returns:
        The list of issues found.
    """
    out = []
    for ins in analysis.instrs:
        ops = ins.operands
        if not ins.known:
            out.append(
                Problem(
                    ins.n,
                    WARNING,
                    "UNK001",
                    "unknown mnemonic: %s" % ins.mnemonic,
                    "it may be a macro, a SIMD instruction outside the collection or a typo",
                )
            )
            continue
        if len(ops) >= 2 and ops[0].type == "mem" and ops[1].type == "mem":
            out.append(
                Problem(
                    ins.n,
                    ERROR,
                    "MEM002",
                    "there is no instruction with memory on both sides",
                    "go through a register: MOV RAX, [source] / MOV [target], RAX",
                )
            )
        if (
            ins.mnemonic in ("mov", "add", "sub", "cmp", "and", "or", "xor", "test")
            and len(ops) >= 2
            and ops[0].type == "mem"
            and ops[1].type == "imm"
            and not ops[0].size
        ):
            out.append(
                Problem(
                    ins.n,
                    ERROR,
                    "MEM001",
                    "ambiguous operand size",
                    "the assembler does not know whether to write 1, 2, 4 or 8 bytes. Write "
                    "%s byte [..], %s" % (ins.mnemonic, ops[1].text),
                )
            )
        if len(ops) >= 2 and ops[0].type == "reg" and ops[1].type == "imm":
            size = REG_INFO[ops[0].reg]["size"]
            unsigned_limit = (1 << (size * 8)) - 1
            signed_limit = 1 << (size * 8 - 1)
            v = ops[1].value
            if v > unsigned_limit or v < -signed_limit:
                out.append(
                    Problem(
                        ins.n,
                        ERROR,
                        "IMM001",
                        "the value %s does not fit in %s (%d bits)"
                        % (ops[1].text, ops[0].text, size * 8),
                        "the assembler truncates or refuses it. Use a larger register or "
                        "review the constant.",
                    )
                )
            elif size == 8 and v > 0xFFFFFFFF and ins.mnemonic != "mov":
                out.append(
                    Problem(
                        ins.n,
                        WARNING,
                        "IMM002",
                        "a 64-bit immediate is only accepted in MOV",
                        "instructions like ADD/CMP accept at most 32 bits with sign; load the "
                        "value into another register first",
                    )
                )
        if (
            ins.mnemonic in ("shl", "shr", "sal", "sar", "rol", "ror")
            and len(ops) >= 2
            and ops[1].type == "imm"
            and ops[0].type == "reg"
        ):
            bits = REG_INFO[ops[0].reg]["size"] * 8
            if int(ops[1].value or 0) >= bits:
                out.append(
                    Problem(
                        ins.n,
                        WARNING,
                        "SHF001",
                        "shift of %d bits on a %d-bit operand" % (int(ops[1].value or 0), bits),
                        "the processor uses only the low 5 or 6 bits of the count; "
                        "the result is not what it looks like",
                    )
                )
    return out


# --------------------------------------------------------------- symbols --
def check_symbols(analysis: Analysis) -> List[Problem]:
    """Checks that every used symbol exists and that every label is used.

    Detects a jump or call to a nonexistent target (SYM001), a label that is
    never used (SYM002) and a referenced symbol without a definition (SYM003).

    Args:
        analysis: Source analysis.

    Returns:
        The list of issues found.
    """
    out = []
    defined_names = set(analysis.label_at) | {
        k for k, v in analysis.symbols.items() if v["type"] in ("data", "extern")
    }
    used_names = set()
    for ins in analysis.instrs:
        for op in ins.operands:
            sym = op.symbol if op.type in ("sym", "mem") else None
            if not sym:
                continue
            used_names.add(sym)
            if sym not in defined_names:
                out.append(
                    Problem(
                        ins.n,
                        ERROR,
                        "SYM003",
                        "%s is not defined anywhere" % sym,
                        "declare the data (%s dq 0), create the label or use EXTERN %s"
                        % (sym, sym),
                    )
                )
        if ins.mnemonic in ("call", "jmp") or is_cond_jump(ins.mnemonic):
            if ins.operands:
                target_name = ins.operands[0].symbol or ins.operands[0].text
                used_names.add(target_name)
                if target_name not in defined_names and not re.fullmatch(
                    r"[\[\]\d+*x-]+", target_name
                ):
                    out.append(
                        Problem(
                            ins.n,
                            ERROR,
                            "SYM001",
                            "%s points to %s, which does not exist in this file"
                            % (ins.mnemonic.upper(), target_name),
                            "define the label or declare EXTERN %s" % target_name,
                        )
                    )
    for name, info in analysis.symbols.items():
        if (
            info["type"] == "label"
            and not info.get("global")
            and name not in used_names
            and name not in ("_start", "main", "start", "WinMain")
        ):
            out.append(
                Problem(
                    info["line"],
                    INFO,
                    "SYM002",
                    "the label %s is never used" % name,
                    "dead code or a label misspelled somewhere else",
                )
            )
    return out


def check_entry(analysis: Analysis) -> List[Problem]:
    """Checks the program entry point.

    Detects the absence of ``_start``/``main`` (ENT001) and an entry point that
    exists but was not declared ``global`` (ENT002).

    Args:
        analysis: Source analysis.

    Returns:
        The list of issues found.
    """
    out = []
    entry_labels = [n for n in ("_start", "main", "start", "WinMain") if n in analysis.label_at]
    if not entry_labels and analysis.instrs:
        out.append(
            Problem(
                analysis.instrs[0].n,
                WARNING,
                "ENT001",
                "no entry point (_start, main) found",
                "the linker needs to know where to start",
            )
        )
    for e in entry_labels:
        info = analysis.symbols.get(e, {})
        if not info.get("global"):
            out.append(
                Problem(
                    info.get("line", 1),
                    ERROR,
                    "ENT002",
                    "%s exists but was not declared global" % e,
                    "add: global %s" % e,
                )
            )
    return out


def check_exit(analysis: Analysis) -> List[Problem]:
    """Checks whether the program has an explicit exit.

    Detects the EXIT001 case: without ``exit`` (syscall 60 on Linux),
    ``ExitProcess`` or RET in ``main``/``WinMain``, execution continues through
    memory that is not code.

    Args:
        analysis: Source analysis.

    Returns:
        The list with the EXIT001 issue, or empty when there is an exit.
    """
    if not analysis.instrs:
        return []
    src = analysis.program.source
    has_exit = (
        (re.search(r"\b(60|0x3c|231)\b", src) and "syscall" in src.lower())
        or re.search(r"ExitProcess", src, re.I)
        or any(
            i.mnemonic.startswith("ret") and (i.func in ("main", "WinMain"))
            for i in analysis.instrs
        )
    )
    if not has_exit:
        return [
            Problem(
                analysis.instrs[-1].n,
                WARNING,
                "EXIT001",
                "the program has no explicit exit",
                "without exit (syscall 60 on Linux, ExitProcess on Windows) execution "
                "continues through memory that is not code and the process crashes",
            )
        ]
    return []


# ------------------------------------------------------------------ flow --
def check_flow(analysis: Analysis) -> List[Problem]:
    """Checks the flow between basic blocks.

    Detects an unreachable block (FLOW001) and a loop that goes back without
    changing a register or memory (FLOW002).

    Args:
        analysis: Source analysis.

    Returns:
        The list of issues found.
    """
    out = []
    entry_labels = {"_start", "main", "start", "WinMain"}
    call_targets = {
        (i.operands[0].symbol or i.operands[0].text)
        for i in analysis.instrs
        if i.mnemonic == "call" and i.operands
    }
    for b in analysis.blocks:
        external_names = [e for e in b.pred if e.target != b.id]
        if b.id == 0 or external_names:
            continue
        if b.name in entry_labels or b.name in call_targets or b.func in call_targets:
            continue
        if analysis.symbols.get(b.name, {}).get("global"):
            continue
        out.append(
            Problem(
                b.instrs[0].n,
                WARNING,
                "FLOW001",
                "block %s is never reached" % b.name,
                "no jump or call leads here — dead code or a wrong label",
            )
        )

    for b in analysis.blocks:
        last = b.instrs[-1]
        return_ins = [e for e in b.succ if e.target <= b.id]
        if not return_ins:
            continue
        changes = False
        for ins in b.instrs:
            if ins.mnemonic in (
                "inc",
                "dec",
                "add",
                "sub",
                "mul",
                "imul",
                "div",
                "idiv",
                "shl",
                "shr",
                "loop",
                "syscall",
                "call",
                "xor",
                "and",
                "or",
                "mov",
                "movzx",
                "movsx",
                "pop",
            ):
                changes = True
                break
        if not changes:
            out.append(
                Problem(
                    last.n,
                    ERROR,
                    "FLOW002",
                    "loop with nothing that changes the stop condition",
                    "this block goes back without changing a register or memory: " "infinite loop",
                )
            )
    return out


# -------------------------------------------------------------- syscalls --
def check_syscalls(analysis: Analysis) -> List[Problem]:
    """Checks the use of SYSCALL inside the blocks.

    Detects a SYSCALL without RAX defined in the same block (SYS001) and a read
    of RCX or R11 after a SYSCALL, which destroys both (SYS002).

    Args:
        analysis: Source analysis.

    Returns:
        The list of issues found.
    """
    out = []
    for b in analysis.blocks:
        rax_defined = False
        for ins in b.instrs:
            if (
                ins.operands
                and ins.operands[0].type == "reg"
                and _base(ins.operands[0].reg) == "rax"
            ):
                rax_defined = True
            if ins.mnemonic == "syscall":
                if not rax_defined:
                    out.append(
                        Problem(
                            ins.n,
                            WARNING,
                            "SYS001",
                            "SYSCALL without defining RAX in this block",
                            "the service number comes from RAX; without it the kernel receives "
                            "a random request",
                        )
                    )
                rax_defined = False
        # RCX and R11 are destroyed by the syscall
        following = False
        for ins in b.instrs:
            if ins.mnemonic == "syscall":
                following = True
                continue
            if not following:
                continue
            for op in ins.operands[1:] if len(ins.operands) > 1 else []:
                if op.type == "reg" and _base(op.reg) in ("rcx", "r11"):
                    out.append(
                        Problem(
                            ins.n,
                            WARNING,
                            "SYS002",
                            "%s is read after a SYSCALL" % op.text.upper(),
                            "the SYSCALL destroys RCX and R11; save it before if you need "
                            "the value",
                        )
                    )
                    following = False
    return out


def check_sections(analysis: Analysis) -> List[Problem]:
    """Checks the use of the file sections.

    Detects instructions outside a code section (SEC001) and a write to a symbol
    in ``.rodata`` (SEC002).

    Args:
        analysis: Source analysis.

    Returns:
        The list of issues found.
    """
    out = []
    section_names = {
        source_line.new_section for source_line in analysis.program.lines if source_line.new_section
    }
    if (
        analysis.instrs
        and "text" not in section_names
        and "code" not in section_names
        and section_names
    ):
        out.append(
            Problem(
                analysis.instrs[0].n,
                WARNING,
                "SEC001",
                "there are instructions outside a code section",
                "declare section .text before the executable code",
            )
        )
    for ins in analysis.instrs:
        if ins.mnemonic == "mov" and ins.operands and ins.operands[0].type == "mem":
            sym = ins.operands[0].symbol
            info = analysis.symbols.get(sym or "", {})
            if info.get("section") == "rodata":
                out.append(
                    Problem(
                        ins.n,
                        ERROR,
                        "SEC002",
                        "write to %s, which is in .rodata" % sym,
                        ".rodata is read-only: the process gets SIGSEGV. "
                        "Move the variable to .data",
                    )
                )
    return out


def check_uninitialized(analysis: Analysis) -> List[Problem]:
    """Checks registers read before receiving any value.

    Detects the REG001 case: the register is not an argument of the function and
    was not written before, so the value is whatever was left over.

    Args:
        analysis: Source analysis.

    Returns:
        The list of REG001 issues found.
    """
    out = []
    plat_args = analysis.platform.abi["args"]
    for name, instrs in _func_ranges(analysis).items():
        written_regs = set(plat_args) | {"rsp", "rbp", "rip"}
        if name in ("_start", "start"):
            written_regs |= set()
        for ins in instrs:
            read_regs = []
            if ins.mnemonic in ("mov", "movzx", "movsx", "lea") and len(ins.operands) > 1:
                read_regs = ins.operands[1:]
            elif ins.mnemonic in ("add", "sub", "cmp", "test", "and", "or", "xor", "imul"):
                read_regs = ins.operands
            elif ins.mnemonic in ("push", "inc", "dec", "neg", "not", "div", "idiv", "mul"):
                read_regs = ins.operands
            for op in read_regs:
                regs = []
                if op.type == "reg":
                    regs = [_base(op.reg)]
                elif op.type == "mem":
                    regs = [_base(r) for r in op.regs]
                for r in regs:
                    if r and r not in written_regs:
                        out.append(
                            Problem(
                                ins.n,
                                WARNING,
                                "REG001",
                                "%s is read before receiving any value in %s" % (r.upper(), name),
                                "the value is whatever was left over; initialize the register",
                            )
                        )
                        written_regs.add(r)
            if (
                ins.operands
                and ins.operands[0].type == "reg"
                and ins.mnemonic not in ("cmp", "test", "push", "div", "idiv", "mul")
            ):
                written_regs.add(_base(ins.operands[0].reg))
            if ins.mnemonic in ("syscall", "call"):
                written_regs |= {"rax", "rcx", "r11"}
            if ins.mnemonic in ("div", "idiv", "mul"):
                written_regs |= {"rax", "rdx"}
    return out


ALL_CHECKS: List[Callable[[Analysis], List[Problem]]] = [
    check_strings,
    check_unterminated,
    check_cstrings,
    check_division,
    check_stack,
    check_missing_ret,
    check_abi,
    check_operands,
    check_symbols,
    check_entry,
    check_exit,
    check_flow,
    check_syscalls,
    check_sections,
    check_uninitialized,
]


def validate(analysis: Analysis) -> List[Problem]:
    """Runs every rule and returns the issues in severity order.

    A rule that blows up becomes an ``INT001`` issue, instead of taking the whole
    validation down.

    Args:
        analysis: Source analysis.

    Returns:
        The list of :class:`Problem` ordered by severity and by line.
    """
    problems: List[Problem] = []
    for check in ALL_CHECKS:
        try:
            problems.extend(check(analysis))
        except Exception as exc:  # noqa: BLE001 - one broken rule cannot stop the rest
            problems.append(
                Problem(
                    1,
                    INFO,
                    "INT001",
                    "internal failure in rule %s: %s" % (check.__name__, exc),
                )
            )
    problems.sort(key=lambda p: (SEVERITY_ORDER[p.severity], p.line))
    return problems


def summary(problems: List[Problem]) -> str:
    """Summarizes the validation in one line.

    Args:
        problems: List returned by :func:`validate`.

    Returns:
        Text like ``"2 error(s), 1 warning(s), 0 info(s)"``.
    """
    e = sum(1 for p in problems if p.severity == ERROR)
    a = sum(1 for p in problems if p.severity == WARNING)
    i = sum(1 for p in problems if p.severity == INFO)
    return "%d error(s), %d warning(s), %d info(s)" % (e, a, i)
