"""x86-64 knowledge base: instructions, registers, flags, syscalls.

The catalogue itself lives in ``asmx/data/isa.json`` and is loaded only once, at
import time. This module just gives it shape: tables ready for lookup
(:data:`ISA`, :data:`REG_INFO`, :data:`LINUX_SYSCALLS`) and the short functions
the rest of the program uses to ask "does this instruction exist?", "which
category is it in?" and "is this mnemonic a conditional branch?".

Example:
    >>> from asmx.isa import doc_for, category_of, is_cond_jump
    >>> doc_for("mov")["cat"]
    'data'
    >>> is_cond_jump("jne"), is_cond_jump("jmp")
    (True, False)
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional, Set

from .logging_setup import get_logger, log_event

logger = get_logger(__name__)

_DATA = os.path.join(os.path.dirname(__file__), "data", "isa.json")

with open(_DATA, encoding="utf-8") as _f:
    _RAW: Dict[str, Any] = json.load(_f)

#: Instruction categories (key -> label and explanation).
CATEGORIES: Dict[str, Dict[str, Any]] = _RAW["CATEGORIES"]

#: Catalogue of documented mnemonics: lowercase key -> full record.
ISA: Dict[str, Dict[str, Any]] = _RAW["ISA"]

#: Branch conditions: suffix (``e``, ``ne``...) -> name and explanation.
CONDITIONS: Dict[str, List[str]] = _RAW["CONDITIONS"]

#: Register documentation.
REG_DOC: Dict[str, str] = _RAW["REG_DOC"]

#: Processor flag documentation.
FLAG_DOC: Dict[str, str] = _RAW["FLAG_DOC"]

#: Linux x86-64 syscalls, indexed by number.
LINUX_SYSCALLS: Dict[int, List[str]] = {int(k): v for k, v in _RAW["LINUX_SYSCALLS"].items()}

#: Windows API functions (kernel32/user32) used by the examples.
WIN_APIS: Dict[str, List[str]] = _RAW["WIN_APIS"]

#: 64-bit registers, in the canonical ABI order.
REGS64: List[str] = [
    "rax",
    "rcx",
    "rdx",
    "rbx",
    "rsp",
    "rbp",
    "rsi",
    "rdi",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
]

#: Registers the called function must preserve in System V AMD64.
CALLEE_SAVED_SYSV: List[str] = ["rbx", "rbp", "r12", "r13", "r14", "r15"]

#: Registers the called function must preserve in the Microsoft ABI.
CALLEE_SAVED_WIN: List[str] = ["rbx", "rbp", "rdi", "rsi", "r12", "r13", "r14", "r15"]

#: Function argument order in System V AMD64.
ARG_REGS_SYSV: List[str] = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]

#: Syscall argument order in Linux x86-64 (RCX gives way to R10).
ARG_REGS_SYSCALL: List[str] = ["rdi", "rsi", "rdx", "r10", "r8", "r9"]

#: Function argument order in the Microsoft ABI.
ARG_REGS_WIN: List[str] = ["rcx", "rdx", "r8", "r9"]


def _build_reg_info() -> Dict[str, Dict[str, Any]]:
    """Builds the register map, including the partial names.

    Each entry says which 64-bit register is behind the name (``al`` ->
    ``rax``), how many bytes it takes and whether it is the high half of a
    classic register (``ah``, ``bh``, ``ch``, ``dh``).

    Returns:
        Dictionary ``name -> {"base", "size", "high"}``, with ``"simd": True``
        in the XMM/YMM entries.
    """
    info: Dict[str, Dict[str, Any]] = {}
    low = {
        "rax": "al",
        "rcx": "cl",
        "rdx": "dl",
        "rbx": "bl",
        "rsp": "spl",
        "rbp": "bpl",
        "rsi": "sil",
        "rdi": "dil",
    }
    w16 = {
        "rax": "ax",
        "rcx": "cx",
        "rdx": "dx",
        "rbx": "bx",
        "rsp": "sp",
        "rbp": "bp",
        "rsi": "si",
        "rdi": "di",
    }
    w32 = {
        "rax": "eax",
        "rcx": "ecx",
        "rdx": "edx",
        "rbx": "ebx",
        "rsp": "esp",
        "rbp": "ebp",
        "rsi": "esi",
        "rdi": "edi",
    }
    for r in REGS64:
        info[r] = {"base": r, "size": 8, "high": False}
        if r[0] == "r" and r[1:].isdigit():
            info[r + "d"] = {"base": r, "size": 4, "high": False}
            info[r + "w"] = {"base": r, "size": 2, "high": False}
            info[r + "b"] = {"base": r, "size": 1, "high": False}
        else:
            info[w32[r]] = {"base": r, "size": 4, "high": False}
            info[w16[r]] = {"base": r, "size": 2, "high": False}
            info[low[r]] = {"base": r, "size": 1, "high": False}
    for r in ("ah", "bh", "ch", "dh"):
        info[r] = {"base": "r" + r[0] + "x", "size": 1, "high": True}
    for i in range(16):
        info["xmm%d" % i] = {"base": "xmm%d" % i, "size": 16, "simd": True}
        info["ymm%d" % i] = {"base": "ymm%d" % i, "size": 32, "simd": True}
    info["rip"] = {"base": "rip", "size": 8, "high": False}
    return info


#: Every accepted register name, with its size and originating register.
REG_INFO: Dict[str, Dict[str, Any]] = _build_reg_info()

#: Size keywords accepted before an operand (``byte``, ``qword``...).
SIZE_KEYWORDS: Dict[str, int] = {
    "byte": 1,
    "word": 2,
    "dword": 4,
    "qword": 8,
    "oword": 16,
    "tword": 10,
    "xmmword": 16,
}

#: Directives that define or reserve data, with the size of the unit.
DATA_DIRECTIVES: Dict[str, int] = {
    "db": 1,
    "dw": 2,
    "dd": 4,
    "dq": 8,
    "dt": 10,
    "resb": 1,
    "resw": 2,
    "resd": 4,
    "resq": 8,
    ".byte": 1,
    ".word": 2,
    ".long": 4,
    ".quad": 8,
    ".ascii": 1,
    ".asciz": 1,
    ".asciiz": 1,
    ".string": 1,
    ".space": 1,
    ".zero": 1,
}

#: Directives that organize the file and generate neither code nor data.
CONTROL_DIRECTIVES: Set[str] = {
    "section",
    "segment",
    "global",
    "globl",
    "extern",
    "export",
    "bits",
    "use64",
    "use32",
    "default",
    "org",
    "align",
    "equ",
    "times",
    "struc",
    "endstruc",
    "istruc",
    "iend",
    "%define",
    "%macro",
    "%endmacro",
    "%include",
    "%ifdef",
    "%endif",
    "%assign",
    "include",
    "includelib",
    "proc",
    "endp",
    "end",
    ".code",
    ".data",
    ".const",
    ".text",
    ".bss",
    ".rodata",
    ".globl",
    ".global",
    ".extern",
    ".intel_syntax",
    ".att_syntax",
    ".type",
    ".size",
    ".p2align",
    ".file",
    ".section",
    ".model",
    "option",
    ".align",
    "public",
    ".set",
    ".equ",
    ".comm",
    ".local",
    ".cfi_startproc",
    ".cfi_endproc",
}

#: Suffixes accepted after the ``j`` of a conditional branch.
COND_SUFFIXES: List[str] = list(CONDITIONS.keys()) + ["cxz", "ecxz", "rcxz"]


def is_cond_jump(mnemonic: str) -> bool:
    """Tells whether the mnemonic is a conditional branch.

    Args:
        mnemonic: Lowercase mnemonic (``jne``, ``jmp``, ``mov``...).

    Returns:
        ``True`` for ``j`` + a known condition (``je``, ``jg``, ``jrcxz``...);
        ``False`` for anything else, including ``jmp``.

    Example:
        >>> is_cond_jump("jl"), is_cond_jump("jmp"), is_cond_jump("mov")
        (True, False, False)
    """
    return mnemonic.startswith("j") and mnemonic != "jmp" and mnemonic[1:] in COND_SUFFIXES


def doc_for(mnemonic: str) -> Optional[Dict[str, Any]]:
    """Looks up the documentation record of an instruction.

    Args:
        mnemonic: Mnemonic in any case; ``None`` is also accepted.

    Returns:
        The catalogue record (name, syntax, description, examples, flags) or
        ``None`` when the instruction is not documented.

    Example:
        >>> doc_for("MOV")["cat"]
        'data'
    """
    return ISA.get((mnemonic or "").lower())


def category_of(mnemonic: str) -> str:
    """Returns the category of an instruction.

    Args:
        mnemonic: Mnemonic in any case.

    Returns:
        The category key (``data``, ``branch``, ``sys``...) or ``"misc"`` when
        the instruction is not in the catalogue.

    Example:
        >>> category_of("syscall")
        'sys'
        >>> category_of("nonexistent_instruction")
        'misc'
    """
    d = doc_for(mnemonic)
    return d["cat"] if d else "misc"


log_event(
    logger,
    "isa_loaded",
    level=10,
    mnemonics=len(ISA),
    categories=len(CATEGORIES),
    syscalls=len(LINUX_SYSCALLS),
    win_apis=len(WIN_APIS),
)
