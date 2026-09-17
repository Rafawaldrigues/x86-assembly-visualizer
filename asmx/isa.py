"""Base de conhecimento do x86-64: instruções, registradores, flags, syscalls."""

import json
import os

_DATA = os.path.join(os.path.dirname(__file__), "data", "isa.json")

with open(_DATA, encoding="utf-8") as _f:
    _RAW = json.load(_f)

CATEGORIES = _RAW["CATEGORIES"]
ISA = _RAW["ISA"]
CONDITIONS = _RAW["CONDITIONS"]
REG_DOC = _RAW["REG_DOC"]
FLAG_DOC = _RAW["FLAG_DOC"]
LINUX_SYSCALLS = {int(k): v for k, v in _RAW["LINUX_SYSCALLS"].items()}
WIN_APIS = _RAW["WIN_APIS"]

REGS64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
          "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]

CALLEE_SAVED_SYSV = ["rbx", "rbp", "r12", "r13", "r14", "r15"]
CALLEE_SAVED_WIN = ["rbx", "rbp", "rdi", "rsi", "r12", "r13", "r14", "r15"]
ARG_REGS_SYSV = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
ARG_REGS_SYSCALL = ["rdi", "rsi", "rdx", "r10", "r8", "r9"]
ARG_REGS_WIN = ["rcx", "rdx", "r8", "r9"]


def _build_reg_info():
    info = {}
    low = {"rax": "al", "rcx": "cl", "rdx": "dl", "rbx": "bl",
           "rsp": "spl", "rbp": "bpl", "rsi": "sil", "rdi": "dil"}
    w16 = {"rax": "ax", "rcx": "cx", "rdx": "dx", "rbx": "bx",
           "rsp": "sp", "rbp": "bp", "rsi": "si", "rdi": "di"}
    w32 = {"rax": "eax", "rcx": "ecx", "rdx": "edx", "rbx": "ebx",
           "rsp": "esp", "rbp": "ebp", "rsi": "esi", "rdi": "edi"}
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


REG_INFO = _build_reg_info()

SIZE_KEYWORDS = {"byte": 1, "word": 2, "dword": 4, "qword": 8,
                 "oword": 16, "tword": 10, "xmmword": 16}

DATA_DIRECTIVES = {
    "db": 1, "dw": 2, "dd": 4, "dq": 8, "dt": 10,
    "resb": 1, "resw": 2, "resd": 4, "resq": 8,
    ".byte": 1, ".word": 2, ".long": 4, ".quad": 8,
    ".ascii": 1, ".asciz": 1, ".asciiz": 1, ".string": 1,
    ".space": 1, ".zero": 1,
}

CONTROL_DIRECTIVES = {
    "section", "segment", "global", "globl", "extern", "export", "bits",
    "use64", "use32", "default", "org", "align", "equ", "times", "struc",
    "endstruc", "istruc", "iend", "%define", "%macro", "%endmacro",
    "%include", "%ifdef", "%endif", "%assign", "include", "includelib",
    "proc", "endp", "end", ".code", ".data", ".const", ".text", ".bss",
    ".rodata", ".globl", ".global", ".extern", ".intel_syntax",
    ".att_syntax", ".type", ".size", ".p2align", ".file", ".section",
    ".model", "option", ".align", "public", ".set", ".equ", ".comm",
    ".local", ".cfi_startproc", ".cfi_endproc",
}

COND_SUFFIXES = list(CONDITIONS.keys()) + ["cxz", "ecxz", "rcxz"]


def is_cond_jump(mnemonic: str) -> bool:
    return (mnemonic.startswith("j") and mnemonic != "jmp"
            and mnemonic[1:] in COND_SUFFIXES)


def doc_for(mnemonic: str):
    return ISA.get((mnemonic or "").lower())


def category_of(mnemonic: str) -> str:
    d = doc_for(mnemonic)
    return d["cat"] if d else "misc"
