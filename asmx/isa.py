"""Base de conhecimento do x86-64: instruções, registradores, flags, syscalls.

O acervo em si mora em ``asmx/data/isa.json`` e é carregado uma única vez, na
importação. Este módulo só dá forma a ele: tabelas prontas para consulta
(:data:`ISA`, :data:`REG_INFO`, :data:`LINUX_SYSCALLS`) e as funções curtas que
o resto do programa usa para perguntar "essa instrução existe?", "de que
categoria ela é?" e "esse mnemônico é um desvio condicional?".

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

#: Categorias de instrução (chave -> rótulo e explicação).
CATEGORIES: Dict[str, Dict[str, Any]] = _RAW["CATEGORIES"]

#: Acervo de mnemônicos documentados: chave em minúsculas -> ficha completa.
ISA: Dict[str, Dict[str, Any]] = _RAW["ISA"]

#: Condições dos desvios: sufixo (``e``, ``ne``...) -> nome e explicação.
CONDITIONS: Dict[str, List[str]] = _RAW["CONDITIONS"]

#: Documentação dos registradores.
REG_DOC: Dict[str, str] = _RAW["REG_DOC"]

#: Documentação das flags do processador.
FLAG_DOC: Dict[str, str] = _RAW["FLAG_DOC"]

#: Syscalls do Linux x86-64, indexadas pelo número.
LINUX_SYSCALLS: Dict[int, List[str]] = {int(k): v for k, v in _RAW["LINUX_SYSCALLS"].items()}

#: Funções da API do Windows (kernel32/user32) usadas pelos exemplos.
WIN_APIS: Dict[str, List[str]] = _RAW["WIN_APIS"]

#: Registradores de 64 bits, na ordem canônica da ABI.
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

#: Registradores que a função chamada precisa preservar no System V AMD64.
CALLEE_SAVED_SYSV: List[str] = ["rbx", "rbp", "r12", "r13", "r14", "r15"]

#: Registradores que a função chamada precisa preservar na ABI da Microsoft.
CALLEE_SAVED_WIN: List[str] = ["rbx", "rbp", "rdi", "rsi", "r12", "r13", "r14", "r15"]

#: Ordem dos argumentos de função no System V AMD64.
ARG_REGS_SYSV: List[str] = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]

#: Ordem dos argumentos de syscall no Linux x86-64 (RCX dá lugar a R10).
ARG_REGS_SYSCALL: List[str] = ["rdi", "rsi", "rdx", "r10", "r8", "r9"]

#: Ordem dos argumentos de função na ABI da Microsoft.
ARG_REGS_WIN: List[str] = ["rcx", "rdx", "r8", "r9"]


def _build_reg_info() -> Dict[str, Dict[str, Any]]:
    """Monta o mapa de registradores, incluindo os nomes parciais.

    Cada entrada diz qual é o registrador de 64 bits por trás do nome
    (``al`` -> ``rax``), quantos bytes ele ocupa e se é a metade alta de um
    registrador clássico (``ah``, ``bh``, ``ch``, ``dh``).

    Returns:
        Dicionário ``nome -> {"base", "size", "high"}``, com ``"simd": True``
        nas entradas de XMM/YMM.
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


#: Todo nome de registrador aceito, com tamanho e registrador de origem.
REG_INFO: Dict[str, Dict[str, Any]] = _build_reg_info()

#: Palavras de tamanho aceitas antes de um operando (``byte``, ``qword``...).
SIZE_KEYWORDS: Dict[str, int] = {
    "byte": 1,
    "word": 2,
    "dword": 4,
    "qword": 8,
    "oword": 16,
    "tword": 10,
    "xmmword": 16,
}

#: Diretivas que definem ou reservam dados, com o tamanho da unidade.
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

#: Diretivas que organizam o arquivo e não geram código nem dados.
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

#: Sufixos aceitos depois do ``j`` de um desvio condicional.
COND_SUFFIXES: List[str] = list(CONDITIONS.keys()) + ["cxz", "ecxz", "rcxz"]


def is_cond_jump(mnemonic: str) -> bool:
    """Diz se o mnemônico é um desvio condicional.

    Args:
        mnemonic: Mnemônico em minúsculas (``jne``, ``jmp``, ``mov``...).

    Returns:
        ``True`` para ``j`` + condição conhecida (``je``, ``jg``, ``jrcxz``...);
        ``False`` para qualquer outra coisa, inclusive ``jmp``.

    Example:
        >>> is_cond_jump("jl"), is_cond_jump("jmp"), is_cond_jump("mov")
        (True, False, False)
    """
    return mnemonic.startswith("j") and mnemonic != "jmp" and mnemonic[1:] in COND_SUFFIXES


def doc_for(mnemonic: str) -> Optional[Dict[str, Any]]:
    """Busca a ficha de documentação de uma instrução.

    Args:
        mnemonic: Mnemônico em qualquer caixa; ``None`` também é aceito.

    Returns:
        A ficha do acervo (nome, sintaxe, descrição, exemplos, flags) ou
        ``None`` quando a instrução não está documentada.

    Example:
        >>> doc_for("MOV")["cat"]
        'data'
    """
    return ISA.get((mnemonic or "").lower())


def category_of(mnemonic: str) -> str:
    """Devolve a categoria de uma instrução.

    Args:
        mnemonic: Mnemônico em qualquer caixa.

    Returns:
        A chave da categoria (``data``, ``branch``, ``sys``...) ou ``"misc"``
        quando a instrução não está no acervo.

    Example:
        >>> category_of("syscall")
        'sys'
        >>> category_of("instrucao_inexistente")
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
