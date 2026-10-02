"""Analysis: target platform, semantic reading of each instruction and blocks.

The :data:`LINUX_HINTS` and :data:`WINDOWS_HINTS` tables hold triples
``(pattern, explanation, weight)`` consulted by :func:`detect_platform` to
score the clues of each operating system.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from . import isa
from .isa import (
    ARG_REGS_SYSCALL,
    ARG_REGS_SYSV,
    ARG_REGS_WIN,
    CONDITIONS,
    ISA,
    LINUX_SYSCALLS,
    REG_INFO,
    WIN_APIS,
    is_cond_jump,
)
from .parser import Line, Program, parse


@dataclass
class Semantic:
    """What one instruction does, in plain words.

    Attributes:
        cat: Category from the ISA table (``data``, ``branch``, ``sys``...).
        tag: Short label used by the emulator and by the interface.
        label: Short title of the action (``Reads from memory``).
        detail: Explanation of the instruction effect.
        syscall_name: Service name, when it is a system call.
    """

    cat: str = "misc"
    tag: str = "misc"
    label: str = ""
    detail: str = ""
    syscall_name: Optional[str] = None


@dataclass
class Edge:
    """A link between two basic blocks.

    Attributes:
        target: Index of the target block.
        kind: ``jmp``, ``taken`` or ``fallthrough``.
        why: Explanation of why the edge exists.
    """

    target: int
    kind: str
    why: str


@dataclass
class Block:
    """A basic block: a stretch of code with one entry and one exit.

    Attributes:
        id: Index of the block in the block list.
        start: Index of the first instruction of the block.
        end: Index of the last instruction of the block.
        name: Block label (or ``continuation of ...``).
        func: Function the block belongs to, when there is one.
        instrs: Instructions of the block, in order.
        succ: Outgoing edges of the block.
        pred: Incoming edges of the block.
        calls: Targets of the calls made inside the block.
        exit: Reason why the block ends the flow, when it does.
    """

    id: int
    start: int
    end: int
    name: str
    func: Optional[str]
    instrs: List[Line] = field(default_factory=list)
    succ: List[Edge] = field(default_factory=list)
    pred: List[Edge] = field(default_factory=list)
    calls: List[str] = field(default_factory=list)
    exit: Optional[str] = None


@dataclass
class Platform:
    """Detected operating system and the matching calling convention.

    Attributes:
        os: ``linux``, ``windows``, ``ambiguous`` or ``unknown``.
        confidence: Confidence of the detection, from 0 to 100.
        bits: Detected architecture (16, 32 or 64).
        evidence: Clues found, per system (``linux`` and ``windows``).
        abi: ABI name, argument and return registers, preserved registers
            and notes.
    """

    os: str
    confidence: int
    bits: int
    evidence: Dict[str, List[str]]
    abi: dict


@dataclass
class Analysis:
    """Complete result of the analysis of a source file.

    Attributes:
        program: Program returned by the parser.
        platform: Detected platform.
        blocks: Basic blocks, in code order.
        instrs: Only the instructions, in order.
        label_at: Label -> index of the instruction where it appears.
        stats: General counts (instructions, blocks, syscalls, categories...).
    """

    program: Program
    platform: Platform
    blocks: List[Block]
    instrs: List[Line]
    label_at: Dict[str, int]
    stats: dict

    @property
    def symbols(self) -> Dict[str, Dict[str, Any]]:
        """Program symbols, by name.

        Returns:
            The ``name -> symbol data`` dictionary coming from the parser.
        """
        return self.program.symbols


# (pattern, explanation, weight) — strong clues weigh more than conventions
# shared by both systems, such as "section .text".
LINUX_HINTS = [
    (r"\bsyscall\b", "uses the SYSCALL instruction (Linux 64-bit kernel interface)", 3),
    (r"\bint\s+0x80\b", "uses INT 0x80, the classic Linux system call", 3),
    (r"\bglobal\s+_start\b", "declares _start, the ld entry point on Linux", 3),
    (
        r"\.globl\b|\.cfi_startproc|\.type\s+\w+,\s*@function",
        "uses GNU assembler directives (ELF)",
        3,
    ),
    (r"@plt\b|wrt\s*\.\.plt", "references the PLT, the ELF linking mechanism", 3),
    (r"\bmov\s+(r|e)?ax,\s*(60|0x3c)\b", "uses syscall 60 (exit), specific to Linux x86-64", 2),
    (r"\b(printf|puts|malloc|free|scanf|strlen)\b", "calls standard libc functions", 2),
    (r"/dev/|/proc/|/tmp/", "references typical Unix paths", 2),
    (
        r"\bsection\s+\.(text|data|bss|rodata)\b",
        "uses ELF-style sections (also accepted on Windows)",
        1,
    ),
]

WINDOWS_HINTS = [
    (
        r"\b(ExitProcess|MessageBoxA|MessageBoxW|GetStdHandle|WriteConsoleA|WriteConsoleW|"
        r"ReadConsoleA|CreateFileA|VirtualAlloc|GetProcAddress|LoadLibraryA|CloseHandle|"
        r"GetLastError|CreateProcessA|GetModuleHandleA)\b",
        "calls the Windows API (kernel32/user32)",
        3,
    ),
    (r"\b(kernel32|user32|msvcrt|ucrt)\b", "references Windows DLLs", 3),
    (r"\bincludelib\b|\boption\s+casemap\b|\.model\b", "uses MASM directives", 3),
    (r"(?m)^\s*\w+\s+proc\b", "declares functions with PROC/ENDP, MASM syntax", 3),
    (r"__imp_\w+", "uses import symbols (__imp_) from the PE format", 3),
    (r"\bWinMain\b|\bDllMain\b", "uses a Windows application entry point", 3),
    (
        r"\bsub\s+rsp,\s*(28h|0x28|40|32|20h)\b",
        "reserves the 32-byte shadow space required by the Windows ABI",
        2,
    ),
    (r"[A-Za-z]:\\\\|\\\\\w+\\\\", "references Windows-style paths", 2),
]


def detect_platform(program: Program) -> Platform:
    """Finds the target system, the architecture and the ABI from the source text.

    Scores the clues of :data:`LINUX_HINTS` and :data:`WINDOWS_HINTS` and picks
    the architecture from the ``bits``/``use32`` directives.

    Args:
        program: Program already read by the parser.

    Returns:
        The :class:`Platform` with system, confidence, bits, evidence and ABI.
    """
    src = program.source
    evidence: Dict[str, List[str]] = {"linux": [], "windows": []}
    score: Dict[str, int] = {"linux": 0, "windows": 0}
    for pattern, why, weight in LINUX_HINTS:
        if re.search(pattern, src, re.I):
            evidence["linux"].append(why)
            score["linux"] += weight
    for pattern, why, weight in WINDOWS_HINTS:
        if re.search(pattern, src, re.I):
            evidence["windows"].append(why)
            score["windows"] += weight

    lin, win = score["linux"], score["windows"]
    if lin > win:
        os_name, conf = "linux", min(100, 45 + (lin - win) * 12 + lin * 3)
    elif win > lin:
        os_name, conf = "windows", min(100, 45 + (win - lin) * 12 + win * 3)
    elif lin == 0:
        os_name, conf = "unknown", 0
    else:
        os_name, conf = "ambiguous", 35

    if re.search(r"\bbits\s+16\b", src, re.I):
        bits = 16
    elif re.search(r"\bbits\s+32\b|\buse32\b", src, re.I) and not re.search(
        r"\br[a-z]x\b", src, re.I
    ):
        bits = 32
    else:
        bits = 64

    if os_name == "windows":
        abi = {
            "name": "Microsoft x64",
            "args": ARG_REGS_WIN,
            "ret": "RAX",
            "preserved": isa.CALLEE_SAVED_WIN,
            "notes": "The first 4 arguments go in RCX, RDX, R8, R9. The caller "
            "must reserve 32 bytes of shadow space and keep RSP aligned "
            "to 16 bytes.",
        }
    else:
        abi = {
            "name": "System V AMD64",
            "args": ARG_REGS_SYSV,
            "ret": "RAX",
            "preserved": isa.CALLEE_SAVED_SYSV,
            "notes": "The first 6 arguments go in RDI, RSI, RDX, RCX, R8, R9. In "
            "syscalls, RCX is replaced by R10 and the service number goes in RAX.",
        }

    return Platform(os=os_name, confidence=conf, bits=bits, evidence=evidence, abi=abi)


def _mem_name(op: Any) -> str:
    """Describes a memory operand.

    Args:
        op: Operand of type ``mem``.

    Returns:
        Text like ``local variable at rbp-8`` or ``address pointed to by rdi``.
    """
    inner = op.inner or ""
    if re.search(r"rbp\s*-", inner) or re.search(r"rsp\s*\+", inner):
        return "local variable at " + inner
    if re.search(r"rbp\s*\+", inner):
        return "parameter at " + inner
    if op.symbol:
        return "variable " + op.symbol
    if op.regs:
        return "address pointed to by " + " + ".join(op.regs)
    return "memory " + inner


def semantics_of(ins: Line, ctx: Dict[str, Any]) -> Semantic:
    """Builds the explanation of a single instruction.

    Args:
        ins: Instruction already classified by the parser.
        ctx: Analysis context (``platform``, ``symbols``,
            ``pending_syscall``, ``last_compare`` and ``syscall_ahead``).

    Returns:
        The :class:`Semantic` with category, label and detail of the instruction.
    """
    m = ins.mnemonic
    ops = ins.operands
    o0 = ops[0] if ops else None
    o1 = ops[1] if len(ops) > 1 else None
    info = ISA.get(m)
    sem = Semantic(
        cat=info["cat"] if info else "misc",
        tag=info["cat"] if info else "misc",
        label=info["name"].split("—")[0].strip() if info else m.upper(),
    )

    if m in ("mov", "movzx", "movsx", "movsxd"):
        if o0 and o0.type == "mem":
            target_name = o0.symbol or (
                "local" if re.search(r"rbp|rsp", o0.inner or "") else "*pointer"
            )
            sem.tag, sem.label = "store", "Writes to memory"
            sem.detail = "Stores %s in %s. In a high-level language: %s = %s;" % (
                o1.text if o1 else "?",
                _mem_name(o0),
                target_name,
                o1.text if o1 else "?",
            )
        elif o1 and o1.type == "mem":
            sem.tag, sem.label = "load", "Reads from memory"
            sem.detail = "Loads %s into %s. This is a variable read." % (
                _mem_name(o1),
                o0.text,
            )
        elif o1 and o1.type == "imm":
            sem.tag, sem.label = "set", "Sets a constant"
            sem.detail = "%s becomes %s." % (o0.text, o1.text)
            if ctx["platform"].os == "linux" and o0.type == "reg" and o0.reg in ("rax", "eax"):
                sc = LINUX_SYSCALLS.get(o1.value)
                if sc and ctx.get("syscall_ahead"):
                    sem.detail += (
                        " Because it comes before a SYSCALL, it is the service number: %s (%s)."
                        % (sc[0], sc[1])
                    )
        elif o1 and o1.type == "sym":
            sem.tag, sem.label = "set", "Sets address/symbol"
            sym = ctx["symbols"].get(o1.symbol, {})
            extra = " (address of the data %s)" % o1.symbol if sym.get("type") == "data" else ""
            sem.detail = "%s receives %s%s." % (o0.text, o1.symbol, extra)
        else:
            sem.tag, sem.label = "copy", "Copies register"
            if o0 and o1:
                sem.detail = "%s gets a copy of %s." % (o0.text, o1.text)
    elif m == "lea":
        sem.tag, sem.label = "addr", "Computes address"
        target_name = (o1.symbol or o1.inner or o1.text) if o1 else "?"
        sem.detail = (
            "%s receives the ADDRESS of %s, without reading its contents. It is like & in C."
            % (
                o0.text,
                target_name,
            )
        )
    elif m == "push":
        sem.tag, sem.label = "push", "Pushes"
        sem.detail = "Saves %s on the stack (RSP decreases by 8)." % (o0.text if o0 else "")
    elif m == "pop":
        sem.tag, sem.label = "pop", "Pops"
        sem.detail = "Restores %s from the top of the stack (RSP increases by 8)." % (
            o0.text if o0 else ""
        )
    elif m == "call":
        sem.tag, sem.label = "call", "Calls a function"
        target_name = (o0.symbol or o0.text) if o0 else "?"
        api = WIN_APIS.get(re.sub(r"^_+|@.*$", "", str(target_name).lower()))
        sem.detail = "Saves the return address and jumps to %s." % target_name
        if api:
            sem.detail += " This is the Windows API %s: %s (parameters: %s)." % (
                api[0],
                api[1],
                api[2],
            )
        elif ctx["symbols"].get(target_name, {}).get("type") == "extern":
            sem.detail += " External function, resolved at link time."
    elif m.startswith("ret"):
        sem.tag, sem.label = "return", "Returns"
        sem.detail = (
            "Returns to the caller using the address on top of the stack. "
            "The return value comes out in RAX."
        )
    elif m == "jmp":
        sem.tag, sem.label = "jump", "Always jumps"
        sem.detail = (
            "Goes straight to %s. Whatever comes right below only runs if "
            "someone jumps there." % (o0.text if o0 else "?")
        )
    elif is_cond_jump(m):
        cc = m[1:]
        human = CONDITIONS.get(cc, [cc, "the condition"])
        sem.tag, sem.label = "branch", "Jumps if " + human[0]
        sem.detail = "Goes to %s when %s. Otherwise, it continues on the next line." % (
            o0.text if o0 else "?",
            human[1],
        )
        if ctx.get("last_compare"):
            sem.detail += " Condition coming from: %s." % ctx["last_compare"]
    elif m in ("cmp", "test"):
        sem.tag, sem.label = "compare", "Compares"
        base = (
            ("Computes %s - %s" % (o0.text, o1.text))
            if m == "cmp"
            else ("Does %s AND %s" % (o0.text, o1.text))
        )
        sem.detail = (
            base + " only to update the flags. What decides anything with it is the branch below."
        )
        if m == "test" and o0 and o1 and o0.text == o1.text:
            sem.detail += ' Here it is the "%s is zero?" idiom.' % o0.text
    elif m in ("syscall", "int"):
        sem.tag, sem.label = "syscall", "System call"
        num = ctx.get("pending_syscall")
        sc = LINUX_SYSCALLS.get(num) if num is not None else None
        if sc:
            nargs = len([a for a in sc[2].split(",") if a.strip()]) if sc[2] else 0
            regs = ", ".join(r.upper() for r in ARG_REGS_SYSCALL[:nargs])
            sem.detail = "Enters the kernel to run %s — %s.%s The result comes back in RAX." % (
                sc[0],
                sc[1],
                (" Arguments in %s (%s)." % (regs, sc[2])) if nargs else "",
            )
            sem.syscall_name = sc[0]
        else:
            sem.detail = (
                "Hands control to the kernel. The service number is in RAX and the "
                "arguments are in RDI, RSI, RDX, R10, R8, R9."
            )
    elif m in ("add", "sub", "inc", "dec", "mul", "imul", "div", "idiv", "neg", "adc", "sbb"):
        sem.tag, sem.label = "arith", "Arithmetic"
        if m == "sub" and o0 and o0.reg == "rsp":
            sem.tag, sem.label = "frame", "Reserves stack space"
            sem.detail = "Opens %s bytes for local variables." % (o1.text if o1 else "?")
        elif m == "add" and o0 and o0.reg == "rsp":
            sem.tag, sem.label = "frame", "Releases stack space"
            sem.detail = "Gives back %s bytes reserved before." % (o1.text if o1 else "?")
        elif m == "mul" or (m == "imul" and len(ops) == 1):
            sem.detail = (
                "RAX = RAX × %s. The full result goes in RDX:RAX " "(high part in RDX)." % o0.text
            )
        elif m in ("div", "idiv"):
            prep = "XOR RDX, RDX" if m == "div" else "CQO"
            sem.detail = (
                "Divides RDX:RAX by %s: quotient in RAX, remainder in RDX. "
                "RDX must be prepared beforehand (%s)." % (o0.text, prep)
            )
        else:
            op_sign = {"add": "+", "sub": "-", "imul": "*", "adc": "+", "sbb": "-"}.get(m)
            if m == "inc":
                sem.detail = "%s = %s + 1." % (o0.text, o0.text)
            elif m == "dec":
                sem.detail = "%s = %s - 1." % (o0.text, o0.text)
            elif m == "neg":
                sem.detail = "%s = 0 - %s (flips the sign)." % (o0.text, o0.text)
            else:
                sem.detail = "%s = %s %s %s." % (o0.text, o0.text, op_sign, o1.text if o1 else "")
    elif m in ("and", "or", "xor", "not", "shl", "sal", "shr", "sar", "rol", "ror"):
        sem.tag, sem.label = "logic", "Bit operation"
        if m == "xor" and o0 and o1 and o0.text == o1.text:
            sem.label = "Zeroes the register"
            sem.detail = "%s = 0 (the shortest way to zero it)." % o0.text
        elif m == "shl":
            sem.detail = "%s = %s * 2^%s." % (o0.text, o0.text, o1.text if o1 else "n")
        elif m == "shr":
            sem.detail = "%s = %s / 2^%s (unsigned)." % (o0.text, o0.text, o1.text if o1 else "n")
        elif m == "not":
            sem.detail = "Every bit of %s is flipped." % o0.text
        else:
            sem.detail = "%s = %s %s %s, bit by bit." % (
                o0.text,
                o0.text,
                m.upper(),
                o1.text if o1 else "",
            )
    elif m.startswith("set"):
        sem.tag, sem.label = "compare", "Boolean of the condition"
        human = CONDITIONS.get(m[3:], ["the condition"])[0]
        sem.detail = "%s becomes 1 if %s, otherwise 0." % (o0.text, human)
    elif m == "leave":
        sem.tag, sem.label = "frame", "Tears down the frame"
        sem.detail = "Restores RSP and RBP before RET."
    elif m == "nop":
        sem.tag, sem.label = "misc", "Nothing"
        sem.detail = "Empty instruction, used for alignment."
    elif info:
        sem.detail = info["desc"].split(".")[0] + "."
    else:
        sem.tag, sem.label = "unknown", "Not recognized"
        sem.detail = (
            'The tool does not know "%s". It may be a macro, an uncommon SIMD '
            "instruction or a typo." % m
        )
    return sem


def _mark_frames(instrs: List[Line]) -> None:
    """Marks the prologue and the epilogue of the stack frames.

    Args:
        instrs: Instructions of the program, in order.
    """
    for i, a in enumerate(instrs):
        b = instrs[i + 1] if i + 1 < len(instrs) else None
        if (
            a.mnemonic == "push"
            and a.operands
            and a.operands[0].reg == "rbp"
            and b
            and b.mnemonic == "mov"
            and b.operands
            and b.operands[0].reg == "rbp"
            and len(b.operands) > 1
            and b.operands[1].reg == "rsp"
        ):
            a.sem.tag, a.sem.label = "frame", "Function prologue"
            a.sem.detail = "Saves the stack frame of the caller."
            b.sem.tag, b.sem.label = "frame", "Function prologue"
            b.sem.detail = (
                "RBP now points to the base of this frame: from here on the local "
                "variables are [RBP-n]."
            )
        if (
            a.mnemonic == "pop"
            and a.operands
            and a.operands[0].reg == "rbp"
            and b
            and b.mnemonic.startswith("ret")
        ):
            a.sem.tag, a.sem.label = "frame", "Function epilogue"
            a.sem.detail = "Restores the frame of the caller, right before the return."


def _annotate_args(instrs: List[Line], platform: Platform) -> None:
    """Annotates the MOV/LEA that set up arguments before a CALL.

    Args:
        instrs: Instructions of the program, in order.
        platform: Detected platform, which defines the argument registers.
    """
    arg_regs = ARG_REGS_WIN if platform.os == "windows" else ARG_REGS_SYSV
    pending: List[tuple] = []
    last_func: object = object()
    for ins in instrs:
        if (
            ins.func != last_func
            or ins.labels
            or ins.mnemonic.startswith("ret")
            or ins.mnemonic == "jmp"
            or is_cond_jump(ins.mnemonic)
        ):
            pending = []
            last_func = ins.func
        if ins.mnemonic == "call":
            target_name = (
                (ins.operands[0].symbol or ins.operands[0].text) if ins.operands else "function"
            )
            for reg, line in pending:
                if reg in arg_regs:
                    line.sem.detail += " Sets up argument %d of the call to %s." % (
                        arg_regs.index(reg) + 1,
                        target_name,
                    )
            pending = []
        elif ins.mnemonic == "syscall":
            pending = []
        elif (
            ins.mnemonic in ("mov", "lea", "xor", "movzx", "movsx")
            and ins.operands
            and ins.operands[0].type == "reg"
        ):
            base = REG_INFO[ins.operands[0].reg]["base"]
            pending.append((base, ins))
            pending = pending[-12:]


def build_blocks(program: Program) -> Tuple[List[Block], Dict[str, int]]:
    """Splits the instructions into basic blocks and links the blocks together.

    Args:
        program: Program already read by the parser.

    Returns:
        The list of :class:`Block` and the map ``label -> instruction index``.
    """
    instrs = program.instructions
    for i, ins in enumerate(instrs):
        ins.idx = i

    label_at: Dict[str, int] = {}
    pending_labels: List[str] = []
    for source_line in program.lines:
        if source_line.kind == "label":
            pending_labels.append(source_line.label)
        elif source_line.kind == "directive" and source_line.directive == "proc":
            pending_labels.append(source_line.label)
        elif source_line.kind == "instruction":
            source_line.labels = list(pending_labels)
            for lb in pending_labels:
                label_at[lb] = source_line.idx
            pending_labels = []

    leaders = set()
    if instrs:
        leaders.add(0)
    for i, ins in enumerate(instrs):
        if ins.labels:
            leaders.add(i)
        jump = ins.mnemonic == "jmp" or is_cond_jump(ins.mnemonic)
        if (jump or ins.mnemonic.startswith("ret")) and i + 1 < len(instrs):
            leaders.add(i + 1)
        if jump and ins.operands:
            t = ins.operands[0].symbol or ins.operands[0].text
            if t in label_at:
                leaders.add(label_at[t])

    blocks: List[Block] = []
    cur = None
    for i, ins in enumerate(instrs):
        if i in leaders or cur is None:
            name = (
                ins.labels[0]
                if ins.labels
                else ("continuation of " + blocks[-1].name if blocks else "start")
            )
            cur = Block(id=len(blocks), start=i, end=i, name=name, func=ins.func)
            blocks.append(cur)
        cur.instrs.append(ins)
        cur.end = i
        ins.block = cur.id

    block_of = {}
    for b in blocks:
        for i in range(b.start, b.end + 1):
            block_of[i] = b.id

    for b in blocks:
        last = b.instrs[-1]
        m = last.mnemonic
        target = (last.operands[0].symbol or last.operands[0].text) if last.operands else None

        def link(bid: Optional[int], kind: str, why: str) -> None:
            """Creates the forward and the backward edge between two blocks.

            Args:
                bid: Index of the target block, or ``None`` when there is none.
                kind: Edge kind (``jmp``, ``taken`` or ``fallthrough``).
                why: Explanation of the branch.
            """
            if bid is None or bid >= len(blocks):
                return
            b.succ.append(Edge(bid, kind, why))
            blocks[bid].pred.append(Edge(b.id, kind, why))

        if m == "jmp":
            if target in label_at:
                link(block_of[label_at[target]], "jmp", "unconditional jump to " + target)
            else:
                b.exit = "jump to %s (outside the loaded code)" % target
        elif is_cond_jump(m):
            human = CONDITIONS.get(m[1:], ["the condition is true"])[0]
            if target in label_at:
                link(block_of[label_at[target]], "taken", "when " + human)
            if b.id + 1 < len(blocks):
                link(b.id + 1, "fallthrough", "when the condition is false, falls to the next line")
        elif m.startswith("ret"):
            b.exit = "returns to the caller"
        elif m == "syscall" and last.sem and last.sem.syscall_name in ("exit", "exit_group"):
            b.exit = "terminates the process"
        elif m == "call" and re.search(r"exitprocess", str(target), re.I):
            b.exit = "terminates the process"
        elif b.id + 1 < len(blocks):
            link(b.id + 1, "fallthrough", "flows naturally into the next instruction")
        else:
            b.exit = "end of code"

        b.calls = [
            (x.operands[0].symbol or x.operands[0].text) if x.operands else "?"
            for x in b.instrs
            if x.mnemonic == "call"
        ]

    return blocks, label_at


def analyze(text: str) -> Analysis:
    """Analyzes the whole source: platform, semantics, blocks and statistics.

    Args:
        text: Complete assembly code.

    Returns:
        The :class:`Analysis` ready for the validator and for the virtual machine.
    """
    program = parse(text)
    platform = detect_platform(program)
    instrs = program.instructions

    ctx = {
        "platform": platform,
        "symbols": program.symbols,
        "pending_syscall": None,
        "last_compare": None,
        "syscall_ahead": False,
    }

    for i, ins in enumerate(instrs):
        ctx["syscall_ahead"] = any(x.mnemonic in ("syscall", "int") for x in instrs[i + 1 : i + 8])
        ins.sem = semantics_of(ins, ctx)
        if (
            ins.mnemonic == "mov"
            and ins.operands
            and ins.operands[0].reg in ("rax", "eax")
            and len(ins.operands) > 1
            and ins.operands[1].type == "imm"
        ):
            ctx["pending_syscall"] = ins.operands[1].value
        if ins.mnemonic == "xor" and ins.operands and ins.operands[0].reg in ("rax", "eax"):
            ctx["pending_syscall"] = 0
        if ins.mnemonic in ("syscall", "int", "call"):
            ctx["pending_syscall"] = None
        if ins.mnemonic in ("cmp", "test"):
            ctx["last_compare"] = ins.text.split(";")[0].strip()

    _mark_frames(instrs)
    blocks, label_at = build_blocks(program)
    _annotate_args(instrs, platform)

    by_cat: Dict[str, int] = {}
    unknown: List[str] = []
    for ins in instrs:
        by_cat[ins.sem.cat] = by_cat.get(ins.sem.cat, 0) + 1
        if ins.sem.tag == "unknown":
            unknown.append(ins.mnemonic)

    stats = {
        "total": len(program.lines),
        "instructions": len(instrs),
        "by_cat": by_cat,
        "unknown": sorted(set(unknown)),
        "syscalls": sum(1 for i in instrs if i.mnemonic in ("syscall", "int")),
        "calls": sum(1 for i in instrs if i.mnemonic == "call"),
        "labels": sum(1 for s in program.symbols.values() if s["type"] == "label"),
        "blocks": len(blocks),
    }

    return Analysis(
        program=program,
        platform=platform,
        blocks=blocks,
        instrs=instrs,
        label_at=label_at,
        stats=stats,
    )


def callers_of(analysis: Analysis, name: str) -> List[str]:
    """Lists who calls or jumps to a name.

    Args:
        analysis: Analysis already built.
        name: Name of the label or function being searched for.

    Returns:
        Texts like ``main (line 12)`` or ``jump from line 30``.
    """
    out: List[str] = []
    for ins in analysis.instrs:
        if not ins.operands:
            continue
        target = ins.operands[0].symbol or ins.operands[0].text
        if target != name:
            continue
        if ins.mnemonic == "call":
            out.append("%s (line %d)" % (ins.func or "code", ins.n))
        elif ins.mnemonic == "jmp" or is_cond_jump(ins.mnemonic):
            out.append("jump from line %d" % ins.n)
    return out


def functions(analysis: Analysis) -> List[str]:
    """Lists the functions found, in the order they appear.

    Args:
        analysis: Analysis already built.

    Returns:
        Function names, without repetition.
    """
    seen = []
    for b in analysis.blocks:
        if b.func and b.func not in seen:
            seen.append(b.func)
    return seen
