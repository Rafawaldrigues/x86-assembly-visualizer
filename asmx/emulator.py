"""Didactic x86-64 virtual machine in user mode.

The machine holds registers, sparse memory, flags and the text output; it runs
one instruction at a time in :meth:`Machine.step` and records every step in the
history. Linux syscalls and the most common Windows API functions are emulated
approximately, and whatever is not emulated goes into the list of issues.
"""

from __future__ import annotations

import random
import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Set

from .analyzer import Analysis
from .errors import AnalysisTimeoutError
from .isa import LINUX_SYSCALLS, REGS64, REG_INFO, WIN_APIS, is_cond_jump
from .parser import Operand, parse_number

MASK64 = (1 << 64) - 1
DATA_BASE = 0x00400000
BSS_BASE = 0x00600000
STACK_TOP = 0x00007FFFFFFFF000
RET_MAGIC = 0xC0DE0000
RET_SENTINEL = 0xDEAD0000  # return of a function run standalone

#: Translation of the 32-bit ABI (i386) syscall numbers to the 64-bit ones.
#: ``INT 0x80`` uses the old table, where ``write`` is 4 (and not 1) and ``exit``
#: is 1 (and not 60): without this translation, the classic 32-bit example would
#: write to the wrong syscall.
I386_SYSCALLS: Dict[int, int] = {
    1: 60,  # exit
    3: 0,  # read
    4: 1,  # write
    5: 2,  # open
    6: 3,  # close
    13: 201,  # time
    20: 39,  # getpid
    45: 12,  # brk
    162: 35,  # nanosleep
    355: 318,  # getrandom
}


def hexs(v: int) -> str:
    """Formats an integer as a 64-bit hexadecimal.

    Args:
        v: Value to format.

    Returns:
        Text in the ``0x...`` format, already truncated to 64 bits.
    """
    return "0x%x" % (v & MASK64)


def to_signed(v: int, size: int = 8) -> int:
    """Interprets the bits of a value as a signed number.

    Args:
        v: Value to interpret.
        size: Size in bytes.

    Returns:
        The two's complement equivalent value.
    """
    bits = size * 8
    v &= (1 << bits) - 1
    return v - (1 << bits) if v >> (bits - 1) else v


@dataclass
class Step:
    """One executed instruction, as it appears in the interface history.

    Attributes:
        line: Line number in the source.
        text: Instruction text.
        note: What the machine did in this step.
        issue: Issue mark (``"fatal"`` on the stops), when there is one.
    """

    line: int
    text: str
    note: str
    issue: Optional[str] = None


@dataclass
class Symbol:
    """A symbol loaded into the simulated memory.

    Attributes:
        addr: Simulated address, or ``None`` on ``equ`` symbols.
        size: Size in bytes (data and reserves).
        equ: Constant value, when the symbol came from an ``equ``.
        bss: Whether the symbol lives in ``.bss`` (no initial content).
        line: Source line where the symbol was defined.
    """

    addr: Optional[int]
    size: int = 0
    equ: Optional[int] = None
    bss: bool = False
    line: int = 0


class Machine:
    """Runs the analysis instruction by instruction, recording what happens.

    The simulated state (registers, memory, flags and output) lives in the
    attributes created by :meth:`reset`; each step becomes a :class:`Step` in
    the ``trace`` history.
    """

    def __init__(
        self,
        analysis: Analysis,
        stdin: str = "",
        entry: Optional[str] = None,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        """Prepares the machine and loads the program data.

        Args:
            analysis: Complete analysis of the source.
            stdin: Simulated input used by the read syscall.
            entry: Function to run standalone; without it ``_start``,
                ``main``, ``start`` and ``WinMain`` apply.
            clock: Clock used for the time limit (``time.monotonic`` by default).
        """
        self.analysis = analysis
        self.instrs = analysis.instrs
        self.label_at = analysis.label_at
        self.platform = analysis.platform
        self.stdin = stdin
        self.entry = entry
        self.clock: Callable[[], float] = clock or time.monotonic
        self.reset()

    # ------------------------------------------------------------- state --
    def reset(self) -> None:
        """Returns the machine to the initial state and reloads the program data.

        Zeroes registers, memory, flags, output and history; RSP and RBP now
        point to the top of the simulated stack.
        """
        self.regs: Dict[str, int] = {r: 0 for r in REGS64}
        self.xmm: Dict[str, int] = {}
        self.flags = {"ZF": 0, "SF": 0, "CF": 0, "OF": 0, "PF": 0, "DF": 0}
        self.mem: Dict[int, int] = {}
        self.written: set = set()
        self.output = ""
        self.issues: List[str] = []
        self.trace: List[Step] = []
        self.halted = False
        self.exit_code: Optional[int] = None
        self.steps = 0
        self.timed_out = False
        self.stdin_pos = 0
        self.call_depth = 0
        self.regs["rsp"] = STACK_TOP
        self.regs["rbp"] = STACK_TOP
        self.symbols: Dict[str, Symbol] = {}
        self._load_data()
        self.ip = self._entry_index()
        self.entry_ip = self.ip
        if self.entry:
            # running a standalone function: put a fake return address on the
            # stack so that its RET ends the execution without looking like an error
            self.push(RET_SENTINEL)

    def _entry_index(self) -> int:
        """Chooses the index of the instruction where execution starts.

        Returns:
            The index of the requested entry point, or of ``_start``/``main``/
            ``start``/``WinMain``; zero when none of them exists.
        """
        candidates = [self.entry] if self.entry else []
        candidates += ["_start", "main", "start", "WinMain"]
        for c in candidates:
            if c and c in self.label_at:
                return self.label_at[c]
        return 0

    # ------------------------------------------------------------- memory -
    def rd8(self, addr: int) -> int:
        """Reads one byte from the simulated memory.

        Args:
            addr: Address to read from.

        Returns:
            The byte stored at the address, or 0 when nothing was written there.
        """
        return self.mem.get(addr & MASK64, 0)

    def wr8(self, addr: int, value: int) -> None:
        """Writes one byte into the simulated memory.

        Args:
            addr: Address to write to.
            value: Stored value; only the low 8 bits go in.
        """
        addr &= MASK64
        self.mem[addr] = value & 0xFF
        self.written.add(addr)

    def read_mem(self, addr: int, size: int) -> int:
        """Reads a little-endian value from memory.

        Args:
            addr: Address of the first byte.
            size: Number of bytes read.

        Returns:
            The integer formed by the bytes read.
        """
        v = 0
        for i in range(size - 1, -1, -1):
            v = (v << 8) | self.rd8(addr + i)
        return v

    def write_mem(self, addr: int, size: int, value: int) -> None:
        """Writes a little-endian value into memory.

        Args:
            addr: Address of the first byte.
            size: Number of bytes written.
            value: Stored value; bytes above ``size`` are discarded.
        """
        v = value & MASK64
        for i in range(size):
            self.wr8(addr + i, v & 0xFF)
            v >>= 8

    def read_cstring(self, addr: int, limit: int = 4096) -> str:
        """Reads a zero-terminated string.

        Args:
            addr: Address of the first character.
            limit: Maximum number of bytes read.

        Returns:
            The text found before the terminator, or up to the limit.
        """
        out = []
        for i in range(limit):
            b = self.rd8(addr + i)
            if not b:
                break
            out.append(chr(b))
        return "".join(out)

    def _load_data(self) -> None:
        """Loads the data, the reserves and the ``equ`` symbols into memory.

        Builds ``self.symbols``, writes the initial content of ``.data`` and
        gives addresses to the ``.bss`` reserves, which have no content.
        """
        cursor, bss_cursor = DATA_BASE, BSS_BASE
        for linha in self.analysis.program.lines:
            if linha.kind != "data":
                continue
            if linha.directive == "equ":
                if linha.label:
                    self.symbols[linha.label] = Symbol(
                        addr=None,
                        equ=parse_number(linha.args[0] if linha.args else "0"),
                        line=linha.n,
                    )
                continue
            if linha.reserve:
                n = parse_number(linha.args[0] if linha.args else "0") * linha.unit
                if linha.label:
                    self.symbols[linha.label] = Symbol(
                        addr=bss_cursor, size=n, bss=True, line=linha.n
                    )
                linha.addr = bss_cursor
                bss_cursor += max(n, 1)
                continue

            data: List[int] = []
            if linha.directive == "times":
                data = self._repeat_bytes(linha)
            else:
                for a in linha.args:
                    a = a.strip()
                    sm = re.fullmatch(r"(['\"])([\s\S]*)\1", a)
                    if sm:
                        s = (
                            sm.group(2)
                            .replace("\\n", "\n")
                            .replace("\\t", "\t")
                            .replace("\\0", "\0")
                            .replace("\\\\", "\\")
                        )
                        data += [ord(c) & 0xFF for c in s]
                        data += [0] * (linha.unit - 1)
                        continue
                    dm = re.match(r"^(\d+)\s+dup\s*\(\s*([^)]*)\)", a, re.I)
                    if dm:
                        cnt = int(dm.group(1))
                        val = 0 if "?" in dm.group(2) else parse_number(dm.group(2))
                        for _ in range(cnt):
                            for u in range(linha.unit):
                                data.append((val >> (8 * u)) & 0xFF)
                        continue
                    val = 0 if a == "?" else parse_number(a)
                    val &= (1 << (linha.unit * 8)) - 1
                    for u in range(linha.unit):
                        data.append((val >> (8 * u)) & 0xFF)

            addr = cursor
            if linha.label:
                self.symbols[linha.label] = Symbol(addr=addr, size=len(data), line=linha.n)
            for i, b in enumerate(data):
                self.wr8(addr + i, b)
            linha.addr = addr
            cursor += max(len(data), 1)

        # "len equ $ - msg" symbols
        for linha in self.analysis.program.lines:
            if linha.kind == "data" and linha.directive == "equ" and linha.label and linha.args:
                m = re.search(r"\$\s*-\s*([A-Za-z_.$][\w.$]*)", linha.args[0])
                if m and m.group(1) in self.symbols:
                    self.symbols[linha.label] = Symbol(
                        addr=None, equ=self.symbols[m.group(1)].size, line=linha.n
                    )

    @staticmethod
    def _repeat_bytes(line: Any) -> List[int]:
        """Builds the bytes of a ``times`` directive.

        Understands ``times 64 db 0`` (zeros), ``times 3 db 7`` (repeated
        value), ``times 4 dw 0x1234`` (value with more than one byte,
        little-endian) and ``times 2 db "ab"`` (repeated string). When the
        syntax is not recognized, it returns an empty list — the same as the
        directive generating no data at all.

        Args:
            line: Data line from the parser.

        Returns:
            The list of bytes, in the order they go into memory.
        """
        texto = line.args[0] if line.args else ""
        m = re.match(r"^(\w+)\s+(db|dw|dd|dq)\s+(.*)$", texto, re.I)
        if not m:
            return []
        count = parse_number(m.group(1))
        unit = {"db": 1, "dw": 2, "dd": 4, "dq": 8}[m.group(2).lower()]
        valor = m.group(3).strip()
        if count <= 0:
            return []

        sm = re.fullmatch(r"(['\"])([\s\S]*)\1", valor)
        if sm:
            bruto = [ord(c) & 0xFF for c in sm.group(2)]
            return bruto * count

        numero = 0 if valor in ("?", "") else parse_number(valor)
        numero &= (1 << (unit * 8)) - 1
        return [((numero >> (8 * u)) & 0xFF) for _ in range(count) for u in range(unit)]

    # ----------------------------------------------------------- registers -
    def get_reg(self, name: str) -> int:
        """Reads a register by name, respecting the size of the name.

        Args:
            name: Register name (``rax``, ``eax``, ``al``, ``ah``,
                ``xmm0``...).

        Returns:
            The value masked to the size of the name; 0 for an unknown name.
        """
        info = REG_INFO.get(name)
        if not info:
            return 0
        if info.get("simd"):
            return self.xmm.get(info["base"], 0)
        full = self.regs.get(info["base"], 0)
        if info["high"]:
            return (full >> 8) & 0xFF
        return full & ((1 << (info["size"] * 8)) - 1)

    def set_reg(self, name: str, value: int) -> None:
        """Writes to a register by name, respecting the size of the name.

        As on the real CPU, writing to a 32-bit name zeroes the high 32 bits of
        the 64-bit register.

        Args:
            name: Register name.
            value: Value written.
        """
        info = REG_INFO.get(name)
        if not info:
            return
        if info.get("simd"):
            self.xmm[info["base"]] = value & ((1 << 128) - 1)
            return
        v = value & MASK64
        cur = self.regs.get(info["base"], 0)
        if info["size"] == 8:
            self.regs[info["base"]] = v
        elif info["size"] == 4:
            self.regs[info["base"]] = v & 0xFFFFFFFF
        elif info["high"]:
            self.regs[info["base"]] = (cur & ~0xFF00) | ((v & 0xFF) << 8)
        else:
            mask = (1 << (info["size"] * 8)) - 1
            self.regs[info["base"]] = (cur & ~mask) | (v & mask)

    # ----------------------------------------------------------- operands -
    def symbol_addr(self, name: str) -> int:
        """Resolves the address of a symbol.

        Args:
            name: Name of the symbol or of the label.

        Returns:
            The address in the simulated memory, the value of an ``equ`` or 0
            when the name does not exist.
        """
        s = self.symbols.get(name)
        if s:
            return s.addr if s.addr is not None else (s.equ or 0)
        if name in self.label_at:
            return RET_MAGIC + self.label_at[name]
        return 0

    def eval_addr(self, op: Operand) -> int:
        """Computes the address of a memory operand.

        Adds the terms of ``[base + index*scale + displacement]``, accepting
        registers, symbols and numbers.

        Args:
            op: Operand of type ``mem``.

        Returns:
            The address masked to 64 bits.
        """
        inner = re.sub(r"\brel\b", "", op.inner or op.text or "", flags=re.I).strip()
        total = 0
        for term in inner.replace("-", "+-").split("+"):
            term = term.strip()
            if not term:
                continue
            neg = term.startswith("-")
            if neg:
                term = term[1:].strip()
            acc = 1
            for factor in term.split("*"):
                f = factor.strip()
                low = f.lower()
                if low in REG_INFO:
                    acc *= self.get_reg(low)
                elif re.fullmatch(r"[A-Za-z_.$][\w.$@]*", f):
                    acc *= self.symbol_addr(f)
                else:
                    acc *= parse_number(f)
            total += -acc if neg else acc
        return total & MASK64

    def op_size(self, op: Operand, other: Optional[Operand] = None) -> int:
        """Finds the size, in bytes, of an operand.

        Args:
            op: Main operand.
            other: Another operand, consulted when the main one does not declare
                a size.

        Returns:
            The declared size, the register size or 8 as a last resort.
        """
        if op.size:
            return op.size
        if op.type == "reg":
            return REG_INFO[op.reg]["size"]
        if other is not None:
            if other.size:
                return other.size
            if other.type == "reg":
                return REG_INFO[other.reg]["size"]
        return 8

    def read(self, op: Operand, other: Optional[Operand] = None) -> int:
        """Reads the value of an operand.

        Reading memory that was never written records an issue, because on the
        real machine the content would be garbage.

        Args:
            op: Operand to read.
            other: Another operand, used to deduce the size of the memory.

        Returns:
            The value of the register, the immediate, the symbol, the memory or
            the expression; 0 for an unknown operand.
        """
        if op.type == "reg":
            return self.get_reg(op.reg)
        if op.type == "imm":
            return op.value & MASK64
        if op.type == "sym":
            return self.symbol_addr(op.symbol)
        if op.type == "mem":
            addr = self.eval_addr(op)
            size = self.op_size(op, other)
            if not any((addr + i) in self.written for i in range(size)):
                self._issue(
                    "read of memory never written at %s — the real value would be garbage"
                    % hexs(addr)
                )
            return self.read_mem(addr, size)
        if op.type == "expr":
            return self.eval_addr(op)
        return 0

    def write(self, op: Operand, value: int, other: Optional[Operand] = None) -> None:
        """Writes a value to an operand.

        Args:
            op: Target operand (register or memory).
            value: Value written.
            other: Another operand, used to deduce the size of the memory.
        """
        if op.type == "reg":
            self.set_reg(op.reg, value)
        elif op.type == "mem":
            self.write_mem(self.eval_addr(op), self.op_size(op, other), value)

    # -------------------------------------------------------------- flags -
    def _parity(self, v: int) -> int:
        """Computes the parity of the low 8 bits.

        Args:
            v: Value being analyzed.

        Returns:
            1 when the number of 1 bits is even, otherwise 0.
        """
        low = v & 0xFF
        return 0 if bin(low).count("1") % 2 else 1

    def set_logic_flags(self, res: int, size: int) -> None:
        """Updates the flags after a logic operation.

        ZF and SF come from the result, CF and OF are zeroed and PF comes from
        the parity of the low 8 bits.

        Args:
            res: Result of the operation.
            size: Size of the operand, in bytes.
        """
        bits = size * 8
        v = res & ((1 << bits) - 1)
        self.flags["ZF"] = 1 if v == 0 else 0
        self.flags["SF"] = 1 if (v >> (bits - 1)) & 1 else 0
        self.flags["CF"] = 0
        self.flags["OF"] = 0
        self.flags["PF"] = self._parity(v)

    def set_arith_flags(self, a: int, b: int, res: int, size: int, is_sub: bool) -> None:
        """Updates the flags after an addition or a subtraction.

        CF marks the unsigned overflow and OF the signed one; ZF, SF and PF come
        from the result.

        Args:
            a: First operand.
            b: Second operand.
            res: Result of the operation.
            size: Size of the operand, in bytes.
            is_sub: Whether the operation is a subtraction.
        """
        bits = size * 8
        mask = (1 << bits) - 1
        v = res & mask
        self.flags["ZF"] = 1 if v == 0 else 0
        self.flags["SF"] = 1 if (v >> (bits - 1)) & 1 else 0
        if is_sub:
            self.flags["CF"] = 1 if (a & mask) < (b & mask) else 0
        else:
            self.flags["CF"] = 1 if res > mask else 0
        sa, sb, sr = to_signed(a, size), to_signed(b, size), to_signed(v, size)
        if is_sub:
            self.flags["OF"] = 1 if ((sa < 0) != (sb < 0) and (sr < 0) != (sa < 0)) else 0
        else:
            self.flags["OF"] = 1 if ((sa < 0) == (sb < 0) and (sr < 0) != (sa < 0)) else 0
        self.flags["PF"] = self._parity(v)

    def cond(self, cc: str) -> bool:
        """Evaluates a branch condition from the flags.

        Args:
            cc: Condition suffix (``e``, ``ne``, ``g``, ``b``...).

        Returns:
            ``True`` when the condition holds and ``False`` otherwise,
            including for an unknown suffix.
        """
        f = self.flags
        return {
            "e": f["ZF"] == 1,
            "z": f["ZF"] == 1,
            "ne": f["ZF"] == 0,
            "nz": f["ZF"] == 0,
            "g": f["ZF"] == 0 and f["SF"] == f["OF"],
            "ge": f["SF"] == f["OF"],
            "l": f["SF"] != f["OF"],
            "le": f["ZF"] == 1 or f["SF"] != f["OF"],
            "a": f["CF"] == 0 and f["ZF"] == 0,
            "ae": f["CF"] == 0,
            "nc": f["CF"] == 0,
            "b": f["CF"] == 1,
            "c": f["CF"] == 1,
            "be": f["CF"] == 1 or f["ZF"] == 1,
            "s": f["SF"] == 1,
            "ns": f["SF"] == 0,
            "o": f["OF"] == 1,
            "no": f["OF"] == 0,
            "p": f["PF"] == 1,
            "np": f["PF"] == 0,
        }.get(cc, False)

    # -------------------------------------------------------------- stack -
    def push(self, v: int) -> None:
        """Pushes an 8-byte value.

        Args:
            v: Value pushed; RSP decreases by 8 before the write.
        """
        self.regs["rsp"] = (self.regs["rsp"] - 8) & MASK64
        self.write_mem(self.regs["rsp"], 8, v)

    def pop(self) -> int:
        """Pops an 8-byte value.

        Records an issue when the stack is already empty.

        Returns:
            The value that was on top; RSP increases by 8.
        """
        if self.regs["rsp"] >= STACK_TOP:
            self._issue("POP with an empty stack — stack underflow")
        v = self.read_mem(self.regs["rsp"], 8)
        self.regs["rsp"] = (self.regs["rsp"] + 8) & MASK64
        return v

    def _issue(self, msg: str) -> None:
        """Records an issue, without repeating equal messages.

        Args:
            msg: Message added to the issue list.
        """
        if msg not in self.issues:
            self.issues.append(msg)

    # ----------------------------------------------------------- syscalls -
    def do_syscall(self) -> str:
        """Runs the syscall indicated by the number in RAX.

        Emulates ``write``, ``read``, ``exit``/``exit_group``, ``getpid``,
        ``time``, ``nanosleep``, ``brk`` and ``getrandom``; any other one zeroes
        RAX and goes into the issue list.

        Returns:
            Description of what the call did.
        """
        n = self.regs["rax"] & 0xFFFFFFFF
        info = LINUX_SYSCALLS.get(n)
        name = info[0] if info else "syscall %d" % n
        if n == 1:
            length = self.regs["rdx"]
            addr = self.regs["rsi"]
            if length > 1 << 20:
                self._issue("write with an absurd size (%d bytes) — RDX is probably wrong" % length)
                length = 4096
            s = "".join(chr(self.rd8(addr + i)) for i in range(length))
            self.output += s
            self.regs["rax"] = length
            return "write: wrote %d bytes to descriptor %d" % (length, self.regs["rdi"])
        if n == 0:
            cnt = self.regs["rdx"]
            dst = self.regs["rsi"]
            got = 0
            while got < cnt and self.stdin_pos < len(self.stdin):
                self.wr8(dst + got, ord(self.stdin[self.stdin_pos]) & 0xFF)
                self.stdin_pos += 1
                got += 1
            self.regs["rax"] = got
            return "read: read %d bytes from the simulated input" % got
        if n in (60, 231):
            self.halted = True
            self.exit_code = to_signed(self.regs["rdi"], 4)
            return "%s: process terminated with code %d" % (name, self.exit_code)
        if n == 39:
            self.regs["rax"] = 4242
            return "getpid: returned 4242 (simulated)"
        if n == 201:
            self.regs["rax"] = int(time.time())
            return "time: current time"
        if n == 35:
            return "nanosleep: ignored in the simulation"
        if n == 12:
            self.regs["rax"] = BSS_BASE + 0x10000
            return "brk: simulated heap"
        if n == 318:
            qn = self.regs["rsi"]
            for i in range(min(qn, 4096)):
                self.wr8(self.regs["rdi"] + i, random.randrange(256))
            self.regs["rax"] = qn
            return "getrandom: %d random bytes" % qn
        self.regs["rax"] = 0
        self._issue("syscall %d is not emulated — the result in RAX is fictitious" % n)
        return "%s: not emulated, RAX zeroed" % name

    def do_win_api(self, raw_name: str) -> str:
        """Runs a Windows API function, or records that it is not emulated.

        Emulates ``ExitProcess``, ``GetStdHandle``, ``WriteConsoleA``/``WriteFile``,
        ``MessageBoxA``/``MessageBoxW``, ``Sleep`` and ``GetLastError``.

        Args:
            raw_name: Function name as it appeared in the CALL.

        Returns:
            Description of what the call did.
        """
        key = re.sub(r"^_+|@.*$", "", str(raw_name).lower())
        api = WIN_APIS.get(key)
        if key == "exitprocess":
            self.halted = True
            self.exit_code = to_signed(self.regs["rcx"], 4)
            return "ExitProcess: process terminated with code %d" % self.exit_code
        if key == "getstdhandle":
            self.regs["rax"] = 0x13
            return "GetStdHandle: returned a simulated handle (0x13)"
        if key in ("writeconsolea", "writefile"):
            length = self.regs["r8"]
            addr = self.regs["rdx"]
            s = "".join(chr(self.rd8(addr + i)) for i in range(min(length, 1 << 20)))
            self.output += s
            self.regs["rax"] = 1
            return "%s: wrote %d bytes to the console" % (api[0] if api else key, length)
        if key in ("messageboxa", "messageboxw"):
            txt = self.read_cstring(self.regs["rdx"], 512)
            tit = self.read_cstring(self.regs["r8"], 256)
            self.output += "[MessageBox] %s: %s\n" % (tit, txt)
            self.regs["rax"] = 1
            return "MessageBoxA: message box displayed (shown in the output)"
        if key == "sleep":
            return "Sleep: ignored in the simulation"
        if key == "getlasterror":
            self.regs["rax"] = 0
            return "GetLastError: 0"
        self.regs["rax"] = 0
        self._issue("external function %s is not emulated — RAX zeroed" % raw_name)
        return "%s: stub, RAX zeroed" % (api[0] if api else raw_name)

    # --------------------------------------------------------- execution --
    @property
    def current(self) -> Optional[object]:
        """Instruction pointed to by the IP, when it exists.

        Returns:
            The current instruction or ``None`` at the end of the code.
        """
        return self.instrs[self.ip] if 0 <= self.ip < len(self.instrs) else None

    def _jump_target(self, op: Operand, ins: Any) -> Optional[int]:
        """Resolves the target label of a jump.

        Args:
            op: Operand with the target label.
            ins: Jump instruction, used in the unknown label warning.

        Returns:
            The index of the target instruction, or ``None`` when the label does
            not exist in the program.
        """
        t = op.symbol or op.text
        if t in self.label_at:
            return self.label_at[t]
        self._issue("unknown label: %s (line %d)" % (t, ins.n))
        return None

    def step(self) -> Step:  # noqa: C901 (~70 instruction dispatch)
        """Runs one instruction and records what happened.

        Instructions that are not emulated are skipped with a recorded issue;
        internal simulation errors become issues, without taking the machine
        down.

        Returns:
            The :class:`Step` with line, text, note and issue mark.
        """
        if self.halted:
            return Step(0, "", "Execution has already finished.")
        ins = self.current
        if ins is None:
            self.halted = True
            return Step(0, "", "End of code.")

        m = ins.mnemonic
        ops = ins.operands
        o0 = ops[0] if ops else None
        o1 = ops[1] if len(ops) > 1 else None
        o2 = ops[2] if len(ops) > 2 else None
        size = self.op_size(o0, o1) if o0 else 8
        nxt = self.ip + 1
        note = ""
        self.steps += 1

        try:
            if m == "mov":
                v = self.read(o1, o0)
                if o1.type == "imm" and o0.type == "reg":
                    fits = (1 << (size * 8)) - 1
                    if o1.value > fits or o1.value < -(1 << (size * 8 - 1)):
                        self._issue(
                            "line %d: the value %s does not fit in %s (%d bits) and will "
                            "be truncated" % (ins.n, o1.text, o0.text, size * 8)
                        )
                self.write(o0, v, o1)
                note = "%s = %s" % (o0.text, hexs(v))
            elif m == "movzx":
                v = self.read(o1)
                self.write(o0, v)
                note = "%s = %s (leading zeros)" % (o0.text, hexs(v))
            elif m in ("movsx", "movsxd"):
                sz = o1.size or (REG_INFO[o1.reg]["size"] if o1.type == "reg" else 4)
                sv = to_signed(self.read(o1), sz)
                self.write(o0, sv & MASK64)
                note = "%s = %d (sign preserved)" % (o0.text, sv)
            elif m == "lea":
                a = self.eval_addr(o1)
                self.write(o0, a)
                note = "%s = address %s" % (o0.text, hexs(a))
            elif m == "xchg":
                x, y = self.read(o0), self.read(o1)
                self.write(o0, y)
                self.write(o1, x)
                note = "swapped %s with %s" % (o0.text, o1.text)
            elif m == "push":
                self.push(self.read(o0))
                note = "pushed %s; RSP = %s" % (
                    hexs(self.read_mem(self.regs["rsp"], 8)),
                    hexs(self.regs["rsp"]),
                )
            elif m == "pop":
                v = self.pop()
                self.write(o0, v)
                note = "%s = %s; RSP = %s" % (o0.text, hexs(v), hexs(self.regs["rsp"]))
            elif m in ("add", "adc"):
                a, b = self.read(o0), self.read(o1, o0)
                carry = self.flags["CF"] if m == "adc" else 0
                r = a + b + carry
                self.set_arith_flags(a, b, r, size, False)
                if self.flags["CF"]:
                    self._issue(
                        "line %d: the sum overflowed %d bits (CF=1) — result truncated"
                        % (ins.n, size * 8)
                    )
                self.write(o0, r & MASK64)
                note = "%s = %s" % (o0.text, hexs(r & ((1 << (size * 8)) - 1)))
            elif m in ("sub", "sbb"):
                a = self.read(o0)
                b = self.read(o1, o0) + (self.flags["CF"] if m == "sbb" else 0)
                r = a - b
                self.set_arith_flags(a, b, r, size, True)
                self.write(o0, r & MASK64)
                note = "%s = %s" % (o0.text, hexs(r & ((1 << (size * 8)) - 1)))
            elif m in ("inc", "dec"):
                a = self.read(o0)
                r = a + (1 if m == "inc" else -1)
                cf = self.flags["CF"]
                self.set_arith_flags(a, 1, r, size, m == "dec")
                self.flags["CF"] = cf
                self.write(o0, r & MASK64)
                note = "%s = %s" % (o0.text, hexs(r & ((1 << (size * 8)) - 1)))
            elif m == "neg":
                a = self.read(o0)
                r = -a
                self.set_arith_flags(0, a, r, size, True)
                self.write(o0, r & MASK64)
                note = "%s = %d" % (o0.text, to_signed(r, size))
            elif m in ("and", "or", "xor"):
                a, b = self.read(o0), self.read(o1, o0)
                r = a & b if m == "and" else (a | b if m == "or" else a ^ b)
                self.set_logic_flags(r, size)
                self.write(o0, r)
                note = "%s = %s" % (o0.text, hexs(r & ((1 << (size * 8)) - 1)))
            elif m == "not":
                self.write(o0, (~self.read(o0)) & MASK64)
                note = "%s inverted" % o0.text
            elif m == "test":
                r = self.read(o0) & self.read(o1, o0)
                self.set_logic_flags(r, size)
                note = "flags updated: ZF=%d" % self.flags["ZF"]
            elif m == "cmp":
                a, b = self.read(o0), self.read(o1, o0)
                self.set_arith_flags(a, b, a - b, size, True)
                note = "compared %d with %d → ZF=%d SF=%d CF=%d OF=%d" % (
                    to_signed(a, size),
                    to_signed(b, size),
                    self.flags["ZF"],
                    self.flags["SF"],
                    self.flags["CF"],
                    self.flags["OF"],
                )
            elif m in ("shl", "sal", "shr", "sar"):
                val = self.read(o0)
                cnt = (self.read(o1) & 63) if o1 else 1
                if m == "sar":
                    r = to_signed(val, size) >> cnt
                elif m == "shr":
                    r = (val & ((1 << (size * 8)) - 1)) >> cnt
                else:
                    r = val << cnt
                self.set_logic_flags(r & ((1 << (size * 8)) - 1), size)
                self.write(o0, r & MASK64)
                note = "%s = %s" % (o0.text, hexs(r & ((1 << (size * 8)) - 1)))
            elif m == "imul":
                if len(ops) == 1:
                    r = to_signed(self.regs["rax"]) * to_signed(self.read(o0), size)
                    self.regs["rax"] = r & MASK64
                    note = "RAX = %d" % r
                elif o2 is not None:
                    r = to_signed(self.read(o1)) * to_signed(self.read(o2))
                    self.write(o0, r & MASK64)
                    note = "%s = %d" % (o0.text, r)
                else:
                    r = to_signed(self.read(o0)) * to_signed(self.read(o1, o0))
                    self.write(o0, r & MASK64)
                    note = "%s = %d" % (o0.text, r)
            elif m == "mul":
                r = self.regs["rax"] * self.read(o0)
                self.regs["rax"] = r & MASK64
                self.regs["rdx"] = (r >> 64) & MASK64
                note = "RAX = %s" % hexs(self.regs["rax"])
            elif m in ("div", "idiv"):
                d = self.read(o0)
                if d == 0:
                    self._issue(
                        "line %d: division by zero — the real CPU raises the #DE exception "
                        "and the process dies" % ins.n
                    )
                    self.halted = True
                    return self._record(ins, "division by zero", issue="fatal")
                if m == "div":
                    num = (self.regs["rdx"] << 64) | self.regs["rax"]
                    if self.regs["rdx"] and num // d > MASK64:
                        self._issue(
                            "line %d: the quotient does not fit in RAX (#DE). Zero RDX "
                            "before the DIV." % ins.n
                        )
                    self.regs["rax"] = (num // d) & MASK64
                    self.regs["rdx"] = (num % d) & MASK64
                else:
                    sn, sd = to_signed(self.regs["rax"]), to_signed(d)
                    q = abs(sn) // abs(sd) * (1 if (sn < 0) == (sd < 0) else -1)
                    rem = sn - q * sd
                    self.regs["rax"] = q & MASK64
                    self.regs["rdx"] = rem & MASK64
                note = "quotient in RAX = %d, remainder in RDX = %d" % (
                    to_signed(self.regs["rax"]),
                    to_signed(self.regs["rdx"]),
                )
            elif m == "cdq":
                self.regs["rdx"] = 0xFFFFFFFF if to_signed(self.regs["rax"], 4) < 0 else 0
                note = "EDX sign-extended from EAX"
            elif m == "cqo":
                self.regs["rdx"] = MASK64 if to_signed(self.regs["rax"]) < 0 else 0
                note = "RDX sign-extended from RAX"
            elif m == "jmp":
                t = self._jump_target(o0, ins)
                if t is None:
                    self.halted = True
                    return self._record(ins, "jump to a nonexistent label", issue="fatal")
                nxt = t
                note = "jumped to %s" % o0.text
            elif is_cond_jump(m):
                cc = m[1:]
                taken = (self.regs["rcx"] == 0) if cc in ("rcxz", "ecxz", "cxz") else self.cond(cc)
                if taken:
                    t = self._jump_target(o0, ins)
                    if t is not None:
                        nxt = t
                note = (
                    ("condition true → jumped to %s" % o0.text)
                    if taken
                    else "condition false → continued on the next line"
                )
            elif m.startswith("set"):
                b = 1 if self.cond(m[3:]) else 0
                self.write(o0, b)
                note = "%s = %d" % (o0.text, b)
            elif m.startswith("cmov"):
                if self.cond(m[4:]):
                    self.write(o0, self.read(o1, o0))
                    note = "condition true → copied"
                else:
                    note = "condition false → did not copy"
            elif m == "loop":
                self.regs["rcx"] = (self.regs["rcx"] - 1) & MASK64
                if self.regs["rcx"]:
                    t = self._jump_target(o0, ins)
                    if t is not None:
                        nxt = t
                    note = "RCX = %d, repeated" % self.regs["rcx"]
                else:
                    note = "RCX reached zero, left the loop"
            elif m == "call":
                name = o0.symbol or o0.text
                if self.platform.os == "windows" and (self.regs["rsp"] % 16) not in (0, 8):
                    self._issue(
                        "line %d: RSP is not aligned to 16 bytes on the call to %s — "
                        "the Windows ABI requires alignment" % (ins.n, name)
                    )
                if name in self.label_at:
                    self.push(RET_MAGIC + self.ip + 1)
                    nxt = self.label_at[name]
                    self.call_depth += 1
                    note = "called %s; return address pushed" % name
                else:
                    note = self.do_win_api(name)
            elif m.startswith("ret"):
                rv = self.pop()
                if rv == RET_SENTINEL:
                    self.halted = True
                    self.exit_code = to_signed(self.regs["rax"], 4)
                    note = "returned from the function under test; RAX = %d" % to_signed(
                        self.regs["rax"]
                    )
                elif RET_MAGIC <= rv < RET_MAGIC + 1000000:
                    nxt = rv - RET_MAGIC
                    self.call_depth -= 1
                    note = "returned to instruction %d" % (nxt + 1)
                else:
                    self.halted = True
                    self.exit_code = to_signed(self.regs["rax"], 4)
                    if self.call_depth > 0 or rv != 0:
                        self._issue(
                            "line %d: RET took %s from the stack, which is not a valid "
                            "return address — the stack is unbalanced" % (ins.n, hexs(rv))
                        )
                    note = "RET without a valid address on the stack — treated as the end "
                    "of the program"
                if o0 is not None and o0.type == "imm":
                    self.regs["rsp"] = (self.regs["rsp"] + o0.value) & MASK64
            elif m == "leave":
                self.regs["rsp"] = self.regs["rbp"]
                self.regs["rbp"] = self.pop()
                note = "frame torn down; RSP = %s" % hexs(self.regs["rsp"])
            elif m == "syscall":
                note = self.do_syscall()
            elif m == "int":
                if o0 is not None and o0.text in ("0x80", "80h"):
                    self.regs["rdi"] = self.regs["rbx"]
                    self.regs["rsi"] = self.regs["rcx"]
                    i386 = self.regs["rax"] & 0xFFFFFFFF
                    equivalente = I386_SYSCALLS.get(i386)
                    if equivalente is None:
                        note = (
                            "INT 0x80: the 32-bit syscall %d has no known 64-bit "
                            "equivalent" % i386
                        )
                        self._issue("line %d: %s" % (ins.n, note))
                    else:
                        self.regs["rax"] = equivalente
                        note = (
                            "INT 0x80 (32-bit ABI, syscall %d → %d): " % (i386, equivalente)
                        ) + self.do_syscall()
                elif o0 is not None and o0.text == "3":
                    note = "INT 3 — breakpoint"
                else:
                    note = "unemulated interrupt"
            elif m in ("nop", "endbr64", "cld", "std"):
                if m == "cld":
                    self.flags["DF"] = 0
                if m == "std":
                    self.flags["DF"] = 1
                note = "nothing happened" if m == "nop" else "state adjusted"
            elif m in ("stosb", "movsb", "lodsb", "scasb"):
                rep = bool(ins.prefix and ins.prefix.startswith("rep"))
                count = self.regs["rcx"] if rep else 1
                if count > 1 << 20:
                    self._issue(
                        "line %d: REP with RCX = %d — probably a wrong counter" % (ins.n, count)
                    )
                    count = 1 << 20
                delta = -1 if self.flags["DF"] else 1
                done = 0
                while done < count:
                    if m == "stosb":
                        self.wr8(self.regs["rdi"], self.get_reg("al"))
                        self.regs["rdi"] = (self.regs["rdi"] + delta) & MASK64
                    elif m == "movsb":
                        self.wr8(self.regs["rdi"], self.rd8(self.regs["rsi"]))
                        self.regs["rsi"] = (self.regs["rsi"] + delta) & MASK64
                        self.regs["rdi"] = (self.regs["rdi"] + delta) & MASK64
                    elif m == "lodsb":
                        self.set_reg("al", self.rd8(self.regs["rsi"]))
                        self.regs["rsi"] = (self.regs["rsi"] + delta) & MASK64
                    else:
                        v = self.rd8(self.regs["rdi"])
                        self.set_arith_flags(self.get_reg("al"), v, self.get_reg("al") - v, 1, True)
                        self.regs["rdi"] = (self.regs["rdi"] + delta) & MASK64
                        if ins.prefix and "repne" in ins.prefix and self.flags["ZF"]:
                            done += 1
                            break
                    done += 1
                if rep:
                    self.regs["rcx"] = 0
                note = "%s %s" % (m, ("repeated %d times" % done) if rep else "executed")
            elif m == "hlt":
                self.halted = True
                note = "HLT — execution stopped"
            else:
                note = 'instruction "%s" is not emulated; it was skipped' % m
                self._issue("line %d: %s is not emulated by the virtual machine" % (ins.n, m))
        except Exception as exc:  # noqa: BLE001
            self._issue("line %d: simulation error — %s" % (ins.n, exc))
            note = "simulation error: %s" % exc

        self.ip = nxt
        if self.ip >= len(self.instrs):
            self.halted = True
            note += " | end of code reached"
            if self.exit_code is None:
                self._issue(
                    "the code ended without an explicit exit call — in practice execution "
                    "would continue through invalid memory"
                )
        return self._record(ins, note)

    def _record(self, ins: Any, note: str, issue: Optional[str] = None) -> Step:
        """Adds a step to the history, keeping the 2000 most recent ones.

        Args:
            ins: Executed instruction.
            note: Note about the step.
            issue: Issue mark (``"fatal"`` on the stops), when there is one.

        Returns:
            The recorded :class:`Step`.
        """
        s = Step(line=ins.n, text=ins.text, note=note, issue=issue)
        self.trace.append(s)
        if len(self.trace) > 2000:
            self.trace.pop(0)
        return s

    def run(
        self,
        limit: int = 200000,
        breakpoints: Optional[set] = None,
        timeout: Optional[float] = None,
        raise_on_timeout: bool = False,
    ) -> int:
        """Runs to the end, to a breakpoint, to the limit or until time runs out.

        Args:
            limit: Maximum number of instructions executed.
            breakpoints: Lines of the file where execution must stop.
            timeout: Maximum wall time, in seconds (optional).
            raise_on_timeout: Raises :class:`~asmx.errors.AnalysisTimeoutError`
                instead of only marking ``timed_out``.

        Returns:
            How many instructions were executed.

        Raises:
            AnalysisTimeoutError: If ``raise_on_timeout`` is true and the time
                limit is exceeded.
        """
        inicio = self.clock()
        n = 0
        while not self.halted and n < limit:
            self.step()
            n += 1
            if timeout is not None and n % 256 == 0 and (self.clock() - inicio) > timeout:
                self.timed_out = True
                self.halted = True
                self._issue("execution went past %g s — stopped by time (timeout)" % timeout)
                if raise_on_timeout:
                    raise AnalysisTimeoutError(timeout, steps=n)
                break
            if breakpoints and not self.halted:
                cur = self.current
                if cur is not None and cur.n in breakpoints:
                    break
        if n >= limit:
            self._issue("stopped after %d instructions — an infinite loop is very likely" % limit)
            self.halted = True
        return n

    def run_until(self, stop_indexes: Set[int], limit: int = 100000) -> int:
        """Runs until the IP reaches one of the given indexes or until the limit.

        Args:
            stop_indexes: Instruction indexes where execution must stop.
            limit: Maximum number of instructions executed.

        Returns:
            How many instructions were executed.
        """
        n = 0
        while not self.halted and n < limit:
            self.step()
            n += 1
            if self.ip in stop_indexes:
                break
        return n

    def snapshot(self) -> Dict[str, Any]:
        """Takes a snapshot of the current machine state.

        Returns:
            Dictionary with registers, flags, output, exit code, issues, number
            of steps and whether execution finished.
        """
        return {
            "regs": dict(self.regs),
            "flags": dict(self.flags),
            "output": self.output,
            "exit_code": self.exit_code,
            "issues": list(self.issues),
            "steps": self.steps,
            "halted": self.halted,
        }
