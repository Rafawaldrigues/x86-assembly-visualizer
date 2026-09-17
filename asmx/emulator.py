"""Máquina virtual didática de x86-64 em modo usuário."""

import random
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .analyzer import Analysis
from .isa import LINUX_SYSCALLS, REGS64, REG_INFO, WIN_APIS, is_cond_jump
from .parser import Operand, parse_number

MASK64 = (1 << 64) - 1
DATA_BASE = 0x00400000
BSS_BASE = 0x00600000
STACK_TOP = 0x00007FFFFFFFF000
RET_MAGIC = 0xC0DE0000
RET_SENTINEL = 0xDEAD0000   # retorno da função executada isoladamente


def hexs(v: int) -> str:
    return "0x%x" % (v & MASK64)


def to_signed(v: int, size: int = 8) -> int:
    bits = size * 8
    v &= (1 << bits) - 1
    return v - (1 << bits) if v >> (bits - 1) else v


@dataclass
class Step:
    line: int
    text: str
    note: str
    issue: Optional[str] = None


@dataclass
class Symbol:
    addr: Optional[int]
    size: int = 0
    equ: Optional[int] = None
    bss: bool = False
    line: int = 0


class Machine:
    """Executa a análise instrução a instrução, registrando o que acontece."""

    def __init__(self, analysis: Analysis, stdin: str = "", entry: Optional[str] = None):
        self.analysis = analysis
        self.instrs = analysis.instrs
        self.label_at = analysis.label_at
        self.platform = analysis.platform
        self.stdin = stdin
        self.entry = entry
        self.reset()

    # ------------------------------------------------------------ estado --
    def reset(self):
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
        self.stdin_pos = 0
        self.call_depth = 0
        self.regs["rsp"] = STACK_TOP
        self.regs["rbp"] = STACK_TOP
        self.symbols: Dict[str, Symbol] = {}
        self._load_data()
        self.ip = self._entry_index()
        self.entry_ip = self.ip
        if self.entry:
            # rodando uma função isolada: coloca um retorno de mentira na pilha
            # para o RET dela terminar a execução sem parecer erro
            self.push(RET_SENTINEL)

    def _entry_index(self) -> int:
        candidates = [self.entry] if self.entry else []
        candidates += ["_start", "main", "start", "WinMain"]
        for c in candidates:
            if c and c in self.label_at:
                return self.label_at[c]
        return 0

    # ------------------------------------------------------------ memória -
    def rd8(self, addr: int) -> int:
        return self.mem.get(addr & MASK64, 0)

    def wr8(self, addr: int, value: int):
        addr &= MASK64
        self.mem[addr] = value & 0xFF
        self.written.add(addr)

    def read_mem(self, addr: int, size: int) -> int:
        v = 0
        for i in range(size - 1, -1, -1):
            v = (v << 8) | self.rd8(addr + i)
        return v

    def write_mem(self, addr: int, size: int, value: int):
        v = value & MASK64
        for i in range(size):
            self.wr8(addr + i, v & 0xFF)
            v >>= 8

    def read_cstring(self, addr: int, limit: int = 4096) -> str:
        out = []
        for i in range(limit):
            b = self.rd8(addr + i)
            if not b:
                break
            out.append(chr(b))
        return "".join(out)

    def _load_data(self):
        cursor, bss_cursor = DATA_BASE, BSS_BASE
        for l in self.analysis.program.lines:
            if l.kind != "data":
                continue
            if l.directive == "equ":
                if l.label:
                    self.symbols[l.label] = Symbol(addr=None, equ=parse_number(l.args[0] if l.args else "0"), line=l.n)
                continue
            if l.reserve:
                n = parse_number(l.args[0] if l.args else "0") * l.unit
                if l.label:
                    self.symbols[l.label] = Symbol(addr=bss_cursor, size=n, bss=True, line=l.n)
                l.addr = bss_cursor
                bss_cursor += max(n, 1)
                continue

            data: List[int] = []
            if l.directive == "times":
                m = re.match(r"^(\w+)\s+(db|dw|dd|dq)\s+(.*)$", l.args[0] if l.args else "", re.I)
                if m:
                    count = parse_number(m.group(1))
                    unit = {"db": 1, "dw": 2, "dd": 4, "dq": 8}[m.group(2).lower()]
                    data = [0] * (count * unit)
            else:
                for a in l.args:
                    a = a.strip()
                    sm = re.fullmatch(r"(['\"])([\s\S]*)\1", a)
                    if sm:
                        s = (sm.group(2).replace("\\n", "\n").replace("\\t", "\t")
                             .replace("\\0", "\0").replace("\\\\", "\\"))
                        data += [ord(c) & 0xFF for c in s]
                        data += [0] * (l.unit - 1)
                        continue
                    dm = re.match(r"^(\d+)\s+dup\s*\(\s*([^)]*)\)", a, re.I)
                    if dm:
                        cnt = int(dm.group(1))
                        val = 0 if "?" in dm.group(2) else parse_number(dm.group(2))
                        for _ in range(cnt):
                            for u in range(l.unit):
                                data.append((val >> (8 * u)) & 0xFF)
                        continue
                    val = 0 if a == "?" else parse_number(a)
                    val &= (1 << (l.unit * 8)) - 1
                    for u in range(l.unit):
                        data.append((val >> (8 * u)) & 0xFF)

            addr = cursor
            if l.label:
                self.symbols[l.label] = Symbol(addr=addr, size=len(data), line=l.n)
            for i, b in enumerate(data):
                self.wr8(addr + i, b)
            l.addr = addr
            cursor += max(len(data), 1)

        # símbolos "len equ $ - msg"
        for l in self.analysis.program.lines:
            if l.kind == "data" and l.directive == "equ" and l.label and l.args:
                m = re.search(r"\$\s*-\s*([A-Za-z_.$][\w.$]*)", l.args[0])
                if m and m.group(1) in self.symbols:
                    self.symbols[l.label] = Symbol(addr=None, equ=self.symbols[m.group(1)].size, line=l.n)

    # ------------------------------------------------------ registradores -
    def get_reg(self, name: str) -> int:
        info = REG_INFO.get(name)
        if not info:
            return 0
        if info.get("simd"):
            return self.xmm.get(info["base"], 0)
        full = self.regs.get(info["base"], 0)
        if info["high"]:
            return (full >> 8) & 0xFF
        return full & ((1 << (info["size"] * 8)) - 1)

    def set_reg(self, name: str, value: int):
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

    # ---------------------------------------------------------- operandos -
    def symbol_addr(self, name: str) -> int:
        s = self.symbols.get(name)
        if s:
            return s.addr if s.addr is not None else (s.equ or 0)
        if name in self.label_at:
            return RET_MAGIC + self.label_at[name]
        return 0

    def eval_addr(self, op: Operand) -> int:
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
                self._issue("leitura de memória nunca escrita em %s — o valor real seria lixo"
                            % hexs(addr))
            return self.read_mem(addr, size)
        if op.type == "expr":
            return self.eval_addr(op)
        return 0

    def write(self, op: Operand, value: int, other: Optional[Operand] = None):
        if op.type == "reg":
            self.set_reg(op.reg, value)
        elif op.type == "mem":
            self.write_mem(self.eval_addr(op), self.op_size(op, other), value)

    # -------------------------------------------------------------- flags -
    def _parity(self, v: int) -> int:
        low = v & 0xFF
        return 0 if bin(low).count("1") % 2 else 1

    def set_logic_flags(self, res: int, size: int):
        bits = size * 8
        v = res & ((1 << bits) - 1)
        self.flags["ZF"] = 1 if v == 0 else 0
        self.flags["SF"] = 1 if (v >> (bits - 1)) & 1 else 0
        self.flags["CF"] = 0
        self.flags["OF"] = 0
        self.flags["PF"] = self._parity(v)

    def set_arith_flags(self, a: int, b: int, res: int, size: int, is_sub: bool):
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
        f = self.flags
        return {
            "e": f["ZF"] == 1, "z": f["ZF"] == 1,
            "ne": f["ZF"] == 0, "nz": f["ZF"] == 0,
            "g": f["ZF"] == 0 and f["SF"] == f["OF"],
            "ge": f["SF"] == f["OF"],
            "l": f["SF"] != f["OF"],
            "le": f["ZF"] == 1 or f["SF"] != f["OF"],
            "a": f["CF"] == 0 and f["ZF"] == 0,
            "ae": f["CF"] == 0, "nc": f["CF"] == 0,
            "b": f["CF"] == 1, "c": f["CF"] == 1,
            "be": f["CF"] == 1 or f["ZF"] == 1,
            "s": f["SF"] == 1, "ns": f["SF"] == 0,
            "o": f["OF"] == 1, "no": f["OF"] == 0,
            "p": f["PF"] == 1, "np": f["PF"] == 0,
        }.get(cc, False)

    # -------------------------------------------------------------- pilha -
    def push(self, v: int):
        self.regs["rsp"] = (self.regs["rsp"] - 8) & MASK64
        self.write_mem(self.regs["rsp"], 8, v)

    def pop(self) -> int:
        if self.regs["rsp"] >= STACK_TOP:
            self._issue("POP com a pilha vazia — estouro de pilha (stack underflow)")
        v = self.read_mem(self.regs["rsp"], 8)
        self.regs["rsp"] = (self.regs["rsp"] + 8) & MASK64
        return v

    def _issue(self, msg: str):
        if msg not in self.issues:
            self.issues.append(msg)

    # ----------------------------------------------------------- syscalls -
    def do_syscall(self) -> str:
        n = self.regs["rax"] & 0xFFFFFFFF
        info = LINUX_SYSCALLS.get(n)
        name = info[0] if info else "syscall %d" % n
        if n == 1:
            length = self.regs["rdx"]
            addr = self.regs["rsi"]
            if length > 1 << 20:
                self._issue("write com tamanho absurdo (%d bytes) — RDX provavelmente errado" % length)
                length = 4096
            s = "".join(chr(self.rd8(addr + i)) for i in range(length))
            self.output += s
            self.regs["rax"] = length
            return "write: escreveu %d bytes no descritor %d" % (length, self.regs["rdi"])
        if n == 0:
            cnt = self.regs["rdx"]
            dst = self.regs["rsi"]
            got = 0
            while got < cnt and self.stdin_pos < len(self.stdin):
                self.wr8(dst + got, ord(self.stdin[self.stdin_pos]) & 0xFF)
                self.stdin_pos += 1
                got += 1
            self.regs["rax"] = got
            return "read: leu %d bytes da entrada simulada" % got
        if n in (60, 231):
            self.halted = True
            self.exit_code = to_signed(self.regs["rdi"], 4)
            return "%s: processo encerrado com código %d" % (name, self.exit_code)
        if n == 39:
            self.regs["rax"] = 4242
            return "getpid: devolveu 4242 (simulado)"
        if n == 201:
            self.regs["rax"] = int(time.time())
            return "time: hora atual"
        if n == 35:
            return "nanosleep: ignorado na simulação"
        if n == 12:
            self.regs["rax"] = BSS_BASE + 0x10000
            return "brk: heap simulado"
        if n == 318:
            qn = self.regs["rsi"]
            for i in range(min(qn, 4096)):
                self.wr8(self.regs["rdi"] + i, random.randrange(256))
            self.regs["rax"] = qn
            return "getrandom: %d bytes aleatórios" % qn
        self.regs["rax"] = 0
        self._issue("syscall %d não é emulada — o resultado em RAX é fictício" % n)
        return "%s: não emulada, RAX zerado" % name

    def do_win_api(self, raw_name: str) -> str:
        key = re.sub(r"^_+|@.*$", "", str(raw_name).lower())
        api = WIN_APIS.get(key)
        if key == "exitprocess":
            self.halted = True
            self.exit_code = to_signed(self.regs["rcx"], 4)
            return "ExitProcess: processo encerrado com código %d" % self.exit_code
        if key == "getstdhandle":
            self.regs["rax"] = 0x13
            return "GetStdHandle: devolveu um handle simulado (0x13)"
        if key in ("writeconsolea", "writefile"):
            length = self.regs["r8"]
            addr = self.regs["rdx"]
            s = "".join(chr(self.rd8(addr + i)) for i in range(min(length, 1 << 20)))
            self.output += s
            self.regs["rax"] = 1
            return "%s: escreveu %d bytes no console" % (api[0] if api else key, length)
        if key in ("messageboxa", "messageboxw"):
            txt = self.read_cstring(self.regs["rdx"], 512)
            tit = self.read_cstring(self.regs["r8"], 256)
            self.output += "[MessageBox] %s: %s\n" % (tit, txt)
            self.regs["rax"] = 1
            return "MessageBoxA: caixa de mensagem exibida (mostrada na saída)"
        if key == "sleep":
            return "Sleep: ignorado na simulação"
        if key == "getlasterror":
            self.regs["rax"] = 0
            return "GetLastError: 0"
        self.regs["rax"] = 0
        self._issue("função externa %s não é emulada — RAX zerado" % raw_name)
        return "%s: stub, RAX zerado" % (api[0] if api else raw_name)

    # ---------------------------------------------------------- execução --
    @property
    def current(self) -> Optional[object]:
        return self.instrs[self.ip] if 0 <= self.ip < len(self.instrs) else None

    def _jump_target(self, op: Operand, ins) -> Optional[int]:
        t = op.symbol or op.text
        if t in self.label_at:
            return self.label_at[t]
        self._issue("rótulo desconhecido: %s (linha %d)" % (t, ins.n))
        return None

    def step(self) -> Step:
        if self.halted:
            return Step(0, "", "A execução já terminou.")
        ins = self.current
        if ins is None:
            self.halted = True
            return Step(0, "", "Fim do código.")

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
                        self._issue("linha %d: o valor %s não cabe em %s (%d bits) e será truncado"
                                    % (ins.n, o1.text, o0.text, size * 8))
                self.write(o0, v, o1)
                note = "%s = %s" % (o0.text, hexs(v))
            elif m == "movzx":
                v = self.read(o1)
                self.write(o0, v)
                note = "%s = %s (zeros à esquerda)" % (o0.text, hexs(v))
            elif m in ("movsx", "movsxd"):
                sz = o1.size or (REG_INFO[o1.reg]["size"] if o1.type == "reg" else 4)
                sv = to_signed(self.read(o1), sz)
                self.write(o0, sv & MASK64)
                note = "%s = %d (sinal preservado)" % (o0.text, sv)
            elif m == "lea":
                a = self.eval_addr(o1)
                self.write(o0, a)
                note = "%s = endereço %s" % (o0.text, hexs(a))
            elif m == "xchg":
                x, y = self.read(o0), self.read(o1)
                self.write(o0, y)
                self.write(o1, x)
                note = "trocou %s com %s" % (o0.text, o1.text)
            elif m == "push":
                self.push(self.read(o0))
                note = "empilhou %s; RSP = %s" % (hexs(self.read_mem(self.regs['rsp'], 8)), hexs(self.regs["rsp"]))
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
                    self._issue("linha %d: a soma estourou %d bits (CF=1) — resultado truncado"
                                % (ins.n, size * 8))
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
                note = "%s invertido" % o0.text
            elif m == "test":
                r = self.read(o0) & self.read(o1, o0)
                self.set_logic_flags(r, size)
                note = "flags atualizadas: ZF=%d" % self.flags["ZF"]
            elif m == "cmp":
                a, b = self.read(o0), self.read(o1, o0)
                self.set_arith_flags(a, b, a - b, size, True)
                note = ("comparou %d com %d → ZF=%d SF=%d CF=%d OF=%d"
                        % (to_signed(a, size), to_signed(b, size), self.flags["ZF"],
                           self.flags["SF"], self.flags["CF"], self.flags["OF"]))
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
                    self._issue("linha %d: divisão por zero — a CPU real dispara a exceção #DE "
                                "e o processo morre" % ins.n)
                    self.halted = True
                    return self._record(ins, "divisão por zero", issue="fatal")
                if m == "div":
                    num = (self.regs["rdx"] << 64) | self.regs["rax"]
                    if self.regs["rdx"] and num // d > MASK64:
                        self._issue("linha %d: o quociente não cabe em RAX (#DE). Zere RDX antes "
                                    "do DIV." % ins.n)
                    self.regs["rax"] = (num // d) & MASK64
                    self.regs["rdx"] = (num % d) & MASK64
                else:
                    sn, sd = to_signed(self.regs["rax"]), to_signed(d)
                    q = abs(sn) // abs(sd) * (1 if (sn < 0) == (sd < 0) else -1)
                    rem = sn - q * sd
                    self.regs["rax"] = q & MASK64
                    self.regs["rdx"] = rem & MASK64
                note = ("quociente em RAX = %d, resto em RDX = %d"
                        % (to_signed(self.regs["rax"]), to_signed(self.regs["rdx"])))
            elif m == "cdq":
                self.regs["rdx"] = 0xFFFFFFFF if to_signed(self.regs["rax"], 4) < 0 else 0
                note = "EDX estendido pelo sinal de EAX"
            elif m == "cqo":
                self.regs["rdx"] = MASK64 if to_signed(self.regs["rax"]) < 0 else 0
                note = "RDX estendido pelo sinal de RAX"
            elif m == "jmp":
                t = self._jump_target(o0, ins)
                if t is None:
                    self.halted = True
                    return self._record(ins, "desvio para rótulo inexistente", issue="fatal")
                nxt = t
                note = "desviou para %s" % o0.text
            elif is_cond_jump(m):
                cc = m[1:]
                taken = (self.regs["rcx"] == 0) if cc in ("rcxz", "ecxz", "cxz") else self.cond(cc)
                if taken:
                    t = self._jump_target(o0, ins)
                    if t is not None:
                        nxt = t
                note = ("condição verdadeira → desviou para %s" % o0.text) if taken \
                    else "condição falsa → continuou na linha seguinte"
            elif m.startswith("set"):
                b = 1 if self.cond(m[3:]) else 0
                self.write(o0, b)
                note = "%s = %d" % (o0.text, b)
            elif m.startswith("cmov"):
                if self.cond(m[4:]):
                    self.write(o0, self.read(o1, o0))
                    note = "condição verdadeira → copiou"
                else:
                    note = "condição falsa → não copiou"
            elif m == "loop":
                self.regs["rcx"] = (self.regs["rcx"] - 1) & MASK64
                if self.regs["rcx"]:
                    t = self._jump_target(o0, ins)
                    if t is not None:
                        nxt = t
                    note = "RCX = %d, repetiu" % self.regs["rcx"]
                else:
                    note = "RCX chegou a zero, saiu do laço"
            elif m == "call":
                name = o0.symbol or o0.text
                if self.platform.os == "windows" and (self.regs["rsp"] % 16) not in (0, 8):
                    self._issue("linha %d: RSP não está alinhado em 16 bytes na chamada a %s — "
                                "a ABI do Windows exige alinhamento" % (ins.n, name))
                if name in self.label_at:
                    self.push(RET_MAGIC + self.ip + 1)
                    nxt = self.label_at[name]
                    self.call_depth += 1
                    note = "chamou %s; endereço de retorno empilhado" % name
                else:
                    note = self.do_win_api(name)
            elif m.startswith("ret"):
                rv = self.pop()
                if rv == RET_SENTINEL:
                    self.halted = True
                    self.exit_code = to_signed(self.regs["rax"], 4)
                    note = ("retornou da função em teste; RAX = %d"
                            % to_signed(self.regs["rax"]))
                elif RET_MAGIC <= rv < RET_MAGIC + 1000000:
                    nxt = rv - RET_MAGIC
                    self.call_depth -= 1
                    note = "voltou para a instrução %d" % (nxt + 1)
                else:
                    self.halted = True
                    self.exit_code = to_signed(self.regs["rax"], 4)
                    if self.call_depth > 0 or rv != 0:
                        self._issue("linha %d: RET pegou %s da pilha, que não é um endereço de "
                                    "retorno válido — a pilha está desbalanceada" % (ins.n, hexs(rv)))
                    note = "RET sem endereço válido na pilha — tratado como fim do programa"
                if o0 is not None and o0.type == "imm":
                    self.regs["rsp"] = (self.regs["rsp"] + o0.value) & MASK64
            elif m == "leave":
                self.regs["rsp"] = self.regs["rbp"]
                self.regs["rbp"] = self.pop()
                note = "quadro desmontado; RSP = %s" % hexs(self.regs["rsp"])
            elif m == "syscall":
                note = self.do_syscall()
            elif m == "int":
                if o0 is not None and o0.text in ("0x80", "80h"):
                    self.regs["rdi"] = self.regs["rbx"]
                    self.regs["rsi"] = self.regs["rcx"]
                    note = "INT 0x80 (ABI de 32 bits): " + self.do_syscall()
                elif o0 is not None and o0.text == "3":
                    note = "INT 3 — breakpoint"
                else:
                    note = "interrupção não emulada"
            elif m in ("nop", "endbr64", "cld", "std"):
                if m == "cld":
                    self.flags["DF"] = 0
                if m == "std":
                    self.flags["DF"] = 1
                note = "nada aconteceu" if m == "nop" else "estado ajustado"
            elif m in ("stosb", "movsb", "lodsb", "scasb"):
                rep = bool(ins.prefix and ins.prefix.startswith("rep"))
                count = self.regs["rcx"] if rep else 1
                if count > 1 << 20:
                    self._issue("linha %d: REP com RCX = %d — provável contador errado"
                                % (ins.n, count))
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
                note = "%s %s" % (m, ("repetido %d vezes" % done) if rep else "executado")
            elif m == "hlt":
                self.halted = True
                note = "HLT — execução parada"
            else:
                note = 'instrução "%s" não é emulada; foi pulada' % m
                self._issue("linha %d: %s não é emulada pela máquina virtual" % (ins.n, m))
        except Exception as exc:                      # noqa: BLE001
            self._issue("linha %d: erro na simulação — %s" % (ins.n, exc))
            note = "erro na simulação: %s" % exc

        self.ip = nxt
        if self.ip >= len(self.instrs):
            self.halted = True
            note += " | fim do código alcançado"
            if self.exit_code is None:
                self._issue("o código terminou sem uma chamada de saída explícita — na prática a "
                            "execução continuaria por memória inválida")
        return self._record(ins, note)

    def _record(self, ins, note: str, issue: Optional[str] = None) -> Step:
        s = Step(line=ins.n, text=ins.text, note=note, issue=issue)
        self.trace.append(s)
        if len(self.trace) > 2000:
            self.trace.pop(0)
        return s

    def run(self, limit: int = 200000, breakpoints: Optional[set] = None) -> int:
        n = 0
        while not self.halted and n < limit:
            self.step()
            n += 1
            if breakpoints and not self.halted:
                cur = self.current
                if cur is not None and cur.n in breakpoints:
                    break
        if n >= limit:
            self._issue("parou após %d instruções — laço infinito muito provável" % limit)
            self.halted = True
        return n

    def run_until(self, stop_indexes: set, limit: int = 100000) -> int:
        n = 0
        while not self.halted and n < limit:
            self.step()
            n += 1
            if self.ip in stop_indexes:
                break
        return n

    def snapshot(self) -> dict:
        return {"regs": dict(self.regs), "flags": dict(self.flags),
                "output": self.output, "exit_code": self.exit_code,
                "issues": list(self.issues), "steps": self.steps,
                "halted": self.halted}
