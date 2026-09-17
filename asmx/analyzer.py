"""Análise: plataforma alvo, leitura semântica de cada instrução e blocos."""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import isa
from .isa import (ARG_REGS_SYSCALL, ARG_REGS_SYSV, ARG_REGS_WIN, CONDITIONS,
                  ISA, LINUX_SYSCALLS, REG_INFO, WIN_APIS, is_cond_jump)
from .parser import Line, Program, parse


@dataclass
class Semantic:
    cat: str = "misc"
    tag: str = "misc"
    label: str = ""
    detail: str = ""
    syscall_name: Optional[str] = None


@dataclass
class Edge:
    target: int
    kind: str
    why: str


@dataclass
class Block:
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
    os: str
    confidence: int
    bits: int
    evidence: Dict[str, List[str]]
    abi: dict


@dataclass
class Analysis:
    program: Program
    platform: Platform
    blocks: List[Block]
    instrs: List[Line]
    label_at: Dict[str, int]
    stats: dict

    @property
    def symbols(self):
        return self.program.symbols


# (padrão, explicação, peso) — pistas fortes valem mais que convenções
# compartilhadas pelos dois sistemas, como "section .text".
LINUX_HINTS = [
    (r"\bsyscall\b", "usa a instrução SYSCALL (interface do kernel Linux em 64 bits)", 3),
    (r"\bint\s+0x80\b", "usa INT 0x80, a chamada de sistema clássica do Linux", 3),
    (r"\bglobal\s+_start\b", "declara _start, o ponto de entrada do ld no Linux", 3),
    (r"\.globl\b|\.cfi_startproc|\.type\s+\w+,\s*@function", "usa diretivas do assembler GNU (ELF)", 3),
    (r"@plt\b|wrt\s*\.\.plt", "referencia a PLT, mecanismo de ligação do ELF", 3),
    (r"\bmov\s+(r|e)?ax,\s*(60|0x3c)\b", "usa a syscall 60 (exit), específica do Linux x86-64", 2),
    (r"\b(printf|puts|malloc|free|scanf|strlen)\b", "chama funções da libc padrão", 2),
    (r"/dev/|/proc/|/tmp/", "referencia caminhos típicos de Unix", 2),
    (r"\bsection\s+\.(text|data|bss|rodata)\b", "usa seções no estilo ELF (também aceito no Windows)", 1),
]

WINDOWS_HINTS = [
    (r"\b(ExitProcess|MessageBoxA|MessageBoxW|GetStdHandle|WriteConsoleA|WriteConsoleW|"
     r"ReadConsoleA|CreateFileA|VirtualAlloc|GetProcAddress|LoadLibraryA|CloseHandle|"
     r"GetLastError|CreateProcessA|GetModuleHandleA)\b", "chama a API do Windows (kernel32/user32)", 3),
    (r"\b(kernel32|user32|msvcrt|ucrt)\b", "referencia DLLs do Windows", 3),
    (r"\bincludelib\b|\boption\s+casemap\b|\.model\b", "usa diretivas do MASM", 3),
    (r"(?m)^\s*\w+\s+proc\b", "declara funções com PROC/ENDP, sintaxe MASM", 3),
    (r"__imp_\w+", "usa símbolos de importação (__imp_) do formato PE", 3),
    (r"\bWinMain\b|\bDllMain\b", "usa ponto de entrada de aplicação Windows", 3),
    (r"\bsub\s+rsp,\s*(28h|0x28|40|32|20h)\b", "reserva shadow space de 32 bytes exigido pela ABI do Windows", 2),
    (r"[A-Za-z]:\\\\|\\\\\w+\\\\", "referencia caminhos no estilo Windows", 2),
]


def detect_platform(program: Program) -> Platform:
    src = program.source
    evidence = {"linux": [], "windows": []}
    score = {"linux": 0, "windows": 0}
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
        os_name, conf = "indefinido", 0
    else:
        os_name, conf = "ambíguo", 35

    if re.search(r"\bbits\s+16\b", src, re.I):
        bits = 16
    elif re.search(r"\bbits\s+32\b|\buse32\b", src, re.I) and not re.search(r"\br[a-z]x\b", src, re.I):
        bits = 32
    else:
        bits = 64

    if os_name == "windows":
        abi = {"name": "Microsoft x64", "args": ARG_REGS_WIN, "ret": "RAX",
               "preserved": isa.CALLEE_SAVED_WIN,
               "notes": "Os 4 primeiros argumentos vão em RCX, RDX, R8, R9. Quem chama "
                        "precisa reservar 32 bytes de shadow space e manter RSP alinhado "
                        "em 16 bytes."}
    else:
        abi = {"name": "System V AMD64", "args": ARG_REGS_SYSV, "ret": "RAX",
               "preserved": isa.CALLEE_SAVED_SYSV,
               "notes": "Os 6 primeiros argumentos vão em RDI, RSI, RDX, RCX, R8, R9. Em "
                        "syscalls, RCX é trocado por R10 e o número do serviço vai em RAX."}

    return Platform(os=os_name, confidence=conf, bits=bits, evidence=evidence, abi=abi)


def _mem_name(op) -> str:
    inner = op.inner or ""
    if re.search(r"rbp\s*-", inner) or re.search(r"rsp\s*\+", inner):
        return "variável local em " + inner
    if re.search(r"rbp\s*\+", inner):
        return "parâmetro em " + inner
    if op.symbol:
        return "variável " + op.symbol
    if op.regs:
        return "endereço apontado por " + " + ".join(op.regs)
    return "memória " + inner


def semantics_of(ins: Line, ctx: dict) -> Semantic:
    m = ins.mnemonic
    ops = ins.operands
    o0 = ops[0] if ops else None
    o1 = ops[1] if len(ops) > 1 else None
    info = ISA.get(m)
    sem = Semantic(cat=info["cat"] if info else "misc",
                   tag=info["cat"] if info else "misc",
                   label=info["name"].split("—")[0].strip() if info else m.upper())

    if m in ("mov", "movzx", "movsx", "movsxd"):
        if o0 and o0.type == "mem":
            alvo = o0.symbol or ("local" if re.search(r"rbp|rsp", o0.inner or "") else "*ponteiro")
            sem.tag, sem.label = "store", "Escreve na memória"
            sem.detail = ("Guarda %s em %s. Em linguagem de alto nível: %s = %s;"
                          % (o1.text if o1 else "?", _mem_name(o0), alvo, o1.text if o1 else "?"))
        elif o1 and o1.type == "mem":
            sem.tag, sem.label = "load", "Lê da memória"
            sem.detail = "Carrega %s para %s. É a leitura de uma variável." % (_mem_name(o1), o0.text)
        elif o1 and o1.type == "imm":
            sem.tag, sem.label = "set", "Define constante"
            sem.detail = "%s passa a valer %s." % (o0.text, o1.text)
            if ctx["platform"].os == "linux" and o0.type == "reg" and o0.reg in ("rax", "eax"):
                sc = LINUX_SYSCALLS.get(o1.value)
                if sc and ctx.get("syscall_ahead"):
                    sem.detail += " Como vem antes de um SYSCALL, é o número do serviço: %s (%s)." % (sc[0], sc[1])
        elif o1 and o1.type == "sym":
            sem.tag, sem.label = "set", "Define endereço/símbolo"
            sym = ctx["symbols"].get(o1.symbol, {})
            extra = " (endereço do dado %s)" % o1.symbol if sym.get("type") == "data" else ""
            sem.detail = "%s recebe %s%s." % (o0.text, o1.symbol, extra)
        else:
            sem.tag, sem.label = "copy", "Copia registrador"
            if o0 and o1:
                sem.detail = "%s passa a ter uma cópia de %s." % (o0.text, o1.text)
    elif m == "lea":
        sem.tag, sem.label = "addr", "Calcula endereço"
        alvo = (o1.symbol or o1.inner or o1.text) if o1 else "?"
        sem.detail = "%s recebe o ENDEREÇO de %s, sem ler o conteúdo. É como o & de C." % (o0.text, alvo)
    elif m == "push":
        sem.tag, sem.label = "push", "Empilha"
        sem.detail = "Salva %s na pilha (RSP diminui 8)." % (o0.text if o0 else "")
    elif m == "pop":
        sem.tag, sem.label = "pop", "Desempilha"
        sem.detail = "Restaura %s do topo da pilha (RSP aumenta 8)." % (o0.text if o0 else "")
    elif m == "call":
        sem.tag, sem.label = "call", "Chama função"
        alvo = (o0.symbol or o0.text) if o0 else "?"
        api = WIN_APIS.get(re.sub(r"^_+|@.*$", "", str(alvo).lower()))
        sem.detail = "Salva o endereço de retorno e desvia para %s." % alvo
        if api:
            sem.detail += " É a API do Windows %s: %s (parâmetros: %s)." % (api[0], api[1], api[2])
        elif ctx["symbols"].get(alvo, {}).get("type") == "extern":
            sem.detail += " Função externa, resolvida na ligação."
    elif m.startswith("ret"):
        sem.tag, sem.label = "return", "Retorna"
        sem.detail = ("Volta para quem chamou usando o endereço no topo da pilha. "
                      "O valor de retorno sai em RAX.")
    elif m == "jmp":
        sem.tag, sem.label = "jump", "Desvia sempre"
        sem.detail = ("Segue direto para %s. O que vem logo abaixo só roda se alguém "
                      "desviar para lá." % (o0.text if o0 else "?"))
    elif is_cond_jump(m):
        cc = m[1:]
        human = CONDITIONS.get(cc, [cc, "a condição"])
        sem.tag, sem.label = "branch", "Desvia se " + human[0]
        sem.detail = ("Vai para %s quando %s. Caso contrário, continua na próxima linha."
                      % (o0.text if o0 else "?", human[1]))
        if ctx.get("last_compare"):
            sem.detail += " Condição vinda de: %s." % ctx["last_compare"]
    elif m in ("cmp", "test"):
        sem.tag, sem.label = "compare", "Compara"
        base = ("Calcula %s - %s" % (o0.text, o1.text)) if m == "cmp" else ("Faz %s AND %s" % (o0.text, o1.text))
        sem.detail = base + " só para atualizar as flags. Quem decide algo com isso é o desvio logo abaixo."
        if m == "test" and o0 and o1 and o0.text == o1.text:
            sem.detail += ' Aqui é o idioma "%s é zero?".' % o0.text
    elif m in ("syscall", "int"):
        sem.tag, sem.label = "syscall", "Chamada de sistema"
        num = ctx.get("pending_syscall")
        sc = LINUX_SYSCALLS.get(num) if num is not None else None
        if sc:
            nargs = len([a for a in sc[2].split(",") if a.strip()]) if sc[2] else 0
            regs = ", ".join(r.upper() for r in ARG_REGS_SYSCALL[:nargs])
            sem.detail = ("Entra no kernel para executar %s — %s.%s O resultado volta em RAX."
                          % (sc[0], sc[1], (" Argumentos em %s (%s)." % (regs, sc[2])) if nargs else ""))
            sem.syscall_name = sc[0]
        else:
            sem.detail = ("Entrega o controle ao kernel. O número do serviço está em RAX e os "
                          "argumentos em RDI, RSI, RDX, R10, R8, R9.")
    elif m in ("add", "sub", "inc", "dec", "mul", "imul", "div", "idiv", "neg", "adc", "sbb"):
        sem.tag, sem.label = "arith", "Aritmética"
        if m == "sub" and o0 and o0.reg == "rsp":
            sem.tag, sem.label = "frame", "Reserva espaço na pilha"
            sem.detail = "Abre %s bytes para variáveis locais." % (o1.text if o1 else "?")
        elif m == "add" and o0 and o0.reg == "rsp":
            sem.tag, sem.label = "frame", "Libera espaço da pilha"
            sem.detail = "Devolve %s bytes reservados antes." % (o1.text if o1 else "?")
        elif m == "mul" or (m == "imul" and len(ops) == 1):
            sem.detail = ("RAX = RAX × %s. O resultado completo fica em RDX:RAX "
                          "(parte alta em RDX)." % o0.text)
        elif m in ("div", "idiv"):
            prep = "XOR RDX, RDX" if m == "div" else "CQO"
            sem.detail = ("Divide RDX:RAX por %s: quociente em RAX, resto em RDX. "
                          "RDX precisa estar preparado antes (%s)." % (o0.text, prep))
        else:
            op_sign = {"add": "+", "sub": "-", "imul": "*", "adc": "+", "sbb": "-"}.get(m)
            if m == "inc":
                sem.detail = "%s = %s + 1." % (o0.text, o0.text)
            elif m == "dec":
                sem.detail = "%s = %s - 1." % (o0.text, o0.text)
            elif m == "neg":
                sem.detail = "%s = 0 - %s (troca o sinal)." % (o0.text, o0.text)
            else:
                sem.detail = "%s = %s %s %s." % (o0.text, o0.text, op_sign, o1.text if o1 else "")
    elif m in ("and", "or", "xor", "not", "shl", "sal", "shr", "sar", "rol", "ror"):
        sem.tag, sem.label = "logic", "Operação em bits"
        if m == "xor" and o0 and o1 and o0.text == o1.text:
            sem.label = "Zera registrador"
            sem.detail = "%s = 0 (jeito mais curto de zerar)." % o0.text
        elif m == "shl":
            sem.detail = "%s = %s * 2^%s." % (o0.text, o0.text, o1.text if o1 else "n")
        elif m == "shr":
            sem.detail = "%s = %s / 2^%s (sem sinal)." % (o0.text, o0.text, o1.text if o1 else "n")
        elif m == "not":
            sem.detail = "%s tem todos os bits invertidos." % o0.text
        else:
            sem.detail = "%s = %s %s %s, bit a bit." % (o0.text, o0.text, m.upper(), o1.text if o1 else "")
    elif m.startswith("set"):
        sem.tag, sem.label = "compare", "Booleano da condição"
        human = CONDITIONS.get(m[3:], ["a condição"])[0]
        sem.detail = "%s vira 1 se %s, senão 0." % (o0.text, human)
    elif m == "leave":
        sem.tag, sem.label = "frame", "Desmonta o quadro"
        sem.detail = "Restaura RSP e RBP antes do RET."
    elif m == "nop":
        sem.tag, sem.label = "misc", "Nada"
        sem.detail = "Instrução vazia, usada para alinhamento."
    elif info:
        sem.detail = info["desc"].split(".")[0] + "."
    else:
        sem.tag, sem.label = "unknown", "Não reconhecida"
        sem.detail = ('A ferramenta não conhece "%s". Pode ser macro, instrução SIMD '
                      "menos comum ou erro de digitação." % m)
    return sem


def _mark_frames(instrs: List[Line]):
    for i, a in enumerate(instrs):
        b = instrs[i + 1] if i + 1 < len(instrs) else None
        if (a.mnemonic == "push" and a.operands and a.operands[0].reg == "rbp"
                and b and b.mnemonic == "mov" and b.operands and b.operands[0].reg == "rbp"
                and len(b.operands) > 1 and b.operands[1].reg == "rsp"):
            a.sem.tag, a.sem.label = "frame", "Prólogo da função"
            a.sem.detail = "Salva o quadro de pilha de quem chamou."
            b.sem.tag, b.sem.label = "frame", "Prólogo da função"
            b.sem.detail = ("RBP passa a apontar para a base deste quadro: daqui para frente "
                            "as variáveis locais são [RBP-n].")
        if (a.mnemonic == "pop" and a.operands and a.operands[0].reg == "rbp"
                and b and b.mnemonic.startswith("ret")):
            a.sem.tag, a.sem.label = "frame", "Epílogo da função"
            a.sem.detail = "Restaura o quadro de quem chamou, logo antes do retorno."


def _annotate_args(instrs: List[Line], platform: Platform):
    arg_regs = ARG_REGS_WIN if platform.os == "windows" else ARG_REGS_SYSV
    pending = []
    last_func = object()
    for ins in instrs:
        if (ins.func != last_func or ins.labels or ins.mnemonic.startswith("ret")
                or ins.mnemonic == "jmp" or is_cond_jump(ins.mnemonic)):
            pending = []
            last_func = ins.func
        if ins.mnemonic == "call":
            alvo = (ins.operands[0].symbol or ins.operands[0].text) if ins.operands else "função"
            for reg, line in pending:
                if reg in arg_regs:
                    line.sem.detail += (" Prepara o %dº argumento da chamada a %s."
                                        % (arg_regs.index(reg) + 1, alvo))
            pending = []
        elif ins.mnemonic == "syscall":
            pending = []
        elif ins.mnemonic in ("mov", "lea", "xor", "movzx", "movsx") and ins.operands \
                and ins.operands[0].type == "reg":
            base = REG_INFO[ins.operands[0].reg]["base"]
            pending.append((base, ins))
            pending = pending[-12:]


def build_blocks(program: Program) -> (List[Block], Dict[str, int]):
    instrs = program.instructions
    for i, ins in enumerate(instrs):
        ins.idx = i

    label_at: Dict[str, int] = {}
    pending_labels: List[str] = []
    for l in program.lines:
        if l.kind == "label":
            pending_labels.append(l.label)
        elif l.kind == "directive" and l.directive == "proc":
            pending_labels.append(l.label)
        elif l.kind == "instruction":
            l.labels = list(pending_labels)
            for lb in pending_labels:
                label_at[lb] = l.idx
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
            name = ins.labels[0] if ins.labels else (
                "continuação de " + blocks[-1].name if blocks else "início")
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

        def link(bid, kind, why):
            if bid is None or bid >= len(blocks):
                return
            b.succ.append(Edge(bid, kind, why))
            blocks[bid].pred.append(Edge(b.id, kind, why))

        if m == "jmp":
            if target in label_at:
                link(block_of[label_at[target]], "jmp", "desvio incondicional para " + target)
            else:
                b.exit = "desvio para %s (fora do código carregado)" % target
        elif is_cond_jump(m):
            human = CONDITIONS.get(m[1:], ["a condição é verdadeira"])[0]
            if target in label_at:
                link(block_of[label_at[target]], "taken", "quando " + human)
            if b.id + 1 < len(blocks):
                link(b.id + 1, "fallthrough", "quando a condição é falsa, cai na linha seguinte")
        elif m.startswith("ret"):
            b.exit = "retorna para quem chamou"
        elif m == "syscall" and last.sem and last.sem.syscall_name in ("exit", "exit_group"):
            b.exit = "encerra o processo"
        elif m == "call" and re.search(r"exitprocess", str(target), re.I):
            b.exit = "encerra o processo"
        elif b.id + 1 < len(blocks):
            link(b.id + 1, "fallthrough", "segue naturalmente para a próxima instrução")
        else:
            b.exit = "fim do código"

        b.calls = [(x.operands[0].symbol or x.operands[0].text) if x.operands else "?"
                   for x in b.instrs if x.mnemonic == "call"]

    return blocks, label_at


def analyze(text: str) -> Analysis:
    program = parse(text)
    platform = detect_platform(program)
    instrs = program.instructions

    ctx = {"platform": platform, "symbols": program.symbols,
           "pending_syscall": None, "last_compare": None, "syscall_ahead": False}

    for i, ins in enumerate(instrs):
        ctx["syscall_ahead"] = any(x.mnemonic in ("syscall", "int")
                                   for x in instrs[i + 1:i + 8])
        ins.sem = semantics_of(ins, ctx)
        if (ins.mnemonic == "mov" and ins.operands and ins.operands[0].reg in ("rax", "eax")
                and len(ins.operands) > 1 and ins.operands[1].type == "imm"):
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

    by_cat = {}
    unknown = []
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

    return Analysis(program=program, platform=platform, blocks=blocks,
                    instrs=instrs, label_at=label_at, stats=stats)


def callers_of(analysis: Analysis, name: str) -> List[str]:
    out = []
    for ins in analysis.instrs:
        if not ins.operands:
            continue
        target = ins.operands[0].symbol or ins.operands[0].text
        if target != name:
            continue
        if ins.mnemonic == "call":
            out.append("%s (linha %d)" % (ins.func or "código", ins.n))
        elif ins.mnemonic == "jmp" or is_cond_jump(ins.mnemonic):
            out.append("desvio da linha %d" % ins.n)
    return out


def functions(analysis: Analysis) -> List[str]:
    seen = []
    for b in analysis.blocks:
        if b.func and b.func not in seen:
            seen.append(b.func)
    return seen
