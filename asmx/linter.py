"""Validação estática: encontra o que provavelmente vai quebrar antes de rodar."""

import re
from dataclasses import dataclass
from typing import List, Optional

from .analyzer import Analysis
from .isa import (CALLEE_SAVED_SYSV, CALLEE_SAVED_WIN, ISA, REG_INFO,
                  is_cond_jump)

ERRO = "erro"
ALERTA = "alerta"
INFO = "info"
SEVERITY_ORDER = {ERRO: 0, ALERTA: 1, INFO: 2}


@dataclass
class Problem:
    line: int
    severity: str
    code: str
    message: str
    hint: str = ""

    def __str__(self):
        return "L%d [%s] %s: %s" % (self.line, self.severity, self.code, self.message)


def _base(reg: Optional[str]) -> Optional[str]:
    return REG_INFO[reg]["base"] if reg and reg in REG_INFO else None


def _func_ranges(analysis: Analysis):
    """Agrupa instruções por função declarada."""
    groups = {}
    for ins in analysis.instrs:
        groups.setdefault(ins.func or "<sem rótulo>", []).append(ins)
    return groups


# --------------------------------------------------------------- strings --
def check_strings(analysis: Analysis) -> List[Problem]:
    out = []
    for l in analysis.program.lines:
        if l.kind != "data" or l.reserve:
            continue
        body, _ = l.raw, l.comment
        code = body.split(";")[0]
        aspas = code.count('"')
        simples = code.count("'")
        if aspas % 2 or simples % 2:
            out.append(Problem(l.n, ERRO, "STR002",
                               "aspas não fechadas nesta linha de dados",
                               "o montador vai engolir o resto da linha; feche a string"))
        for arg in l.args:
            m = re.fullmatch(r"(['\"])([\s\S]*)\1", arg.strip())
            if not m:
                continue
            texto = m.group(2)
            fora = [c for c in texto if ord(c) > 127]
            if fora:
                out.append(Problem(
                    l.n, ALERTA, "STR001",
                    "a string tem caractere fora do ASCII (%s) — cada um vira 2 ou mais bytes em UTF-8"
                    % " ".join(sorted(set(fora))),
                    "o tamanho calculado com $ - rótulo não vai bater com a quantidade de letras; "
                    "troque por ASCII ou conte os bytes reais"))
            ctrl = [c for c in texto if ord(c) < 32 and c not in "\n\t"]
            if ctrl:
                out.append(Problem(l.n, ALERTA, "STR004",
                                   "a string tem caractere de controle literal",
                                   "prefira escrever o código numérico: db \"texto\", 10"))
            if "\\" in texto and not re.search(r"\\[nt0\\]", texto):
                out.append(Problem(l.n, INFO, "STR005",
                                   "a barra invertida não é escape em toda sintaxe de montador",
                                   "no NASM só strings com aspas duplas aceitam escapes; confira o "
                                   "byte que vai realmente sair"))
    return out


def check_unterminated(analysis: Analysis) -> List[Problem]:
    """String de dados sem terminador 0 e sem um tamanho calculado por equ."""
    out = []
    tamanhos = set()
    for l in analysis.program.lines:
        if l.kind == "data" and l.directive == "equ" and l.args:
            m = re.search(r"\$\s*-\s*([A-Za-z_.$][\w.$]*)", l.args[0])
            if m:
                tamanhos.add(m.group(1))
    for l in analysis.program.lines:
        if l.kind != "data" or l.reserve or not l.label or not l.args:
            continue
        tem_texto = any(re.fullmatch(r"(['\"])[\s\S]*\1", a.strip()) for a in l.args)
        if not tem_texto or l.label in tamanhos:
            continue
        ultimo = l.args[-1].strip()
        if re.fullmatch(r"-?0+", ultimo) or re.fullmatch(r"\d+", ultimo):
            continue
        out.append(Problem(
            l.n, ALERTA, "STR006",
            "a string %s não termina em 0 nem tem tamanho calculado" % l.label,
            "sem terminador e sem '%s_len equ $ - %s' não há como saber onde ela acaba; "
            "quem for imprimir vai chutar o tamanho" % (l.label, l.label)))
    return out


def check_cstrings(analysis: Analysis) -> List[Problem]:
    """Strings passadas para funções que esperam terminador nulo."""
    out = []
    machine_syms = {}
    for l in analysis.program.lines:
        if l.kind == "data" and l.label and not l.reserve:
            ends_zero = bool(l.args) and re.fullmatch(r"-?0+", l.args[-1].strip())
            machine_syms[l.label] = (l.n, ends_zero)

    consumers = re.compile(r"printf|puts|strlen|strcpy|MessageBox|CreateFile|LoadLibrary|"
                           r"GetProcAddress|OutputDebugString", re.I)
    pending = {}
    for ins in analysis.instrs:
        if ins.mnemonic in ("mov", "lea") and len(ins.operands) > 1:
            sym = ins.operands[1].symbol
            if sym in machine_syms:
                pending[_base(ins.operands[0].reg)] = sym
        if ins.mnemonic == "call" and ins.operands:
            alvo = ins.operands[0].symbol or ins.operands[0].text
            if consumers.search(str(alvo)):
                for sym in set(pending.values()):
                    line, ends_zero = machine_syms[sym]
                    if not ends_zero:
                        out.append(Problem(
                            line, ERRO, "STR003",
                            "a string %s é passada para %s mas não termina em 0" % (sym, alvo),
                            "acrescente o terminador: %s db \"...\", 0" % sym))
            pending = {}
    return out


# --------------------------------------------------------------- divisão --
def check_division(analysis: Analysis) -> List[Problem]:
    out = []
    for b in analysis.blocks:
        prepared = False
        for ins in b.instrs:
            m = ins.mnemonic
            if m in ("cqo", "cdq"):
                prepared = True
            if m == "xor" and len(ins.operands) > 1 and \
                    _base(ins.operands[0].reg) == "rdx" and _base(ins.operands[1].reg) == "rdx":
                prepared = True
            if m == "mov" and ins.operands and _base(ins.operands[0].reg) == "rdx" and \
                    len(ins.operands) > 1 and ins.operands[1].type == "imm" and ins.operands[1].value == 0:
                prepared = True
            if m in ("div", "idiv"):
                if not prepared:
                    correcao = "XOR RDX, RDX" if m == "div" else "CQO"
                    out.append(Problem(
                        ins.n, ERRO, "DIV001",
                        "%s sem preparar RDX neste bloco" % m.upper(),
                        "a CPU divide RDX:RAX; com lixo em RDX o quociente estoura e dispara "
                        "exceção. Coloque %s antes." % correcao))
                op = ins.operands[0] if ins.operands else None
                if op is not None and op.type == "imm":
                    if op.value == 0:
                        out.append(Problem(ins.n, ERRO, "DIV002", "divisão por zero literal",
                                           "o processo morre com exceção #DE"))
                    else:
                        out.append(Problem(ins.n, ERRO, "DIV003",
                                           "DIV/IDIV não aceita operando imediato",
                                           "carregue o divisor num registrador antes"))
                prepared = False
    return out


# ----------------------------------------------------------------- pilha --
def check_stack(analysis: Analysis) -> List[Problem]:
    out = []
    for name, instrs in _func_ranges(analysis).items():
        if not any(i.mnemonic.startswith("ret") for i in instrs):
            continue
        saldo = 0
        primeiro = instrs[0].n
        for ins in instrs:
            if ins.mnemonic == "push":
                saldo += 1
            elif ins.mnemonic == "pop":
                saldo -= 1
            elif ins.mnemonic == "leave":
                saldo = 0
            elif ins.mnemonic.startswith("ret"):
                if saldo > 0:
                    out.append(Problem(
                        ins.n, ERRO, "STK001",
                        "%s retorna com %d valor(es) a mais na pilha" % (name, saldo),
                        "cada PUSH precisa do POP correspondente antes do RET, senão o RET "
                        "pega o valor errado e desvia para um endereço inválido"))
                elif saldo < 0:
                    out.append(Problem(
                        ins.n, ERRO, "STK002",
                        "%s desempilha %d valor(es) a mais do que empilhou" % (name, -saldo),
                        "a função está consumindo a pilha de quem chamou"))
                saldo = 0
        _ = primeiro
    return out


def check_missing_ret(analysis: Analysis) -> List[Problem]:
    out = []
    chamadas = {(i.operands[0].symbol or i.operands[0].text)
                for i in analysis.instrs if i.mnemonic == "call" and i.operands}
    for name, instrs in _func_ranges(analysis).items():
        if name not in chamadas:
            continue
        tem_saida = any(i.mnemonic.startswith("ret") or i.mnemonic == "jmp" for i in instrs)
        if not tem_saida:
            out.append(Problem(instrs[0].n, ERRO, "STK003",
                               "%s é chamada com CALL mas não tem RET" % name,
                               "a execução vai escorregar para o código seguinte"))
    return out


# -------------------------------------------------------------------- ABI -
def check_abi(analysis: Analysis) -> List[Problem]:
    out = []
    win = analysis.platform.os == "windows"
    preserved = CALLEE_SAVED_WIN if win else CALLEE_SAVED_SYSV
    for name, instrs in _func_ranges(analysis).items():
        if not any(i.mnemonic.startswith("ret") for i in instrs):
            continue
        salvos = {_base(i.operands[0].reg) for i in instrs
                  if i.mnemonic == "push" and i.operands and i.operands[0].type == "reg"}
        for ins in instrs:
            if ins.mnemonic in ("mov", "add", "sub", "xor", "lea", "inc", "dec", "pop") \
                    and ins.operands and ins.operands[0].type == "reg":
                base = _base(ins.operands[0].reg)
                if base in preserved and base not in salvos and base != "rbp":
                    out.append(Problem(
                        ins.n, ALERTA, "ABI002",
                        "%s altera %s sem salvar antes" % (name, base.upper()),
                        "%s precisa voltar intacto para quem chamou (%s). Faça PUSH no começo e "
                        "POP no fim." % (base.upper(), analysis.platform.abi["name"])))
                    salvos.add(base)   # avisa uma vez só por registrador
        if win:
            reserva = any(i.mnemonic == "sub" and i.operands
                          and _base(i.operands[0].reg) == "rsp"
                          and len(i.operands) > 1 and i.operands[1].type == "imm"
                          and i.operands[1].value >= 32 for i in instrs)
            chama = [i for i in instrs if i.mnemonic == "call"]
            if chama and not reserva:
                out.append(Problem(
                    chama[0].n, ERRO, "ABI001",
                    "chamada sem shadow space reservado",
                    "a ABI do Windows exige SUB RSP, 40 (32 de shadow space + alinhamento) "
                    "antes de chamar qualquer função"))
    return out


# ------------------------------------------------------------- operandos --
def check_operands(analysis: Analysis) -> List[Problem]:
    out = []
    for ins in analysis.instrs:
        ops = ins.operands
        if not ins.known:
            out.append(Problem(ins.n, ALERTA, "UNK001",
                               "mnemônico desconhecido: %s" % ins.mnemonic,
                               "pode ser macro, instrução SIMD fora do acervo ou erro de digitação"))
            continue
        if len(ops) >= 2 and ops[0].type == "mem" and ops[1].type == "mem":
            out.append(Problem(ins.n, ERRO, "MEM002",
                               "não existe instrução com memória nos dois lados",
                               "passe por um registrador: MOV RAX, [origem] / MOV [destino], RAX"))
        if ins.mnemonic in ("mov", "add", "sub", "cmp", "and", "or", "xor", "test") \
                and len(ops) >= 2 and ops[0].type == "mem" and ops[1].type == "imm" \
                and not ops[0].size:
            out.append(Problem(ins.n, ERRO, "MEM001",
                               "tamanho do operando ambíguo",
                               "o montador não sabe se grava 1, 2, 4 ou 8 bytes. Escreva "
                               "%s byte [..], %s" % (ins.mnemonic, ops[1].text)))
        if len(ops) >= 2 and ops[0].type == "reg" and ops[1].type == "imm":
            size = REG_INFO[ops[0].reg]["size"]
            limite_u = (1 << (size * 8)) - 1
            limite_s = 1 << (size * 8 - 1)
            v = ops[1].value
            if v > limite_u or v < -limite_s:
                out.append(Problem(
                    ins.n, ERRO, "IMM001",
                    "o valor %s não cabe em %s (%d bits)" % (ops[1].text, ops[0].text, size * 8),
                    "o montador trunca ou recusa. Use um registrador maior ou reveja a constante."))
            elif size == 8 and v > 0xFFFFFFFF and ins.mnemonic != "mov":
                out.append(Problem(
                    ins.n, ALERTA, "IMM002",
                    "imediato de 64 bits só é aceito em MOV",
                    "instruções como ADD/CMP aceitam no máximo 32 bits com sinal; carregue o "
                    "valor em outro registrador primeiro"))
        if ins.mnemonic in ("shl", "shr", "sal", "sar", "rol", "ror") and len(ops) >= 2 \
                and ops[1].type == "imm" and ops[0].type == "reg":
            bits = REG_INFO[ops[0].reg]["size"] * 8
            if ops[1].value >= bits:
                out.append(Problem(ins.n, ALERTA, "SHF001",
                                   "deslocamento de %d bits num operando de %d bits"
                                   % (ops[1].value, bits),
                                   "o processador usa só os 5 ou 6 bits baixos da contagem; "
                                   "o resultado não é o que parece"))
    return out


# --------------------------------------------------------------- símbolos -
def check_symbols(analysis: Analysis) -> List[Problem]:
    out = []
    definidos = set(analysis.label_at) | {
        k for k, v in analysis.symbols.items() if v["type"] in ("data", "extern")}
    usados = set()
    for ins in analysis.instrs:
        for op in ins.operands:
            sym = op.symbol if op.type in ("sym", "mem") else None
            if not sym:
                continue
            usados.add(sym)
            if sym not in definidos:
                out.append(Problem(
                    ins.n, ERRO, "SYM003",
                    "%s não está definido em lugar nenhum" % sym,
                    "declare o dado (%s dq 0), crie o rótulo ou use EXTERN %s" % (sym, sym)))
        if ins.mnemonic in ("call", "jmp") or is_cond_jump(ins.mnemonic):
            if ins.operands:
                alvo = ins.operands[0].symbol or ins.operands[0].text
                usados.add(alvo)
                if alvo not in definidos and not re.fullmatch(r"[\[\]\d+*x-]+", alvo):
                    out.append(Problem(
                        ins.n, ERRO, "SYM001",
                        "%s aponta para %s, que não existe neste arquivo" % (ins.mnemonic.upper(), alvo),
                        "defina o rótulo ou declare EXTERN %s" % alvo))
    for name, info in analysis.symbols.items():
        if info["type"] == "label" and not info.get("global") and name not in usados \
                and name not in ("_start", "main", "start", "WinMain"):
            out.append(Problem(info["line"], INFO, "SYM002",
                               "o rótulo %s nunca é usado" % name,
                               "código morto ou rótulo escrito errado em outro lugar"))
    return out


def check_entry(analysis: Analysis) -> List[Problem]:
    out = []
    entradas = [n for n in ("_start", "main", "start", "WinMain") if n in analysis.label_at]
    if not entradas and analysis.instrs:
        out.append(Problem(analysis.instrs[0].n, ALERTA, "ENT001",
                           "nenhum ponto de entrada (_start, main) encontrado",
                           "o ligador precisa saber onde começar"))
    for e in entradas:
        info = analysis.symbols.get(e, {})
        if not info.get("global"):
            out.append(Problem(info.get("line", 1), ERRO, "ENT002",
                               "%s existe mas não foi declarado global" % e,
                               "acrescente: global %s" % e))
    return out


def check_exit(analysis: Analysis) -> List[Problem]:
    if not analysis.instrs:
        return []
    src = analysis.program.source
    tem_saida = (re.search(r"\b(60|0x3c|231)\b", src) and "syscall" in src.lower()) \
        or re.search(r"ExitProcess", src, re.I) \
        or any(i.mnemonic.startswith("ret") and (i.func in ("main", "WinMain"))
               for i in analysis.instrs)
    if not tem_saida:
        return [Problem(analysis.instrs[-1].n, ALERTA, "EXIT001",
                        "o programa não tem uma saída explícita",
                        "sem exit (syscall 60 no Linux, ExitProcess no Windows) a execução "
                        "continua por memória que não é código e o processo quebra")]
    return []


# ----------------------------------------------------------------- fluxo --
def check_flow(analysis: Analysis) -> List[Problem]:
    out = []
    entradas = {"_start", "main", "start", "WinMain"}
    alvos_de_call = {(i.operands[0].symbol or i.operands[0].text)
                     for i in analysis.instrs if i.mnemonic == "call" and i.operands}
    for b in analysis.blocks:
        externos = [e for e in b.pred if e.target != b.id]
        if b.id == 0 or externos:
            continue
        if b.name in entradas or b.name in alvos_de_call or b.func in alvos_de_call:
            continue
        if analysis.symbols.get(b.name, {}).get("global"):
            continue
        out.append(Problem(b.instrs[0].n, ALERTA, "FLOW001",
                           "o bloco %s nunca é alcançado" % b.name,
                           "nenhum desvio ou chamada leva até aqui — código morto ou rótulo errado"))

    for b in analysis.blocks:
        last = b.instrs[-1]
        volta = [e for e in b.succ if e.target <= b.id]
        if not volta:
            continue
        muda = False
        for ins in b.instrs:
            if ins.mnemonic in ("inc", "dec", "add", "sub", "mul", "imul", "div", "idiv",
                                "shl", "shr", "loop", "syscall", "call", "xor", "and", "or",
                                "mov", "movzx", "movsx", "pop"):
                muda = True
                break
        if not muda:
            out.append(Problem(last.n, ERRO, "FLOW002",
                               "laço sem nada que altere a condição de parada",
                               "este bloco volta para trás sem mudar registrador nem memória: "
                               "laço infinito"))
    return out


# -------------------------------------------------------------- syscalls --
def check_syscalls(analysis: Analysis) -> List[Problem]:
    out = []
    for b in analysis.blocks:
        rax_definido = False
        for ins in b.instrs:
            if ins.operands and ins.operands[0].type == "reg" and _base(ins.operands[0].reg) == "rax":
                rax_definido = True
            if ins.mnemonic == "syscall":
                if not rax_definido:
                    out.append(Problem(ins.n, ALERTA, "SYS001",
                                       "SYSCALL sem definir RAX neste bloco",
                                       "o número do serviço vem de RAX; sem ele o kernel recebe "
                                       "um pedido aleatório"))
                rax_definido = False
        # RCX e R11 são destruídos pelo syscall
        depois = False
        for ins in b.instrs:
            if ins.mnemonic == "syscall":
                depois = True
                continue
            if not depois:
                continue
            for op in ins.operands[1:] if len(ins.operands) > 1 else []:
                if op.type == "reg" and _base(op.reg) in ("rcx", "r11"):
                    out.append(Problem(ins.n, ALERTA, "SYS002",
                                       "%s é lido depois de um SYSCALL" % op.text.upper(),
                                       "o SYSCALL destrói RCX e R11; salve antes se precisar "
                                       "do valor"))
                    depois = False
    return out


def check_sections(analysis: Analysis) -> List[Problem]:
    out = []
    secoes = {l.new_section for l in analysis.program.lines if l.new_section}
    if analysis.instrs and "text" not in secoes and "code" not in secoes and secoes:
        out.append(Problem(analysis.instrs[0].n, ALERTA, "SEC001",
                           "há instruções fora de uma seção de código",
                           "declare section .text antes do código executável"))
    for ins in analysis.instrs:
        if ins.mnemonic == "mov" and ins.operands and ins.operands[0].type == "mem":
            sym = ins.operands[0].symbol
            info = analysis.symbols.get(sym or "", {})
            if info.get("section") == "rodata":
                out.append(Problem(ins.n, ERRO, "SEC002",
                                   "escrita em %s, que está em .rodata" % sym,
                                   ".rodata é somente leitura: o processo recebe SIGSEGV. "
                                   "Mova a variável para .data"))
    return out


def check_uninitialized(analysis: Analysis) -> List[Problem]:
    """Leitura de registrador que a função nunca escreveu e que não é argumento."""
    out = []
    plat_args = analysis.platform.abi["args"]
    for name, instrs in _func_ranges(analysis).items():
        escritos = set(plat_args) | {"rsp", "rbp", "rip"}
        if name in ("_start", "start"):
            escritos |= set()
        for ins in instrs:
            leituras = []
            if ins.mnemonic in ("mov", "movzx", "movsx", "lea") and len(ins.operands) > 1:
                leituras = ins.operands[1:]
            elif ins.mnemonic in ("add", "sub", "cmp", "test", "and", "or", "xor", "imul"):
                leituras = ins.operands
            elif ins.mnemonic in ("push", "inc", "dec", "neg", "not", "div", "idiv", "mul"):
                leituras = ins.operands
            for op in leituras:
                regs = []
                if op.type == "reg":
                    regs = [_base(op.reg)]
                elif op.type == "mem":
                    regs = [_base(r) for r in op.regs]
                for r in regs:
                    if r and r not in escritos:
                        out.append(Problem(
                            ins.n, ALERTA, "REG001",
                            "%s é lido antes de receber qualquer valor em %s" % (r.upper(), name),
                            "o valor é o que sobrou de antes; inicialize o registrador"))
                        escritos.add(r)
            if ins.operands and ins.operands[0].type == "reg" and \
                    ins.mnemonic not in ("cmp", "test", "push", "div", "idiv", "mul"):
                escritos.add(_base(ins.operands[0].reg))
            if ins.mnemonic in ("syscall", "call"):
                escritos |= {"rax", "rcx", "r11"}
            if ins.mnemonic in ("div", "idiv", "mul"):
                escritos |= {"rax", "rdx"}
    return out


ALL_CHECKS = [
    check_strings, check_unterminated, check_cstrings, check_division, check_stack, check_missing_ret,
    check_abi, check_operands, check_symbols, check_entry, check_exit,
    check_flow, check_syscalls, check_sections, check_uninitialized,
]


def validate(analysis: Analysis) -> List[Problem]:
    problems: List[Problem] = []
    for check in ALL_CHECKS:
        try:
            problems.extend(check(analysis))
        except Exception as exc:                    # noqa: BLE001
            problems.append(Problem(1, INFO, "INT001",
                                    "falha interna na regra %s: %s" % (check.__name__, exc)))
    problems.sort(key=lambda p: (SEVERITY_ORDER[p.severity], p.line))
    return problems


def summary(problems: List[Problem]) -> str:
    e = sum(1 for p in problems if p.severity == ERRO)
    a = sum(1 for p in problems if p.severity == ALERTA)
    i = sum(1 for p in problems if p.severity == INFO)
    return "%d erro(s), %d alerta(s), %d informação(ões)" % (e, a, i)
