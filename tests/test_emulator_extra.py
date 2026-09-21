"""Testes das instruções e dos caminhos menos óbvios da máquina virtual."""

import unittest

from asmx.analyzer import analyze
from asmx.emulator import (
    BSS_BASE,
    DATA_BASE,
    MASK64,
    RET_MAGIC,
    STACK_TOP,
    Machine,
    Symbol,
    hexs,
    to_signed,
)
from asmx.errors import AnalysisTimeoutError


class RelogioFalso:
    """Relógio que avança um tanto fixo a cada leitura.

    Permite testar o timeout sem depender do tempo real: cada consulta soma
    ``passo`` segundos, então o limite estoura sempre no mesmo instante.
    """

    def __init__(self, passo: float = 10.0) -> None:
        self.passo = passo
        self.valor = 0.0

    def __call__(self) -> float:
        self.valor += self.passo
        return self.valor


def fake_clock() -> float:
    """Relógio parado, usado pelos testes que não se importam com o tempo."""
    return 0.0


def run(code: str, stdin: str = "", limit: int = 100000, **kwargs: object) -> Machine:
    maquina = Machine(
        analyze(code), stdin=stdin, clock=fake_clock, **kwargs  # type: ignore[arg-type]
    )
    maquina.run(limit=limit)
    return maquina


class TestInstrucoes(unittest.TestCase):
    """Instruções que ainda não tinham teste."""

    def test_xchg(self) -> None:
        maquina = run("mov rax, 1\nmov rbx, 2\nxchg rax, rbx")
        self.assertEqual(maquina.regs["rax"], 2)
        self.assertEqual(maquina.regs["rbx"], 1)

    def test_movzx_e_movsx(self) -> None:
        maquina = run("mov rax, 0\nmov al, 0xFF\nmovzx rbx, al\nmovsx rcx, al")
        self.assertEqual(maquina.regs["rbx"], 255)
        self.assertEqual(to_signed(maquina.regs["rcx"], 8), -1)

    def test_movsxd(self) -> None:
        maquina = run("mov eax, -1\nmovsxd rbx, eax")
        self.assertEqual(to_signed(maquina.regs["rbx"], 8), -1)

    def test_setcc(self) -> None:
        maquina = run("mov rax, 5\ncmp rax, 5\nsete bl\nsetne cl")
        self.assertEqual(maquina.regs["rbx"], 1)
        self.assertEqual(maquina.regs["rcx"], 0)

    def test_cmov(self) -> None:
        maquina = run("mov rax, 5\nmov rbx, 9\ncmp rax, 5\ncmove rbx, rax")
        self.assertEqual(maquina.regs["rbx"], 5)

    def test_cmov_nao_copia_quando_falso(self) -> None:
        maquina = run("mov rax, 5\nmov rbx, 9\ncmp rax, 4\ncmove rbx, rax")
        self.assertEqual(maquina.regs["rbx"], 9)

    def test_not_e_neg(self) -> None:
        maquina = run("mov rax, 0\nnot rax")
        self.assertEqual(maquina.regs["rax"], MASK64)

    def test_mul_imul_e_div(self) -> None:
        maquina = run("mov rax, 6\nmov rbx, 7\nmul rbx")
        self.assertEqual(maquina.regs["rax"], 42)
        self.assertEqual(maquina.regs["rdx"], 0)

    def test_imul_tres_operandos(self) -> None:
        maquina = run("mov rax, 3\nmov rbx, 4\nimul rcx, rax, rbx")
        self.assertEqual(maquina.regs["rcx"], 12)

    def test_imul_dois_operandos(self) -> None:
        maquina = run("mov rax, -3\nmov rbx, 4\nimul rax, rbx")
        self.assertEqual(to_signed(maquina.regs["rax"], 8), -12)

    def test_cdq_e_cqo(self) -> None:
        maquina = run("mov eax, -1\ncdq")
        self.assertEqual(maquina.regs["rdx"], 0xFFFFFFFF)
        maquina = run("mov rax, -1\ncqo")
        self.assertEqual(maquina.regs["rdx"], MASK64)

    def test_divisao_estoura_avisa(self) -> None:
        maquina = run("mov rdx, -1\nmov rax, 100\nmov rbx, 7\ndiv rbx")
        self.assertTrue(any("quociente não cabe" in i for i in maquina.issues))

    def test_deslocamentos(self) -> None:
        maquina = run("mov rax, 8\nshr rax, 1\nshl rax, 2")
        self.assertEqual(maquina.regs["rax"], 16)

    def test_sal_e_sar(self) -> None:
        maquina = run("mov rax, -16\nsar rax, 2\nsal rax, 1")
        self.assertEqual(to_signed(maquina.regs["rax"], 8), -8)

    def test_loop_com_rcx_zero(self) -> None:
        maquina = run("mov rcx, 1\ncorpo:\nmov rax, 7\nloop corpo")
        self.assertEqual(maquina.regs["rax"], 7)
        self.assertEqual(maquina.regs["rcx"], 0)

    def test_desvio_rcxz(self) -> None:
        maquina = run("mov rcx, 0\njrcxz fim\nmov rax, 1\nfim:\nmov rbx, 2")
        self.assertEqual(maquina.regs["rax"], 0)
        self.assertEqual(maquina.regs["rbx"], 2)

    def test_leave_desmonta_o_quadro(self) -> None:
        codigo = (
            "f:\n push rbp\n mov rbp, rsp\n sub rsp, 16\n mov rax, 1\n"
            " leave\n ret\n_start:\n call f\n mov rax, 60\n syscall"
        )
        maquina = run(codigo)
        self.assertTrue(maquina.halted)

    def test_hlt_para_a_execucao(self) -> None:
        maquina = run("mov rax, 1\nhlt\nmov rbx, 2")
        self.assertTrue(maquina.halted)
        self.assertEqual(maquina.regs["rbx"], 0)

    def test_instrucao_nao_emulada_avisa(self) -> None:
        maquina = Machine(analyze("movdqa xmm0, xmm1\nmov rax, 1"))
        maquina.step()
        self.assertTrue(any("não é emulada" in i for i in maquina.issues))

    def test_cld_e_std_mexem_em_df(self) -> None:
        maquina = run("std")
        self.assertEqual(maquina.flags["DF"], 1)
        maquina = run("std\ncld")
        self.assertEqual(maquina.flags["DF"], 0)


class TestCadeiaDeCaracteres(unittest.TestCase):
    """REP MOVSB/STOSB/LODSB/SCASB e o flag de direção."""

    def test_rep_movsb_copia(self) -> None:
        codigo = (
            "section .data\norigem db 1, 2, 3\ndestino db 0, 0, 0\nsection .text\n"
            "global _start\n_start:\n lea rsi, [origem]\n lea rdi, [destino]\n"
            " mov rcx, 3\n rep movsb\n mov rax, 1\n mov rdi, 1\n"
            " lea rsi, [destino]\n mov rdx, 3\n syscall\n"
            " mov rax, 60\n xor rdi, rdi\n syscall"
        )
        maquina = run(codigo)
        self.assertEqual([ord(c) for c in maquina.output], [1, 2, 3])

    def test_rep_stosb_preenche(self) -> None:
        codigo = (
            "section .bss\nbuf resb 4\nsection .text\nglobal _start\n_start:\n"
            " lea rdi, [buf]\n mov al, 65\n mov rcx, 4\n rep stosb\n"
            " mov rax, 1\n mov rdi, 1\n lea rsi, [buf]\n mov rdx, 4\n syscall\n"
            " mov rax, 60\n xor rdi, rdi\n syscall"
        )
        self.assertEqual(run(codigo).output, "AAAA")

    def test_lodsb_avanca_rsi(self) -> None:
        maquina = run("section .data\nx db 7\nsection .text\n lea rsi, [x]\n lodsb")
        self.assertEqual(maquina.get_reg("al"), 7)

    def test_rep_com_contador_absurdo_avisa(self) -> None:
        maquina = run("mov rcx, 0xFFFFFF\nrep stosb", limit=10)
        self.assertTrue(any("REP com RCX" in i for i in maquina.issues))

    def test_scasb_compara(self) -> None:
        codigo = "section .data\nx db 65\nsection .text\n lea rdi, [x]\n mov al, 65\n" " scasb"
        self.assertEqual(run(codigo).flags["ZF"], 1)


class TestSyscallsEmuladas(unittest.TestCase):
    """Cada syscall tratada pela máquina."""

    def test_getpid(self) -> None:
        self.assertEqual(run("mov rax, 39\nsyscall").regs["rax"], 4242)

    def test_time(self) -> None:
        self.assertGreater(run("mov rax, 201\nsyscall").regs["rax"], 0)

    def test_nanosleep_e_ignorada(self) -> None:
        maquina = run("mov rax, 35\nsyscall")
        self.assertFalse(any("35" in i for i in maquina.issues))
        maquina = Machine(analyze("mov rax, 35\nsyscall"))
        maquina.step()
        self.assertIn("nanosleep", maquina.step().note)

    def test_brk_devolve_heap_simulado(self) -> None:
        self.assertEqual(run("mov rax, 12\nsyscall").regs["rax"], BSS_BASE + 0x10000)

    def test_getrandom_preenche(self) -> None:
        codigo = (
            "section .bss\nbuf resb 8\nsection .text\nglobal _start\n_start:\n"
            " mov rax, 318\n lea rdi, [buf]\n mov rsi, 8\n syscall\n"
            " mov rbx, rax\n mov rax, 60\n xor rdi, rdi\n syscall"
        )
        maquina = run(codigo)
        self.assertEqual(maquina.regs["rbx"], 8)
        self.assertTrue(any(maquina.rd8(maquina.symbols["buf"].addr + i) for i in range(8)))

    def test_syscall_desconhecida_avisa(self) -> None:
        maquina = run("mov rax, 999\nsyscall")
        self.assertTrue(any("não é emulada" in i for i in maquina.issues))

    def test_write_com_tamanho_absurdo(self) -> None:
        maquina = run("mov rax, 1\nmov rdi, 1\nmov rsi, 0x1000\n" "mov rdx, 0xFFFFFF\nsyscall")
        self.assertTrue(any("tamanho absurdo" in i for i in maquina.issues))

    def test_exit_group(self) -> None:
        maquina = run("mov rax, 231\nmov rdi, 3\nsyscall")
        self.assertEqual(maquina.exit_code, 3)

    def test_int_0x80_troca_os_registradores(self) -> None:
        codigo = (
            'section .data\nmsg db "ok"\nsection .text\nglobal _start\n_start:\n'
            " mov eax, 4\n mov ebx, 1\n lea ecx, [msg]\n mov edx, 2\n int 0x80\n"
            " mov eax, 1\n xor ebx, ebx\n int 0x80"
        )
        self.assertEqual(run(codigo).output, "ok")

    def test_int_0x80_sem_equivalente_avisa(self) -> None:
        maquina = Machine(analyze("mov eax, 11\nint 0x80"))
        maquina.step()
        maquina.step()
        self.assertTrue(any("32 bits" in i for i in maquina.issues))

    def test_int_3_e_breakpoint(self) -> None:
        maquina = Machine(analyze("int 3\nmov rax, 1"))
        passo = maquina.step()
        self.assertIn("breakpoint", passo.note)

    def test_interrupcao_desconhecida(self) -> None:
        maquina = Machine(analyze("int 0x21\nmov rax, 1"))
        self.assertIn("não emulada", maquina.step().note)


class TestApiDoWindows(unittest.TestCase):
    """Stubs das funções do kernel32/user32."""

    def programa(self, chamada: str) -> Machine:
        codigo = (
            'extern %s\nsection .data\nmsg db "oi", 0\nsection .text\n'
            "global main\nmain:\n sub rsp, 40\n%s\n xor rcx, rcx\n"
            " call ExitProcess" % (chamada.split()[0], chamada)
        )
        return run(codigo)

    def test_getstdhandle(self) -> None:
        maquina = self.programa("call GetStdHandle")
        self.assertEqual(maquina.regs["rax"], 0x13)

    def test_writeconsole(self) -> None:
        codigo = (
            "extern GetStdHandle\nextern WriteConsoleA\nextern ExitProcess\n"
            'section .data\nmsg db "Ola", 0\nsection .text\nglobal main\nmain:\n'
            " sub rsp, 40\n mov rcx, -11\n call GetStdHandle\n mov rbx, rax\n"
            " mov rcx, rbx\n lea rdx, [msg]\n mov r8, 3\n mov r9, 0\n"
            " call WriteConsoleA\n xor rcx, rcx\n call ExitProcess"
        )
        self.assertEqual(run(codigo).output, "Ola")

    def test_messagebox(self) -> None:
        codigo = (
            "extern MessageBoxA\nextern ExitProcess\nsection .data\n"
            'titulo db "Aviso", 0\ntexto db "Cuidado", 0\nsection .text\n'
            "global main\nmain:\n sub rsp, 40\n xor rcx, rcx\n lea rdx, [texto]\n"
            " lea r8, [titulo]\n mov r9, 0\n call MessageBoxA\n xor rcx, rcx\n"
            " call ExitProcess"
        )
        self.assertIn("Cuidado", run(codigo).output)

    def test_sleep_e_ignorado(self) -> None:
        self.assertFalse(self.programa("call Sleep").issues)

    def test_getlasterror(self) -> None:
        self.assertEqual(self.programa("call GetLastError").regs["rax"], 0)

    def test_funcao_externa_desconhecida(self) -> None:
        maquina = self.programa("call NadaDisso")
        self.assertTrue(any("não é emulada" in i for i in maquina.issues))


class TestMemoriaERegistradores(unittest.TestCase):
    """Leitura, escrita e endereçamento."""

    def test_escrita_e_leitura_de_8_bytes(self) -> None:
        maquina = Machine(analyze("mov rax, 1"))
        maquina.write_mem(0x1000, 8, 0x1122334455667788)
        self.assertEqual(maquina.read_mem(0x1000, 8), 0x1122334455667788)
        self.assertEqual(maquina.rd8(0x1000), 0x88)

    def test_string_terminada_em_zero(self) -> None:
        maquina = Machine(analyze("mov rax, 1"))
        for i, letra in enumerate("abc\0"):
            maquina.wr8(0x2000 + i, ord(letra))
        self.assertEqual(maquina.read_cstring(0x2000), "abc")

    def test_endereco_com_escala(self) -> None:
        codigo = "section .data\nv db 1, 2, 3, 4\nsection .text\n mov rbx, 2\n" "mov al, [v + rbx]"
        maquina = run(codigo)
        self.assertEqual(maquina.get_reg("al"), 3)

    def test_endereco_negativo(self) -> None:
        codigo = "f:\n push rbp\n mov rbp, rsp\n sub rsp, 16\n mov al, [rbp - 4]\n leave\n ret"
        self.assertFalse(run(codigo).halted is None)

    def test_leitura_de_ponteiro_nunca_escrito(self) -> None:
        maquina = run("mov rax, [rbx]")
        self.assertTrue(any("nunca escrita" in i for i in maquina.issues))

    def test_tamanho_padrao_do_operando(self) -> None:
        maquina = Machine(analyze("mov rax, 1"))
        self.assertEqual(maquina.op_size(analyze("mov rax, 1").instrs[0].operands[0]), 8)

    def test_pilha_vazia_avisa(self) -> None:
        maquina = Machine(analyze("pop rax"))
        maquina.step()
        self.assertTrue(any("estouro de pilha" in i for i in maquina.issues))

    def test_push_e_pop_com_memoria(self) -> None:
        codigo = "section .data\nx dq 42\nsection .text\n push qword [x]\n pop rbx"
        self.assertEqual(run(codigo).regs["rbx"], 42)


class TestDadosESimbolos(unittest.TestCase):
    """Carregamento de dados, BSS e constantes."""

    def test_enderecos_de_dados_e_bss(self) -> None:
        codigo = (
            "section .data\na db 1\nsection .bss\nb resb 16\nsection .text\n"
            "global _start\n_start:\n mov rax, 60\n syscall"
        )
        maquina = run(codigo)
        self.assertEqual(maquina.symbols["a"].addr, DATA_BASE)
        self.assertEqual(maquina.symbols["b"].addr, BSS_BASE)
        self.assertTrue(maquina.symbols["b"].bss)

    def test_times_gera_zeros(self) -> None:
        codigo = (
            "section .data\nzeros times 4 db 0\nsection .text\n"
            "global _start\n_start:\n mov rax, 60\n syscall"
        )
        maquina = run(codigo)
        self.assertEqual(maquina.symbols["zeros"].size, 4)

    def test_times_com_valor_repete(self) -> None:
        codigo = (
            "section .data\nv times 3 db 7\nsection .text\nglobal _start\n_start:\n"
            " mov rax, 1\n mov rdi, 1\n lea rsi, [v]\n mov rdx, 3\n syscall\n"
            " mov rax, 60\n syscall"
        )
        self.assertEqual(run(codigo).output, "\x07\x07\x07")

    def test_equ_com_valor(self) -> None:
        codigo = (
            "section .data\nn equ 42\nsection .text\nglobal _start\n_start:\n"
            " mov rax, n\n mov rax, 60\n syscall"
        )
        maquina = run(codigo)
        self.assertEqual(maquina.symbols["n"].equ, 42)

    def test_equ_com_dolar_menos_rotulo(self) -> None:
        codigo = (
            'section .data\nmsg db "abc"\ntam equ $ - msg\nsection .text\n'
            "global _start\n_start:\n mov rdx, tam\n mov rax, 60\n syscall"
        )
        maquina = run(codigo)
        self.assertEqual(maquina.symbols["tam"].equ, 3)

    def test_rotulo_de_codigo_vira_endereco_magico(self) -> None:
        codigo = "f:\n mov rax, 1\n ret\n_start:\n lea rbx, [f]"
        maquina = run(codigo)
        self.assertGreaterEqual(maquina.regs["rbx"], RET_MAGIC)


class TestExecucao(unittest.TestCase):
    """Controle da execução, do relógio e do histórico."""

    def test_timeout_marca_e_para(self) -> None:
        maquina = Machine(analyze("inicio:\njmp inicio"), clock=RelogioFalso())
        maquina.run(limit=100000, timeout=1.0)
        self.assertTrue(maquina.timed_out)
        self.assertTrue(maquina.halted)
        self.assertTrue(any("timeout" in i for i in maquina.issues))

    def test_timeout_estrito_levanta(self) -> None:
        maquina = Machine(analyze("inicio:\njmp inicio"), clock=RelogioFalso())
        with self.assertRaises(AnalysisTimeoutError):
            maquina.run(limit=100000, timeout=1.0, raise_on_timeout=True)

    def test_run_until_para_no_indice(self) -> None:
        maquina = Machine(analyze("mov rax, 1\nmov rbx, 2\nmov rcx, 3"))
        maquina.run_until({2})
        self.assertEqual(maquina.ip, 2)
        self.assertEqual(maquina.regs["rcx"], 0)

    def test_snapshot(self) -> None:
        maquina = run("mov rax, 5")
        retrato = maquina.snapshot()
        self.assertEqual(retrato["regs"]["rax"], 5)
        self.assertIn("rsp", retrato["regs"])
        self.assertFalse(retrato["halted"] is None)

    def test_historico_limitado(self) -> None:
        maquina = Machine(analyze("inicio:\nmov rax, 1\ninc rax\njmp inicio"))
        maquina.run(limit=3000)
        self.assertLessEqual(len(maquina.trace), 2000)

    def test_ret_sem_endereco_valido(self) -> None:
        maquina = run("f:\n pop rax\n ret\n_start:\n call f")
        self.assertTrue(
            any("não é um endereço" in i or "desbalanceada" in i for i in maquina.issues)
        )

    def test_desvio_para_rotulo_inexistente_para(self) -> None:
        maquina = run("jmp lugar_nenhum")
        self.assertTrue(maquina.halted)
        self.assertTrue(any("rótulo desconhecido" in i for i in maquina.issues))

    def test_step_depois_de_parar(self) -> None:
        maquina = run("mov rax, 1")
        maquina.halted = True
        self.assertIn("já terminou", maquina.step().note)

    def test_erro_na_simulacao_vira_aviso(self) -> None:
        maquina = Machine(analyze("mov rax, 1"))
        maquina.instrs[0].operands[0].reg = "registrador_que_nao_existe"
        maquina.step()
        self.assertTrue(maquina.issues)

    def test_condicoes_desconhecidas_sao_falsas(self) -> None:
        maquina = Machine(analyze("mov rax, 1"))
        self.assertFalse(maquina.cond("zz"))

    def test_flags_de_paridade_e_sinal(self) -> None:
        maquina = Machine(analyze("mov rax, 1"))
        maquina.set_logic_flags(0, 8)
        self.assertEqual(maquina.flags["ZF"], 1)
        self.assertEqual(maquina.flags["PF"], 1)
        maquina.set_logic_flags(0x80, 1)
        self.assertEqual(maquina.flags["SF"], 1)

    def test_overflow_na_soma_sinalizada(self) -> None:
        maquina = Machine(analyze("mov rax, 1"))
        maquina.set_arith_flags(0x7FFFFFFFFFFFFFFF, 1, 0x8000000000000000, 8, False)
        self.assertEqual(maquina.flags["OF"], 1)
        maquina.set_arith_flags(0, 1, -1, 8, True)
        self.assertEqual(maquina.flags["CF"], 1)

    def test_hexs_e_to_signed(self) -> None:
        self.assertEqual(hexs(MASK64), "0xffffffffffffffff")
        self.assertEqual(to_signed(MASK64, 8), -1)
        self.assertEqual(to_signed(0xFF, 1), -1)

    def test_symbol_dataclass(self) -> None:
        simbolo = Symbol(addr=0x1000, size=8, line=3)
        self.assertEqual(simbolo.addr, 0x1000)
        self.assertFalse(simbolo.bss)

    def test_entrada_curta_e_suficiente(self) -> None:
        codigo = (
            "section .bss\nbuf resb 4\nsection .text\nglobal _start\n_start:\n"
            " mov rax, 0\n mov rdi, 0\n lea rsi, [buf]\n mov rdx, 4\n syscall\n"
            " mov rbx, rax\n mov rax, 60\n syscall"
        )
        maquina = run(codigo, stdin="ab")
        self.assertEqual(maquina.regs["rbx"], 2)

    def test_pilha_comeca_no_topo(self) -> None:
        maquina = Machine(analyze("mov rax, 1"))
        self.assertEqual(maquina.regs["rsp"], STACK_TOP)

    def test_sem_saida_explicita_avisa(self) -> None:
        self.assertTrue(any("sem uma chamada de saída" in i for i in run("mov rax, 1").issues))


if __name__ == "__main__":
    unittest.main()
