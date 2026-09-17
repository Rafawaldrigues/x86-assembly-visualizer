import unittest

from asmx.analyzer import analyze
from asmx.emulator import MASK64, Machine, to_signed
from asmx.examples import EXAMPLES


def run(code, **kw):
    m = Machine(analyze(code), **kw)
    m.run(limit=100000)
    return m


class TestEmuladorBasico(unittest.TestCase):

    def test_mov_e_aritmetica(self):
        m = run("mov rax, 10\nadd rax, 5\nsub rax, 3\nimul rax, 2")
        self.assertEqual(m.regs["rax"], 24)

    def test_registradores_parciais(self):
        m = run("mov rax, 0x1122334455667788\nmov al, 0xff")
        self.assertEqual(m.regs["rax"], 0x11223344556677FF)
        m = run("mov rax, 0x1122334455667788\nmov eax, 1")
        self.assertEqual(m.regs["rax"], 1, "escrever em EAX zera a parte alta")

    def test_flags_de_comparacao(self):
        m = run("mov rax, 5\ncmp rax, 5")
        self.assertEqual(m.flags["ZF"], 1)
        m = run("mov rax, 2\ncmp rax, 5")
        self.assertEqual(m.flags["ZF"], 0)
        self.assertEqual(m.flags["CF"], 1)

    def test_desvio_condicional(self):
        code = ("mov rax, 3\ncmp rax, 3\njne fim\nmov rbx, 1\nfim:\nmov rcx, 9")
        m = run(code)
        self.assertEqual(m.regs["rbx"], 1)
        self.assertEqual(m.regs["rcx"], 9)

    def test_pilha_push_pop(self):
        m = run("mov rax, 7\npush rax\nmov rax, 0\npop rbx")
        self.assertEqual(m.regs["rbx"], 7)

    def test_call_ret(self):
        code = ("jmp inicio\nsoma:\n add rdi, rsi\n mov rax, rdi\n ret\n"
                "inicio:\n mov rdi, 20\n mov rsi, 22\n call soma")
        m = run(code)
        self.assertEqual(m.regs["rax"], 42)

    def test_divisao_com_resto(self):
        m = run("xor rdx, rdx\nmov rax, 100\nmov rbx, 7\ndiv rbx")
        self.assertEqual(m.regs["rax"], 14)
        self.assertEqual(m.regs["rdx"], 2)

    def test_divisao_por_zero_e_fatal(self):
        m = run("xor rdx, rdx\nmov rax, 1\nxor rbx, rbx\ndiv rbx")
        self.assertTrue(m.halted)
        self.assertTrue(any("divisão por zero" in i for i in m.issues))

    def test_idiv_com_negativo(self):
        m = run("mov rax, -100\ncqo\nmov rbx, 7\nidiv rbx")
        self.assertEqual(to_signed(m.regs["rax"]), -14)
        self.assertEqual(to_signed(m.regs["rdx"]), -2)

    def test_deslocamento(self):
        m = run("mov rax, 1\nshl rax, 10")
        self.assertEqual(m.regs["rax"], 1024)
        m = run("mov rax, -8\nsar rax, 1")
        self.assertEqual(to_signed(m.regs["rax"]), -4)

    def test_lea_nao_le_memoria(self):
        m = run("section .data\nx dq 99\nsection .text\nlea rax, [x]\nmov rbx, [x]")
        self.assertNotEqual(m.regs["rax"], 99)
        self.assertEqual(m.regs["rbx"], 99)

    def test_loop_conta_ate_zero(self):
        m = run("mov rcx, 5\nmov rax, 0\ncorpo:\ninc rax\nloop corpo")
        self.assertEqual(m.regs["rax"], 5)


class TestEmuladorPrograma(unittest.TestCase):

    def test_hello_linux(self):
        m = run(EXAMPLES["linux-hello"]["code"])
        self.assertEqual(m.output, "Ola, mundo!\n")
        self.assertEqual(m.exit_code, 0)
        self.assertTrue(m.halted)

    def test_laco_imprime_cinco_vezes(self):
        m = run(EXAMPLES["linux-loop"]["code"])
        self.assertEqual(m.output.count("iteracao do laco"), 5)

    def test_funcao_converte_numero(self):
        m = run(EXAMPLES["linux-funcao"]["code"])
        self.assertEqual(m.output, "42\n")

    def test_bubble_ordena(self):
        m = run(EXAMPLES["bubble"]["code"])
        self.assertEqual(m.output.strip(), "12345789")

    def test_windows_escreve_no_console(self):
        m = run(EXAMPLES["windows-hello"]["code"])
        self.assertIn("Ola do Windows!", m.output)
        self.assertEqual(m.exit_code, 0)

    def test_att_do_gcc(self):
        m = run(EXAMPLES["gcc-att"]["code"])
        self.assertEqual(m.exit_code, 10)

    def test_entrada_simulada(self):
        code = ("section .bss\nbuf resb 16\nsection .text\nglobal _start\n_start:\n"
                "mov rax, 0\nmov rdi, 0\nmov rsi, buf\nmov rdx, 5\nsyscall\n"
                "mov rax, 1\nmov rdi, 1\nmov rsi, buf\nmov rdx, 5\nsyscall\n"
                "mov rax, 60\nxor rdi, rdi\nsyscall")
        m = run(code, stdin="abcde")
        self.assertEqual(m.output, "abcde")

    def test_passo_a_passo(self):
        m = Machine(analyze("mov rax, 1\nmov rbx, 2\nmov rcx, 3"))
        m.step()
        self.assertEqual(m.regs["rax"], 1)
        self.assertEqual(m.regs["rbx"], 0)
        m.step()
        self.assertEqual(m.regs["rbx"], 2)
        self.assertEqual(len(m.trace), 2)

    def test_entrada_alternativa(self):
        code = "f:\n mov rax, 123\n ret\n_start:\n mov rax, 1\n"
        m = Machine(analyze(code), entry="f")
        m.run()
        self.assertEqual(m.regs["rax"], 123)


class TestDeteccaoDeProblemas(unittest.TestCase):

    def test_laco_infinito_para_no_limite(self):
        m = Machine(analyze("inicio:\njmp inicio"))
        m.run(limit=500)
        self.assertTrue(m.halted)
        self.assertTrue(any("laço infinito" in i for i in m.issues))

    def test_valor_grande_truncado(self):
        m = run("mov al, 300")
        self.assertTrue(any("não cabe" in i for i in m.issues))

    def test_estouro_de_soma(self):
        m = run("mov rax, -1\nadd rax, 2")
        self.assertTrue(any("estourou" in i for i in m.issues))

    def test_leitura_de_memoria_nunca_escrita(self):
        m = run("mov rax, [0x500000]")
        self.assertTrue(any("nunca escrita" in i for i in m.issues))

    def test_pilha_desbalanceada_no_ret(self):
        code = "jmp i\nf:\n push rax\n ret\ni:\n call f"
        m = run(code)
        self.assertTrue(any("desbalanceada" in i or "não é um endereço" in i for i in m.issues))

    def test_sem_saida_explicita(self):
        m = run("mov rax, 1\nmov rbx, 2")
        self.assertTrue(any("sem uma chamada de saída" in i for i in m.issues))

    def test_snapshot(self):
        m = run("mov rax, 5")
        s = m.snapshot()
        self.assertEqual(s["regs"]["rax"], 5)
        self.assertIn("flags", s)


if __name__ == "__main__":
    unittest.main()
