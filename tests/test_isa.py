"""Testes do acervo de instruções: consultas, registradores e tabelas."""

import json
import os
import unittest

from asmx import isa
from asmx.isa import (
    ARG_REGS_SYSCALL,
    ARG_REGS_SYSV,
    ARG_REGS_WIN,
    CALLEE_SAVED_SYSV,
    CALLEE_SAVED_WIN,
    CATEGORIES,
    CONDITIONS,
    CONTROL_DIRECTIVES,
    DATA_DIRECTIVES,
    FLAG_DOC,
    ISA,
    LINUX_SYSCALLS,
    REG_DOC,
    REG_INFO,
    REGS64,
    SIZE_KEYWORDS,
    WIN_APIS,
    category_of,
    doc_for,
    is_cond_jump,
)


class TestAcervo(unittest.TestCase):
    """O acervo precisa estar completo e coerente."""

    def test_quantidades(self) -> None:
        self.assertEqual(len(ISA), 148)
        self.assertEqual(len(LINUX_SYSCALLS), 43)
        self.assertEqual(len(CATEGORIES), 11)
        self.assertGreaterEqual(len(WIN_APIS), 18)

    def test_toda_instrucao_tem_os_campos_usados_pelo_programa(self) -> None:
        for mnemonic, ficha in ISA.items():
            with self.subTest(mnemonic=mnemonic):
                for campo in ("name", "cat", "syntax", "desc", "ex", "flags"):
                    self.assertIn(campo, ficha)
                self.assertIn(ficha["cat"], CATEGORIES)

    def test_categorias_em_minusculas(self) -> None:
        for chave in CATEGORIES:
            self.assertEqual(chave, chave.lower())

    def test_json_existe_e_e_o_mesmo_conteudo(self) -> None:
        caminho = os.path.join(os.path.dirname(isa.__file__), "data", "isa.json")
        with open(caminho, encoding="utf-8") as arquivo:
            dados = json.load(arquivo)
        self.assertEqual(len(dados["ISA"]), len(ISA))

    def test_registradores_e_flags_documentados(self) -> None:
        self.assertIn("rax", REG_DOC)
        self.assertIn("ZF", FLAG_DOC)

    def test_syscalls_conhecidas(self) -> None:
        self.assertEqual(LINUX_SYSCALLS[1][0], "write")
        self.assertEqual(LINUX_SYSCALLS[60][0], "exit")
        self.assertEqual(LINUX_SYSCALLS[0][0], "read")

    def test_chaves_de_syscall_sao_inteiros(self) -> None:
        for numero in LINUX_SYSCALLS:
            self.assertIsInstance(numero, int)


class TestDocFor(unittest.TestCase):
    """Consulta de documentação."""

    def test_instrucao_conhecida(self) -> None:
        self.assertEqual(doc_for("mov")["cat"], "data")

    def test_maiusculas_e_minusculas(self) -> None:
        self.assertEqual(doc_for("MOV"), doc_for("mov"))

    def test_desconhecida(self) -> None:
        self.assertIsNone(doc_for("xyzzy"))

    def test_vazio(self) -> None:
        self.assertIsNone(doc_for(""))
        self.assertIsNone(doc_for(None))

    def test_category_of(self) -> None:
        self.assertEqual(category_of("syscall"), "sys")
        self.assertEqual(category_of("jne"), "branch")
        self.assertEqual(category_of("desconhecida"), "misc")


class TestDesviosCondicionais(unittest.TestCase):
    """Distinguir desvio condicional de incondicional é usado em todo o resto."""

    def test_condicionais(self) -> None:
        for mnemonic in ("je", "jne", "jl", "jge", "ja", "jb", "jrcxz", "jecxz"):
            with self.subTest(mnemonic=mnemonic):
                self.assertTrue(is_cond_jump(mnemonic))

    def test_jmp_nao_e_condicional(self) -> None:
        self.assertFalse(is_cond_jump("jmp"))

    def test_outras_instrucoes(self) -> None:
        for mnemonic in ("mov", "call", "ret", "j", "jx"):
            with self.subTest(mnemonic=mnemonic):
                self.assertFalse(is_cond_jump(mnemonic))

    def test_condicoes_tem_nome_e_explicacao(self) -> None:
        for sufixo, texto in CONDITIONS.items():
            with self.subTest(sufixo=sufixo):
                self.assertEqual(len(texto), 2)
                self.assertTrue(texto[0] and texto[1])


class TestRegistradores(unittest.TestCase):
    """O mapa de registradores cobre os nomes parciais e os SIMD."""

    def test_64_bits(self) -> None:
        for nome in REGS64:
            self.assertEqual(REG_INFO[nome]["size"], 8)
            self.assertEqual(REG_INFO[nome]["base"], nome)

    def test_nomes_parciais(self) -> None:
        self.assertEqual(REG_INFO["eax"]["base"], "rax")
        self.assertEqual(REG_INFO["eax"]["size"], 4)
        self.assertEqual(REG_INFO["ax"]["size"], 2)
        self.assertEqual(REG_INFO["al"]["size"], 1)

    def test_metade_alta(self) -> None:
        self.assertTrue(REG_INFO["ah"]["high"])
        self.assertEqual(REG_INFO["ah"]["base"], "rax")
        self.assertFalse(REG_INFO["al"]["high"])

    def test_r8_a_r15(self) -> None:
        self.assertEqual(REG_INFO["r8d"]["base"], "r8")
        self.assertEqual(REG_INFO["r15b"]["size"], 1)

    def test_simd(self) -> None:
        self.assertTrue(REG_INFO["xmm0"]["simd"])
        self.assertEqual(REG_INFO["xmm0"]["size"], 16)
        self.assertEqual(REG_INFO["ymm15"]["size"], 32)

    def test_rip(self) -> None:
        self.assertEqual(REG_INFO["rip"]["size"], 8)


class TestTabelas(unittest.TestCase):
    """Palavras de tamanho, diretivas e ABIs."""

    def test_palavras_de_tamanho(self) -> None:
        self.assertEqual(SIZE_KEYWORDS["byte"], 1)
        self.assertEqual(SIZE_KEYWORDS["qword"], 8)
        self.assertEqual(SIZE_KEYWORDS["xmmword"], 16)

    def test_diretivas_de_dados(self) -> None:
        self.assertEqual(DATA_DIRECTIVES["db"], 1)
        self.assertEqual(DATA_DIRECTIVES["dq"], 8)
        self.assertEqual(DATA_DIRECTIVES["resb"], 1)

    def test_diretivas_de_controle(self) -> None:
        for diretiva in ("section", "global", "extern", "proc", ".cfi_startproc"):
            self.assertIn(diretiva, CONTROL_DIRECTIVES)

    def test_ordem_dos_argumentos(self) -> None:
        self.assertEqual(ARG_REGS_SYSV[:3], ["rdi", "rsi", "rdx"])
        self.assertEqual(ARG_REGS_SYSCALL[3], "r10")
        self.assertEqual(ARG_REGS_WIN, ["rcx", "rdx", "r8", "r9"])

    def test_registradores_preservados(self) -> None:
        self.assertIn("rbx", CALLEE_SAVED_SYSV)
        self.assertIn("rdi", CALLEE_SAVED_WIN)
        self.assertNotIn("rdi", CALLEE_SAVED_SYSV)


if __name__ == "__main__":
    unittest.main()
