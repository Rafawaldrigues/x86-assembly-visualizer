"""Testes dos exemplos embutidos e da sua cópia em ``examples/``."""

import os
import unittest

from asmx.analyzer import analyze
from asmx.examples import EXAMPLES, count_lines, names, title_of
from asmx.linter import ERRO, validate
from asmx.source import read_source

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PASTA = os.path.join(RAIZ, "examples")

#: Exemplos que precisam passar sem nenhum erro de validação.
LIMPOS = ("linux-hello", "linux-loop", "linux-funcao", "windows-hello", "bubble")


class TestCatalogo(unittest.TestCase):
    """O catálogo em memória."""

    def test_oito_exemplos(self) -> None:
        self.assertEqual(len(EXAMPLES), 8)

    def test_names_em_ordem(self) -> None:
        self.assertEqual(names(), sorted(EXAMPLES))
        self.assertEqual(names()[0], "bubble")

    def test_todo_exemplo_tem_titulo_e_codigo(self) -> None:
        for nome, exemplo in EXAMPLES.items():
            with self.subTest(exemplo=nome):
                self.assertTrue(exemplo["title"])
                self.assertTrue(exemplo["code"].strip())
                self.assertEqual(set(exemplo), {"title", "code"})

    def test_title_of(self) -> None:
        self.assertIn("Linux", title_of("linux-hello"))
        self.assertEqual(title_of("nao_existe"), "")

    def test_count_lines(self) -> None:
        self.assertEqual(
            count_lines("linux-hello"), EXAMPLES["linux-hello"]["code"].count("\n") + 1
        )
        self.assertEqual(count_lines("nao_existe"), 0)


class TestAnalise(unittest.TestCase):
    """Todo exemplo precisa ser analisado e validado sem explodir."""

    def test_analisa_e_valida_todos(self) -> None:
        for nome, exemplo in EXAMPLES.items():
            with self.subTest(exemplo=nome):
                analise = analyze(exemplo["code"])
                self.assertGreater(analise.stats["instructions"], 0)
                validate(analise)

    def test_exemplos_limpos_sem_erro(self) -> None:
        for nome in LIMPOS:
            with self.subTest(exemplo=nome):
                erros = [p for p in validate(analyze(EXAMPLES[nome]["code"])) if p.severity == ERRO]
                self.assertEqual(erros, [], "%s tem erro: %s" % (nome, erros))

    def test_quebrado_acusa_os_defeitos_esperados(self) -> None:
        codigos = {p.code for p in validate(analyze(EXAMPLES["quebrado"]["code"]))}
        for esperado in ("STR001", "STR006", "DIV001", "IMM001", "STK001", "FLOW002", "SYM003"):
            with self.subTest(codigo=esperado):
                self.assertIn(esperado, codigos)

    def test_plataformas_detectadas(self) -> None:
        self.assertEqual(analyze(EXAMPLES["linux-hello"]["code"]).platform.os, "linux")
        self.assertEqual(analyze(EXAMPLES["windows-hello"]["code"]).platform.os, "windows")

    def test_dialetos_detectados(self) -> None:
        self.assertEqual(analyze(EXAMPLES["gcc-att"]["code"]).program.flavor, "att")
        self.assertEqual(analyze(EXAMPLES["linux-hello"]["code"]).program.flavor, "intel")


class TestArquivosEmDisco(unittest.TestCase):
    """Os arquivos em ``examples/`` são a mesma coisa que o catálogo."""

    def test_pasta_existe(self) -> None:
        self.assertTrue(os.path.isdir(PASTA), "a pasta examples/ deveria existir")

    def test_um_arquivo_por_exemplo(self) -> None:
        esperados = {"%s.asm" % nome for nome in EXAMPLES}
        encontrados = {f for f in os.listdir(PASTA) if f.endswith(".asm")}
        self.assertEqual(esperados, encontrados)

    def test_conteudo_igual_ao_do_pacote(self) -> None:
        for nome, exemplo in EXAMPLES.items():
            with self.subTest(exemplo=nome):
                caminho = os.path.join(PASTA, "%s.asm" % nome)
                with open(caminho, encoding="utf-8") as arquivo:
                    self.assertEqual(arquivo.read(), exemplo["code"].rstrip("\n") + "\n")

    def test_arquivos_sao_lidos_pelo_leitor_do_projeto(self) -> None:
        fonte = read_source(os.path.join(PASTA, "linux-hello.asm"))
        self.assertEqual(fonte.suffix, ".asm")
        self.assertEqual(fonte.encoding, "utf-8")
        self.assertIn("global _start", fonte.text)


if __name__ == "__main__":
    unittest.main()
