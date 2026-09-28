"""Testes dos comandos ``report`` e ``analyze`` da linha de comando."""

import contextlib
import io
import json
import os
import tempfile
import unittest
import unittest.mock

from asmx.cli import (
    EXIT_INPUT,
    EXIT_OK,
    EXIT_PROBLEMS,
    _atingiu,
    _expand_sources,
    _risk_rank,
    build_parser,
    build_payload,
    main,
)
from asmx.examples import EXAMPLES
from asmx.logging_setup import reset_logging

LIMPO = EXAMPLES["linux-hello"]["code"]
QUEBRADO = EXAMPLES["quebrado"]["code"]


class BaseCLI(unittest.TestCase):
    """Arquivos temporários, captura de saída e ambiente limpo."""

    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.ambiente = unittest.mock.patch.dict(
            os.environ, {"ASMX_OUTPUT_DIR": os.path.join(self.dir.name, "results")}
        )
        self.ambiente.start()
        self.limpo = self.escreve("limpo.asm", LIMPO)
        self.quebrado = self.escreve("quebrado.asm", QUEBRADO)

    def tearDown(self) -> None:
        self.ambiente.stop()
        self.dir.cleanup()
        reset_logging()

    def escreve(self, nome: str, conteudo: str) -> str:
        caminho = os.path.join(self.dir.name, nome)
        os.makedirs(os.path.dirname(caminho), exist_ok=True)
        with open(caminho, "w", encoding="utf-8") as arquivo:
            arquivo.write(conteudo)
        return caminho

    def run_cli(self, *argv: str) -> tuple:
        saida, erro = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(saida), contextlib.redirect_stderr(erro):
            codigo = main(list(argv))
        return codigo, saida.getvalue(), erro.getvalue()

    def run_json(self, *argv: str) -> tuple:
        """Roda o comando com ``--json`` e devolve o JSON já carregado."""
        codigo, saida, erro = self.run_cli(*argv, "--json")
        return codigo, json.loads(saida), erro


class TestAuxiliares(unittest.TestCase):
    """Funções pequenas que sustentam os dois comandos."""

    def test_risk_rank_ordena(self) -> None:
        self.assertLess(_risk_rank("baixo"), _risk_rank("medio"))
        self.assertLess(_risk_rank("medio"), _risk_rank("alto"))
        self.assertLess(_risk_rank("alto"), _risk_rank("critico"))
        self.assertEqual(_risk_rank("desconhecido"), 0)

    def test_atingiu_com_e_sem_limite(self) -> None:
        from asmx.report import ReportData

        dados = ReportData(risk={"level": "alto"})
        self.assertTrue(_atingiu("alto", dados))
        self.assertTrue(_atingiu("medio", dados))
        self.assertFalse(_atingiu("critico", dados))
        self.assertFalse(_atingiu(None, dados))

    def test_expand_sources_em_diretorio(self) -> None:
        with tempfile.TemporaryDirectory() as pasta:
            for nome in ("a.asm", "b.s", "c.txt", "d.bin"):
                with open(os.path.join(pasta, nome), "w", encoding="utf-8") as arquivo:
                    arquivo.write("nop\n")
            os.makedirs(os.path.join(pasta, "sub"))
            with open(os.path.join(pasta, "sub", "e.asm"), "w", encoding="utf-8") as arquivo:
                arquivo.write("nop\n")
            os.makedirs(os.path.join(pasta, ".oculto"))
            with open(os.path.join(pasta, ".oculto", "f.asm"), "w", encoding="utf-8") as a:
                a.write("nop\n")
            encontrados = [os.path.basename(c) for c in _expand_sources([pasta])]
        self.assertIn("a.asm", encontrados)
        self.assertIn("b.s", encontrados)
        self.assertIn("c.txt", encontrados)
        self.assertNotIn("d.bin", encontrados)
        self.assertIn("e.asm", encontrados)
        self.assertNotIn("f.asm", encontrados)

    def test_expand_sources_mantem_arquivo_explicito(self) -> None:
        self.assertEqual(_expand_sources(["/tmp/x.bin"]), ["/tmp/x.bin"])

    def test_payload_inclui_campos_novos(self) -> None:
        args = build_parser().parse_args(["report", "a.asm", "--out", "r.html", "--format", "json"])
        dados = build_payload(args)
        self.assertEqual(dados["out"], "r.html")
        self.assertEqual(dados["format"], "json")


class TestReport(BaseCLI):
    """Comando ``report``."""

    def test_html_no_caminho_indicado(self) -> None:
        destino = os.path.join(self.dir.name, "saida", "rel.html")
        codigo, saida, _ = self.run_cli("report", self.limpo, "--out", destino, "--no-color")
        self.assertEqual(codigo, EXIT_OK)
        self.assertTrue(os.path.exists(destino))
        with open(destino, encoding="utf-8") as arquivo:
            conteudo = arquivo.read()
        self.assertIn("<!DOCTYPE html>", conteudo)
        self.assertIn("limpo.asm", saida + conteudo)

    def test_html_padrao_vai_para_output_dir(self) -> None:
        codigo, saida, _ = self.run_cli("report", self.limpo, "--no-color")
        self.assertEqual(codigo, EXIT_OK)
        esperado = os.path.join(os.environ["ASMX_OUTPUT_DIR"], "limpo.report.html")
        self.assertTrue(os.path.exists(esperado))
        self.assertIn("relatório gravado em", saida)

    def test_resumo_json_sem_gravar_arquivo(self) -> None:
        codigo, dados, _ = self.run_json("report", self.limpo)
        self.assertEqual(codigo, EXIT_OK)
        self.assertEqual(dados["schema"], "asmx-report/1")
        self.assertEqual(dados["file"], "limpo.asm")
        self.assertEqual(dados["counts"]["instructions"], 8)
        self.assertEqual(dados["output"], "-")
        self.assertFalse(
            os.path.exists(os.path.join(os.environ["ASMX_OUTPUT_DIR"], "limpo.report.html"))
        )

    def test_relatorio_json_na_tela(self) -> None:
        codigo, saida, _ = self.run_cli("report", self.limpo, "--format", "json")
        self.assertEqual(codigo, EXIT_OK)
        self.assertEqual(json.loads(saida)["schema"], "asmx-report/1")

    def test_resumo_json_com_arquivo_gravado(self) -> None:
        destino = os.path.join(self.dir.name, "com-resumo.html")
        _, dados, _ = self.run_json("report", self.limpo, "--out", destino)
        self.assertEqual(dados["output"], destino)
        self.assertTrue(os.path.exists(destino))

    def test_markdown_e_dot_e_svg(self) -> None:
        for formato, marca in (
            ("md", "# ASM X"),
            ("dot", "digraph"),
            ("svg", "<svg"),
            ("mermaid", "flowchart"),
        ):
            with self.subTest(formato=formato):
                codigo, saida, _ = self.run_cli("report", self.limpo, "--format", formato)
                self.assertEqual(codigo, EXIT_OK)
                self.assertIn(marca, saida)

    def test_sem_emulacao(self) -> None:
        _, dados, _ = self.run_json("report", self.limpo, "--format", "json", "--no-emulate")
        self.assertEqual(dados["counts"]["instructions"], 8)

    def test_fail_on_alto(self) -> None:
        codigo, _, _ = self.run_cli(
            "report",
            self.quebrado,
            "--fail-on",
            "alto",
            "--out",
            os.path.join(self.dir.name, "q.html"),
        )
        self.assertEqual(codigo, EXIT_PROBLEMS)

    def test_fail_on_nao_atingido(self) -> None:
        codigo, _, _ = self.run_cli(
            "report",
            self.limpo,
            "--fail-on",
            "critico",
            "--out",
            os.path.join(self.dir.name, "l.html"),
        )
        self.assertEqual(codigo, EXIT_OK)

    def test_json_com_fail_on(self) -> None:
        codigo, dados, _ = self.run_json(
            "report",
            self.quebrado,
            "--fail-on",
            "medio",
            "--out",
            os.path.join(self.dir.name, "q2.html"),
        )
        self.assertEqual(codigo, EXIT_PROBLEMS)
        self.assertEqual(dados["exit_code"], EXIT_PROBLEMS)
        self.assertTrue(dados["behaviors"])

    def test_abre_no_navegador(self) -> None:
        destino = os.path.join(self.dir.name, "abre.html")
        with unittest.mock.patch("asmx.cli.webbrowser.open") as abrir:
            codigo, _, _ = self.run_cli("report", self.limpo, "--out", destino, "--open")
        self.assertEqual(codigo, EXIT_OK)
        abrir.assert_called_once()
        self.assertTrue(str(abrir.call_args[0][0]).startswith("file://"))

    def test_arquivo_ausente(self) -> None:
        codigo, _, erro = self.run_cli("report", os.path.join(self.dir.name, "nada.asm"))
        self.assertEqual(codigo, EXIT_INPUT)
        self.assertIn("ERR_SOURCE_NOT_FOUND", erro)

    def test_entrada_inexistente(self) -> None:
        codigo, _, erro = self.run_cli("report", self.limpo, "--entry", "nao_existe")
        self.assertEqual(codigo, EXIT_INPUT)
        self.assertIn("rótulo", erro)

    def test_stdin_muda_a_saida(self) -> None:
        codigo_fonte = (
            "section .bss\nbuf resb 8\nsection .text\nglobal _start\n_start:\n"
            "mov rax, 0\nmov rdi, 0\nmov rsi, buf\nmov rdx, 3\nsyscall\n"
            "mov rax, 1\nmov rdi, 1\nmov rsi, buf\nmov rdx, 3\nsyscall\n"
            "mov rax, 60\nxor rdi, rdi\nsyscall"
        )
        caminho = self.escreve("le.asm", codigo_fonte)
        destino = os.path.join(self.dir.name, "le.report.html")
        _, _, _ = self.run_cli("report", caminho, "--stdin", "abc", "--out", destino)
        with open(destino, encoding="utf-8") as arquivo:
            self.assertIn(">abc<", arquivo.read())


class TestAnalyze(BaseCLI):
    """Comando ``analyze`` (lote com índice)."""

    def setUp(self) -> None:
        super().setUp()
        self.pasta = os.path.join(self.dir.name, "lote")
        os.makedirs(self.pasta)
        self.escreve("lote/a.asm", LIMPO)
        self.escreve("lote/b.asm", QUEBRADO)
        self.escreve("lote/c.txt", "nop\n")
        self.escreve("lote/sub/d.asm", EXAMPLES["linux-loop"]["code"])
        self.saida = os.path.join(self.dir.name, "saida-lote")

    def test_lote_gera_relatorios_e_indice(self) -> None:
        codigo, saida, _ = self.run_cli("analyze", self.pasta, "--out", self.saida, "--no-color")
        self.assertEqual(codigo, EXIT_OK)
        arquivos = sorted(os.listdir(self.saida))
        self.assertIn("index.html", arquivos)
        self.assertIn("a.report.html", arquivos)
        self.assertIn("b.report.html", arquivos)
        self.assertIn("d.report.html", arquivos)
        with open(os.path.join(self.saida, "index.html"), encoding="utf-8") as arquivo:
            indice = arquivo.read()
        self.assertIn("a.report.html", indice)
        self.assertIn("4 arquivo(s)", indice)
        self.assertIn("resumo:", saida)

    def test_lote_json(self) -> None:
        codigo, dados, _ = self.run_json("analyze", self.pasta, "--out", self.saida)
        self.assertEqual(codigo, EXIT_OK)
        self.assertEqual(dados["schema"], "asmx-analyze/1")
        self.assertEqual(len(dados["files"]), 4)
        nomes = {f["name"] for f in dados["files"]}
        self.assertEqual(nomes, {"a.asm", "b.asm", "c.txt", "d.asm"})
        self.assertTrue(all("risk" in f for f in dados["files"]))

    def test_sem_indice(self) -> None:
        _, _, _ = self.run_cli("analyze", self.pasta, "--out", self.saida, "--no-index")
        self.assertNotIn("index.html", os.listdir(self.saida))

    def test_formato_json_no_lote(self) -> None:
        _, _, _ = self.run_cli("analyze", self.pasta, "--out", self.saida, "--format", "json")
        arquivos = os.listdir(self.saida)
        self.assertIn("a.report.json", arquivos)
        self.assertNotIn("index.html", arquivos)

    def test_fail_on_medio(self) -> None:
        codigo, _, _ = self.run_cli(
            "analyze", self.pasta, "--out", self.saida, "--fail-on", "medio"
        )
        self.assertEqual(codigo, EXIT_PROBLEMS)

    def test_pasta_vazia(self) -> None:
        vazia = os.path.join(self.dir.name, "vazia")
        os.makedirs(vazia)
        codigo, _, erro = self.run_cli("analyze", vazia, "--out", self.saida)
        self.assertEqual(codigo, EXIT_INPUT)
        self.assertIn("nenhum arquivo", erro)

    def test_arquivo_solto(self) -> None:
        codigo, _, _ = self.run_cli("analyze", self.limpo, "--out", self.saida)
        self.assertEqual(codigo, EXIT_OK)
        self.assertIn("limpo.report.html", os.listdir(self.saida))

    def test_sem_emulacao_no_lote(self) -> None:
        _, _, _ = self.run_cli(
            "analyze", self.limpo, "--out", self.saida, "--no-emulate", "--format", "json"
        )
        with open(os.path.join(self.saida, "limpo.report.json"), encoding="utf-8") as arquivo:
            self.assertIsNone(json.load(arquivo)["execution"])


if __name__ == "__main__":
    unittest.main()
