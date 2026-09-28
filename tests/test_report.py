"""Testes do relatório: coleta, risco, e os quatro formatos de saída."""

import contextlib
import io
import json
import os
import re
import tempfile
import unittest

from asmx.errors import ProjectError, SourceWriteError
from asmx.examples import EXAMPLES
from asmx.linter import ALERTA, ERRO, INFO, Problem
from asmx.report import (
    FORMATS,
    REPORT_SCHEMA,
    ReportData,
    collect,
    executive_summary,
    guess_format,
    render_dot,
    render_html,
    render_index,
    render_json,
    render_markdown,
    render_svg,
    risk_assessment,
    write_report,
)
from asmx.source import read_source

LIMPO = EXAMPLES["linux-hello"]["code"]
QUEBRADO = EXAMPLES["quebrado"]["code"]
FUNCAO = EXAMPLES["linux-funcao"]["code"]


def relatorio(codigo: str = LIMPO, **kwargs: object) -> ReportData:
    """Coleta um relatório de teste a partir de um código."""
    return collect(codigo, **kwargs)  # type: ignore[arg-type]


class TestRisco(unittest.TestCase):
    """O cálculo de risco precisa ser explicável."""

    def test_sem_nada_e_baixo(self) -> None:
        risco = risk_assessment([], [])
        self.assertEqual(risco["level"], "baixo")
        self.assertEqual(risco["score"], 0)
        self.assertIn("color", risco)
        self.assertIn("emoji", risco)

    def test_erro_pesa_mais_que_alerta(self) -> None:
        erro = risk_assessment([Problem(1, ERRO, "X", "m")], [])["score"]
        alerta = risk_assessment([Problem(1, ALERTA, "X", "m")], [])["score"]
        info = risk_assessment([Problem(1, INFO, "X", "m")], [])["score"]
        self.assertGreater(erro, alerta)
        self.assertGreater(alerta, info)

    def test_comportamento_alto_pesa(self) -> None:
        from asmx.behavior import Behavior

        alto = Behavior("network", "Rede", "d", "alto", 90, (1,), ("e",), ("T1071",))
        risco = risk_assessment([], [alto])
        self.assertGreaterEqual(risco["score"], 18)
        self.assertTrue(any("alto" in razao for razao in risco["reasons"]))

    def test_teto_de_cem(self) -> None:
        problemas = [Problem(i, ERRO, "X", "m") for i in range(20)]
        self.assertEqual(risk_assessment(problemas, [])["score"], 100)
        self.assertEqual(risk_assessment(problemas, [])["level"], "critico")


class TestFormatoEUtilitarios(unittest.TestCase):
    """Descoberta de formato e resumo executivo."""

    def test_guess_format(self) -> None:
        self.assertEqual(guess_format("a.html"), "html")
        self.assertEqual(guess_format("a.md"), "md")
        self.assertEqual(guess_format("a.json"), "json")
        self.assertEqual(guess_format("a.svg"), "svg")
        self.assertEqual(guess_format("a.dot"), "dot")
        self.assertEqual(guess_format("a.mermaid"), "mermaid")
        self.assertEqual(guess_format("a.desconhecido"), "html")

    def test_formatos_declarados(self) -> None:
        self.assertEqual(set(FORMATS), {"html", "md", "json", "dot", "svg", "mermaid"})

    def test_resumo_executivo_cita_arquivo_e_plataforma(self) -> None:
        dados = relatorio(emulate=False)
        texto = executive_summary(dados)
        self.assertIn("programa.asm", texto)
        self.assertIn("linux", texto)
        self.assertIn("instruções", texto)


class TestColeta(unittest.TestCase):
    """O que o relatório junta a partir de um código."""

    def test_metadados_basicos(self) -> None:
        dados = relatorio(emulate=False, source=None)
        self.assertEqual(dados.schema, REPORT_SCHEMA)
        self.assertEqual(dados.source["name"], "programa.asm")
        self.assertTrue(dados.source["fingerprint"])
        self.assertEqual(dados.dialect, "intel")
        self.assertEqual(dados.platform["os"], "linux")
        self.assertIn("System V", str(dados.platform["abi"]))
        self.assertTrue(dados.platform["arg_regs"])
        self.assertTrue(dados.platform["evidence"]["linux"])

    def test_instrucoes_explicadas(self) -> None:
        dados = relatorio(emulate=False)
        self.assertEqual(len(dados.instructions), dados.counts["instructions"])
        primeira = dados.instructions[0]
        self.assertEqual(
            set(primeira),
            {"line", "text", "mnemonic", "label", "detail", "tag", "func", "section", "block"},
        )
        self.assertTrue(primeira["detail"])

    def test_blocos_com_vizinhos(self) -> None:
        dados = relatorio(EXAMPLES["linux-loop"]["code"], emulate=False)
        self.assertTrue(dados.blocks)
        bloco = dados.blocks[0]
        self.assertIn("name", bloco)
        self.assertIn("goes_to", bloco)
        self.assertEqual(len(bloco["lines"]), 2)

    def test_grafos_presentes(self) -> None:
        dados = relatorio(FUNCAO, emulate=False)
        self.assertIn("svg", dados.cfg)
        self.assertIn("dot", dados.cfg)
        self.assertIn("mermaid", dados.cfg)
        self.assertFalse(dados.cfg["graph"]["empty"])
        self.assertFalse(dados.calls["graph"]["empty"])

    def test_syscalls_e_apis(self) -> None:
        dados = relatorio(emulate=False)
        nomes = {s["name"]: s for s in dados.syscalls}
        self.assertEqual(set(nomes), {"write", "exit"})
        self.assertEqual(nomes["write"]["count"], 1)
        self.assertEqual(nomes["write"]["number"], 1)
        self.assertEqual(nomes["exit"]["number"], 60)
        self.assertTrue(nomes["write"]["lines"])
        self.assertEqual(dados.apis, [])

    def test_apis_externas_do_windows(self) -> None:
        dados = relatorio(EXAMPLES["windows-hello"]["code"], emulate=False)
        self.assertIn("ExitProcess", dados.apis)
        self.assertEqual(dados.platform["os"], "windows")

    def test_comportamentos_e_mitre(self) -> None:
        dados = relatorio(emulate=False)
        self.assertTrue(dados.behaviors)
        categorias = {b["category"] for b in dados.behaviors}
        self.assertIn("console-io", categorias)
        for tecnica in dados.techniques:
            self.assertIn("tactic", tecnica)
            self.assertTrue(tecnica["url"].startswith("https://attack.mitre.org/techniques/"))

    def test_indicadores(self) -> None:
        dados = relatorio(emulate=False)
        self.assertIn("string", dados.iocs)
        valores = [i["value"] for i in dados.iocs["string"]]
        self.assertIn("Ola, mundo!", valores)

    def test_problemas_do_quebrado(self) -> None:
        dados = relatorio(QUEBRADO, emulate=False)
        self.assertTrue(dados.problems)
        self.assertEqual(dados.risk["level"] in ("medio", "alto", "critico"), True)
        codigos = {p["code"] for p in dados.problems}
        self.assertIn("DIV001", codigos)

    def test_execucao_e_linha_do_tempo(self) -> None:
        dados = relatorio()
        self.assertIsNotNone(dados.execution)
        self.assertEqual(dados.execution["output"], "Ola, mundo!\n")
        self.assertEqual(dados.execution["exit_code"], 0)
        self.assertTrue(dados.timeline)
        self.assertIn("registers", dados.execution)
        self.assertIn("flags", dados.execution)

    def test_sem_emulacao_nao_tem_execucao(self) -> None:
        dados = relatorio(emulate=False)
        self.assertIsNone(dados.execution)
        self.assertEqual(dados.timeline, [])

    def test_entrada_inexistente(self) -> None:
        with self.assertRaises(ProjectError):
            collect(LIMPO, entry="nao_existe")

    def test_fonte_lida_do_disco(self) -> None:
        with tempfile.TemporaryDirectory() as pasta:
            caminho = os.path.join(pasta, "prog.asm")
            with open(caminho, "w", encoding="utf-8") as arquivo:
                arquivo.write(LIMPO)
            tamanho = os.path.getsize(caminho)
            dados = collect(LIMPO, source=read_source(caminho), emulate=False)
        self.assertEqual(dados.source["name"], "prog.asm")
        self.assertEqual(dados.source["size"], tamanho)
        self.assertTrue(dados.source["sha256"])

    def test_codigo_vazio_nao_quebra(self) -> None:
        dados = collect("", emulate=False)
        self.assertEqual(dados.counts["instructions"], 0)
        self.assertEqual(dados.blocks, [])
        self.assertIn("sem código", render_html(dados))

    def test_emulacao_que_estoura_o_limite(self) -> None:
        dados = collect("global _start\nsection .text\n_start:\ntrava:\n jmp trava", limit=500)
        self.assertEqual(dados.execution["steps"], 500)
        self.assertTrue(dados.execution["issues"])

    def test_counts(self) -> None:
        dados = relatorio(emulate=False)
        contagens = dados.counts
        self.assertEqual(contagens["instructions"], dados.stats["instructions"])
        self.assertEqual(contagens["behaviors"], len(dados.behaviors))
        self.assertEqual(contagens["problems"], len(dados.problems))
        self.assertEqual(contagens["iocs"], sum(len(v) for v in dados.iocs.values()))


class TestSerializacao(unittest.TestCase):
    """JSON, Markdown, HTML, DOT, SVG e índice."""

    def test_json_valido_e_com_esquema(self) -> None:
        dados = relatorio(emulate=False)
        carregado = json.loads(render_json(dados))
        self.assertEqual(carregado["schema"], REPORT_SCHEMA)
        self.assertIn("behaviors", carregado)
        self.assertIn("cfg", carregado)
        self.assertNotIn("svg", carregado["cfg"])
        self.assertFalse(render_json(dados).endswith("\n\n"))

    def test_json_com_svg_quando_pedido(self) -> None:
        dados = relatorio(emulate=False)
        carregado = json.loads(render_json(dados, include_svg=True))
        self.assertIn("<svg", carregado["cfg"]["svg"])

    def test_to_dict_com_campos_obrigatorios(self) -> None:
        dados = relatorio(emulate=False)
        chaves = set(dados.to_dict())
        for esperada in (
            "schema",
            "generated_at",
            "version",
            "source",
            "platform",
            "stats",
            "risk",
            "summary",
            "problems",
            "behaviors",
            "techniques",
            "iocs",
            "instructions",
            "blocks",
            "cfg",
            "calls",
            "execution",
            "timeline",
        ):
            self.assertIn(esperada, chaves)

    def test_markdown_tem_secoes_e_tabelas(self) -> None:
        dados = relatorio(EXAMPLES["quebrado"]["code"], emulate=False)
        texto = render_markdown(dados)
        for secao in (
            "# ASM X",
            "## Metadados",
            "## Números",
            "## Comportamentos",
            "## Fluxo de controle",
            "## Validação",
            "## Instruções",
        ):
            self.assertIn(secao, texto)
        self.assertIn("```mermaid", texto)
        self.assertIn("|", texto)

    def test_markdown_de_programa_limpo(self) -> None:
        texto = render_markdown(collect(LIMPO, emulate=False))
        self.assertIn("## Comportamentos", texto)
        self.assertIn("Nenhum problema encontrado", texto)

    def test_html_sem_comportamento_explica_o_vazio(self) -> None:
        pagina = render_html(collect("nop", emulate=False))
        self.assertIn("Nenhum comportamento relevante", pagina)

    def test_html_autocontido_e_sem_rede(self) -> None:
        dados = relatorio(emulate=False)
        pagina = render_html(dados)
        self.assertTrue(pagina.startswith("<!DOCTYPE html>"))
        self.assertIn("<title>", pagina)
        self.assertIn("<svg", pagina)
        self.assertIn("showTab", pagina)
        for proibido in ("<script src", "<link rel=", "cdn.", "@import", "<img src"):
            self.assertNotIn(proibido, pagina)

    def test_html_escapa_conteudo_do_programa(self) -> None:
        codigo = 'section .data\nmsg db "<img src=x onerror=alert(1)>", 0\n'
        pagina = render_html(collect(codigo, emulate=False))
        self.assertNotIn("<img src=x", pagina)
        self.assertIn("&lt;img", pagina)

    def test_html_nao_escapa_o_proprio_html(self) -> None:
        """Células com marcação (chips, links, spans) precisam sair como HTML.

        Se uma delas for escapada, a página mostra o código no lugar do
        elemento — foi assim que o `caminho` do arquivo virou
        ``&lt;span class="mono"&gt;`` na primeira versão do relatório.
        """
        pagina = render_html(relatorio(EXAMPLES["suspeito"]["code"], emulate=False))
        for escapado in ("&lt;span", "&lt;a href", "&lt;div"):
            self.assertNotIn(escapado, pagina)
        self.assertIn('<span class="mono">', pagina)
        self.assertIn("attack.mitre.org", pagina)

    def test_html_mostra_risco_e_contagens(self) -> None:
        dados = relatorio(QUEBRADO, emulate=False)
        pagina = render_html(dados)
        self.assertIn("RISCO", pagina.upper())
        self.assertIn(str(dados.risk["score"]), pagina)
        self.assertIn("instruções", pagina)
        self.assertIn("DIV001", pagina)

    def test_html_das_abas_aparece(self) -> None:
        pagina = render_html(relatorio(emulate=False))
        for aba in (
            "Resumo",
            "Fluxo",
            "Comportamentos",
            "Indicadores",
            "Instruções",
            "Validação",
            "Execução",
            "Dados",
        ):
            self.assertIn(">%s</button>" % aba, pagina)

    def test_dot_e_svg(self) -> None:
        dados = relatorio(FUNCAO, emulate=False)
        self.assertIn("digraph", render_dot(dados))
        self.assertIn("<svg", render_svg(dados))

    def test_indice_compara_relatorios(self) -> None:
        primeiro = relatorio(LIMPO, emulate=False)
        primeiro.source["report_file"] = "limpo.report.html"
        segundo = relatorio(QUEBRADO, emulate=False)
        segundo.source["report_file"] = "quebrado.report.html"
        pagina = render_index([primeiro, segundo], command="asmx analyze x")
        self.assertIn("limpo.report.html", pagina)
        self.assertIn("quebrado.report.html", pagina)
        self.assertIn("2 arquivo(s) analisado(s)", pagina)
        self.assertIn("tabela-indice", pagina)


class TestEscrita(unittest.TestCase):
    """Gravação em disco, formato por extensão e erros."""

    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.dados = relatorio(emulate=False)

    def tearDown(self) -> None:
        self.dir.cleanup()

    def caminho(self, nome: str) -> str:
        return os.path.join(self.dir.name, nome)

    def test_grava_por_extensao(self) -> None:
        esperado = {
            "rel.html": "<!DOCTYPE html>",
            "rel.md": "# ASM X",
            "rel.json": '"schema"',
            "rel.dot": "digraph",
            "rel.svg": "<svg",
            "rel.mermaid": "flowchart",
        }
        for nome, marca in esperado.items():
            with self.subTest(arquivo=nome):
                caminho = write_report(self.dados, self.caminho(nome))
                with open(caminho, encoding="utf-8") as arquivo:
                    self.assertIn(marca, arquivo.read())

    def test_formato_explicito(self) -> None:
        caminho = write_report(self.dados, self.caminho("sem_extensao"), fmt="json")
        with open(caminho, encoding="utf-8") as arquivo:
            self.assertEqual(json.loads(arquivo.read())["schema"], REPORT_SCHEMA)

    def test_formato_desconhecido(self) -> None:
        with self.assertRaises(ProjectError):
            write_report(self.dados, self.caminho("x.html"), fmt="pdf")

    def test_caminho_invalido(self) -> None:
        with self.assertRaises(SourceWriteError):
            write_report(self.dados, self.dir.name)

    def test_saida_padrao(self) -> None:
        fluxo = io.StringIO()
        with contextlib.redirect_stdout(fluxo):
            escrito = write_report(self.dados, "-", fmt="json")
        self.assertEqual(escrito, "-")
        self.assertIn(REPORT_SCHEMA, fluxo.getvalue())

    def test_nao_deixa_lixo(self) -> None:
        write_report(self.dados, self.caminho("rel.html"))
        self.assertEqual(sorted(os.listdir(self.dir.name)), ["rel.html"])

    def test_html_nao_depende_de_arquivo_externo(self) -> None:
        pagina = render_html(self.dados)
        self.assertIsNone(
            re.search(r"""(src|href)\s*=\s*["'](?!https://attack\.mitre\.org)""", pagina)
        )


if __name__ == "__main__":
    unittest.main()
