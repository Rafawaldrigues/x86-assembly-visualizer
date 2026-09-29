"""Tests for the local dashboard (:mod:`asmx.dashboard`).

The dashboard serves files that came from analysing untrusted assembly, so the
tests care about three things beyond the happy path: a hostile sample name must
not become markup, a request must not escape the served directory, and the
server must not become an open door when it is bound beyond the loopback.
"""

from __future__ import annotations

import http.client
import json
import os
import tempfile
import unittest
from unittest import mock

from asmx import dashboard

from asmx.dashboard import (
    DASHBOARD_SCHEMA,
    Sample,
    build_index,
    find_manifest,
    load_samples,
    render_page,
    serve,
)
from asmx.errors import ProjectError, SourceReadError

MANIFESTO = {
    "schema": "asmx-analyze/1",
    "files": [
        {
            "name": "clean.asm",
            "risk": "low",
            "score": 3,
            "instructions": 8,
            "behaviors": 1,
            "indicators": 1,
            "problems": 0,
            "platform": "linux · 64-bit",
            "report": "clean.report.html",
            "reason": "nothing stands out",
        },
        {
            "name": "suspicious.asm",
            "risk": "high",
            "score": 42,
            "instructions": 44,
            "behaviors": 5,
            "indicators": 6,
            "problems": 0,
            "report": "suspicious.report.html",
            "reason": "network code",
        },
        {
            "name": "broken.asm",
            "risk": "critical",
            "score": 100,
            "instructions": 10,
            "behaviors": 2,
            "indicators": 2,
            "problems": 10,
            "report": "broken.report.html",
        },
    ],
}

# The real shape of an ``asmx-report/1`` payload: risk is a mapping with
# ``reasons``, the counts live in ``stats`` and in the length of the lists, and
# ``summary`` is a prose string (not a mapping).
RELATORIO = {
    "schema": "asmx-report/1",
    "source": {"name": "solo.asm", "size": 1200, "lines": 40},
    "platform": {"os": "linux", "bits": 64, "abi": "System V AMD64"},
    "stats": {"instructions": 20, "blocks": 2},
    "risk": {
        "level": "medium",
        "score": 18,
        "description": "worth a read",
        "reasons": ["a few signals"],
    },
    "problems": [{"code": "DIV001"}, {"code": "MEM001"}],
    "behaviors": [{"category": "network"}, {"category": "crypto"}, {"category": "console-io"}],
    "iocs": {
        "url": [{"value": "x"}],
        "string": [{"value": "a"}, {"value": "b"}],
        "path_unix": [{"value": "/tmp/x"}],
    },
    "summary": "solo.asm has 20 instructions...",
}


class TestModelo(unittest.TestCase):
    """The sample model and the index it feeds."""

    def test_to_dict_traz_os_campos_e_os_extras(self) -> None:
        amostra = Sample("a.asm", extra={"size": 10})
        dados = amostra.to_dict()
        self.assertEqual(dados["name"], "a.asm")
        self.assertEqual(dados["size"], 10)
        self.assertIn("risk", dados)

    def test_rank_ordena_por_gravidade_e_depois_por_pontos(self) -> None:
        critico = Sample("a", risk="critical", score=10)
        alto_alto = Sample("b", risk="high", score=90)
        alto_baixo = Sample("c", risk="high", score=10)
        desconhecido = Sample("d")
        self.assertLess(critico.rank, alto_alto.rank)
        self.assertLess(alto_alto.rank, alto_baixo.rank)
        self.assertLess(alto_baixo.rank, desconhecido.rank)

    def test_build_index_conta_por_nivel(self) -> None:
        indice = build_index(
            [
                Sample("a", risk="high", score=40),
                Sample("b", risk="high", score=10),
                Sample("c", risk="low", score=1),
            ],
            title="lote",
        )
        self.assertEqual(indice["schema"], DASHBOARD_SCHEMA)
        self.assertEqual(indice["total"], 3)
        self.assertEqual(indice["by_risk"]["high"], 2)
        self.assertEqual(indice["worst"], 40)
        self.assertEqual(indice["title"], "lote")

    def test_build_index_vazio(self) -> None:
        indice = build_index([])
        self.assertEqual(indice["total"], 0)
        self.assertEqual(indice["worst"], 0)
        self.assertEqual(indice["samples"], [])


class TestRender(unittest.TestCase):
    """The page must be self-contained, escaped and readable."""

    def pagina(self, **kwargs: object) -> str:
        indice = build_index(
            [
                Sample(
                    "suspicious.asm",
                    risk="high",
                    score=42,
                    instructions=44,
                    behaviors=5,
                    indicators=6,
                    report="suspicious.report.html",
                    reason="network code",
                )
            ],
            title="ASM X",
        )
        return render_page(indice, title="ASM X", **kwargs)

    def test_traz_titulo_tabela_e_link(self) -> None:
        pagina = self.pagina()
        self.assertIn("<title>ASM X — dashboard</title>", pagina)
        self.assertIn("suspicious.asm", pagina)
        self.assertIn('href="report/suspicious.report.html"', pagina)
        self.assertIn("network code", pagina)

    def test_nao_carrega_recurso_externo(self) -> None:
        pagina = self.pagina()
        for proibido in ("http://", "https://", "<script src", "<link ", "cdn."):
            with self.subTest(proibido=proibido):
                self.assertNotIn(proibido, pagina)

    def test_sem_requisicao_de_amostra_a_pagina_e_estatica(self) -> None:
        pagina = self.pagina(live=False)
        self.assertNotIn("<script>", pagina)
        self.assertNotIn("oninput", pagina)
        self.assertIn("suspicious.asm", pagina)

    def test_escapa_nome_hostil(self) -> None:
        indice = build_index([Sample('<script>alert("x")</script>.asm', risk="low")])
        pagina = render_page(indice)
        self.assertNotIn("<script>alert", pagina)
        self.assertIn("&lt;script&gt;", pagina)

    def test_pasta_sem_amostras_avisa(self) -> None:
        self.assertIn("no samples in this folder", render_page(build_index([])))

    def test_cartoes_mostram_os_totais(self) -> None:
        pagina = self.pagina()
        self.assertIn("<b>1</b><span>samples</span>", pagina)
        self.assertIn("<b>42</b><span>worst score</span>", pagina)

    def test_sem_relatorio_nao_cria_link(self) -> None:
        pagina = render_page(build_index([Sample("sem-relatorio.asm", risk="low")]))
        self.assertNotIn('href="report/"', pagina)
        self.assertIn("sem-relatorio.asm", pagina)


class TestCarregamento(unittest.TestCase):
    """Reading a folder: manifest first, then the reports themselves."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.pasta = self.tmp.name

    def escrever(self, nome: str, dados: object) -> str:
        caminho = os.path.join(self.pasta, nome)
        with open(caminho, "w", encoding="utf-8") as arquivo:
            if isinstance(dados, str):
                arquivo.write(dados)
            else:
                json.dump(dados, arquivo)
        return caminho

    def test_le_o_manifesto_e_ordena_por_risco(self) -> None:
        self.escrever("index.json", MANIFESTO)
        amostras = load_samples(self.pasta)
        self.assertEqual([a.name for a in amostras], ["broken.asm", "suspicious.asm", "clean.asm"])
        self.assertEqual(amostras[0].risk, "critical")
        self.assertEqual(find_manifest(self.pasta), os.path.join(self.pasta, "index.json"))

    def test_sem_manifesto_le_os_relatorios(self) -> None:
        self.escrever("solo.report.json", RELATORIO)
        amostras = load_samples(self.pasta)
        self.assertEqual(len(amostras), 1)
        self.assertEqual(amostras[0].name, "solo")
        self.assertEqual(amostras[0].risk, "medium")
        self.assertEqual(amostras[0].score, 18)
        self.assertEqual(amostras[0].instructions, 20)
        self.assertEqual(amostras[0].behaviors, 3)
        self.assertEqual(amostras[0].indicators, 4)
        self.assertEqual(amostras[0].problems, 2)
        self.assertEqual(amostras[0].platform, "linux 64-bit")
        self.assertEqual(amostras[0].reason, "a few signals")
        self.assertEqual(amostras[0].report, "solo.report.json")

    def test_sem_manifesto_nem_json_lista_o_html(self) -> None:
        self.escrever("velho.report.html", "<html></html>")
        amostras = load_samples(self.pasta)
        self.assertEqual([a.name for a in amostras], ["velho"])
        self.assertEqual(amostras[0].risk, "")

    def test_json_quebrado_e_ignorado(self) -> None:
        """One broken report must not take the whole folder down."""
        self.escrever("quebrado.report.json", "{ not json }")
        self.escrever("bom.report.json", RELATORIO)
        self.assertEqual([a.name for a in load_samples(self.pasta)], ["bom"])

    def test_pasta_inexistente(self) -> None:
        with self.assertRaises(ProjectError):
            load_samples(os.path.join(self.pasta, "nao-existe"))

    def test_manifesto_com_entradas_invalidas(self) -> None:
        self.escrever("index.json", {"files": ["texto", {"name": "ok.asm"}]})
        self.assertEqual([a.name for a in load_samples(self.pasta)], ["ok.asm"])

    def test_risco_em_texto_simples(self) -> None:
        self.escrever("a.report.json", {"risk": "high", "score": 7})
        amostra = load_samples(self.pasta)[0]
        self.assertEqual(amostra.risk, "high")
        self.assertEqual(amostra.score, 7)

    def test_risco_sem_motivos_usa_a_descricao(self) -> None:
        self.escrever(
            "b.report.json",
            {"risk": {"level": "low", "score": 1, "description": "nothing stands out"}},
        )
        self.assertEqual(load_samples(self.pasta)[0].reason, "nothing stands out")

    def test_relatorio_sem_risco(self) -> None:
        self.escrever("b.report.json", {"schema": "asmx-report/1"})
        self.assertEqual(load_samples(self.pasta)[0].risk, "")

    def test_arquivo_grande_demais_e_recusado(self) -> None:
        self.escrever("grande.report.json", {"x": "y"})
        with mock.patch.object(dashboard, "MAX_REPORT_BYTES", 5):
            with self.assertRaises(SourceReadError) as capturado:
                dashboard._load_json(os.path.join(self.pasta, "grande.report.json"))
        self.assertIn("larger than the limit", str(capturado.exception))

    def test_relatorio_ilegivel_e_pulado(self) -> None:
        self.escrever("grande.report.json", {"x": "y"})
        with mock.patch.object(dashboard, "MAX_REPORT_BYTES", 5):
            self.assertEqual(load_samples(self.pasta), [])

    def test_manifesto_inexistente_quando_nao_ha(self) -> None:
        self.assertIsNone(find_manifest(self.pasta))


class TestServidor(unittest.TestCase):
    """The HTTP surface: routes, content types, traversal and the token."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        pasta = cls.tmp.name
        with open(os.path.join(pasta, "index.json"), "w", encoding="utf-8") as arquivo:
            json.dump(MANIFESTO, arquivo)
        with open(os.path.join(pasta, "suspicious.report.html"), "w", encoding="utf-8") as a:
            a.write("<html><body>report</body></html>")
        cls.pasta = pasta

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def pedir(
        self, servidor: object, caminho: str, metodo: str = "GET", cabecalhos: dict | None = None
    ) -> tuple:
        """Sends one request to the running dashboard."""
        conexao = http.client.HTTPConnection(
            "127.0.0.1", servidor.server_port, timeout=5  # type: ignore[attr-defined]
        )
        try:
            conexao.request(metodo, caminho, headers=cabecalhos or {})
            resposta = conexao.getresponse()
            return resposta.status, resposta.getheader("Content-Type"), resposta.read()
        finally:
            conexao.close()

    def servidor(self, **kwargs: object) -> object:
        servidor, _ = serve(self.pasta, port=0, background=True, **kwargs)
        self.addCleanup(servidor.server_close)  # type: ignore[attr-defined]
        self.addCleanup(servidor.shutdown)  # type: ignore[attr-defined]
        return servidor

    def test_pagina_inicial(self) -> None:
        servidor = self.servidor()
        status, tipo, corpo = self.pedir(servidor, "/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", tipo)
        self.assertIn(b"suspicious.asm", corpo)

    def test_api_samples(self) -> None:
        servidor = self.servidor()
        status, tipo, corpo = self.pedir(servidor, "/api/samples")
        self.assertEqual(status, 200)
        self.assertIn("application/json", tipo)
        dados = json.loads(corpo)
        self.assertEqual(dados["schema"], DASHBOARD_SCHEMA)
        self.assertEqual(dados["total"], 3)

    def test_api_summary(self) -> None:
        servidor = self.servidor()
        status, _, corpo = self.pedir(servidor, "/api/summary")
        self.assertEqual(status, 200)
        dados = json.loads(corpo)
        self.assertNotIn("samples", dados)
        self.assertEqual(dados["by_risk"]["critical"], 1)

    def test_serve_relatorio(self) -> None:
        servidor = self.servidor()
        status, tipo, corpo = self.pedir(servidor, "/report/suspicious.report.html")
        self.assertEqual(status, 200)
        self.assertIn("text/html", tipo)
        self.assertIn(b"report", corpo)

    def test_serve_json_como_json(self) -> None:
        servidor = self.servidor()
        status, tipo, _ = self.pedir(servidor, "/report/index.json")
        self.assertEqual(status, 200)
        self.assertIn("application/json", tipo)

    def test_head_nao_devolve_corpo(self) -> None:
        servidor = self.servidor()
        status, _, corpo = self.pedir(servidor, "/", metodo="HEAD")
        self.assertEqual(status, 200)
        self.assertEqual(corpo, b"")

    def test_traversal_bloqueado(self) -> None:
        servidor = self.servidor()
        for caminho in (
            "/report/../index.json",
            "/report/..%2F..%2Fetc%2Fpasswd",
            "/report/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ):
            with self.subTest(caminho=caminho):
                status, _, _ = self.pedir(servidor, caminho)
                self.assertEqual(status, 404)

    def test_caminho_desconhecido(self) -> None:
        servidor = self.servidor()
        self.assertEqual(self.pedir(servidor, "/nada")[0], 404)
        self.assertEqual(self.pedir(servidor, "/report/nao-existe.html")[0], 404)

    def test_token_protege_as_rotas(self) -> None:
        servidor = self.servidor(token="segredo")
        self.assertEqual(self.pedir(servidor, "/")[0], 403)
        self.assertEqual(self.pedir(servidor, "/?token=segredo")[0], 200)
        self.assertEqual(self.pedir(servidor, "/", cabecalhos={"X-ASMX-Token": "segredo"})[0], 200)
        self.assertEqual(self.pedir(servidor, "/?token=errado")[0], 403)

    def test_url_gerada(self) -> None:
        servidor, url = serve(self.pasta, port=0, background=True)
        self.addCleanup(servidor.shutdown)
        self.addCleanup(servidor.server_close)
        self.assertTrue(url.startswith("http://127.0.0.1:"))
        self.assertNotIn("token", url)

    def test_url_com_token_quando_exigido(self) -> None:
        servidor, url = serve(self.pasta, port=0, background=True, token="abc")
        self.addCleanup(servidor.shutdown)
        self.addCleanup(servidor.server_close)
        self.assertIn("?token=abc", url)

    def test_pasta_inexistente_nao_sobe(self) -> None:
        with self.assertRaises(ProjectError):
            serve(os.path.join(self.pasta, "nao-existe"), port=0)

    def test_host_externo_gera_token(self) -> None:
        try:
            servidor, url = serve(self.pasta, host="0.0.0.0", port=0, background=True)
        except OSError as erro:  # the sandbox may refuse to expose the interface
            self.skipTest("cannot bind 0.0.0.0 here: %s" % erro)
        self.addCleanup(servidor.shutdown)
        self.addCleanup(servidor.server_close)
        self.assertIn("token=", url)


if __name__ == "__main__":
    unittest.main()
