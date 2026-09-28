"""Testes dos grafos de fluxo de controle e de chamadas e do desenho em SVG.

Os casos cobrem os exemplos prontos do projeto (``linux-loop``, ``linux-funcao``,
``windows-hello``, ``quebrado``, ``bubble``...), programas pequenos montados na
hora e grafos construídos à mão, para conferir:

* o grafo de fluxo de controle: entrada, saída, laços, código inalcançável;
* o grafo de chamadas: funções, APIs externas e contagem de chamadas;
* o posicionamento determinístico e sem sobreposição;
* o SVG (XML válido, sem ``http``, sem ``script``, com setas e cores por tipo);
* DOT e Mermaid.
"""

from __future__ import annotations

import dataclasses
import json
import unittest
import xml.dom.minidom
from typing import Dict, List, Set, Tuple

from asmx.analyzer import analyze
from asmx.cfg import (
    THEME,
    Graph,
    GraphEdge,
    GraphNode,
    call_graph,
    control_flow_graph,
    escape,
    layout,
    size_of,
    to_dot,
    to_mermaid,
    to_svg,
)
from asmx.examples import EXAMPLES

LOOP = EXAMPLES["linux-loop"]["code"]
FUNCAO = EXAMPLES["linux-funcao"]["code"]
WINDOWS = EXAMPLES["windows-hello"]["code"]
QUEBRADO = EXAMPLES["quebrado"]["code"]
BUBBLE = EXAMPLES["bubble"]["code"]
GCC = EXAMPLES["gcc-att"]["code"]

#: Chaves que o relatório espera encontrar nos dois temas.
CHAVES_DO_TEMA = (
    "bg",
    "node",
    "node_entry",
    "node_exit",
    "text",
    "edge",
    "edge_taken",
    "edge_fall",
    "border",
    "dim",
)


def programa_com_blocos(quantos: int) -> str:
    """Monta um programa com um bloco por rótulo numerado.

    Args:
        quantos: Quantidade de blocos desejada.

    Returns:
        Código em que cada bloco tem um ``nop`` e cai no seguinte.
    """
    return "".join("bloco%d:\n    nop\n" % i for i in range(quantos))


def sem_sobreposicao(posicoes: Dict[str, Tuple[int, int]]) -> bool:
    """Diz se duas caixas de nó poderiam se sobrepor.

    Args:
        posicoes: ``id -> (x, y)`` devolvido por :func:`layout`.

    Returns:
        ``True`` quando nenhum par de nós ocupa a mesma área.
    """
    pontos = list(posicoes.items())
    for i, (_, (x1, y1)) in enumerate(pontos):
        for _, (x2, y2) in pontos[i + 1 :]:
            if abs(x1 - x2) < 190 and abs(y1 - y2) < 56:
                return False
    return True


class TestFluxoDeControle(unittest.TestCase):
    """O grafo de fluxo de controle: nós, tipos de bloco e arestas."""

    def grafo(self, codigo: str) -> Graph:
        """Grafo de fluxo do código dado."""
        return control_flow_graph(analyze(codigo))

    def test_um_no_por_bloco(self) -> None:
        analise = analyze(LOOP)
        grafo = control_flow_graph(analise)
        self.assertEqual(len(grafo.nodes), len(analise.blocks))
        self.assertEqual([no.id for no in grafo.nodes], ["b0", "b1", "b2", "b3"])

    def test_bloco_de_entrada_marcado(self) -> None:
        grafo = self.grafo(LOOP)
        entradas = [no for no in grafo.nodes if no.kind == "entry"]
        self.assertEqual(len(entradas), 1)
        self.assertEqual(entradas[0].label, "_start")
        self.assertEqual(entradas[0].id, "b0")

    def test_entrada_nao_e_o_primeiro_bloco(self) -> None:
        grafo = self.grafo(FUNCAO)
        entradas = [no for no in grafo.nodes if no.kind == "entry"]
        self.assertEqual(len(entradas), 1)
        self.assertEqual(entradas[0].label, "_start")
        self.assertEqual(entradas[0].id, "b4")

    def test_tipo_e_titulo(self) -> None:
        grafo = self.grafo(LOOP)
        self.assertEqual(grafo.kind, "cfg")
        self.assertEqual(grafo.title, "Fluxo de controle")
        self.assertIn("fluxo", grafo.to_dict()["title"].lower())

    def test_aresta_de_volta_do_laco(self) -> None:
        grafo = self.grafo(LOOP)
        voltas = [a for a in grafo.edges if a.source == "b2" and a.target == "b1"]
        self.assertEqual(len(voltas), 1)
        self.assertEqual(voltas[0].kind, "jmp")

    def test_aresta_de_saida_do_laco(self) -> None:
        grafo = self.grafo(LOOP)
        saidas = [a for a in grafo.edges if a.source == "b1" and a.target == "b3"]
        self.assertEqual(len(saidas), 1)
        self.assertEqual(saidas[0].kind, "taken")
        self.assertEqual(saidas[0].label, "quando igual")

    def test_rotulo_de_aresta_e_encurtado(self) -> None:
        grafo = self.grafo(LOOP)
        rotulos = [a.label for a in grafo.edges]
        self.assertTrue(rotulos)
        for rotulo in rotulos:
            self.assertLessEqual(len(rotulo), 28)
        longos = [r for r in rotulos if r.endswith("…")]
        self.assertTrue(longos)
        self.assertTrue(any(r.startswith("segue naturalmente") for r in longos))

    def test_aresta_fallthrough(self) -> None:
        grafo = self.grafo(LOOP)
        arestas = [a for a in grafo.edges if a.kind == "fallthrough"]
        self.assertEqual(len(arestas), 2)
        self.assertTrue(all(a.label for a in arestas))

    def test_bloco_de_saida_marcado(self) -> None:
        grafo = self.grafo(LOOP)
        saidas = [no for no in grafo.nodes if no.kind == "exit"]
        self.assertEqual([no.label for no in saidas], [".fim"])
        self.assertIn("encerra o processo", saidas[0].detail)

    def test_detalhe_conta_instrucoes(self) -> None:
        grafo = self.grafo(LOOP)
        por_id = {no.id: no for no in grafo.nodes}
        self.assertEqual(por_id["b0"].detail, "1 instrução · L10-L10")
        self.assertEqual(por_id["b1"].detail, "2 instruções · L13-L14")

    def test_linhas_do_bloco(self) -> None:
        grafo = self.grafo(LOOP)
        por_id = {no.id: no for no in grafo.nodes}
        self.assertEqual(por_id["b1"].lines, (13, 14))
        self.assertEqual(por_id["b3"].lines, (26, 28))

    def test_funcao_do_no(self) -> None:
        grafo = self.grafo(FUNCAO)
        por_id = {no.id: no for no in grafo.nodes}
        self.assertEqual(por_id["b0"].func, "soma")
        self.assertEqual(por_id["b1"].func, "itoa")
        self.assertEqual(por_id["b4"].func, "_start")

    def test_bloco_inalcancavel_aparece(self) -> None:
        grafo = self.grafo(QUEBRADO)
        por_id = {no.id: no for no in grafo.nodes}
        self.assertIn("b0", por_id)
        self.assertEqual(por_id["b0"].label, "divide")
        self.assertNotIn("b0", [a.target for a in grafo.edges])
        self.assertEqual(len(grafo.nodes), 3)

    def test_laco_infinito(self) -> None:
        grafo = self.grafo(QUEBRADO)
        lacos = [a for a in grafo.edges if a.source == a.target]
        self.assertEqual(len(lacos), 1)
        self.assertEqual(lacos[0].source, "b2")
        self.assertEqual(lacos[0].kind, "jmp")

    def test_jmp_para_fora_do_codigo(self) -> None:
        codigo = "_start:\n    cmp rax, 0\n    je .x\n    jmp fora\n.x:\n    ret\n"
        grafo = self.grafo(codigo)
        saidas = [no for no in grafo.nodes if no.kind == "exit"]
        self.assertTrue(any("fora do código carregado" in no.detail for no in saidas))
        self.assertTrue(any("retorna para quem chamou" in no.detail for no in saidas))

    def test_programa_vazio(self) -> None:
        grafo = control_flow_graph(analyze(""))
        self.assertTrue(grafo.is_empty())
        self.assertEqual(grafo.nodes, ())
        self.assertEqual(grafo.edges, ())

    def test_programa_so_com_comentario(self) -> None:
        grafo = control_flow_graph(analyze("; nada aqui\n"))
        self.assertTrue(grafo.is_empty())

    def test_bloco_unico(self) -> None:
        grafo = self.grafo(GCC)
        self.assertEqual(len(grafo.nodes), 1)
        self.assertEqual(grafo.nodes[0].kind, "entry")
        self.assertEqual(grafo.nodes[0].label, "main")
        self.assertEqual(grafo.edges, ())
        self.assertIn("retorna para quem chamou", grafo.nodes[0].detail)

    def test_todos_os_blocos_do_bubble(self) -> None:
        analise = analyze(BUBBLE)
        grafo = control_flow_graph(analise)
        self.assertEqual([no.id for no in grafo.nodes], ["b%d" % i for i in range(9)])
        self.assertEqual(len(grafo.edges), sum(len(b.succ) for b in analise.blocks))

    def test_exit_preenchido_vira_no_de_saida(self) -> None:
        analise = analyze(BUBBLE)
        grafo = control_flow_graph(analise)
        por_id = {no.id: no for no in grafo.nodes}
        for bloco in analise.blocks:
            if bloco.exit and por_id["b%d" % bloco.id].kind != "entry":
                self.assertEqual(por_id["b%d" % bloco.id].kind, "exit")


class TestGrafoDeChamadas(unittest.TestCase):
    """O grafo de chamadas: funções, APIs externas e contagem."""

    def test_funcoes_do_linux_funcao(self) -> None:
        grafo = call_graph(analyze(FUNCAO))
        self.assertEqual(grafo.kind, "calls")
        self.assertEqual([no.id for no in grafo.nodes], ["f:_start", "f:soma", "f:itoa"])

    def test_funcao_de_entrada_marcada(self) -> None:
        grafo = call_graph(analyze(FUNCAO))
        por_id = {no.id: no for no in grafo.nodes}
        self.assertEqual(por_id["f:_start"].kind, "entry")
        self.assertEqual(por_id["f:soma"].kind, "function")
        self.assertEqual(por_id["f:itoa"].kind, "function")

    def test_arestas_de_chamada(self) -> None:
        grafo = call_graph(analyze(FUNCAO))
        alvos = sorted(a.target for a in grafo.edges)
        self.assertEqual(alvos, ["f:itoa", "f:soma"])
        self.assertTrue(all(a.kind == "call" for a in grafo.edges))
        self.assertTrue(all(a.source == "f:_start" for a in grafo.edges))

    def test_detalhe_de_chamada(self) -> None:
        grafo = call_graph(analyze(FUNCAO))
        por_id = {no.id: no for no in grafo.nodes}
        self.assertEqual(por_id["f:soma"].detail, "chamada 1×")
        self.assertEqual(por_id["f:_start"].detail, "nenhuma chamada recebida")

    def test_linhas_da_funcao(self) -> None:
        grafo = call_graph(analyze(FUNCAO))
        por_id = {no.id: no for no in grafo.nodes}
        self.assertEqual(por_id["f:soma"].lines, (14, 19))
        self.assertEqual(por_id["f:itoa"].lines, (23, 40))

    def test_nos_de_api_do_windows(self) -> None:
        grafo = call_graph(analyze(WINDOWS))
        apis = [no for no in grafo.nodes if no.kind == "api"]
        self.assertEqual(
            [no.label for no in apis], ["GetStdHandle", "WriteConsoleA", "ExitProcess"]
        )
        self.assertTrue(all(no.lines == () for no in apis))
        self.assertTrue(all("API do Windows" in no.detail for no in apis))
        self.assertTrue(all(a.kind == "api" for a in grafo.edges))

    def test_contagem_de_chamadas_repetidas(self) -> None:
        codigo = "_start:\n    call foo\n    call foo\n    call foo\n    ret\nfoo:\n    ret\n"
        grafo = call_graph(analyze(codigo))
        self.assertEqual(len(grafo.edges), 1)
        self.assertEqual(grafo.edges[0].label, "3×")
        por_id = {no.id: no for no in grafo.nodes}
        self.assertEqual(por_id["f:foo"].detail, "chamada 3×")

    def test_funcao_externa_do_linux(self) -> None:
        codigo = "_start:\n    call printf\n    ret\n"
        grafo = call_graph(analyze(codigo))
        api = [no for no in grafo.nodes if no.kind == "api"]
        self.assertEqual([no.label for no in api], ["printf"])
        self.assertIn("função externa", api[0].detail)

    def test_chamada_fora_de_funcao(self) -> None:
        grafo = call_graph(analyze("call printf\nret\n"))
        self.assertEqual([no.id for no in grafo.nodes], ["f:código", "f:printf"])

    def test_chamada_para_rotulo_local(self) -> None:
        grafo = call_graph(analyze("_start:\n    call .sub\n    ret\n.sub:\n    ret\n"))
        self.assertIn("f:.sub", [no.id for no in grafo.nodes])
        self.assertEqual(grafo.edges[0].kind, "call")

    def test_toda_aresta_tem_no(self) -> None:
        ids = {no.id for no in call_graph(analyze(FUNCAO)).nodes}
        for aresta in call_graph(analyze(FUNCAO)).edges:
            self.assertIn(aresta.source, ids)
            self.assertIn(aresta.target, ids)

    def test_sem_chamadas_grafo_vazio(self) -> None:
        grafo = call_graph(analyze(LOOP))
        self.assertTrue(grafo.is_empty())
        self.assertEqual(grafo.nodes, ())

    def test_programa_vazio(self) -> None:
        self.assertTrue(call_graph(analyze("")).is_empty())

    def test_ordem_estavel_dos_nos_de_api(self) -> None:
        primeiro = call_graph(analyze(WINDOWS))
        segundo = call_graph(analyze(WINDOWS))
        self.assertEqual([no.id for no in primeiro.nodes], [no.id for no in segundo.nodes])


class TestLayout(unittest.TestCase):
    """Posicionamento em camadas: determinístico, sem sobreposição."""

    def test_determinismo(self) -> None:
        grafo = control_flow_graph(analyze(BUBBLE))
        self.assertEqual(layout(grafo), layout(grafo))

    def test_determinismo_entre_analises(self) -> None:
        primeiro = layout(control_flow_graph(analyze(FUNCAO)))
        segundo = layout(control_flow_graph(analyze(FUNCAO)))
        self.assertEqual(primeiro, segundo)

    def test_todos_os_nos_posicionados(self) -> None:
        grafo = control_flow_graph(analyze(BUBBLE))
        posicoes = layout(grafo)
        self.assertEqual(set(posicoes), {no.id for no in grafo.nodes})

    def test_sem_sobreposicao(self) -> None:
        for codigo in (BUBBLE, FUNCAO, QUEBRADO, LOOP):
            posicoes = layout(control_flow_graph(analyze(codigo)))
            self.assertTrue(sem_sobreposicao(posicoes))

    def test_sem_sobreposicao_no_grafo_de_chamadas(self) -> None:
        posicoes = layout(call_graph(analyze(WINDOWS)))
        self.assertTrue(sem_sobreposicao(posicoes))

    def test_camadas_por_busca_em_largura(self) -> None:
        posicoes = layout(control_flow_graph(analyze(LOOP)))
        self.assertLess(posicoes["b0"][1], posicoes["b1"][1])
        self.assertLess(posicoes["b1"][1], posicoes["b2"][1])
        self.assertEqual(posicoes["b2"][1], posicoes["b3"][1])
        self.assertLess(posicoes["b2"][0], posicoes["b3"][0])

    def test_inalcancaveis_no_fim(self) -> None:
        posicoes = layout(control_flow_graph(analyze(QUEBRADO)))
        alcancaveis = max(posicoes[nid][1] for nid in ("b1", "b2"))
        self.assertGreater(posicoes["b0"][1], alcancaveis)

    def test_grafo_vazio(self) -> None:
        self.assertEqual(layout(control_flow_graph(analyze(""))), {})

    def test_espacamento_segue_os_parametros(self) -> None:
        grafo = control_flow_graph(analyze(LOOP))
        posicoes = layout(grafo, node_width=100, node_height=40, gap_x=20, gap_y=10)
        self.assertEqual(posicoes["b0"], (26, 26))
        self.assertEqual(posicoes["b1"], (26, 76))
        self.assertGreater(posicoes["b3"][0], posicoes["b2"][0])

    def test_laco_da_espaco_no_topo(self) -> None:
        com_laco = layout(control_flow_graph(analyze(QUEBRADO)))
        sem_laco = layout(control_flow_graph(analyze(LOOP)))
        self.assertGreater(com_laco["b1"][1], sem_laco["b0"][1])


class TestSvg(unittest.TestCase):
    """O desenho em SVG: XML válido, autocontido e com as cores do tema."""

    def svg(self, codigo: str, tema: str = "dark") -> str:
        """SVG do grafo de fluxo do código dado."""
        return to_svg(control_flow_graph(analyze(codigo)), theme=tema)

    def test_contem_svg_e_marker(self) -> None:
        desenho = self.svg(LOOP)
        self.assertIn("<svg", desenho)
        self.assertIn("<marker", desenho)
        self.assertIn("marker-end=", desenho)
        self.assertTrue(desenho.startswith("<svg"))
        self.assertTrue(desenho.rstrip().endswith("</svg>"))

    def test_sem_http_e_sem_script(self) -> None:
        for codigo in (LOOP, FUNCAO, WINDOWS, QUEBRADO, BUBBLE):
            desenho = self.svg(codigo)
            self.assertNotIn("http", desenho)
            self.assertNotIn("<script", desenho)
            self.assertNotIn("href", desenho)
            self.assertNotIn("<image", desenho)
            self.assertNotIn("@import", desenho)

    def test_xml_valido_em_tres_exemplos(self) -> None:
        for codigo in (LOOP, WINDOWS, BUBBLE):
            desenho = self.svg(codigo)
            documento = xml.dom.minidom.parseString(desenho)
            self.assertEqual(documento.documentElement.tagName, "svg")

    def test_xml_valido_no_grafo_de_chamadas(self) -> None:
        desenho = to_svg(call_graph(analyze(WINDOWS)))
        documento = xml.dom.minidom.parseString(desenho)
        self.assertEqual(documento.documentElement.tagName, "svg")

    def test_namespace_do_svg(self) -> None:
        documento = xml.dom.minidom.parseString(self.svg(LOOP))
        self.assertEqual(documento.documentElement.namespaceURI, "http://www.w3.org/2000/svg")

    def test_viewbox_bate_com_size_of(self) -> None:
        grafo = control_flow_graph(analyze(BUBBLE))
        largura, altura = size_of(grafo)
        desenho = to_svg(grafo)
        self.assertIn('viewBox="0 0 %d %d"' % (largura, altura), desenho)
        self.assertIn('width="%d"' % largura, desenho)
        self.assertIn('height="%d"' % altura, desenho)

    def test_rotulo_de_aresta_aparece(self) -> None:
        self.assertIn("quando igual", self.svg(LOOP))

    def test_cores_por_tipo_de_no(self) -> None:
        desenho = self.svg(LOOP)
        self.assertIn(THEME["dark"]["node_entry"], desenho)
        self.assertIn(THEME["dark"]["node"], desenho)
        self.assertIn(THEME["dark"]["node_exit"], desenho)

    def test_tema_claro(self) -> None:
        claro = self.svg(LOOP, "light")
        escuro = self.svg(LOOP, "dark")
        self.assertIn(THEME["light"]["bg"], claro)
        self.assertNotEqual(claro, escuro)
        xml.dom.minidom.parseString(claro)

    def test_tema_desconhecido_cai_no_escuro(self) -> None:
        self.assertEqual(self.svg(LOOP, "neon"), self.svg(LOOP, "dark"))

    def test_fundo_do_tema(self) -> None:
        self.assertIn('fill="%s"' % THEME["dark"]["bg"], self.svg(LOOP))

    def test_grafo_vazio_tem_mensagem(self) -> None:
        desenho = to_svg(control_flow_graph(analyze("")))
        self.assertIn("sem código para desenhar", desenho)
        self.assertIn("<svg", desenho)
        self.assertNotIn("http", desenho)
        xml.dom.minidom.parseString(desenho)

    def test_grafo_de_chamadas_vazio_tem_mensagem(self) -> None:
        desenho = to_svg(call_graph(analyze(LOOP)))
        self.assertIn("nenhuma chamada para desenhar", desenho)
        xml.dom.minidom.parseString(desenho)

    def test_escape_de_rotulo(self) -> None:
        no = GraphNode(
            id="b0",
            label="a & b <c>",
            kind="block",
            lines=(1, 2),
            detail='diz "oi" & tchau',
        )
        grafo = Graph(kind="cfg", title="Rótulos & sinais", nodes=(no,))
        desenho = to_svg(grafo)
        self.assertIn("a &amp; b &lt;c&gt;", desenho)
        self.assertIn("&quot;oi&quot;", desenho)
        self.assertNotIn("a & b <c>", desenho)
        xml.dom.minidom.parseString(desenho)
        self.assertIn("Rótulos &amp; sinais", desenho)

    def test_determinismo_do_svg(self) -> None:
        grafo = control_flow_graph(analyze(FUNCAO))
        self.assertEqual(to_svg(grafo), to_svg(grafo))
        outro = control_flow_graph(analyze(FUNCAO))
        self.assertEqual(to_svg(grafo), to_svg(outro))

    def test_grafo_grande_reduz_a_fonte(self) -> None:
        grafo = control_flow_graph(analyze(programa_com_blocos(70)))
        self.assertGreater(len(grafo.nodes), 60)
        desenho = to_svg(grafo)
        self.assertIn('font-size="9"', desenho)
        self.assertNotIn('font-size="12.5"', desenho)
        self.assertIn("70", desenho)
        xml.dom.minidom.parseString(desenho)

    def test_grafo_pequeno_usa_a_fonte_cheia(self) -> None:
        self.assertIn('font-size="12.5"', self.svg(LOOP))

    def test_no_com_rotulo_longo_e_quebrado(self) -> None:
        desenho = self.svg(BUBBLE)
        self.assertIn("continuação de", desenho)
        self.assertIn("…", desenho)

    def test_tema_tem_as_chaves_do_relatorio(self) -> None:
        for nome in ("dark", "light"):
            for chave in CHAVES_DO_TEMA:
                self.assertIn(chave, THEME[nome])
                self.assertTrue(THEME[nome][chave].startswith("#"))


class TestDot(unittest.TestCase):
    """O desenho em DOT, o formato do Graphviz."""

    def test_digrafo_de_fluxo(self) -> None:
        ponto = to_dot(control_flow_graph(analyze(LOOP)))
        self.assertTrue(ponto.startswith("digraph cfg {"))
        self.assertTrue(ponto.rstrip().endswith("}"))
        self.assertIn("rankdir=TB", ponto)

    def test_digrafo_de_chamadas(self) -> None:
        ponto = to_dot(call_graph(analyze(FUNCAO)))
        self.assertIn("digraph calls {", ponto)
        self.assertIn('"f:soma"', ponto)

    def test_atributos_de_forma_e_cor(self) -> None:
        ponto = to_dot(control_flow_graph(analyze(LOOP)))
        self.assertIn("shape=box", ponto)
        self.assertIn("style=filled", ponto)
        self.assertIn(THEME["dark"]["node"], ponto)
        self.assertIn(THEME["dark"]["node_entry"], ponto)

    def test_rotulos_das_arestas(self) -> None:
        ponto = to_dot(control_flow_graph(analyze(LOOP)))
        self.assertIn('label="quando igual"', ponto)
        self.assertIn("->", ponto)

    def test_lista_de_chamadas_no_rotulo(self) -> None:
        ponto = to_dot(call_graph(analyze(FUNCAO)))
        self.assertIn('label="soma\\nchamada 1×"', ponto)
        self.assertIn('label="1×"', ponto)

    def test_aspas_escapadas(self) -> None:
        no = GraphNode(id="b0", label='diz "oi"', kind="block", detail="1 instrução · L1-L1")
        grafo = Graph(kind="cfg", title='aspas "aqui"', nodes=(no,))
        ponto = to_dot(grafo)
        self.assertIn('\\"oi\\"', ponto)
        self.assertIn('label="aspas \\"aqui\\""', ponto)

    def test_grafo_vazio_e_valido(self) -> None:
        ponto = to_dot(control_flow_graph(analyze("")))
        self.assertIn("digraph cfg {", ponto)
        self.assertTrue(ponto.rstrip().endswith("}"))

    def test_determinismo(self) -> None:
        grafo = control_flow_graph(analyze(BUBBLE))
        self.assertEqual(to_dot(grafo), to_dot(grafo))


class TestMermaid(unittest.TestCase):
    """O desenho em Mermaid."""

    def test_flowchart(self) -> None:
        texto = to_mermaid(control_flow_graph(analyze(LOOP)))
        self.assertTrue(texto.startswith("flowchart TD"))
        self.assertIn('["', texto)

    def test_rotulos_entre_colchetes(self) -> None:
        texto = to_mermaid(control_flow_graph(analyze(LOOP)))
        self.assertIn('b0["_start', texto)
        self.assertIn("-->", texto)

    def test_ids_sanitizados(self) -> None:
        texto = to_mermaid(call_graph(analyze(FUNCAO)))
        self.assertIn('f_soma["soma', texto)
        self.assertNotIn("f:soma", texto)
        for linha in texto.splitlines()[1:]:
            if "[" in linha:
                identificador = linha.strip().split("[", 1)[0]
                self.assertRegex(identificador, r"^[A-Za-z_][0-9A-Za-z_]*$")

    def test_aresta_com_contagem(self) -> None:
        codigo = "_start:\n    call foo\n    call foo\n    ret\nfoo:\n    ret\n"
        texto = to_mermaid(call_graph(analyze(codigo)))
        self.assertIn('-->|"2×"|', texto)

    def test_rotulo_com_aspas_e_escapado(self) -> None:
        no = GraphNode(id="b0", label='a "b" <c>', kind="block")
        texto = to_mermaid(Graph(kind="cfg", title="t", nodes=(no,)))
        self.assertIn("#quot;", texto)
        self.assertIn("#lt;", texto)

    def test_grafo_vazio(self) -> None:
        vazio = to_mermaid(control_flow_graph(analyze("")))
        self.assertIn("flowchart TD", vazio)
        self.assertIn("sem código para desenhar", vazio)
        chamadas = to_mermaid(call_graph(analyze(LOOP)))
        self.assertIn("nenhuma chamada para desenhar", chamadas)

    def test_determinismo(self) -> None:
        grafo = call_graph(analyze(WINDOWS))
        self.assertEqual(to_mermaid(grafo), to_mermaid(grafo))


class TestUtilidades(unittest.TestCase):
    """Escape, medidas e conversão para dicionário."""

    def test_escape(self) -> None:
        self.assertEqual(escape("a & b"), "a &amp; b")
        self.assertEqual(escape("<b>"), "&lt;b&gt;")
        self.assertEqual(escape('diz "oi"'), "diz &quot;oi&quot;")
        self.assertEqual(escape("sem nada"), "sem nada")
        self.assertEqual(escape('&<>"'), "&amp;&lt;&gt;&quot;")

    def test_size_of_do_grafo(self) -> None:
        grafo = control_flow_graph(analyze(LOOP))
        posicoes = layout(grafo)
        largura, altura = size_of(grafo)
        self.assertEqual(largura, max(x for x, _ in posicoes.values()) + 190 + 26)
        self.assertEqual(altura, max(y for _, y in posicoes.values()) + 56 + 26)

    def test_size_of_com_posicoes_dadas(self) -> None:
        grafo = control_flow_graph(analyze(GCC))
        self.assertEqual(size_of(grafo, {"b0": (0, 0)}), (216, 82))

    def test_size_of_vazio(self) -> None:
        self.assertEqual(size_of(control_flow_graph(analyze(""))), (360, 120))

    def test_size_of_cresce_com_o_grafo(self) -> None:
        pequeno = size_of(control_flow_graph(analyze(GCC)))
        grande = size_of(control_flow_graph(analyze(BUBBLE)))
        self.assertGreater(grande[0], pequeno[0])
        self.assertGreater(grande[1], pequeno[1])

    def test_to_dict_do_no(self) -> None:
        no = GraphNode(id="b7", label=".fim", kind="exit", lines=(26, 28), detail="3 instruções")
        dados = no.to_dict()
        self.assertEqual(dados["id"], "b7")
        self.assertEqual(dados["lines"], [26, 28])
        self.assertEqual(dados["detail"], "3 instruções")
        self.assertIsNone(dados["func"])

    def test_to_dict_da_aresta(self) -> None:
        aresta = GraphEdge(source="b0", target="b1", label="quando igual", kind="taken")
        self.assertEqual(
            aresta.to_dict(),
            {"source": "b0", "target": "b1", "label": "quando igual", "kind": "taken"},
        )

    def test_to_dict_do_grafo_vira_json(self) -> None:
        grafo = control_flow_graph(analyze(LOOP))
        dados = grafo.to_dict()
        self.assertEqual(set(dados), {"kind", "title", "nodes", "edges", "empty"})
        self.assertFalse(dados["empty"])
        self.assertEqual(len(dados["nodes"]), 4)
        self.assertEqual(len(dados["edges"]), 4)
        self.assertIsInstance(json.dumps(dados), str)

    def test_to_dict_do_grafo_vazio(self) -> None:
        dados = control_flow_graph(analyze("")).to_dict()
        self.assertTrue(dados["empty"])
        self.assertEqual(dados["nodes"], [])

    def test_is_empty(self) -> None:
        self.assertTrue(Graph(kind="cfg", title="vazio").is_empty())
        self.assertFalse(
            Graph(kind="cfg", title="t", nodes=(GraphNode("b0", "x", "block"),)).is_empty()
        )
        self.assertTrue(call_graph(analyze(LOOP)).is_empty())
        self.assertFalse(call_graph(analyze(FUNCAO)).is_empty())

    def test_aresta_orfa_nao_quebra(self) -> None:
        grafo = Graph(
            kind="cfg",
            title="aresta sem destino",
            nodes=(GraphNode("b0", "início", "block"),),
            edges=(GraphEdge("b0", "b9", "para o vazio", "jmp"),),
        )
        self.assertEqual(list(layout(grafo)), ["b0"])
        self.assertEqual(size_of(grafo), (242, 108))
        for desenho in (to_svg(grafo), to_dot(grafo), to_mermaid(grafo)):
            self.assertIn("b0", desenho)
        xml.dom.minidom.parseString(to_svg(grafo))

    def test_rotulo_vazio_nao_quebra(self) -> None:
        grafo = Graph(
            kind="cfg",
            title="sem rótulo",
            nodes=(GraphNode("b0", "", "block"), GraphNode("b1", "x" * 400, "exit")),
        )
        desenho = to_svg(grafo)
        xml.dom.minidom.parseString(desenho)
        self.assertIn("…", desenho)
        self.assertIn("x" * 20, desenho)

    def test_nos_e_arestas_sao_imutaveis(self) -> None:
        no = GraphNode(id="b0", label="x", kind="block")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            no.label = "y"  # type: ignore[misc]

    def test_ids_de_bloco_e_de_funcao(self) -> None:
        blocos: Set[str] = {no.id for no in control_flow_graph(analyze(FUNCAO)).nodes}
        funcoes: Set[str] = {no.id for no in call_graph(analyze(FUNCAO)).nodes}
        self.assertEqual(blocos, {"b0", "b1", "b2", "b3", "b4"})
        self.assertEqual(funcoes, {"f:_start", "f:soma", "f:itoa"})

    def test_ordem_dos_nos_e_estavel(self) -> None:
        primeira: List[str] = [no.id for no in control_flow_graph(analyze(BUBBLE)).nodes]
        segunda: List[str] = [no.id for no in control_flow_graph(analyze(BUBBLE)).nodes]
        self.assertEqual(primeira, segunda)
        self.assertEqual(primeira, sorted(primeira, key=lambda nid: int(nid[1:])))


if __name__ == "__main__":
    unittest.main()
