"""Grafos de fluxo de controle e de chamadas, com desenho em SVG, DOT e Mermaid.

O analisador já sabe onde cada bloco começa e termina e para onde cada desvio
aponta; este módulo transforma isso em :class:`Graph` — nós e arestas prontos
para virar desenho — e escreve o desenho em três formatos, todos montados por
concatenação de strings, sem nenhuma biblioteca externa:

* :func:`to_svg` — SVG autocontido, feito para ser colado dentro do relatório
  HTML e também para ser aberto sozinho no navegador;
* :func:`to_dot` — DOT do Graphviz, para quem preferir renderizar por fora;
* :func:`to_mermaid` — ``flowchart`` do Mermaid, para o relatório que usa
  Mermaid.

O posicionamento (:func:`layout`) é determinístico: o mesmo grafo produz sempre
as mesmas coordenadas, porque nada aqui percorre um ``set`` nem depende do hash
dos nomes.  O desenho sai estável entre execuções e entre máquinas, o que
também deixa os testes de SVG comparáveis byte a byte.  As camadas descem (a
entrada em cima, quem ela alcança abaixo), que é a orientação que sobrevive
bem à coluna estreita do relatório; código inalcançável fica na última linha.

O ``xmlns`` do SVG é escrito com uma referência de caractere (``&#104;``) para
que o texto final não cite ``http`` em lugar nenhum — o relatório embute o
desenho e não busca nada na rede.  Depois de lido pelo navegador ou por um
analisador XML, o valor do atributo é o endereço normal do padrão SVG; o teste
``test_namespace_do_svg`` e a conferência com o navegador confirmam isso.

Example:
    >>> from asmx.analyzer import analyze
    >>> grafo = control_flow_graph(analyze("_start:\\n    mov rax, 60\\n    syscall"))
    >>> [(no.id, no.kind) for no in grafo.nodes]
    [('b0', 'entry')]
    >>> to_dot(grafo).splitlines()[0]
    'digraph cfg {'
"""

from __future__ import annotations

import math
import re
from collections import deque
from dataclasses import dataclass
from typing import Any, Deque, Dict, List, Optional, Sequence, Tuple

from .analyzer import Analysis, Block
from .isa import WIN_APIS
from .parser import Line

# ---------------------------------------------------------------------------
# Cores
# ---------------------------------------------------------------------------

#: Paleta de cada tema: ``dark`` (padrão do relatório) e ``light``.
#:
#: As chaves ``bg``, ``node``, ``node_entry``, ``node_exit``, ``text``,
#: ``edge``, ``edge_taken``, ``edge_fall``, ``border`` e ``dim`` são as usadas
#: pelo relatório; ``node_function``, ``node_api``, ``edge_call`` e
#: ``edge_api`` completam os tipos de nó e de aresta do grafo de chamadas, para
#: que cada ``kind`` tenha a sua cor.
THEME: Dict[str, Dict[str, str]] = {
    "dark": {
        "bg": "#0f1420",
        "node": "#1d2839",
        "node_entry": "#16452f",
        "node_exit": "#5a2130",
        "node_function": "#22314b",
        "node_api": "#3a2f1c",
        "text": "#e8eef8",
        "edge": "#8296b0",
        "edge_taken": "#f0a35e",
        "edge_fall": "#5fa8d3",
        "edge_call": "#a795f2",
        "edge_api": "#d7b45a",
        "border": "#3a4a63",
        "dim": "#93a3ba",
    },
    "light": {
        "bg": "#ffffff",
        "node": "#eef2f8",
        "node_entry": "#d8f3dc",
        "node_exit": "#fbdcdc",
        "node_function": "#e2ecff",
        "node_api": "#fdf1d6",
        "text": "#16202e",
        "edge": "#5b6b82",
        "edge_taken": "#c2410c",
        "edge_fall": "#1d4ed8",
        "edge_call": "#6d28d9",
        "edge_api": "#a16207",
        "border": "#b6c2d4",
        "dim": "#5f6b7f",
    },
}

#: Chave de cor do tema usada por cada tipo de nó.
_COR_DO_NO: Dict[str, str] = {
    "entry": "node_entry",
    "block": "node",
    "function": "node_function",
    "exit": "node_exit",
    "api": "node_api",
}

#: Chave de cor do tema usada por cada tipo de aresta.
_COR_DA_ARESTA: Dict[str, str] = {
    "taken": "edge_taken",
    "fallthrough": "edge_fall",
    "jmp": "edge",
    "call": "edge_call",
    "api": "edge_api",
}

# ---------------------------------------------------------------------------
# Medidas do desenho
# ---------------------------------------------------------------------------

#: Margem em volta do desenho, em pixels.
_MARGEM = 26

#: Largura e altura de um nó, em pixels.
_LARGURA_NO = 190
_ALTURA_NO = 56

#: Espaço entre as colunas e entre as linhas de nós, em pixels.
_ESPACO_X = 46
_ESPACO_Y = 42

#: Tamanho da moldura devolvida para um grafo sem nada para desenhar.
_LARGURA_VAZIA = 360
_ALTURA_VAZIA = 120

#: A partir de quantos nós o desenho usa fonte menor e rótulos mais curtos.
_LIMITE_GRANDE = 60

#: Tamanho da fonte do nome do nó e do detalhe, nos dois modos.
_FONTE = 12.5
_FONTE_DETALHE = 9.5
_FONTE_GRANDE = 9.0
_FONTE_DETALHE_GRANDE = 7.5

#: Fonte dos rótulos de aresta e limite de caracteres no modo econômico.
_FONTE_ARESTA = 9.0
_FONTE_ARESTA_GRANDE = 7.5
_ROTULO_ARESTA_GRANDE = 16

#: Raio dos cantos arredondados, em pixels.
_RAIO = 9

#: Altura da alça desenhada para um desvio de um bloco para ele mesmo.  Ela
#: precisa caber no espaço entre duas camadas, junto com o rótulo da aresta.
_ALTURA_DO_LACO = 24.0

#: Recuo da seta para que a ponta não encoste na borda do nó, em pixels.
_FOLGA_SETA = 3.0

#: Tamanho máximo do rótulo de uma aresta vindo do analisador.
_MAX_ROTULO = 28

#: Endereço do padrão SVG, escrito com uma referência de caractere para que o
#: texto gerado não cite ``http`` (veja a explicação no topo do módulo).
_NAMESPACE_SVG = "&#104;ttp://www.w3.org/2000/svg"

#: Família tipográfica do desenho: só genéricas, nada de fonte externa.
_FONTE_FAMILIA = "sans-serif"

#: Modelo do ``id`` de cada seta: ``asmx-<grafo>-<tema>-<tipo>``.
_ID_SETA = "asmx-%s-%s-%s"

#: Rótulos que marcam o ponto de entrada, na ordem de prioridade.
ROTULOS_DE_ENTRADA: Tuple[str, ...] = ("_start", "main", "start", "winmain")

#: Nome dado ao código que está fora de qualquer rótulo (chamador anônimo).
_NOME_SEM_FUNCAO = "código"


# ---------------------------------------------------------------------------
# Estruturas do grafo
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GraphNode:
    """Um nó do grafo: um bloco básico, uma função ou uma API externa.

    Attributes:
        id: Identificador estável (``b0``, ``b1``... ou ``f:soma``).
        label: Nome do bloco ou da função, como aparece no código.
        kind: ``entry``, ``block`` ou ``exit`` no fluxo de controle;
            ``entry``, ``function`` ou ``api`` no grafo de chamadas.
        lines: Linhas do arquivo cobertas, como ``(12, 20)``; vazio para API.
        detail: Texto curto mostrado abaixo do nome, como
            ``8 instruções · L12-L20`` ou ``chamada 3×``.
        func: Função a que o nó pertence, quando houver.
    """

    id: str
    label: str
    kind: str
    lines: Tuple[int, ...] = ()
    detail: str = ""
    func: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Converte o nó em dicionário simples, pronto para virar JSON.

        Returns:
            Dicionário com ``id``, ``label``, ``kind``, ``lines`` (em lista),
            ``detail`` e ``func``.
        """
        return {
            "id": self.id,
            "label": self.label,
            "kind": self.kind,
            "lines": list(self.lines),
            "detail": self.detail,
            "func": self.func,
        }


@dataclass(frozen=True)
class GraphEdge:
    """Uma ligação do grafo, já com o rótulo que o desenho mostra.

    Attributes:
        source: ``id`` do nó de origem.
        target: ``id`` do nó de destino.
        label: Texto mostrado no meio da linha, como ``quando igual`` ou ``3×``.
        kind: ``taken``, ``fallthrough``, ``jmp``, ``call`` ou ``api``.
    """

    source: str
    target: str
    label: str = ""
    kind: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Converte a aresta em dicionário simples, pronto para virar JSON.

        Returns:
            Dicionário com ``source``, ``target``, ``label`` e ``kind``.
        """
        return {
            "source": self.source,
            "target": self.target,
            "label": self.label,
            "kind": self.kind,
        }


@dataclass(frozen=True)
class Graph:
    """Um grafo inteiro: tipo, título, nós e arestas.

    Attributes:
        kind: ``cfg`` (fluxo de controle) ou ``calls`` (chamadas).
        title: Título do desenho, em português.
        nodes: Nós, na ordem em que devem ser desenhados.
        edges: Arestas, na ordem em que devem ser desenhadas.
    """

    kind: str
    title: str
    nodes: Tuple[GraphNode, ...] = ()
    edges: Tuple[GraphEdge, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        """Converte o grafo em dicionário simples, pronto para virar JSON.

        Returns:
            Dicionário com ``kind``, ``title``, ``nodes``, ``edges`` e
            ``empty`` (o resultado de :meth:`is_empty`).
        """
        return {
            "kind": self.kind,
            "title": self.title,
            "nodes": [no.to_dict() for no in self.nodes],
            "edges": [aresta.to_dict() for aresta in self.edges],
            "empty": self.is_empty(),
        }

    def is_empty(self) -> bool:
        """Diz se o grafo não tem nada para desenhar.

        Returns:
            ``True`` quando não há nó nenhum; um programa sem chamadas devolve
            um grafo de chamadas vazio.
        """
        return not self.nodes


# ---------------------------------------------------------------------------
# Texto
# ---------------------------------------------------------------------------


def escape(text: str) -> str:
    """Escapa os caracteres que o XML reserva.

    Args:
        text: Texto livre, como nome de bloco ou motivo do desvio.

    Returns:
        O texto com ``&``, ``<``, ``>`` e ``"`` trocados por entidades.
    """
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    )


def _encurtar(texto: str, limite: int) -> str:
    """Encurta um texto até o limite, marcando o corte com reticências.

    Args:
        texto: Texto original.
        limite: Número máximo de caracteres do resultado.

    Returns:
        O próprio texto quando já cabe; senão, o prefixo terminado em ``…``.
    """
    if len(texto) <= limite:
        return texto
    if limite <= 1:
        return "…"[:limite]
    return texto[: limite - 1].rstrip() + "…"


def _quebrar(texto: str, limite: int, max_linhas: int = 2) -> List[str]:
    """Quebra um texto em linhas de no máximo ``limite`` caracteres.

    Args:
        texto: Texto original.
        limite: Número máximo de caracteres por linha.
        max_linhas: Número máximo de linhas devolvidas.

    Returns:
        As linhas já aparadas; quando o texto não cabe, a última linha termina
        em ``…`` para deixar claro que faltou pedaço.
    """
    limite = max(4, limite)
    linhas: List[str] = []
    atual = ""
    for palavra in texto.split():
        if not atual:
            atual = palavra
        elif len(atual) + 1 + len(palavra) <= limite:
            atual = atual + " " + palavra
        else:
            linhas.append(atual)
            atual = palavra
    if atual:
        linhas.append(atual)
    if len(linhas) > max_linhas:
        linhas = linhas[:max_linhas]
        linhas[-1] = _encurtar(linhas[-1] + "…", limite)
    return [_encurtar(linha, limite) for linha in linhas]


def _caracteres_por_linha(largura: float, fonte: float) -> int:
    """Estima quantos caracteres cabem numa linha de texto.

    Args:
        largura: Largura útil da caixa, em pixels.
        fonte: Tamanho da fonte, em pixels.

    Returns:
        O número de caracteres que cabe, nunca menor que 6.
    """
    return max(6, int((largura - 18) / (fonte * 0.56)))


def _largura_do_texto(texto: str, fonte: float) -> float:
    """Estima a largura de um texto, em pixels.

    Args:
        texto: Texto a medir.
        fonte: Tamanho da fonte, em pixels.

    Returns:
        A largura estimada, usada para o fundo do rótulo de aresta.
    """
    return len(texto) * fonte * 0.56


def _numero(valor: float) -> str:
    """Formata um número sem casas decimais inúteis.

    Args:
        valor: Número a formatar.

    Returns:
        Texto como ``12`` ou ``12.5``.
    """
    if abs(valor - round(valor)) < 0.05:
        return "%d" % round(valor)
    return ("%.1f" % valor).rstrip("0").rstrip(".")


# ---------------------------------------------------------------------------
# Montagem dos grafos
# ---------------------------------------------------------------------------


def _rotulo_de_entrada(analysis: Analysis) -> Optional[str]:
    """Descobre qual rótulo marca a entrada do programa.

    Args:
        analysis: Análise já pronta.

    Returns:
        O nome do rótulo (``_start``, ``main``, ``start`` ou ``WinMain``) ou
        ``None`` quando nenhum deles aparece no código.
    """
    por_minusculas = {nome.lower(): nome for nome in analysis.label_at}
    for candidato in ROTULOS_DE_ENTRADA:
        if candidato in analysis.label_at:
            return candidato
        if candidato in por_minusculas:
            return por_minusculas[candidato]
    return None


def _indice_do_rotulo(analysis: Analysis, nome: str) -> Optional[int]:
    """Índice da instrução em que um rótulo aparece.

    Args:
        analysis: Análise já pronta.
        nome: Nome do rótulo procurado.

    Returns:
        O índice entre as instruções, ou ``None`` quando o rótulo não existe.
    """
    indice = analysis.label_at.get(nome)
    if indice is None or not 0 <= indice < len(analysis.instrs):
        return None
    return indice


def _bloco_de_entrada(analysis: Analysis) -> Optional[int]:
    """Índice do bloco de entrada do programa.

    Args:
        analysis: Análise já pronta.

    Returns:
        O ``id`` do bloco que contém ``_start``/``main``/``start``/``WinMain``;
        o bloco 0 quando o programa tem blocos mas nenhum desses rótulos; e
        ``None`` quando não há bloco nenhum.
    """
    if not analysis.blocks:
        return None
    nome = _rotulo_de_entrada(analysis)
    if nome is not None:
        indice = _indice_do_rotulo(analysis, nome)
        if indice is not None:
            bloco = analysis.instrs[indice].block
            if bloco is not None:
                return bloco
    return 0


def _faixa_de_linhas(instrs: Sequence[Line]) -> Tuple[int, ...]:
    """Linhas do arquivo cobertas por uma sequência de instruções.

    Args:
        instrs: Instruções do bloco ou da função, na ordem.

    Returns:
        ``(primeira, última)`` ou ``()`` quando a sequência está vazia.
    """
    if not instrs:
        return ()
    return (instrs[0].n, instrs[-1].n)


def _detalhe_do_bloco(bloco: Block) -> str:
    """Monta o texto de apoio de um nó de bloco.

    Args:
        bloco: Bloco básico devolvido pelo analisador.

    Returns:
        Texto como ``3 instruções · L23-L25``; quando o bloco encerra o fluxo,
        o motivo entra no fim (``· retorna para quem chamou``).
    """
    quantas = len(bloco.instrs)
    if not quantas:
        return "bloco sem instruções"
    faixa = _faixa_de_linhas(bloco.instrs)
    detalhe = "%d %s · L%d-L%d" % (
        quantas,
        "instrução" if quantas == 1 else "instruções",
        faixa[0],
        faixa[1],
    )
    if bloco.exit:
        detalhe += " · " + bloco.exit
    return detalhe


def control_flow_graph(analysis: Analysis) -> Graph:
    """Monta o grafo de fluxo de controle: um nó por bloco básico.

    Blocos inalcançáveis continuam no grafo — o relatório precisa mostrar
    código morto — e o :func:`layout` reserva as últimas colunas para eles.

    Args:
        analysis: Análise já pronta.

    Returns:
        O :class:`Graph` de tipo ``cfg``, vazio quando não há bloco nenhum.
    """
    titulo = "Fluxo de controle"
    if not analysis.blocks:
        return Graph(kind="cfg", title=titulo)
    entrada = _bloco_de_entrada(analysis)
    nos: List[GraphNode] = []
    for bloco in analysis.blocks:
        if bloco.id == entrada:
            tipo = "entry"
        elif bloco.exit:
            tipo = "exit"
        else:
            tipo = "block"
        nos.append(
            GraphNode(
                id="b%d" % bloco.id,
                label=bloco.name,
                kind=tipo,
                lines=_faixa_de_linhas(bloco.instrs),
                detail=_detalhe_do_bloco(bloco),
                func=bloco.func,
            )
        )
    arestas: List[GraphEdge] = []
    for bloco in analysis.blocks:
        for aresta in bloco.succ:
            arestas.append(
                GraphEdge(
                    source="b%d" % bloco.id,
                    target="b%d" % aresta.target,
                    label=_encurtar(aresta.why, _MAX_ROTULO),
                    kind=aresta.kind,
                )
            )
    return Graph(kind="cfg", title=titulo, nodes=tuple(nos), edges=tuple(arestas))


def _chamadas(analysis: Analysis) -> List[Tuple[str, str]]:
    """Lista as chamadas do código, na ordem em que aparecem.

    Args:
        analysis: Análise já pronta.

    Returns:
        Pares ``(quem chama, alvo)``; o chamador é ``código`` quando a chamada
        está fora de qualquer rótulo.
    """
    chamadas: List[Tuple[str, str]] = []
    for ins in analysis.instrs:
        if ins.mnemonic != "call" or not ins.operands:
            continue
        alvo = ins.operands[0].symbol or ins.operands[0].text
        if not alvo:
            continue
        chamadas.append((ins.func or _NOME_SEM_FUNCAO, alvo))
    return chamadas


def _funcao_de_entrada(analysis: Analysis) -> Optional[str]:
    """Nome da função que contém o ponto de entrada.

    Args:
        analysis: Análise já pronta.

    Returns:
        O nome da função (``_start``, ``main``...) ou ``None`` quando o
        programa não tem rótulo de entrada conhecido.
    """
    nome = _rotulo_de_entrada(analysis)
    if nome is None:
        return None
    indice = _indice_do_rotulo(analysis, nome)
    if indice is None:
        return None
    return analysis.instrs[indice].func or nome


def _funcoes_em_ordem(analysis: Analysis) -> List[str]:
    """Nomes das funções na ordem em que os blocos aparecem.

    Args:
        analysis: Análise já pronta.

    Returns:
        Lista sem repetição, com a função de entrada na frente quando existe.
    """
    nomes: List[str] = []
    for bloco in analysis.blocks:
        if bloco.func and bloco.func not in nomes:
            nomes.append(bloco.func)
    entrada = _funcao_de_entrada(analysis)
    if entrada is not None and entrada in nomes:
        nomes.remove(entrada)
        nomes.insert(0, entrada)
    return nomes


def _linhas_da_funcao(analysis: Analysis, nome: str) -> Tuple[int, ...]:
    """Linhas do arquivo cobertas por uma função.

    Args:
        analysis: Análise já pronta.
        nome: Nome da função procurada.

    Returns:
        ``(primeira, última)`` ou ``()`` quando nenhum bloco é dessa função.
    """
    faixas = [_faixa_de_linhas(b.instrs) for b in analysis.blocks if b.func == nome]
    faixas = [faixa for faixa in faixas if faixa]
    if not faixas:
        return ()
    return (min(faixa[0] for faixa in faixas), max(faixa[1] for faixa in faixas))


def _e_api_do_windows(alvo: str) -> bool:
    """Diz se um alvo de chamada é uma API do Windows conhecida.

    Args:
        alvo: Nome do alvo, como aparece no ``call``.

    Returns:
        ``True`` quando o nome (sem ``_`` inicial nem ``@N``) está no acervo.
    """
    return re.sub(r"^_+|@.*$", "", alvo.lower()) in WIN_APIS


def _detalhe_da_funcao(chamadas_recebidas: int) -> str:
    """Texto de apoio de um nó de função do grafo de chamadas.

    Args:
        chamadas_recebidas: Quantas vezes a função é chamada no código.

    Returns:
        ``chamada 3×`` quando alguém chama, ``nenhuma chamada recebida``
        quando ninguém chama.
    """
    if chamadas_recebidas:
        return "chamada %d×" % chamadas_recebidas
    return "nenhuma chamada recebida"


def call_graph(analysis: Analysis) -> Graph:
    """Monta o grafo de chamadas, com contagem por par chamador/alvo.

    Entram no desenho as funções envolvidas em alguma chamada (quem chama ou
    quem é chamado) e um nó ``api`` para cada alvo que não é rótulo do arquivo
    — API do Windows ou função externa.  Quando o código não chama nada, o
    grafo volta vazio (:meth:`Graph.is_empty`), porque não há chamada para
    desenhar.

    Args:
        analysis: Análise já pronta.

    Returns:
        O :class:`Graph` de tipo ``calls``.
    """
    titulo = "Grafo de chamadas"
    chamadas = _chamadas(analysis)
    if not chamadas:
        return Graph(kind="calls", title=titulo)

    recebidas: Dict[str, int] = {}
    pares: List[Tuple[str, str]] = []
    contagem: Dict[Tuple[str, str], int] = {}
    for quem, alvo in chamadas:
        recebidas[alvo] = recebidas.get(alvo, 0) + 1
        par = (quem, alvo)
        if par not in contagem:
            pares.append(par)
        contagem[par] = contagem.get(par, 0) + 1

    internos = set(analysis.label_at)
    chamadores = {quem for quem, _ in chamadas}
    recebidos_internos = {alvo for _, alvo in chamadas if alvo in internos}
    entrada = _funcao_de_entrada(analysis)

    # Toda ponta de aresta precisa de nó: além das funções declaradas, entram
    # aqui os rótulos internos chamados por ``call`` (um rótulo local, por
    # exemplo) e o código que está fora de qualquer rótulo.
    funcoes = _funcoes_em_ordem(analysis)
    nomes = [nome for nome in funcoes if nome in chamadores or nome in recebidos_internos]
    for quem, alvo in chamadas:
        for nome in (quem, alvo if alvo in internos else None):
            if nome is not None and nome not in funcoes and nome not in nomes:
                nomes.append(nome)

    nos: List[GraphNode] = []
    for nome in nomes:
        if nome == entrada:
            tipo = "entry"
        else:
            tipo = "function"
        nos.append(
            GraphNode(
                id="f:" + nome,
                label=nome,
                kind=tipo,
                lines=_linhas_da_funcao(analysis, nome),
                detail=_detalhe_da_funcao(recebidas.get(nome, 0)),
                func=None if nome == _NOME_SEM_FUNCAO else nome,
            )
        )
    criados = {no.id for no in nos}
    for _, alvo in chamadas:
        if "f:" + alvo in criados:
            continue
        if _e_api_do_windows(alvo):
            detalhe = "API do Windows · " + _detalhe_da_funcao(recebidas.get(alvo, 0))
        else:
            detalhe = "função externa · " + _detalhe_da_funcao(recebidas.get(alvo, 0))
        nos.append(GraphNode(id="f:" + alvo, label=alvo, kind="api", lines=(), detail=detalhe))
        criados.add("f:" + alvo)

    arestas = [
        GraphEdge(
            source="f:" + quem,
            target="f:" + alvo,
            label="%d×" % contagem[(quem, alvo)],
            kind="call" if alvo in internos else "api",
        )
        for quem, alvo in pares
    ]
    return Graph(kind="calls", title=titulo, nodes=tuple(nos), edges=tuple(arestas))


# ---------------------------------------------------------------------------
# Posicionamento
# ---------------------------------------------------------------------------


def _tem_laco(graph: Graph) -> bool:
    """Diz se o grafo tem algum desvio de um nó para ele mesmo.

    Args:
        graph: Grafo a conferir.

    Returns:
        ``True`` quando existe aresta com origem e destino iguais.
    """
    return any(aresta.source == aresta.target for aresta in graph.edges)


def _chave_de_ordem(
    nid: str,
    antecessores: Dict[str, List[str]],
    posicao: Dict[str, int],
    ordem: Dict[str, int],
) -> Tuple[int, float, int]:
    """Chave que decide a ordem dos nós dentro de uma camada.

    O nó desce para perto da média das posições de quem aponta para ele, o que
    reduz cruzamentos sem deixar de ser determinístico.

    Args:
        nid: ``id`` do nó.
        antecessores: ``id`` -> lista de nós que apontam para ele.
        posicao: ``id`` -> posição já decidida dentro da própria camada.
        ordem: ``id`` -> posição do nó na lista original do grafo.

    Returns:
        Tupla ``(sem_antecessor, média, desempate)`` pronta para o ``sorted``.
    """
    anteriores = [posicao[p] for p in antecessores[nid] if p in posicao]
    if not anteriores:
        return (1, 0.0, ordem[nid])
    return (0, sum(anteriores) / float(len(anteriores)), ordem[nid])


def _camadas(graph: Graph) -> List[List[str]]:
    """Agrupa os nós em camadas, pela distância BFS até as entradas.

    Args:
        graph: Grafo a organizar.

    Returns:
        Uma lista de camadas; cada camada é a lista de ``id`` na ordem em que
        deve ser desenhada.  Nós que nenhuma entrada alcança vão para a última
        camada, para que código morto não suma do desenho.
    """
    ids = [no.id for no in graph.nodes]
    ordem = {nid: indice for indice, nid in enumerate(ids)}
    sucessores: Dict[str, List[str]] = {nid: [] for nid in ids}
    antecessores: Dict[str, List[str]] = {nid: [] for nid in ids}
    for aresta in graph.edges:
        if aresta.source in sucessores and aresta.target in sucessores:
            sucessores[aresta.source].append(aresta.target)
            antecessores[aresta.target].append(aresta.source)

    raizes = [no.id for no in graph.nodes if no.kind == "entry"]
    if not raizes:
        raizes = [nid for nid in ids if not antecessores[nid]]
    if not raizes:
        raizes = ids[:1]

    distancia: Dict[str, int] = {}
    fila: Deque[str] = deque()
    for raiz in raizes:
        if raiz not in distancia:
            distancia[raiz] = 0
            fila.append(raiz)
    while fila:
        atual = fila.popleft()
        for vizinho in sucessores[atual]:
            if vizinho not in distancia:
                distancia[vizinho] = distancia[atual] + 1
                fila.append(vizinho)

    fundo = max(distancia.values()) + 1 if distancia else 0
    for nid in ids:
        if nid not in distancia:
            distancia[nid] = fundo

    por_camada: Dict[int, List[str]] = {}
    for nid in ids:
        por_camada.setdefault(distancia[nid], []).append(nid)

    posicao: Dict[str, int] = {}
    camadas: List[List[str]] = []
    for indice in sorted(por_camada):
        ordenada = sorted(
            por_camada[indice],
            key=lambda nid: _chave_de_ordem(nid, antecessores, posicao, ordem),
        )
        for lugar, nid in enumerate(ordenada):
            posicao[nid] = lugar
        camadas.append(ordenada)
    return camadas


def layout(
    graph: Graph,
    *,
    node_width: int = 190,
    node_height: int = 56,
    gap_x: int = 46,
    gap_y: int = 42,
) -> Dict[str, Tuple[int, int]]:
    """Posiciona os nós em camadas, sem sobreposição e sempre igual.

    As camadas vêm da distância em BFS até a entrada e descem: a entrada fica
    na primeira linha, quem ela alcança vem abaixo, e os nós inalcançáveis
    ficam na última linha, lado a lado na ordem do código.  Dentro de uma
    camada cada nó ocupa uma coluna, então dois nós nunca se sobrepõem.  O
    fluxo de cima para baixo foi escolhido porque o relatório mostra o desenho
    numa coluna estreita: uma cadeia longa demais na horizontal encolheria até
    o texto ficar ilegível.

    Args:
        graph: Grafo a posicionar.
        node_width: Largura de cada nó, em pixels.
        node_height: Altura de cada nó, em pixels.
        gap_x: Espaço horizontal entre as colunas, em pixels.
        gap_y: Espaço vertical entre as camadas, em pixels.

    Returns:
        ``id -> (x, y)`` com o canto superior esquerdo de cada nó.  As
        coordenadas já incluem a margem do desenho; um grafo vazio devolve
        ``{}``.
    """
    if not graph.nodes:
        return {}
    topo = _MARGEM + (_ALTURA_DO_LACO + 16 if _tem_laco(graph) else 0)
    posicoes: Dict[str, Tuple[int, int]] = {}
    for linha, camada in enumerate(_camadas(graph)):
        for coluna, nid in enumerate(camada):
            posicoes[nid] = (
                _MARGEM + coluna * (node_width + gap_x),
                int(topo + linha * (node_height + gap_y)),
            )
    return posicoes


def size_of(
    graph: Graph, positions: Optional[Dict[str, Tuple[int, int]]] = None
) -> Tuple[int, int]:
    """Tamanho do desenho, em pixels.

    A conta usa o tamanho padrão de nó (:data:`_LARGURA_NO` por
    :data:`_ALTURA_NO`); posições vindas de um :func:`layout` com outro tamanho
    de nó precisam ser medidas por fora.

    Args:
        graph: Grafo a medir.
        positions: Posições já calculadas por :func:`layout`; quando ``None``,
            esta função chama o próprio :func:`layout`.

    Returns:
        ``(largura, altura)``, contando a margem em volta; um grafo sem nós
        devolve o tamanho da moldura usada por :func:`to_svg`.
    """
    posicoes = layout(graph) if positions is None else positions
    ids = {no.id for no in graph.nodes}
    pontos = [ponto for nid, ponto in posicoes.items() if nid in ids]
    if not pontos:
        return (_LARGURA_VAZIA, _ALTURA_VAZIA)
    largura = max(x for x, _ in pontos) + _LARGURA_NO + _MARGEM
    altura = max(y for _, y in pontos) + _ALTURA_NO + _MARGEM
    return (largura, altura)


# ---------------------------------------------------------------------------
# Geometria do desenho
# ---------------------------------------------------------------------------


def _na_borda(
    centro: Tuple[float, float], alvo: Tuple[float, float], largura: float, altura: float
) -> Tuple[float, float]:
    """Ponto em que a reta centro->alvo cruza a borda do retângulo do nó.

    Args:
        centro: Centro do nó, em pixels.
        alvo: Ponto para onde a reta aponta, em pixels.
        largura: Largura do nó, em pixels.
        altura: Altura do nó, em pixels.

    Returns:
        O ponto de saída (ou de entrada) na borda do retângulo.
    """
    dx = alvo[0] - centro[0]
    dy = alvo[1] - centro[1]
    if not dx and not dy:
        return centro
    escalas = []
    if dx:
        escalas.append((largura / 2.0) / abs(dx))
    if dy:
        escalas.append((altura / 2.0) / abs(dy))
    escala = min(escalas)
    return (centro[0] + dx * escala, centro[1] + dy * escala)


def _deslocamento_da_aresta(indice: int, total: int, tem_reversa: bool) -> float:
    """Deslocamento perpendicular de uma aresta, para linhas não se colarem.

    Args:
        indice: Posição da aresta entre as de mesma origem e destino.
        total: Quantas arestas existem com essa mesma origem e destino.
        tem_reversa: Se existe também a aresta no sentido contrário.

    Returns:
        O deslocamento em pixels, positivo ou negativo.
    """
    deslocamento = (indice - (total - 1) / 2.0) * 12.0
    if tem_reversa:
        deslocamento += 6.0
    return deslocamento


def _deslocamentos(graph: Graph) -> List[float]:
    """Calcula o deslocamento perpendicular de cada aresta do grafo.

    Args:
        graph: Grafo a desenhar.

    Returns:
        Um deslocamento por aresta, na ordem do grafo; arestas repetidas (mesma
        origem e destino) e arestas de mão dupla saem paralelas, sem se colar.
    """
    chaves = [(a.source, a.target) for a in graph.edges]
    totais: Dict[Tuple[str, str], int] = {}
    for par in chaves:
        totais[par] = totais.get(par, 0) + 1
    existentes = set(chaves)
    vistos: Dict[Tuple[str, str], int] = {}
    deslocamentos: List[float] = []
    for par in chaves:
        indice = vistos.get(par, 0)
        vistos[par] = indice + 1
        deslocamentos.append(
            _deslocamento_da_aresta(indice, totais[par], (par[1], par[0]) in existentes)
        )
    return deslocamentos


def _caminho_da_aresta(
    origem: Tuple[int, int],
    destino: Tuple[int, int],
    deslocamento: float,
) -> Tuple[str, float, float]:
    """Monta o ``d`` de uma aresta e o ponto onde o rótulo deve ficar.

    Args:
        origem: Canto superior esquerdo do nó de origem.
        destino: Canto superior esquerdo do nó de destino.
        deslocamento: Deslocamento perpendicular, em pixels.

    Returns:
        ``(d, x, y)``: o caminho do SVG e o meio da linha, onde entra o
        rótulo.  Uma aresta de um nó para ele mesmo vira uma alça acima dele.
    """
    if origem == destino:
        centro_x = origem[0] + _LARGURA_NO / 2.0
        topo = float(origem[1])
        esquerda = centro_x - _LARGURA_NO * 0.28
        direita = centro_x + _LARGURA_NO * 0.28
        caminho = "M %s %s C %s %s, %s %s, %s %s" % (
            _numero(esquerda),
            _numero(topo),
            _numero(esquerda),
            _numero(topo - _ALTURA_DO_LACO),
            _numero(direita),
            _numero(topo - _ALTURA_DO_LACO),
            _numero(direita),
            _numero(topo),
        )
        return (caminho, centro_x, topo - _ALTURA_DO_LACO - 6)

    centro_origem = (origem[0] + _LARGURA_NO / 2.0, origem[1] + _ALTURA_NO / 2.0)
    centro_destino = (destino[0] + _LARGURA_NO / 2.0, destino[1] + _ALTURA_NO / 2.0)
    dx = centro_destino[0] - centro_origem[0]
    dy = centro_destino[1] - centro_origem[1]
    comprimento = math.hypot(dx, dy) or 1.0
    normal = (-dy / comprimento * deslocamento, dx / comprimento * deslocamento)
    origem_deslocada = (centro_origem[0] + normal[0], centro_origem[1] + normal[1])
    destino_deslocado = (centro_destino[0] + normal[0], centro_destino[1] + normal[1])
    inicio = _na_borda(origem_deslocada, destino_deslocado, _LARGURA_NO, _ALTURA_NO)
    fim = _na_borda(destino_deslocado, origem_deslocada, _LARGURA_NO, _ALTURA_NO)
    volta_x = inicio[0] - fim[0]
    volta_y = inicio[1] - fim[1]
    volta = math.hypot(volta_x, volta_y) or 1.0
    fim = (fim[0] + volta_x / volta * _FOLGA_SETA, fim[1] + volta_y / volta * _FOLGA_SETA)
    caminho = "M %s %s L %s %s" % (
        _numero(inicio[0]),
        _numero(inicio[1]),
        _numero(fim[0]),
        _numero(fim[1]),
    )
    return (caminho, (inicio[0] + fim[0]) / 2.0, (inicio[1] + fim[1]) / 2.0)


def _linhas_do_no(
    no: GraphNode, fonte: float, fonte_detalhe: float, largura: float
) -> Tuple[List[str], List[str]]:
    """Quebra o nome e o detalhe de um nó no que couber dentro da caixa.

    Args:
        no: Nó a desenhar.
        fonte: Tamanho da fonte do nome, em pixels.
        fonte_detalhe: Tamanho da fonte do detalhe, em pixels.
        largura: Largura útil da caixa, em pixels.

    Returns:
        Duas listas: as linhas do nome (até duas) e as do detalhe (até uma,
        vazia quando não existe detalhe).
    """
    rotulo = _quebrar(no.label, _caracteres_por_linha(largura, fonte), 2)
    detalhe = _quebrar(no.detail, _caracteres_por_linha(largura, fonte_detalhe), 1)
    return (rotulo, detalhe)


# ---------------------------------------------------------------------------
# SVG
# ---------------------------------------------------------------------------


def _svg_vazio(graph: Graph, cores: Dict[str, str]) -> str:
    """Desenha a moldura mostrada quando não há nada para desenhar.

    Args:
        graph: Grafo vazio.
        cores: Cores do tema escolhido.

    Returns:
        Um SVG mínimo, com a mensagem no meio.
    """
    fundo = cores.get("bg", "#0f1420")
    no = cores.get("node", "#1d2839")
    borda = cores.get("border", "#3a4a63")
    fraco = cores.get("dim", "#93a3ba")
    if graph.kind == "calls":
        mensagem = "nenhuma chamada para desenhar"
    else:
        mensagem = "sem código para desenhar"
    linhas = [
        '<svg xmlns="%s" width="%d" height="%d" viewBox="0 0 %d %d" role="img" '
        'aria-label="%s">'
        % (
            _NAMESPACE_SVG,
            _LARGURA_VAZIA,
            _ALTURA_VAZIA,
            _LARGURA_VAZIA,
            _ALTURA_VAZIA,
            escape(graph.title),
        ),
        "  <title>%s</title>" % escape(graph.title),
        '  <rect x="0" y="0" width="%d" height="%d" fill="%s"/>'
        % (_LARGURA_VAZIA, _ALTURA_VAZIA, fundo),
        '  <rect x="16" y="16" width="%d" height="%d" rx="10" fill="%s" stroke="%s" '
        'stroke-dasharray="7 6"/>' % (_LARGURA_VAZIA - 32, _ALTURA_VAZIA - 32, no, borda),
        '  <text x="%d" y="%d" text-anchor="middle" font-family="%s" font-size="13" '
        'fill="%s">%s</text>'
        % (_LARGURA_VAZIA // 2, _ALTURA_VAZIA // 2 + 5, _FONTE_FAMILIA, fraco, escape(mensagem)),
        "</svg>",
    ]
    return "\n".join(linhas) + "\n"


def to_svg(graph: Graph, *, theme: str = "dark") -> str:
    """Desenha o grafo como um SVG autocontido e determinístico.

    O desenho não tem ``script``, não usa ``href``, não busca fonte externa e
    não cita ``http``: pode ser colado dentro do HTML do relatório ou salvo
    como arquivo ``.svg`` e aberto no navegador.  Grafos com mais de 60 nós
    saem com fonte menor e rótulos mais curtos, para não virar um borrão — o
    conteúdo continua o mesmo, só mais apertado.

    Args:
        graph: Grafo devolvido por :func:`control_flow_graph` ou
            :func:`call_graph`.
        theme: ``dark`` ou ``light``; qualquer outro valor cai no ``dark``.

    Returns:
        O documento SVG completo, em texto.
    """
    nome_do_tema = theme if theme in THEME else "dark"
    cores = THEME[nome_do_tema]
    if not graph.nodes:
        return _svg_vazio(graph, cores)

    fundo = cores.get("bg", "#0f1420")
    texto = cores.get("text", "#e8eef8")
    borda = cores.get("border", "#3a4a63")
    fraco = cores.get("dim", "#93a3ba")

    grande = len(graph.nodes) > _LIMITE_GRANDE
    fonte = _FONTE_GRANDE if grande else _FONTE
    fonte_detalhe = _FONTE_DETALHE_GRANDE if grande else _FONTE_DETALHE
    fonte_aresta = _FONTE_ARESTA_GRANDE if grande else _FONTE_ARESTA
    limite_aresta = _ROTULO_ARESTA_GRANDE if grande else _MAX_ROTULO

    posicoes = layout(graph)
    largura, altura = size_of(graph, posicoes)

    # Uma seta por cor usada, na ordem em que as arestas aparecem.
    setas: List[Tuple[str, str]] = []
    for aresta in graph.edges:
        chave = _COR_DA_ARESTA.get(aresta.kind, "edge")
        cor = cores.get(chave, "#8296b0")
        if all(cor != existente for _, existente in setas):
            setas.append((chave, cor))
    if not setas:
        setas.append(("edge", cores.get("edge", "#8296b0")))

    partes: List[str] = [
        '<svg xmlns="%s" width="%d" height="%d" viewBox="0 0 %d %d" role="img" '
        'aria-label="%s">'
        % (_NAMESPACE_SVG, largura, altura, largura, altura, escape(graph.title)),
        "  <title>%s</title>" % escape(graph.title),
        "  <defs>",
    ]
    for chave, cor in setas:
        partes.append(
            '    <marker id="%s" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
            'markerHeight="7" orient="auto" markerUnits="strokeWidth">'
            % (_ID_SETA % (graph.kind, nome_do_tema, chave))
        )
        partes.append('      <path d="M 0 0 L 10 5 L 0 10 z" fill="%s"/>' % cor)
        partes.append("    </marker>")
    partes.append("  </defs>")
    partes.append(
        '  <rect x="0" y="0" width="%d" height="%d" fill="%s"/>' % (largura, altura, fundo)
    )

    # As arestas saem antes dos nós, para que a linha não invada a caixa.
    afastamentos = _deslocamentos(graph)
    partes.append('  <g class="arestas">')
    for indice, aresta in enumerate(graph.edges):
        origem = posicoes.get(aresta.source)
        destino = posicoes.get(aresta.target)
        if origem is None or destino is None:
            continue
        caminho, _, _ = _caminho_da_aresta(origem, destino, afastamentos[indice])
        cor_aresta = cores.get(_COR_DA_ARESTA.get(aresta.kind, "edge"), "#8296b0")
        partes.append(
            '    <path d="%s" fill="none" stroke="%s" stroke-width="1.6" '
            'stroke-linecap="round" marker-end="url(#%s)"/>'
            % (
                caminho,
                cor_aresta,
                _ID_SETA % (graph.kind, nome_do_tema, _COR_DA_ARESTA.get(aresta.kind, "edge")),
            )
        )
    partes.append("  </g>")

    partes.append('  <g class="nos">')
    for no in graph.nodes:
        ponto = posicoes.get(no.id)
        if ponto is None:
            continue
        x, y = float(ponto[0]), float(ponto[1])
        cor = cores.get(_COR_DO_NO.get(no.kind, "node"), "#1d2839")
        rotulo, detalhe = _linhas_do_no(no, fonte, fonte_detalhe, float(_LARGURA_NO))
        altura_rotulo = fonte + 3.0
        altura_detalhe = fonte_detalhe + 2.5
        total = len(rotulo) * altura_rotulo + len(detalhe) * altura_detalhe
        base = y + (_ALTURA_NO - total) / 2.0 + fonte * 0.85
        partes.append('    <g class="no no-%s">' % no.kind)
        partes.append(
            "      <title>%s</title>" % escape(no.label + (": " + no.detail if no.detail else ""))
        )
        partes.append(
            '      <rect x="%s" y="%s" width="%d" height="%d" rx="%d" fill="%s" '
            'stroke="%s" stroke-width="1.5"/>'
            % (_numero(x), _numero(y), _LARGURA_NO, _ALTURA_NO, _RAIO, cor, borda)
        )
        for indice, linha in enumerate(rotulo):
            partes.append(
                '      <text x="%s" y="%s" text-anchor="middle" font-family="%s" '
                'font-size="%s" font-weight="600" fill="%s">%s</text>'
                % (
                    _numero(x + _LARGURA_NO / 2.0),
                    _numero(base + indice * altura_rotulo),
                    _FONTE_FAMILIA,
                    _numero(fonte),
                    texto,
                    escape(linha),
                )
            )
        for indice, linha in enumerate(detalhe):
            partes.append(
                '      <text x="%s" y="%s" text-anchor="middle" font-family="%s" '
                'font-size="%s" fill="%s">%s</text>'
                % (
                    _numero(x + _LARGURA_NO / 2.0),
                    _numero(base + len(rotulo) * altura_rotulo + indice * altura_detalhe),
                    _FONTE_FAMILIA,
                    _numero(fonte_detalhe),
                    fraco,
                    escape(linha),
                )
            )
        partes.append("    </g>")
    partes.append("  </g>")

    # Os rótulos ficam por cima de tudo, com fundo semitransparente.
    partes.append('  <g class="rotulos">')
    for indice, aresta in enumerate(graph.edges):
        origem = posicoes.get(aresta.source)
        destino = posicoes.get(aresta.target)
        if origem is None or destino is None or not aresta.label:
            continue
        _, meio_x, meio_y = _caminho_da_aresta(origem, destino, afastamentos[indice])
        linha = _encurtar(aresta.label, limite_aresta)
        cor_aresta = cores.get(_COR_DA_ARESTA.get(aresta.kind, "edge"), "#8296b0")
        largura_texto = _largura_do_texto(linha, fonte_aresta)
        partes.append(
            '    <rect x="%s" y="%s" width="%s" height="%s" rx="4" fill="%s" '
            'fill-opacity="0.82"/>'
            % (
                _numero(meio_x - largura_texto / 2.0 - 4),
                _numero(meio_y - fonte_aresta),
                _numero(largura_texto + 8),
                _numero(fonte_aresta + 4),
                fundo,
            )
        )
        partes.append(
            '    <text x="%s" y="%s" text-anchor="middle" font-family="%s" '
            'font-size="%s" fill="%s">%s</text>'
            % (
                _numero(meio_x),
                _numero(meio_y),
                _FONTE_FAMILIA,
                _numero(fonte_aresta),
                cor_aresta,
                escape(linha),
            )
        )
    partes.append("  </g>")
    partes.append("</svg>")
    return "\n".join(partes) + "\n"


# ---------------------------------------------------------------------------
# DOT e Mermaid
# ---------------------------------------------------------------------------


def _escapar_dot(texto: str) -> str:
    """Escapa um texto para caber entre aspas no DOT.

    Args:
        texto: Texto livre.

    Returns:
        O texto com barras e aspas escapadas e quebras de linha em ``\\n``.
    """
    return texto.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _rotulo_do_no(no: GraphNode) -> str:
    """Rótulo do nó nos formatos que aceitam quebra de linha.

    Args:
        no: Nó a rotular.

    Returns:
        O nome e, quando existe, o detalhe na linha de baixo.
    """
    if no.detail:
        return no.label + "\n" + no.detail
    return no.label


def to_dot(graph: Graph) -> str:
    """Escreve o grafo em DOT, o formato do Graphviz.

    Args:
        graph: Grafo a escrever.

    Returns:
        Um ``digraph`` válido, com uma cor por tipo de nó e de aresta.
    """
    nome = "cfg" if graph.kind == "cfg" else "calls"
    linhas = [
        "digraph %s {" % nome,
        "  rankdir=TB;",
        '  label="%s";' % _escapar_dot(graph.title),
        '  labelloc="t";',
        '  fontname="Helvetica";',
        '  node [shape=box, style=filled, fontname="Helvetica", fontsize=11];',
        '  edge [fontname="Helvetica", fontsize=9];',
    ]
    cores = THEME["dark"]
    if not graph.nodes:
        linhas.append("  // sem nada para desenhar")
    for no in graph.nodes:
        linhas.append(
            '  "%s" [label="%s", fillcolor="%s", color="%s", fontcolor="%s"];'
            % (
                _escapar_dot(no.id),
                _escapar_dot(_rotulo_do_no(no)),
                cores.get(_COR_DO_NO.get(no.kind, "node"), "#1d2839"),
                cores.get("border", "#3a4a63"),
                cores.get("text", "#e8eef8"),
            )
        )
    for aresta in graph.edges:
        atributos = ['color="%s"' % cores.get(_COR_DA_ARESTA.get(aresta.kind, "edge"), "#8296b0")]
        if aresta.label:
            atributos.append('label="%s"' % _escapar_dot(aresta.label))
        linhas.append(
            '  "%s" -> "%s" [%s];'
            % (_escapar_dot(aresta.source), _escapar_dot(aresta.target), ", ".join(atributos))
        )
    linhas.append("}")
    return "\n".join(linhas) + "\n"


def _escapar_mermaid(texto: str) -> str:
    """Escapa um texto para caber entre aspas no Mermaid.

    Args:
        texto: Texto livre.

    Returns:
        O texto com aspas, ``&``, ``<`` e ``>`` trocados por entidades que o
        Mermaid entende.
    """
    return (
        texto.replace("&", "#amp;").replace('"', "#quot;").replace("<", "#lt;").replace(">", "#gt;")
    )


def _id_mermaid(nid: str, usados: Dict[str, int]) -> str:
    """Transforma o ``id`` do nó num identificador aceito pelo Mermaid.

    Args:
        nid: ``id`` original, como ``b0`` ou ``f:soma``.
        usados: Contador de ids já usados, para desempatar colisões.

    Returns:
        Um identificador só com letras, números e ``_``, sem repetição.
    """
    base = re.sub(r"[^0-9A-Za-z_]", "_", nid)
    if not base or base[0].isdigit():
        base = "n_" + base
    usados[base] = usados.get(base, 0) + 1
    if usados[base] > 1:
        base = "%s_%d" % (base, usados[base])
    return base


def to_mermaid(graph: Graph) -> str:
    """Escreve o grafo como um ``flowchart`` do Mermaid.

    Args:
        graph: Grafo a escrever.

    Returns:
        O diagrama em texto, com os rótulos entre ``["..."]`` e a contagem de
        chamadas nas arestas.
    """
    linhas = ["flowchart TD"]
    if not graph.nodes:
        if graph.kind == "calls":
            mensagem = "nenhuma chamada para desenhar"
        else:
            mensagem = "sem código para desenhar"
        linhas.append('    vazio["%s"]' % _escapar_mermaid(mensagem))
        return "\n".join(linhas) + "\n"

    usados: Dict[str, int] = {}
    identificadores: Dict[str, str] = {}
    for no in graph.nodes:
        identificadores[no.id] = _id_mermaid(no.id, usados)
        rotulo = _escapar_mermaid(_rotulo_do_no(no)).replace("\n", "<br/>")
        linhas.append('    %s["%s"]' % (identificadores[no.id], rotulo))
    for aresta in graph.edges:
        origem = identificadores.get(aresta.source)
        destino = identificadores.get(aresta.target)
        if origem is None or destino is None:
            continue
        if aresta.label:
            linhas.append('    %s -->|"%s"| %s' % (origem, _escapar_mermaid(aresta.label), destino))
        else:
            linhas.append("    %s --> %s" % (origem, destino))
    return "\n".join(linhas) + "\n"
