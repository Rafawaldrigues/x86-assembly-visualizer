"""Relatório: transforma a análise em algo que se pode olhar, salvar e publicar.

Este módulo junta tudo o que as outras camadas produzem — metadados do arquivo,
plataforma, instruções explicadas, validação, comportamentos com MITRE ATT&CK,
indicadores, grafos de fluxo e de chamadas, e a execução na máquina virtual —
num único objeto (:class:`ReportData`) e sabe desenhar esse objeto em quatro
formatos:

* **HTML** — um arquivo só, sem rede: CSS, JavaScript e os grafos em SVG vão
  embutidos, então o relatório abre offline, no navegador, sem CDN e sem
  servidor. É o formato para olhar e compartilhar;
* **Markdown** — texto para colar em issue, pull request ou blog, com o grafo em
  Mermaid que o GitHub desenha sozinho;
* **JSON** — os dados crus, com o esquema ``asmx-report/1``, para automação;
* **DOT/Mermaid/SVG** — os grafos isolados, para quem quer editar no Graphviz.

Nada aqui depende de biblioteca externa, e nenhum formato faz requisição de
rede: o relatório é do usuário, não de um serviço.

Example:
    >>> from asmx.report import collect, render_markdown
    >>> dados = collect("global _start\\nsection .text\\n_start:\\n mov rax, 60\\n syscall")
    >>> dados.risk["level"] in ("baixo", "medio", "alto", "critico")
    True
    >>> "ASM X" in render_markdown(dados)
    True
"""

from __future__ import annotations

import datetime
import html
import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import __version__
from .analyzer import Analysis, analyze
from .behavior import Behavior, classify, severity_rank, techniques, to_dicts as behaviors_to_dicts
from .cfg import call_graph, control_flow_graph, to_dot, to_mermaid, to_svg
from .emulator import Machine, hexs, to_signed
from .errors import ProjectError, SourceWriteError
from .iocs import extract as extract_iocs
from .iocs import from_memory as iocs_from_memory
from .iocs import to_dicts as iocs_to_dicts
from .isa import LINUX_SYSCALLS
from .linter import ERRO, INFO, ALERTA, Problem, summary as problem_summary, validate
from .logging_setup import get_logger, log_event
from .source import SourceFile, fingerprint

logger = get_logger(__name__)

__all__ = [
    "REPORT_SCHEMA",
    "FORMATS",
    "ReportData",
    "collect",
    "risk_assessment",
    "executive_summary",
    "render_html",
    "render_markdown",
    "render_json",
    "render_dot",
    "render_svg",
    "render_index",
    "write_report",
    "guess_format",
]

#: Esquema do relatório em JSON, para quem for consumir os dados.
REPORT_SCHEMA = "asmx-report/1"

#: Formatos aceitos por :func:`write_report`.
FORMATS: Tuple[str, ...] = ("html", "md", "json", "dot", "svg", "mermaid")

#: Quantos passos da execução entram na linha do tempo do relatório.
TIMELINE_LIMIT = 400

#: Pesos usados no cálculo de risco.
PROBLEM_WEIGHTS = {ERRO: 25, ALERTA: 8, INFO: 2}
BEHAVIOR_WEIGHTS = {"alto": 18, "medio": 9, "baixo": 3}

#: Cor e emoji de cada nível de risco.
RISK_STYLE = {
    "baixo": ("#5FD4A8", "🟢", "Nada aqui indica comportamento perigoso."),
    "medio": ("#E3A44B", "🟡", "Há sinais que merecem leitura atenta antes de rodar."),
    "alto": ("#F08A5D", "🟠", "O conjunto dos sinais pede cuidado: revise antes de montar."),
    "critico": ("#EF7D9D", "🔴", "Muitos sinais fortes ao mesmo tempo: trate como hostil."),
}


def _now() -> str:
    """Devolve o instante da geração em ISO-8601 local.

    Returns:
        Texto como ``2026-09-21T19:40:12``.
    """
    return datetime.datetime.now().replace(microsecond=0).isoformat()


def guess_format(path: str) -> str:
    """Descobre o formato do relatório pela extensão do arquivo.

    Args:
        path: Caminho de saída.

    Returns:
        Um nome de :data:`FORMATS`; ``"html"`` quando a extensão é desconhecida.
    """
    extensao = os.path.splitext(path)[1].lstrip(".").lower()
    return extensao if extensao in FORMATS else "html"


@dataclass
class ReportData:
    """Tudo o que o relatório mostra, já em tipos simples.

    Attributes:
        schema: Identificador do esquema (``asmx-report/1``).
        generated_at: Instante da geração.
        version: Versão do ASM X que gerou o relatório.
        command: Linha de comando usada, quando houver.
        source: Metadados do arquivo (nome, hashes, tamanho, codificação).
        platform: Sistema, bits, confiança da detecção, ABI e evidências.
        dialect: Dialeto detectado pelo parser (``intel``, ``masm``, ``att``).
        stats: Contagens do analisador (instruções, blocos, syscalls...).
        risk: Nível de risco, cor, emoji e descrição.
        summary: Texto do resumo executivo.
        problems: Problemas de validação, já como dicionários.
        behaviors: Comportamentos detectados.
        techniques: Técnicas MITRE ATT&CK agregadas.
        iocs: Indicadores agrupados por tipo.
        instructions: Instruções com a explicação de cada uma.
        blocks: Blocos básicos com "vem de" e "vai para".
        cfg: Grafo de fluxo de controle (grafo, SVG, DOT e Mermaid).
        calls: Grafo de chamadas (mesma estrutura).
        syscalls: Syscalls encontradas, agregadas por nome.
        apis: APIs externas chamadas.
        execution: Resultado da execução na máquina virtual, quando pedido.
        timeline: Passos da execução, na ordem.
    """

    schema: str = REPORT_SCHEMA
    generated_at: str = field(default_factory=_now)
    version: str = __version__
    command: str = ""
    source: Dict[str, Any] = field(default_factory=dict)
    platform: Dict[str, Any] = field(default_factory=dict)
    dialect: str = "intel"
    stats: Dict[str, Any] = field(default_factory=dict)
    risk: Dict[str, Any] = field(default_factory=dict)
    summary: str = ""
    problems: List[Dict[str, Any]] = field(default_factory=list)
    behaviors: List[Dict[str, Any]] = field(default_factory=list)
    techniques: List[Dict[str, Any]] = field(default_factory=list)
    iocs: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    instructions: List[Dict[str, Any]] = field(default_factory=list)
    blocks: List[Dict[str, Any]] = field(default_factory=list)
    cfg: Dict[str, Any] = field(default_factory=dict)
    calls: Dict[str, Any] = field(default_factory=dict)
    syscalls: List[Dict[str, Any]] = field(default_factory=list)
    apis: List[str] = field(default_factory=list)
    execution: Optional[Dict[str, Any]] = None
    timeline: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self, *, include_svg: bool = False) -> Dict[str, Any]:
        """Converte o relatório em dicionário pronto para JSON.

        Args:
            include_svg: Quando ``True``, mantém o SVG dos grafos (útil para
                gerar um HTML a partir do JSON; deixa o arquivo bem maior).

        Returns:
            Dicionário com o esquema, os metadados e todas as seções.
        """
        dados: Dict[str, Any] = {
            "schema": self.schema,
            "generated_at": self.generated_at,
            "version": self.version,
            "command": self.command,
            "source": self.source,
            "platform": self.platform,
            "dialect": self.dialect,
            "stats": self.stats,
            "risk": self.risk,
            "summary": self.summary,
            "problems": self.problems,
            "behaviors": self.behaviors,
            "techniques": self.techniques,
            "iocs": self.iocs,
            "instructions": self.instructions,
            "blocks": self.blocks,
            "cfg": {k: v for k, v in self.cfg.items() if include_svg or k != "svg"},
            "calls": {k: v for k, v in self.calls.items() if include_svg or k != "svg"},
            "syscalls": self.syscalls,
            "apis": self.apis,
            "execution": self.execution,
            "timeline": self.timeline,
        }
        return dados

    @property
    def counts(self) -> Dict[str, int]:
        """Contagens usadas nos cartões do topo do relatório.

        Returns:
            Dicionário com instruções, blocos, chamadas, syscalls, problemas,
            comportamentos, indicadores e strings.
        """
        total_iocs = sum(len(lista) for lista in self.iocs.values())
        return {
            "instructions": int(self.stats.get("instructions", 0)),
            "blocks": int(self.stats.get("blocks", 0)),
            "calls": int(self.stats.get("calls", 0)),
            "syscalls": int(self.stats.get("syscalls", 0)),
            "problems": len(self.problems),
            "behaviors": len(self.behaviors),
            "iocs": total_iocs,
            "strings": len(self.iocs.get("string", [])),
        }


# --------------------------------------------------------------- coleta ----
def risk_assessment(
    problems: Sequence[Problem],
    behaviors: Sequence[Behavior],
    stats: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Calcula o nível de risco a partir dos problemas e dos comportamentos.

    A conta é simples e explicável de propósito: cada erro de validação pesa 25,
    cada alerta 8 e cada informação 2; cada comportamento de severidade alta
    pesa 18, média 9 e baixa 3. O total é limitado a 100.

    Args:
        problems: Problemas devolvidos pelo validador.
        behaviors: Comportamentos classificados.
        stats: Estatísticas do analisador (usadas só para citar o tamanho).

    Returns:
        Dicionário com ``score``, ``level``, ``color``, ``emoji``,
        ``description`` e ``reasons`` (o que mais pesou).

    Example:
        >>> risk_assessment([], [])["level"]
        'baixo'
    """
    score = 0
    razoes: List[str] = []
    for problema in problems:
        score += PROBLEM_WEIGHTS.get(problema.severity, 0)
    if problems:
        erros = sum(1 for p in problems if p.severity == ERRO)
        alertas = sum(1 for p in problems if p.severity == ALERTA)
        if erros:
            razoes.append("%d erro(s) de validação" % erros)
        if alertas:
            razoes.append("%d alerta(s) de validação" % alertas)
    for comportamento in behaviors:
        score += BEHAVIOR_WEIGHTS.get(comportamento.severity, 0)
    for severidade in ("alto", "medio", "baixo"):
        nomes = [b.label for b in behaviors if b.severity == severidade]
        if nomes:
            razoes.append("%s: %s" % (severidade, ", ".join(sorted(nomes))))
    score = max(0, min(100, score))
    if score >= 70:
        nivel = "critico"
    elif score >= 40:
        nivel = "alto"
    elif score >= 15:
        nivel = "medio"
    else:
        nivel = "baixo"
    cor, emoji, descricao = RISK_STYLE[nivel]
    return {
        "score": score,
        "level": nivel,
        "color": cor,
        "emoji": emoji,
        "description": descricao,
        "reasons": razoes,
        "instructions": int((stats or {}).get("instructions", 0)),
    }


def executive_summary(data: ReportData) -> str:
    """Escreve o parágrafo de resumo executivo do relatório.

    Args:
        data: Relatório já preenchido (menos o próprio resumo).

    Returns:
        Duas ou três frases em português dizendo o que o programa é, o que faz
        e o que merece atenção.
    """
    fonte = data.source.get("name", "programa")
    plataforma = data.platform.get("os", "indefinido")
    bits = data.platform.get("bits", 64)
    abi = data.platform.get("abi") or "ABI indefinida"
    contagens = data.counts
    partes = [
        "%s tem %d instruções em %d bloco(s), escrito para %s de %d bits (%s)."
        % (fonte, contagens["instructions"], contagens["blocks"], plataforma, bits, abi)
    ]
    if contagens["behaviors"]:
        nomes = ", ".join(b["label"] for b in data.behaviors[:4])
        partes.append("Comportamentos observados: %s." % nomes)
    else:
        partes.append("Nenhum comportamento relevante foi identificado.")
    if contagens["problems"]:
        partes.append(
            "A validação apontou %s."
            % problem_summary(
                [
                    Problem(p["line"], p["severity"], p["code"], p["message"], p.get("hint", ""))
                    for p in data.problems
                ]
            )
        )
    else:
        partes.append("A validação não encontrou problema nenhum.")
    if contagens["iocs"]:
        partes.append("Há %d indicador(es) no texto do programa." % contagens["iocs"])
    if data.execution is not None:
        saida = (data.execution.get("output") or "").strip()
        resumo_exec = "A execução simulada terminou com código %s" % data.execution.get("exit_code")
        if saida:
            resumo_exec += " e produziu %d byte(s) de saída" % len(
                data.execution.get("output") or ""
            )
        partes.append(resumo_exec + ".")
    return " ".join(partes)


def _syscall_table(instrs: Sequence[Any]) -> List[Dict[str, Any]]:
    """Agrega as syscalls do programa por nome.

    Args:
        instrs: Instruções analisadas.

    Returns:
        Lista de dicionários com ``name``, ``number``, ``count`` e ``lines``.
    """
    agregado: Dict[str, Dict[str, Any]] = {}
    for ins in instrs:
        if ins.mnemonic not in ("syscall", "int"):
            continue
        nome = ins.sem.syscall_name if ins.sem and ins.sem.syscall_name else None
        if not nome:
            nome = "syscall desconhecida"
        registro = agregado.setdefault(
            nome, {"name": nome, "number": None, "count": 0, "lines": []}
        )
        registro["count"] += 1
        registro["lines"].append(ins.n)
        if registro["number"] is None and ins.sem and ins.sem.detail:
            for numero, ficha in LINUX_SYSCALLS.items():
                if ficha[0] == nome:
                    registro["number"] = numero
                    break
    return sorted(agregado.values(), key=lambda r: (-r["count"], r["name"]))


def _external_apis(instrs: Sequence[Any], label_at: Dict[str, int]) -> List[str]:
    """Lista as chamadas que apontam para fora do arquivo (APIs e libc).

    Args:
        instrs: Instruções analisadas.
        label_at: Índice dos rótulos definidos no arquivo.

    Returns:
        Nomes únicos, em ordem alfabética.
    """
    nomes = set()
    for ins in instrs:
        if ins.mnemonic == "call" and ins.operands:
            alvo = ins.operands[0].symbol or ins.operands[0].text
            if alvo and alvo not in label_at:
                nomes.add(str(alvo))
    return sorted(nomes)


def _blocks_table(analysis: Analysis) -> List[Dict[str, Any]]:
    """Resume os blocos básicos para o relatório.

    Args:
        analysis: Análise do programa.

    Returns:
        Lista de dicionários com nome, função, linhas, contagens e vizinhos.
    """
    linhas: List[Dict[str, Any]] = []
    for bloco in analysis.blocks:
        if not bloco.instrs:
            continue
        linhas.append(
            {
                "id": bloco.id,
                "name": bloco.name,
                "func": bloco.func,
                "lines": [bloco.instrs[0].n, bloco.instrs[-1].n],
                "instructions": len(bloco.instrs),
                "comes_from": [
                    analysis.blocks[e.target].name
                    for e in bloco.pred
                    if e.target < len(analysis.blocks)
                ],
                "goes_to": [
                    analysis.blocks[e.target].name
                    for e in bloco.succ
                    if e.target < len(analysis.blocks)
                ],
                "calls": list(bloco.calls),
                "exit": bloco.exit,
            }
        )
    return linhas


def _execution_dict(machine: Machine) -> Dict[str, Any]:
    """Resume o resultado da execução na máquina virtual.

    Args:
        machine: Máquina já executada.

    Returns:
        Dicionário com saída, código de saída, passos, flags, registradores e
        problemas detectados durante a execução.
    """
    return {
        "output": machine.output,
        "exit_code": machine.exit_code,
        "steps": machine.steps,
        "halted": machine.halted,
        "timed_out": machine.timed_out,
        "issues": list(machine.issues),
        "flags": dict(machine.flags),
        "registers": {chave: hexs(valor) for chave, valor in machine.regs.items() if valor},
        "registers_decimal": {
            chave: to_signed(valor) for chave, valor in machine.regs.items() if valor
        },
    }


#: Nomes que podem aparecer no início de uma anotação de syscall ("write: ...").
_SYSCALL_WORDS = frozenset(ficha[0] for ficha in LINUX_SYSCALLS.values()) | {"syscall"}


def _timeline(machine: Machine, limit: int = TIMELINE_LIMIT) -> List[Dict[str, Any]]:
    """Monta a linha do tempo da execução a partir do histórico da máquina.

    Args:
        machine: Máquina já executada.
        limit: Quantidade máxima de passos incluídos.

    Returns:
        Lista de dicionários com ``step``, ``line``, ``text``, ``note`` e
        ``syscall`` (nome da syscall, quando o passo for uma).
    """
    passos = machine.trace[-limit:] if limit else machine.trace
    linha_do_tempo: List[Dict[str, Any]] = []
    for indice, passo in enumerate(passos):
        syscall = None
        if ":" in passo.note:
            possivel = passo.note.split(":", 1)[0].strip()
            if possivel in _SYSCALL_WORDS:
                syscall = possivel
        linha_do_tempo.append(
            {
                "step": indice,
                "line": passo.line,
                "text": passo.text,
                "note": passo.note,
                "syscall": syscall,
                "issue": passo.issue,
            }
        )
    return linha_do_tempo


def _merge_iocs(
    base: Dict[str, List[Dict[str, Any]]], extra: Dict[str, List[Dict[str, Any]]]
) -> Dict[str, List[Dict[str, Any]]]:
    """Junta indicadores de duas origens sem repetir valor.

    A memória da máquina virtual revela strings que só existem em tempo de
    execução (bytes montados por ``times``/``dup``, por exemplo); elas entram
    junto com as do texto, marcadas com a linha 0.

    Args:
        base: Indicadores extraídos do código fonte.
        extra: Indicadores extraídos da memória durante a execução.

    Returns:
        Novo dicionário ``tipo -> lista`` sem valores repetidos.
    """
    resultado: Dict[str, List[Dict[str, Any]]] = {tipo: list(lista) for tipo, lista in base.items()}
    for tipo, lista in extra.items():
        destino = resultado.setdefault(tipo, [])
        vistos = {item["value"] for item in destino}
        for item in lista:
            if item["value"] not in vistos:
                destino.append(item)
                vistos.add(item["value"])
    return resultado


def collect(
    text: str,
    *,
    source: Optional[SourceFile] = None,
    emulate: bool = True,
    limit: int = 200000,
    timeout: Optional[float] = None,
    stdin: str = "",
    entry: Optional[str] = None,
    command: str = "",
) -> ReportData:
    """Junta a análise completa de um código num relatório.

    Args:
        text: Código fonte em assembly.
        source: Metadados do arquivo lido (nome, hashes, tamanho). Sem ele, o
            relatório usa um nome genérico e calcula a impressão digital.
        emulate: Se deve executar o programa na máquina virtual e incluir a
            seção de execução com a linha do tempo.
        limit: Limite de instruções da execução simulada.
        timeout: Tempo máximo de parede da execução, em segundos.
        stdin: Entrada simulada entregue à syscall ``read``.
        entry: Rótulo onde a execução começa (``None`` = ponto de entrada).
        command: Linha de comando que gerou o relatório, para o rodapé.

    Returns:
        O :class:`ReportData` pronto para ser renderizado.

    Raises:
        ProjectError: Se ``entry`` aponta para um rótulo que não existe.

    Example:
        >>> dados = collect("nop")
        >>> dados.counts["instructions"]
        1
    """
    analysis = analyze(text)
    problemas = validate(analysis)
    comportamentos = classify(analysis, problemas)
    iocs = extract_iocs(text, include_comments=False)

    if entry and entry not in analysis.label_at:
        raise ProjectError("rótulo não encontrado para começar a execução: %s" % entry)

    dados_fonte: Dict[str, Any] = (
        source.to_dict()
        if source is not None
        else {
            "name": "programa.asm",
            "path": "",
            "size": len(text.encode("utf-8")),
            "lines": text.count("\n") + (0 if text.endswith("\n") or not text else 1),
            "encoding": "utf-8",
            "sha256": "",
            "fingerprint": fingerprint(text),
        }
    )

    grafo_cfg = control_flow_graph(analysis)
    grafo_chamadas = call_graph(analysis)

    data = ReportData(
        command=command,
        source=dados_fonte,
        platform={
            "os": analysis.platform.os,
            "bits": analysis.platform.bits,
            "confidence": analysis.platform.confidence,
            "abi": analysis.platform.abi.get("name"),
            "abi_notes": analysis.platform.abi.get("notes"),
            "arg_regs": list(analysis.platform.abi.get("args") or []),
            "preserved": list(analysis.platform.abi.get("preserved") or []),
            "evidence": {
                chave: list(valores) for chave, valores in analysis.platform.evidence.items()
            },
        },
        dialect=analysis.program.flavor,
        stats=dict(analysis.stats),
        problems=[p.to_dict() for p in problemas],
        behaviors=behaviors_to_dicts(comportamentos),
        techniques=techniques(comportamentos),
        iocs=iocs_to_dicts(iocs),
        instructions=[
            {
                "line": ins.n,
                "text": ins.text,
                "mnemonic": ins.mnemonic,
                "label": ins.sem.label if ins.sem else "",
                "detail": ins.sem.detail if ins.sem else "",
                "tag": ins.sem.tag if ins.sem else "",
                "func": ins.func,
                "section": ins.section,
                "block": ins.block,
            }
            for ins in analysis.instrs
        ],
        blocks=_blocks_table(analysis),
        cfg={
            "graph": grafo_cfg.to_dict(),
            "svg": to_svg(grafo_cfg),
            "dot": to_dot(grafo_cfg),
            "mermaid": to_mermaid(grafo_cfg),
        },
        calls={
            "graph": grafo_chamadas.to_dict(),
            "svg": to_svg(grafo_chamadas),
            "dot": to_dot(grafo_chamadas),
            "mermaid": to_mermaid(grafo_chamadas),
        },
        syscalls=_syscall_table(analysis.instrs),
        apis=_external_apis(analysis.instrs, analysis.label_at),
    )
    data.risk = risk_assessment(problemas, comportamentos, analysis.stats)

    if emulate:
        maquina = Machine(analysis, stdin=stdin, entry=entry)
        passos = maquina.run(limit=limit, timeout=timeout)
        data.execution = _execution_dict(maquina)
        data.execution["limit"] = limit
        data.execution["steps_returned"] = passos
        data.timeline = _timeline(maquina)
        data.execution["timeline_truncated"] = len(maquina.trace) > len(data.timeline)
        da_memoria = iocs_from_memory(maquina, min_length=6)
        if da_memoria:
            data.iocs = _merge_iocs(data.iocs, iocs_to_dicts(da_memoria))

    data.summary = executive_summary(data)
    log_event(
        logger,
        "report_collected",
        level=10,
        name=data.source.get("name"),
        instructions=data.counts["instructions"],
        behaviors=data.counts["behaviors"],
        iocs=data.counts["iocs"],
        risk=data.risk.get("level"),
        emulated=data.execution is not None,
    )
    return data


# ------------------------------------------------------------------ json ----
def render_json(data: ReportData, *, indent: int = 2, include_svg: bool = False) -> str:
    """Serializa o relatório em JSON.

    Args:
        data: Relatório a serializar.
        indent: Indentação do JSON.
        include_svg: Se o SVG dos grafos entra no JSON.

    Returns:
        Texto JSON terminado em quebra de linha.
    """
    return (
        json.dumps(
            data.to_dict(include_svg=include_svg), ensure_ascii=False, indent=indent, default=str
        )
        + "\n"
    )


# -------------------------------------------------------------- markdown ----
def _md_table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    """Monta uma tabela Markdown.

    Args:
        headers: Cabeçalhos das colunas.
        rows: Linhas já em texto.

    Returns:
        Bloco de tabela Markdown; string vazia quando não há linhas.
    """
    if not rows:
        return ""
    linhas = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    for linha in rows:
        linhas.append(
            "| " + " | ".join(str(c).replace("|", "\\|").replace("\n", " ") for c in linha) + " |"
        )
    return "\n".join(linhas)


def render_markdown(data: ReportData) -> str:
    """Desenha o relatório em Markdown, pronto para issue, PR ou blog.

    Args:
        data: Relatório a renderizar.

    Returns:
        Texto Markdown; o grafo entra como bloco Mermaid, que o GitHub desenha.
    """
    fonte = data.source
    contagens = data.counts
    partes: List[str] = []
    partes.append("# ASM X — análise de `%s`\n" % fonte.get("name", "programa"))
    partes.append("> %s\n" % data.summary)
    partes.append(
        "**Risco:** %s %s (%d/100) — %s\n"
        % (
            data.risk.get("emoji", ""),
            str(data.risk.get("level", "")).upper(),
            int(data.risk.get("score", 0)),
            data.risk.get("description", ""),
        )
    )

    partes.append("## Metadados\n")
    partes.append(
        _md_table(
            ["campo", "valor"],
            [
                ["arquivo", fonte.get("name", "")],
                ["tamanho", "%s bytes" % fonte.get("size", 0)],
                ["linhas", fonte.get("lines", 0)],
                ["codificação", fonte.get("encoding", "")],
                ["sha256", fonte.get("sha256", "") or "(não calculado)"],
                ["impressão digital", fonte.get("fingerprint", "")],
                ["dialeto", data.dialect],
                [
                    "plataforma",
                    "%s · %d bits · %d%% de confiança"
                    % (
                        data.platform.get("os"),
                        data.platform.get("bits", 64),
                        data.platform.get("confidence", 0),
                    ),
                ],
                ["ABI", data.platform.get("abi") or "—"],
                ["gerado em", data.generated_at],
                ["gerado por", "ASM X %s" % data.version],
            ],
        )
        + "\n"
    )

    partes.append("## Números\n")
    partes.append(
        _md_table(
            [
                "instruções",
                "blocos",
                "chamadas",
                "syscalls",
                "comportamentos",
                "indicadores",
                "problemas",
            ],
            [
                [
                    contagens["instructions"],
                    contagens["blocks"],
                    contagens["calls"],
                    contagens["syscalls"],
                    contagens["behaviors"],
                    contagens["iocs"],
                    contagens["problems"],
                ]
            ],
        )
        + "\n"
    )

    if data.behaviors:
        partes.append("## Comportamentos\n")
        partes.append(
            _md_table(
                ["comportamento", "severidade", "confiança", "evidências"],
                [
                    [
                        b["label"],
                        b["severity"],
                        "%d%%" % b["confidence"],
                        "; ".join(b["evidence"][:3]),
                    ]
                    for b in data.behaviors
                ],
            )
            + "\n"
        )
    if data.techniques:
        partes.append("## MITRE ATT&CK (indícios)\n")
        partes.append(
            _md_table(
                ["técnica", "tática", "id", "ligada a"],
                [
                    [t["name"], t["tactic"], t["id"], ", ".join(t.get("behaviors", []))]
                    for t in data.techniques
                ],
            )
            + "\n"
        )
    if data.cfg.get("mermaid"):
        partes.append("## Fluxo de controle\n")
        partes.append("```mermaid\n%s\n```\n" % data.cfg["mermaid"])
    if data.calls.get("mermaid") and not data.calls.get("graph", {}).get("empty", True):
        partes.append("## Chamadas\n")
        partes.append("```mermaid\n%s\n```\n" % data.calls["mermaid"])

    if data.iocs:
        partes.append("## Indicadores e strings\n")
        for tipo, lista in sorted(data.iocs.items()):
            if not lista:
                continue
            rotulo = lista[0].get("label", tipo)
            partes.append("**%s** (%d)\n" % (rotulo, len(lista)))
            partes.append(
                _md_table(["valor", "linha"], [[i["value"], i["line"]] for i in lista[:40]]) + "\n"
            )

    if data.problems:
        partes.append("## Validação\n")
        partes.append(
            _md_table(
                ["linha", "severidade", "código", "problema", "dica"],
                [
                    [p["line"], p["severity"], p["code"], p["message"], p.get("hint", "")]
                    for p in data.problems
                ],
            )
            + "\n"
        )
    else:
        partes.append("## Validação\n\nNenhum problema encontrado.\n")

    if data.execution is not None:
        execucao = data.execution
        partes.append("## Execução simulada\n")
        partes.append("```text\n%s\n```\n" % (execucao.get("output") or "(sem saída)"))
        partes.append(
            _md_table(
                ["passos", "código de saída", "parou por timeout"],
                [
                    [
                        execucao.get("steps", 0),
                        execucao.get("exit_code"),
                        "sim" if execucao.get("timed_out") else "não",
                    ]
                ],
            )
            + "\n"
        )
        if execucao.get("issues"):
            partes.append("**Problemas detectados na execução**\n")
            for problema in execucao["issues"]:
                partes.append("- %s" % problema)
            partes.append("")

    partes.append("## Instruções\n")
    partes.append(
        _md_table(
            ["linha", "instrução", "etiqueta", "explicação"],
            [[i["line"], "`%s`" % i["text"], i["label"], i["detail"]] for i in data.instructions],
        )
        + "\n"
    )
    partes.append("---\n\nGerado por ASM X %s · esquema %s\n" % (data.version, data.schema))
    return "\n".join(partes)


# ------------------------------------------------------------------- html ----
_CSS = """
:root {
  --bg: #0F1826; --panel: #16202E; --panel2: #1C2A3A; --line: #26394E;
  --fg: #DCE6F2; --dim: #8AA0B8; --white: #F2F7FF; --accent: #E3A44B;
  --cyan: #57C8D2; --green: #5FD4A8; --violet: #9C8CF0; --pink: #EF7D9D;
  --orange: #F08A5D; --blue: #79A6E8;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg);
  font: 15px/1.55 "Segoe UI", "DejaVu Sans", system-ui, sans-serif; }
a { color: var(--cyan); }
header { padding: 28px 32px 18px; border-bottom: 1px solid var(--line);
  background: linear-gradient(180deg, #121B28, #0F1826); }
h1 { margin: 0 0 6px; font-size: 26px; color: var(--white); }
h2 { margin: 0 0 14px; font-size: 19px; color: var(--white); }
h3 { margin: 22px 0 10px; font-size: 16px; color: var(--white); }
.sub { color: var(--dim); font-size: 14px; }
.wrap { max-width: 1180px; margin: 0 auto; padding: 0 32px 60px; }
.mono { font-family: "JetBrains Mono", "DejaVu Sans Mono", Consolas, monospace; }
.risk { display: flex; gap: 16px; align-items: center; margin: 18px 0 0;
  padding: 16px 20px; border-radius: 12px; border: 1px solid var(--line);
  background: var(--panel); }
.risk .score { font-size: 30px; font-weight: 700; }
.risk .level { font-size: 20px; font-weight: 700; letter-spacing: .5px; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 12px; margin: 22px 0 8px; }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 10px;
  padding: 12px 14px; }
.card b { display: block; font-size: 22px; color: var(--white); }
.card span { color: var(--dim); font-size: 13px; }
nav { display: flex; flex-wrap: wrap; gap: 6px; margin: 26px 0 18px;
  border-bottom: 1px solid var(--line); padding-bottom: 10px; }
nav button { background: var(--panel2); color: var(--fg); border: 1px solid var(--line);
  border-radius: 8px; padding: 7px 13px; cursor: pointer; font-size: 14px; }
nav button.active { background: var(--accent); color: #0F1826; font-weight: 700;
  border-color: var(--accent); }
section.tab { display: none; }
section.tab.active { display: block; }
table { width: 100%; border-collapse: collapse; margin: 8px 0 18px; font-size: 14px; }
th, td { text-align: left; padding: 7px 9px; border-bottom: 1px solid var(--line);
  vertical-align: top; }
th { color: var(--dim); font-weight: 600; font-size: 13px; text-transform: uppercase;
  letter-spacing: .4px; }
tr:hover td { background: #17253A; }
code, pre { font-family: "JetBrains Mono", "DejaVu Sans Mono", Consolas, monospace; }
pre { background: #0B1220; border: 1px solid var(--line); border-radius: 10px;
  padding: 12px 14px; overflow-x: auto; font-size: 13px; }
.chip { display: inline-block; padding: 2px 8px; border-radius: 20px; font-size: 12px;
  border: 1px solid var(--line); color: var(--dim); margin: 0 4px 4px 0; }
.sev-alto, .sev-erro { color: var(--pink); border-color: var(--pink); }
.sev-medio, .sev-alerta { color: var(--accent); border-color: var(--accent); }
.sev-baixo, .sev-info { color: var(--blue); border-color: var(--blue); }
.behavior { background: var(--panel); border: 1px solid var(--line); border-left-width: 4px;
  border-radius: 10px; padding: 14px 16px; margin: 0 0 12px; }
.behavior.alto { border-left-color: var(--pink); }
.behavior.medio { border-left-color: var(--accent); }
.behavior.baixo { border-left-color: var(--green); }
.behavior h3 { margin: 0 0 4px; }
.bar { height: 6px; border-radius: 4px; background: var(--panel2); margin: 8px 0 4px;
  overflow: hidden; }
.bar i { display: block; height: 100%; background: var(--cyan); }
.muted { color: var(--dim); }
.grid2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: 18px; }
.svgbox { background: var(--panel); border: 1px solid var(--line); border-radius: 12px;
  padding: 10px; overflow: auto; }
.svgbox svg { max-width: 100%; height: auto; }
input.filter { width: 100%; padding: 9px 12px; border-radius: 8px; border: 1px solid var(--line);
  background: var(--panel2); color: var(--fg); margin: 6px 0 12px; font-size: 14px; }
footer { border-top: 1px solid var(--line); color: var(--dim); font-size: 13px;
  padding: 18px 32px 40px; text-align: center; }
.empty { color: var(--dim); font-style: italic; }
@media print {
  nav { display: none; }
  section.tab { display: block !important; page-break-inside: avoid; }
  body { background: #fff; color: #111; }
  .card, .behavior, pre, .svgbox { border-color: #ccc; background: #fafafa; }
  h1, h2, h3, .card b { color: #000; }
}
"""

_JS = """
function showTab(id, botao) {
  document.querySelectorAll('section.tab').forEach(function (s) { s.classList.remove('active'); });
  document.querySelectorAll('nav button').forEach(function (b) { b.classList.remove('active'); });
  var alvo = document.getElementById(id);
  if (alvo) { alvo.classList.add('active'); }
  if (botao) { botao.classList.add('active'); }
}
function filtrar(campoId, tabelaId) {
  var termo = (document.getElementById(campoId).value || '').toLowerCase();
  var linhas = document.getElementById(tabelaId).getElementsByTagName('tr');
  for (var i = 1; i < linhas.length; i++) {
    var texto = (linhas[i].innerText || '').toLowerCase();
    linhas[i].style.display = (termo === '' || texto.indexOf(termo) >= 0) ? '' : 'none';
  }
}
function copiar(id, botao) {
  var alvo = document.getElementById(id);
  if (!alvo) { return; }
  navigator.clipboard.writeText(alvo.innerText).then(function () {
    var antigo = botao.innerText;
    botao.innerText = 'copiado';
    setTimeout(function () { botao.innerText = antigo; }, 1200);
  });
}
"""


class _Raw(str):
    """Texto que já é HTML e não deve ser escapado de novo."""


def _esc(valor: Any) -> str:
    """Escapa um texto para HTML.

    Args:
        valor: Qualquer valor; é convertido em texto antes de escapar.

    Returns:
        Texto seguro para entrar no HTML.
    """
    return html.escape("" if valor is None else str(valor), quote=True)


def _md_to_html(texto: str) -> str:
    """Escapa um texto e preserva as quebras de linha.

    Args:
        texto: Texto puro.

    Returns:
        HTML com ``<br>`` nas quebras de linha.
    """
    return _esc(texto).replace("\n", "<br>")


def _table(
    headers: Sequence[str],
    rows: Sequence[Sequence[Any]],
    *,
    table_id: str = "",
    empty: str = "nada por aqui",
) -> str:
    """Monta uma tabela HTML.

    Args:
        headers: Cabeçalhos das colunas.
        rows: Linhas, já no formato final (o texto é escapado aqui).
        table_id: Identificador usado pelo filtro JavaScript.
        empty: Texto mostrado quando não há linhas.

    Returns:
        Bloco HTML da tabela.
    """
    if not rows:
        return '<p class="empty">%s</p>' % _esc(empty)
    ident = ' id="%s"' % _esc(table_id) if table_id else ""
    partes = ["<table%s>" % ident, "<thead><tr>"]
    partes.extend("<th>%s</th>" % _esc(h) for h in headers)
    partes.append("</tr></thead><tbody>")
    for linha in rows:
        partes.append("<tr>")
        for celula in linha:
            partes.append("<td>%s</td>" % (celula if isinstance(celula, _Raw) else _esc(celula)))
        partes.append("</tr>")
    partes.append("</tbody></table>")
    return "".join(partes)


def _cards(contagens: Dict[str, int]) -> str:
    """Monta os cartões de números do topo.

    Args:
        contagens: Contagens devolvidas por :attr:`ReportData.counts`.

    Returns:
        HTML da grade de cartões.
    """
    rotulos = [
        ("instructions", "instruções"),
        ("blocks", "blocos"),
        ("calls", "chamadas"),
        ("syscalls", "syscalls"),
        ("behaviors", "comportamentos"),
        ("iocs", "indicadores"),
        ("strings", "strings"),
        ("problems", "problemas"),
    ]
    itens = ["<div class='cards'>"]
    for chave, rotulo in rotulos:
        itens.append(
            "<div class='card'><b>%d</b><span>%s</span></div>"
            % (contagens.get(chave, 0), _esc(rotulo))
        )
    itens.append("</div>")
    return "".join(itens)


def _risk_banner(data: ReportData) -> str:
    """Desenha a faixa de risco do relatório.

    Args:
        data: Relatório preenchido.

    Returns:
        HTML da faixa, com o motivo que mais pesou.
    """
    risco = data.risk
    cor = _esc(risco.get("color", "#8AA0B8"))
    razoes = risco.get("reasons") or []
    detalhe = " · ".join(razoes[:3]) if razoes else "sem sinal relevante"
    return (
        "<div class='risk' style='border-color:%s'>"
        "<div class='score' style='color:%s'>%d<small>/100</small></div>"
        "<div><div class='level' style='color:%s'>%s risco %s</div>"
        "<div class='sub'>%s</div><div class='sub'>%s</div></div></div>"
        % (
            cor,
            cor,
            int(risco.get("score", 0)),
            cor,
            _esc(risco.get("emoji", "")),
            _esc(str(risco.get("level", "")).upper()),
            _esc(risco.get("description", "")),
            _esc(detalhe),
        )
    )


def _meta_section(data: ReportData) -> str:
    """Monta a seção de metadados do arquivo e da plataforma.

    Args:
        data: Relatório preenchido.

    Returns:
        HTML da seção de resumo.
    """
    fonte = data.source
    plataforma = data.platform
    pistas = []
    for origem, lista in (plataforma.get("evidence") or {}).items():
        for pista in lista:
            pistas.append("<span class='chip'>%s: %s</span>" % (_esc(origem), _esc(pista)))
    linhas = [
        ["arquivo", _esc(fonte.get("name", ""))],
        ["caminho", _Raw('<span class="mono">%s</span>' % _esc(fonte.get("path", "") or "—"))],
        ["tamanho", "%s bytes" % _esc(fonte.get("size", 0))],
        ["linhas", _esc(fonte.get("lines", 0))],
        ["codificação", _esc(fonte.get("encoding", ""))],
        ["sha256", _Raw('<span class="mono">%s</span>' % _esc(fonte.get("sha256", "") or "—"))],
        [
            "impressão digital",
            _Raw('<span class="mono">%s</span>' % _esc(fonte.get("fingerprint", ""))),
        ],
        ["dialeto", _esc(data.dialect)],
        [
            "plataforma",
            "%s · %d bits · %d%% de confiança"
            % (
                _esc(plataforma.get("os")),
                plataforma.get("bits", 64),
                plataforma.get("confidence", 0),
            ),
        ],
        ["ABI", _esc(plataforma.get("abi") or "—")],
        ["gerado em", _esc(data.generated_at)],
        ["gerado por", "ASM X %s (esquema %s)" % (_esc(data.version), _esc(data.schema))],
    ]
    corpo = [_table(["campo", "valor"], linhas)]
    if plataforma.get("abi_notes"):
        corpo.append("<p class='sub'>%s</p>" % _esc(plataforma["abi_notes"]))
    if plataforma.get("arg_regs"):
        corpo.append(
            "<p><b>Argumentos em</b> %s</p>"
            % " ".join(
                "<span class='chip mono'>%s</span>" % _esc(r) for r in plataforma["arg_regs"]
            )
        )
    if plataforma.get("preserved"):
        corpo.append(
            "<p><b>Preservados</b> %s</p>"
            % " ".join(
                "<span class='chip mono'>%s</span>" % _esc(r) for r in plataforma["preserved"]
            )
        )
    if pistas:
        corpo.append("<h3>Pistas que levaram à conclusão</h3><p>%s</p>" % "".join(pistas))
    corpo.append("<h2>Resumo executivo</h2><p>%s</p>" % _esc(data.summary))
    return "".join(corpo)


def _behaviors_section(data: ReportData) -> str:
    """Monta a seção de comportamentos e MITRE ATT&CK.

    Args:
        data: Relatório preenchido.

    Returns:
        HTML da seção.
    """
    if not data.behaviors:
        return "<p class='empty'>Nenhum comportamento relevante foi identificado.</p>"
    partes = []
    for comportamento in sorted(data.behaviors, key=lambda b: severity_rank(b["severity"])):
        evidencias = "".join("<li>%s</li>" % _esc(e) for e in comportamento["evidence"])
        chips = "".join(
            "<span class='chip mono'>%s</span>" % _esc(t) for t in comportamento.get("mitre", [])
        )
        partes.append(
            "<div class='behavior %s'>"
            "<h3>%s <span class='chip sev-%s'>%s</span></h3>"
            "<p>%s</p>"
            "<div class='bar'><i style='width:%d%%'></i></div>"
            "<p class='sub'>confiança %d%% · linhas %s</p>"
            "<ul>%s</ul>%s</div>"
            % (
                _esc(comportamento["severity"]),
                _esc(comportamento["label"]),
                _esc(comportamento["severity"]),
                _esc(comportamento["severity"]),
                _esc(comportamento["description"]),
                int(comportamento["confidence"]),
                int(comportamento["confidence"]),
                _esc(", ".join(str(n) for n in comportamento["lines"])),
                evidencias,
                "<p>%s</p>" % chips if chips else "",
            )
        )
    if data.techniques:
        linhas = [
            [
                _Raw(
                    '<a href="%s" target="_blank" rel="noopener">%s</a>'
                    % (_esc(t["url"]), _esc(t["id"]))
                ),
                _esc(t["name"]),
                _esc(t["tactic"]),
                _Raw(
                    " ".join(
                        "<span class='chip'>%s</span>" % _esc(b) for b in t.get("behaviors", [])
                    )
                ),
                _esc(t.get("description", "")),
            ]
            for t in data.techniques
        ]
        partes.append("<h2>MITRE ATT&CK — indícios</h2>")
        partes.append(
            "<p class='sub'>Mapeamento derivado de padrões estáticos: indício, "
            "não prova de comportamento malicioso.</p>"
        )
        partes.append(_table(["id", "técnica", "tática", "comportamentos", "o que é"], linhas))
    return "".join(partes)


def _iocs_section(data: ReportData) -> str:
    """Monta a seção de indicadores e strings.

    Args:
        data: Relatório preenchido.

    Returns:
        HTML da seção.
    """
    if not data.iocs:
        return "<p class='empty'>Nenhuma string ou indicador encontrado.</p>"
    partes = []
    for tipo, lista in sorted(data.iocs.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        if not lista:
            continue
        rotulo = lista[0].get("label", tipo)
        linhas = [
            [
                _Raw('<span class="mono">%s</span>' % _esc(i["value"])),
                _esc(i["line"]),
                _Raw('<span class="sub">%s</span>' % _esc(i.get("context", ""))),
            ]
            for i in lista
        ]
        partes.append("<h3>%s <span class='chip'>%d</span></h3>" % (_esc(rotulo), len(lista)))
        partes.append(_table(["valor", "linha", "contexto"], linhas, empty="nada deste tipo"))
    return "".join(partes)


def _instructions_section(data: ReportData) -> str:
    """Monta a tabela filtrável de instruções.

    Args:
        data: Relatório preenchido.

    Returns:
        HTML da seção.
    """
    if not data.instructions:
        return "<p class='empty'>O arquivo não tem instruções.</p>"
    corpo = [
        '<input class="filter" id="filtro-instrucoes" placeholder="filtrar por '
        'linha, instrução, etiqueta ou explicação…" '
        "oninput=\"filtrar('filtro-instrucoes', 'tabela-instrucoes')\">"
    ]
    linhas = [
        [
            i["line"],
            _Raw('<span class="mono">%s</span>' % _esc(i["text"])),
            _Raw('<span class="chip sev-info">%s</span>' % _esc(i["label"])),
            _esc(i["detail"]),
        ]
        for i in data.instructions
    ]
    corpo.append(
        _table(
            ["linha", "instrução", "etiqueta", "o que faz"], linhas, table_id="tabela-instrucoes"
        )
    )
    return "".join(corpo)


def _problems_section(data: ReportData) -> str:
    """Monta a seção de validação.

    Args:
        data: Relatório preenchido.

    Returns:
        HTML da seção.
    """
    if not data.problems:
        return "<p class='empty'>Nenhum problema encontrado pelo validador.</p>"
    partes = []
    for severidade in (ERRO, ALERTA, INFO):
        do_tipo = [p for p in data.problems if p["severity"] == severidade]
        if not do_tipo:
            continue
        linhas = [
            [
                p["line"],
                _Raw('<span class="chip mono">%s</span>' % _esc(p["code"])),
                _esc(p["message"]),
                _Raw('<span class="sub">%s</span>' % _esc(p.get("hint", ""))),
            ]
            for p in do_tipo
        ]
        partes.append(
            "<h3>%s <span class='chip sev-%s'>%d</span></h3>"
            % (_esc(severidade.capitalize()), _esc(severidade), len(do_tipo))
        )
        partes.append(_table(["linha", "código", "problema", "como corrigir"], linhas))
    return "".join(partes)


def _execution_section(data: ReportData) -> str:
    """Monta a seção de execução simulada.

    Args:
        data: Relatório preenchido.

    Returns:
        HTML da seção.
    """
    if data.execution is None:
        return (
            "<p class='empty'>A execução não foi simulada neste relatório. "
            "Gere de novo sem <code>--no-emulate</code> para preencher esta aba.</p>"
        )
    execucao = data.execution
    partes = [
        "<h2>Saída do programa</h2>",
        "<pre>%s</pre>" % _esc(execucao.get("output") or "(nenhuma saída)"),
    ]
    partes.append(
        _table(
            ["passos", "código de saída", "terminou", "timeout"],
            [
                [
                    execucao.get("steps", 0),
                    _esc(execucao.get("exit_code")),
                    "sim" if execucao.get("halted") else "não",
                    "sim" if execucao.get("timed_out") else "não",
                ]
            ],
        )
    )
    problemas = execucao.get("issues") or []
    if problemas:
        partes.append("<h3>Problemas detectados durante a execução</h3><ul>")
        partes.extend("<li>%s</li>" % _esc(p) for p in problemas)
        partes.append("</ul>")
    registradores = execucao.get("registers") or {}
    if registradores:
        linhas = [
            [
                _Raw('<span class="mono">%s</span>' % _esc(r)),
                _Raw('<span class="mono">%s</span>' % _esc(v)),
                (execucao.get("registers_decimal") or {}).get(r, ""),
            ]
            for r, v in sorted(registradores.items())
        ]
        partes.append("<h3>Registradores ao final</h3>")
        partes.append(_table(["registrador", "hexadecimal", "decimal"], linhas))
    bandeiras = execucao.get("flags") or {}
    if bandeiras:
        partes.append(
            "<h3>Flags</h3><p>%s</p>"
            % "".join(
                "<span class='chip mono'>%s=%s</span>" % (_esc(f), _esc(v))
                for f, v in bandeiras.items()
            )
        )
    if data.timeline:
        aviso = (
            " (mostrando os últimos %d passos)" % len(data.timeline)
            if execucao.get("timeline_truncated")
            else ""
        )
        partes.append("<h3>Linha do tempo%s</h3>" % _esc(aviso))
        linhas = [
            [
                p["step"],
                p["line"],
                _Raw('<span class="mono">%s</span>' % _esc(p["text"])),
                _esc(p["note"]),
            ]
            for p in data.timeline
        ]
        partes.append(
            _table(["passo", "linha", "instrução", "efeito"], linhas, table_id="tabela-timeline")
        )
    return "".join(partes)


def _flow_section(data: ReportData) -> str:
    """Monta a seção de fluxo: grafo de controle, chamadas e exportações.

    Args:
        data: Relatório preenchido.

    Returns:
        HTML da seção.
    """
    partes = [
        "<h2>Grafo de fluxo de controle</h2>",
        "<p class='sub'>Cada caixa é um bloco básico; as setas são os desvios, "
        "com o motivo. Blocos cinza-escuros são inalcançáveis.</p>",
    ]
    if data.cfg.get("graph", {}).get("empty", True):
        partes.append("<p class='empty'>Sem código para desenhar.</p>")
    else:
        partes.append("<div class='svgbox'>%s</div>" % data.cfg.get("svg", ""))
    partes.append("<h2>Grafo de chamadas</h2>")
    if data.calls.get("graph", {}).get("empty", True):
        partes.append("<p class='empty'>Este programa não chama ninguém.</p>")
    else:
        partes.append("<div class='svgbox'>%s</div>" % data.calls.get("svg", ""))
    partes.append("<h2>Blocos básicos</h2>")
    linhas = [
        [
            b["name"],
            _esc(b["func"] or "—"),
            "L%d–L%d" % (b["lines"][0], b["lines"][1]),
            b["instructions"],
            _esc(", ".join(b["comes_from"]) or "—"),
            _esc(", ".join(b["goes_to"]) or (b["exit"] or "—")),
        ]
        for b in data.blocks
    ]
    partes.append(_table(["bloco", "função", "linhas", "instr.", "vem de", "vai para"], linhas))
    partes.append("<h2>Exportar o grafo</h2>")
    for chave, rotulo in (("cfg", "fluxo de controle"), ("calls", "chamadas")):
        grafo = data.cfg if chave == "cfg" else data.calls
        if grafo.get("graph", {}).get("empty", True):
            continue
        ident = "dot-%s" % chave
        partes.append("<h3>%s — DOT (Graphviz)</h3>" % _esc(rotulo.capitalize()))
        partes.append("<pre id='%s'>%s</pre>" % (ident, _esc(grafo.get("dot", ""))))
        partes.append("<button onclick=\"copiar('%s', this)\">copiar DOT</button>" % ident)
    return "".join(partes)


def _data_section(data: ReportData) -> str:
    """Monta a aba de dados crus (JSON) e a nota de offline.

    Args:
        data: Relatório preenchido.

    Returns:
        HTML da seção.
    """
    dados = render_json(data, indent=2)
    ident = "json-cru"
    return (
        "<h2>JSON do relatório</h2>"
        "<p class='sub'>Mesmo conteúdo desta página, no esquema <code>%s</code>. "
        "Para salvar sem copiar da tela: <code>asmx report arquivo.asm --format json</code>.</p>"
        "<pre id='%s'>%s</pre>"
        "<button onclick=\"copiar('%s', this)\">copiar JSON</button>"
        % (_esc(data.schema), ident, _esc(dados), ident)
    )


def render_html(data: ReportData) -> str:
    """Desenha o relatório como uma página HTML autocontida.

    O arquivo gerado não faz nenhuma requisição de rede: CSS, JavaScript e os
    grafos em SVG vão embutidos, então ele abre offline no navegador (e pode ser
    anexado a um e-mail ou commit sem quebrar).

    Args:
        data: Relatório a renderizar.

    Returns:
        Documento HTML completo, pronto para gravar em disco.
    """
    titulo = "ASM X — análise de %s" % data.source.get("name", "programa")
    abas = [
        ("resumo", "Resumo"),
        ("fluxo", "Fluxo"),
        ("comportamentos", "Comportamentos"),
        ("iocs", "Indicadores"),
        ("instrucoes", "Instruções"),
        ("validacao", "Validação"),
        ("execucao", "Execução"),
        ("dados", "Dados"),
    ]
    botoes = "".join(
        "<button class='%s' onclick=\"showTab('%s', this)\">%s</button>"
        % ("active" if indice == 0 else "", chave, _esc(rotulo))
        for indice, (chave, rotulo) in enumerate(abas)
    )
    secoes = "".join(
        "<section class='tab %s' id='%s'>%s</section>"
        % ("active" if indice == 0 else "", chave, corpo)
        for indice, (chave, corpo) in enumerate(
            [
                ("resumo", _meta_section(data)),
                ("fluxo", _flow_section(data)),
                ("comportamentos", _behaviors_section(data)),
                ("iocs", _iocs_section(data)),
                ("instrucoes", _instructions_section(data)),
                ("validacao", _problems_section(data)),
                ("execucao", _execution_section(data)),
                ("dados", _data_section(data)),
            ]
        )
    )
    rodape = (
        "Gerado por ASM X %s em %s · esquema %s · página autocontida, "
        "sem requisição de rede" % (_esc(data.version), _esc(data.generated_at), _esc(data.schema))
    )
    if data.command:
        rodape += " · <span class='mono'>%s</span>" % _esc(data.command)
    return (
        "<!DOCTYPE html>\n<html lang='pt-BR'>\n<head>\n"
        "<meta charset='utf-8'>\n"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>\n"
        "<title>%s</title>\n<style>%s</style>\n</head>\n<body>\n"
        "<header><div class='wrap' style='padding-bottom:0'>"
        "<h1>%s</h1>"
        "<p class='sub'>%s</p>%s</div></header>\n"
        "<div class='wrap'>%s<nav>%s</nav>%s</div>\n"
        "<footer>%s</footer>\n<script>%s</script>\n</body>\n</html>\n"
        % (
            _esc(titulo),
            _CSS,
            _esc(titulo),
            _esc(
                "%d instruções · %s · gerado em %s"
                % (data.counts["instructions"], data.platform.get("os", "?"), data.generated_at)
            ),
            _risk_banner(data),
            _cards(data.counts),
            botoes,
            secoes,
            rodape,
            _JS,
        )
    )


def render_index(
    reports: Sequence[ReportData], *, title: str = "ASM X — índice de análises", command: str = ""
) -> str:
    """Desenha um índice HTML comparando vários relatórios.

    Serve para a análise em lote: uma linha por arquivo, com risco, tamanho,
    plataforma, comportamentos e problemas, além do link para o relatório
    individual de cada um.

    Args:
        reports: Relatórios coletados, na ordem em que aparecem.
        title: Título da página.
        command: Linha de comando usada, mostrada no rodapé.

    Returns:
        Documento HTML completo.
    """
    linhas: List[List[Any]] = []
    for data in reports:
        nome = data.source.get("name", "programa")
        arquivo = data.source.get("report_file") or ("%s.html" % nome)
        linhas.append(
            [
                _Raw('<a href="%s">%s</a>' % (_esc(arquivo), _esc(nome))),
                _Raw(
                    '<span class="chip sev-%s">%s</span>'
                    % (
                        _esc(data.risk.get("level", "baixo")),
                        _esc(str(data.risk.get("level", "")).upper()),
                    )
                ),
                int(data.risk.get("score", 0)),
                data.platform.get("os", "?"),
                data.counts["instructions"],
                data.counts["behaviors"],
                data.counts["iocs"],
                data.counts["problems"],
                _esc(", ".join(b["label"] for b in data.behaviors[:3]) or "—"),
            ]
        )
    total = len(reports)
    criticos = sum(1 for r in reports if r.risk.get("level") in ("alto", "critico"))
    resumo = (
        "%d arquivo(s) analisado(s) · %d com risco alto ou crítico · %d "
        "comportamento(s) no total" % (total, criticos, sum(r.counts["behaviors"] for r in reports))
    )
    corpo = _table(
        [
            "arquivo",
            "risco",
            "score",
            "plataforma",
            "instr.",
            "comport.",
            "IOCs",
            "problemas",
            "destaques",
        ],
        linhas,
        table_id="tabela-indice",
    )
    rodape = "Gerado por ASM X %s · esquema %s" % (_esc(__version__), _esc(REPORT_SCHEMA))
    if command:
        rodape += " · <span class='mono'>%s</span>" % _esc(command)
    return (
        "<!DOCTYPE html>\n<html lang='pt-BR'>\n<head>\n<meta charset='utf-8'>\n"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>\n"
        "<title>%s</title>\n<style>%s</style>\n</head>\n<body>\n"
        "<header><div class='wrap' style='padding-bottom:0'><h1>%s</h1>"
        "<p class='sub'>%s</p></div></header>\n"
        "<div class='wrap'>%s</div>\n<footer>%s</footer>\n</body>\n</html>\n"
        % (_esc(title), _CSS, _esc(title), _esc(resumo), corpo, rodape)
    )


# ---------------------------------------------------------------- arquivos --
def render_dot(data: ReportData) -> str:
    """Devolve o grafo de fluxo em DOT (Graphviz).

    Args:
        data: Relatório preenchido.

    Returns:
        Texto DOT terminado em quebra de linha.
    """
    return data.cfg.get("dot", "") or 'digraph cfg { label="sem código"; }\n'


def render_svg(data: ReportData) -> str:
    """Devolve o grafo de fluxo em SVG.

    Args:
        data: Relatório preenchido.

    Returns:
        Documento SVG autocontido.
    """
    return data.cfg.get("svg", "")


def write_report(data: ReportData, path: str, *, fmt: Optional[str] = None) -> str:
    """Grava o relatório no formato pedido.

    Args:
        data: Relatório a gravar.
        path: Caminho de destino (``-`` grava em ``stdout``). O diretório é
            criado quando ainda não existe.
        fmt: Formato explícito; sem ele, a extensão do arquivo decide.

    Returns:
        O caminho gravado (``"-"`` quando foi para a saída padrão).

    Raises:
        ProjectError: Se o formato não existe.
        SourceWriteError: Se a gravação falhou.
    """
    formato = (fmt or guess_format(path)).lower()
    if formato not in FORMATS:
        raise ProjectError(
            "formato de relatório desconhecido: %s (use %s)" % (formato, ", ".join(FORMATS))
        )
    if formato == "mermaid":
        conteudo = data.cfg.get("mermaid", "flowchart TD\n") + "\n"
    elif formato == "html":
        conteudo = render_html(data)
    elif formato == "md":
        conteudo = render_markdown(data)
    elif formato == "json":
        conteudo = render_json(data, include_svg=False)
    elif formato == "dot":
        conteudo = render_dot(data)
    else:
        conteudo = render_svg(data)
    if path == "-":
        print(conteudo, end="")
        return "-"
    pasta = os.path.dirname(os.path.abspath(path))
    try:
        os.makedirs(pasta, exist_ok=True)
        with open(path, "w", encoding="utf-8") as arquivo:
            arquivo.write(conteudo)
    except OSError as erro:
        raise SourceWriteError(path, str(erro)) from erro
    log_event(logger, "report_written", path=path, format=formato, bytes=len(conteudo))
    return path
