"""Linha de comando do ASM X — a mesma análise da interface, sem interface.

Comandos:

* ``check``    — analisa e valida, mostrando os problemas por linha;
* ``run``      — executa o programa na máquina virtual e mostra a saída;
* ``explain``  — explica uma instrução do acervo ou uma linha do arquivo;
* ``info``     — versão, acervo de instruções e configuração em vigor;
* ``examples`` — lista, mostra ou grava os programas de exemplo;
* ``version``  — só a versão.

Códigos de saída (contrato estável para CI)::

    0  tudo certo
    1  problemas encontrados no código
    2  erro de uso (argumento inválido)
    3  erro de entrada (arquivo ausente, formato, configuração, rótulo)
    4  tempo limite estourado

As opções globais (``--config``, ``-v``, ``--log-json``...) vêm antes do
comando: ``asmx --config asmx.json check prog.asm``.

Example:
    >>> from asmx.cli import main
    >>> main(["version"])                     # doctest: +SKIP
    0
"""

from __future__ import annotations

import argparse
import json
import os
import platform as _platform
import sys
from typing import Any, Callable, Dict, List, Optional, Sequence, TextIO, Tuple

from . import __version__
from .analyzer import Analysis, analyze
from .config import SandboxConfig
from .emulator import Machine, hexs
from .errors import (
    AnalysisTimeoutError,
    AsmxError,
    ConfigError,
    EmulationError,
    LineNotFoundError,
    SourceNotFoundError,
    SourceReadError,
    UnknownMnemonicError,
    UnsupportedSourceError,
)
from .examples import EXAMPLES, render
from .isa import CATEGORIES, ISA, LINUX_SYSCALLS, WIN_APIS
from .linter import ALL_CHECKS, ALERTA, ERRO, INFO, Problem, summary, validate
from .logging_setup import LoggingState, configure_logging, get_logger, log_event
from .source import SOURCE_SUFFIXES, SourceFile, read_source

__all__ = [
    "main",
    "build_parser",
    "build_payload",
    "describe_instruction",
    "load_config",
    "COMMANDS",
    "EXIT_OK",
    "EXIT_PROBLEMS",
    "EXIT_USAGE",
    "EXIT_INPUT",
    "EXIT_TIMEOUT",
]

logger = get_logger(__name__)

#: Tudo certo.
EXIT_OK = 0
#: Problemas encontrados no código analisado.
EXIT_PROBLEMS = 1
#: Erro de uso da linha de comando.
EXIT_USAGE = 2
#: Erro de entrada: arquivo, formato, configuração ou rótulo.
EXIT_INPUT = 3
#: A execução passou do tempo limite.
EXIT_TIMEOUT = 4

#: Severidades na ordem em que aparecem no relatório.
SEVERITIES: Tuple[str, ...] = (ERRO, ALERTA, INFO)

#: Nomes das chaves de contagem no JSON, na mesma ordem de :data:`SEVERITIES`.
SUMMARY_KEYS: Tuple[str, ...] = ("errors", "warnings", "infos")

#: Cores ANSI usadas na saída de terminal.
_COLORS = {
    "erro": "\033[31m",
    "alerta": "\033[33m",
    "info": "\033[34m",
    "titulo": "\033[1;36m",
    "bom": "\033[32m",
    "fraco": "\033[90m",
    "forte": "\033[1m",
}
_RESET = "\033[0m"


class Palette:
    """Pinta texto no terminal quando o destino aceita cor.

    Attributes:
        enabled: Se as sequências ANSI entram na saída.
    """

    def __init__(self, enabled: bool = True) -> None:
        """Guarda se a cor está ligada.

        Args:
            enabled: ``False`` devolve o texto intacto.
        """
        self.enabled = enabled

    def paint(self, text: str, color: str = "") -> str:
        """Envolve o texto na cor pedida.

        Args:
            text: Texto original.
            color: Nome em :data:`_COLORS`; vazio não pinta nada.

        Returns:
            Texto com as sequências ANSI, ou intacto quando desligado.

        Example:
            >>> Palette(False).paint("erro", "erro")
            'erro'
        """
        if not self.enabled or color not in _COLORS:
            return text
        return "%s%s%s" % (_COLORS[color], text, _RESET)

    def severity(self, severity: str, text: str) -> str:
        """Pinta um texto conforme a severidade do problema.

        Args:
            severity: ``erro``, ``alerta`` ou ``info``.
            text: Texto a pintar.

        Returns:
            Texto colorido.
        """
        return self.paint(text, severity)


# ------------------------------------------------------------------ parser --
def _add_global_options(parser: argparse.ArgumentParser, suppress: bool = False) -> None:
    """Registra as opções que valem para qualquer comando.

    O mesmo grupo é registrado no analisador principal e em cada subcomando,
    com ``default=SUPPRESS`` nos subcomandos. Assim ``asmx --no-color check x``
    e ``asmx check x --no-color`` funcionam igual, e a opção dada antes do
    comando não é sobrescrita pelo padrão do subcomando.

    Args:
        parser: Analisador (ou subcomando) que recebe as opções.
        suppress: Quando ``True``, as opções só entram em ``args`` se forem
            usadas de fato.
    """
    padrao: Any = argparse.SUPPRESS if suppress else False
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=padrao,
        help="mostra o log de depuração (DEBUG)",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        default=padrao,
        help="silencia o log; sobra só o resultado",
    )
    parser.add_argument(
        "--log-json",
        action="store_true",
        default=padrao,
        help="emite o log em JSON (uma linha por evento)",
    )
    parser.add_argument(
        "--log-file",
        metavar="CAMINHO",
        default=argparse.SUPPRESS if suppress else None,
        help="grava também o log neste arquivo",
    )
    parser.add_argument(
        "--config",
        metavar="CAMINHO",
        default=argparse.SUPPRESS if suppress else None,
        help="arquivo de configuração (.json, .yaml ou .yml)",
    )
    parser.add_argument(
        "--no-color", action="store_true", default=padrao, help="não usa cor na saída"
    )


def build_parser() -> argparse.ArgumentParser:
    """Monta o analisador de argumentos da linha de comando.

    Returns:
        O :class:`argparse.ArgumentParser` com os comandos e as opções globais.

    Example:
        >>> build_parser().parse_args(["check", "a.asm"]).command
        'check'
        >>> build_parser().parse_args(["check", "a.asm", "--no-color"]).no_color
        True
    """
    parser = argparse.ArgumentParser(
        prog="asmx",
        description="ASM X — ambiente de estudo e depuração de assembly x86-64.",
        epilog="sem argumentos abre a interface gráfica. As opções globais "
        "(--config, -v, --log-json) vêm antes do comando. "
        "Exemplos: asmx check prog.asm · asmx run prog.asm · "
        "asmx explain prog.asm --line 12",
    )
    parser.add_argument("--version", action="version", version="ASM X %s" % __version__)
    parser.add_argument(
        "--gui", action="store_true", help="abre a interface gráfica (mesmo comando sem argumentos)"
    )
    _add_global_options(parser)

    sub = parser.add_subparsers(dest="command", metavar="COMANDO")

    check = sub.add_parser("check", help="analisa e valida o código")
    check.add_argument("files", nargs="+", metavar="ARQUIVO", help="um ou mais fontes .asm")
    check.add_argument("--json", action="store_true", help="saída em JSON")
    check.add_argument(
        "--min-severity",
        choices=SEVERITIES,
        default=ALERTA,
        help="severidade mínima que faz o comando falhar (padrão: alerta)",
    )
    check.add_argument(
        "--exit-zero", action="store_true", help="sempre devolve 0, mesmo com problemas encontrados"
    )
    check.add_argument(
        "--summary-only", action="store_true", help="mostra só o resumo, sem a lista de problemas"
    )
    _add_global_options(check, suppress=True)

    run = sub.add_parser("run", help="executa o programa na máquina virtual")
    run.add_argument("file", metavar="ARQUIVO", help="fonte .asm")
    run.add_argument(
        "--entry",
        metavar="RÓTULO",
        default=None,
        help="começa a execução neste rótulo (função isolada)",
    )
    run.add_argument(
        "--stdin", metavar="TEXTO", default="", help="entrada simulada para a syscall read"
    )
    run.add_argument(
        "--limit",
        type=int,
        default=None,
        help="limite de instruções (padrão: max_steps da configuração)",
    )
    run.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="tempo máximo em segundos; ao estourar, sai com código 4",
    )
    run.add_argument("--json", action="store_true", help="saída em JSON")
    run.add_argument("--trace", action="store_true", help="mostra o histórico de execução")
    run.add_argument(
        "--max-trace", type=int, default=40, help="quantas linhas do histórico mostrar (padrão: 40)"
    )
    _add_global_options(run, suppress=True)

    explain = sub.add_parser("explain", help="explica uma instrução ou uma linha")
    explain.add_argument("file", metavar="ARQUIVO", help="fonte .asm")
    grupo = explain.add_mutually_exclusive_group(required=True)
    grupo.add_argument("--line", type=int, metavar="N", help="número da linha (1-based)")
    grupo.add_argument("--mnemonic", metavar="MNEMÔNICO", help="instrução a documentar")
    explain.add_argument("--json", action="store_true", help="saída em JSON")
    _add_global_options(explain, suppress=True)

    info = sub.add_parser("info", help="versão, acervo e configuração em vigor")
    info.add_argument("--json", action="store_true", help="saída em JSON")
    _add_global_options(info, suppress=True)

    examples = sub.add_parser("examples", help="lista, mostra ou grava os exemplos")
    examples.add_argument("--list", action="store_true", help="lista os nomes e títulos")
    examples.add_argument("--show", metavar="NOME", default=None, help="imprime o código")
    examples.add_argument(
        "--dump", metavar="DIRETÓRIO", default=None, help="grava todos os exemplos como .asm"
    )
    examples.add_argument("--json", action="store_true", help="saída em JSON")
    _add_global_options(examples, suppress=True)

    version = sub.add_parser("version", help="mostra a versão")
    version.add_argument("--json", action="store_true", help="saída em JSON")
    _add_global_options(version, suppress=True)
    return parser


# ------------------------------------------------------------- utilidades --
def _palette(args: argparse.Namespace) -> Palette:
    """Decide se a saída usa cor, conforme as opções e o terminal.

    Returns:
        A paleta ligada quando a saída é um terminal e nada pediu para desligar.
    """
    if getattr(args, "no_color", False) or os.environ.get("NO_COLOR"):
        return Palette(False)
    return Palette(sys.stdout.isatty())


def _severity_rank(severity: str) -> int:
    """Converte a severidade em número para comparar com o mínimo aceito.

    Returns:
        ``0`` para erro, ``1`` para alerta, ``2`` para informação e ``3`` para
        severidade desconhecida.
    """
    return {ERRO: 0, ALERTA: 1, INFO: 2}.get(severity, 3)


def _platform_dict(analysis: Analysis) -> Dict[str, Any]:
    """Resume a plataforma detectada para o JSON.

    Returns:
        Dicionário com sistema, bits, confiança, ABI e as pistas encontradas.
    """
    plataforma = analysis.platform
    return {
        "os": plataforma.os,
        "bits": plataforma.bits,
        "confidence": plataforma.confidence,
        "abi": plataforma.abi.get("name"),
        "evidence": {chave: list(valores) for chave, valores in plataforma.evidence.items()},
    }


def _emit_json(payload: Any, stream: Optional[TextIO] = None) -> None:
    """Imprime um dicionário como JSON indentado.

    Args:
        payload: Estrutura serializável.
        stream: Destino (padrão ``sys.stdout``).
    """
    destino = stream or sys.stdout
    destino.write(json.dumps(payload, ensure_ascii=False, indent=2, default=str) + "\n")


def _write(text: str, stream: Optional[TextIO] = None) -> None:
    """Escreve uma linha no destino, sem `print` (mais fácil de testar)."""
    (stream or sys.stdout).write(text + "\n")


def describe_instruction(ins: Any) -> Dict[str, Any]:
    """Monta a ficha de uma instrução analisada.

    Args:
        ins: Objeto :class:`~asmx.parser.Line` de uma instrução.

    Returns:
        Dicionário com linha, texto, mnemônico, rótulo semântico, explicação,
        categoria, documentação do acervo e operandos classificados.

    Example:
        >>> from asmx.analyzer import analyze
        >>> describe_instruction(analyze("mov rax, 1").instrs[0])["label"]
        'Define constante'
    """
    doc = ISA.get(ins.mnemonic or "")
    return {
        "line": ins.n,
        "text": ins.text,
        "mnemonic": ins.mnemonic,
        "label": ins.sem.label if ins.sem else "",
        "detail": ins.sem.detail if ins.sem else "",
        "tag": ins.sem.tag if ins.sem else "",
        "category": doc["cat"] if doc else None,
        "documentation": doc if doc else None,
        "operands": [
            {
                "text": op.text,
                "type": op.type,
                "size": op.size,
                "reg": op.reg,
                "value": op.value,
                "symbol": op.symbol,
            }
            for op in (ins.operands or [])
        ],
    }


def load_config(args: argparse.Namespace) -> SandboxConfig:
    """Carrega a configuração combinando arquivo, ambiente e opções da linha.

    Args:
        args: Namespace já analisado pelo :func:`build_parser`.

    Returns:
        Configuração validada, já com as sobreposições do comando.

    Raises:
        ConfigError: Arquivo indicado ausente ou conteúdo inválido.
    """
    config = SandboxConfig.load(getattr(args, "config", None))
    return config.merged(
        log_level="DEBUG" if getattr(args, "verbose", False) else None,
        log_file=getattr(args, "log_file", None),
        log_json=True if getattr(args, "log_json", False) else None,
        timeout=getattr(args, "timeout", None),
        max_steps=getattr(args, "limit", None),
    )


def build_payload(args: argparse.Namespace) -> Dict[str, Any]:
    """Descreve a chamada em um dicionário (usado no log e nos testes).

    Args:
        args: Namespace analisado.

    Returns:
        Dicionário com comando e opções relevantes.

    Example:
        >>> build_payload(build_parser().parse_args(["check", "a.asm"]))["command"]
        'check'
    """
    dados: Dict[str, Any] = {"command": args.command}
    for campo in ("file", "files", "entry", "line", "mnemonic", "show", "dump"):
        valor = getattr(args, campo, None)
        if valor not in (None, False, []):
            dados[campo] = valor
    return dados


# ---------------------------------------------------------------- comandos --
def cmd_check(args: argparse.Namespace, config: SandboxConfig, palette: Palette) -> int:
    """Executa o comando ``check``.

    Args:
        args: Namespace do comando.
        config: Configuração em vigor.
        palette: Paleta de cores da saída.

    Returns:
        :data:`EXIT_OK` quando nada atinge a severidade mínima, senão
        :data:`EXIT_PROBLEMS` (ou ``EXIT_OK`` com ``--exit-zero``).
    """
    limite = _severity_rank(args.min_severity)
    relatorios: List[Dict[str, Any]] = []
    todos: List[Problem] = []
    total = {nome: 0 for nome in SUMMARY_KEYS}
    codigo = EXIT_OK

    for caminho in args.files:
        fonte = read_source(caminho, suffixes=SOURCE_SUFFIXES)
        analise = analyze(fonte.text)
        problemas = validate(analise)
        contagem: Dict[str, Any] = {
            nome: sum(1 for p in problemas if p.severity == sev)
            for sev, nome in zip(SEVERITIES, SUMMARY_KEYS)
        }
        for sev, nome in zip(SEVERITIES, SUMMARY_KEYS):
            total[nome] += contagem[nome]
        todos.extend(problemas)
        if any(_severity_rank(p.severity) <= limite for p in problemas):
            codigo = EXIT_PROBLEMS
        relatorios.append(
            {
                "source": fonte.to_dict(),
                "platform": _platform_dict(analise),
                "stats": dict(analise.stats),
                "problems": [p.to_dict() for p in problemas],
                "summary": contagem,
            }
        )
        log_event(
            logger,
            "check_finished",
            path=fonte.path,
            lines=fonte.lines,
            instructions=analise.stats["instructions"],
            **contagem,
        )
        if not args.json:
            _print_check_report(fonte, analise, problemas, palette, args.summary_only)

    if args.exit_zero:
        codigo = EXIT_OK
    if args.json:
        _emit_json(
            {
                "schema": "asmx-check/1",
                "command": "check",
                "files": relatorios,
                "summary": {"files": len(relatorios), **total},
                "exit_code": codigo,
            }
        )
    elif len(relatorios) > 1:
        _write(
            palette.paint(
                "%d arquivo(s): %s" % (len(relatorios), summary(todos)),
                "erro" if total["errors"] else "alerta",
            )
        )
    return codigo


def _print_check_report(
    source: SourceFile,
    analysis: Analysis,
    problems: Sequence[Problem],
    palette: Palette,
    summary_only: bool,
) -> None:
    """Imprime o relatório legível de um arquivo no comando ``check``.

    Args:
        source: Arquivo lido.
        analysis: Resultado da análise.
        problems: Problemas encontrados.
        palette: Paleta de cores.
        summary_only: Quando ``True``, omite a lista de problemas.
    """
    plataforma = analysis.platform
    stats = analysis.stats
    _write(
        "%s %s"
        % (
            palette.paint(source.name, "forte"),
            palette.paint(
                "(%d bytes · %d linhas · sha256 %s…)"
                % (source.size, source.lines, source.sha256[:12]),
                "fraco",
            ),
        )
    )
    if source.encoding != "utf-8":
        _write(
            "  %s"
            % palette.paint(
                "codificação detectada: %s (o ideal é UTF-8)" % source.encoding, "alerta"
            )
        )
    _write(
        "  plataforma  %s · %d bits · %d%% de confiança  (%s)"
        % (plataforma.os, plataforma.bits, plataforma.confidence, plataforma.abi.get("name"))
    )
    _write(
        "  %d instruções · %d blocos · %d syscall(s) · %d chamada(s) · %d rótulo(s)"
        % (
            stats["instructions"],
            stats["blocks"],
            stats["syscalls"],
            stats["calls"],
            stats["labels"],
        )
    )
    if stats["unknown"]:
        _write("  %s" % palette.paint("sem documentação: " + ", ".join(stats["unknown"]), "alerta"))
    if not problems:
        _write("  %s" % palette.paint("nenhum problema encontrado", "bom"))
        return
    if not summary_only:
        for problema in problems:
            marca = {ERRO: "erro  ", ALERTA: "alerta", INFO: "info  "}.get(
                problema.severity, "?     "
            )
            _write(
                "  %s L%-4d %-7s %s"
                % (
                    palette.severity(problema.severity, marca),
                    problema.line,
                    problema.code,
                    problema.message,
                )
            )
            if problema.hint:
                _write("         %s" % palette.paint("→ " + problema.hint, "fraco"))
    _write(
        "  %s"
        % palette.paint(
            summary(list(problems)),
            "erro" if any(p.severity == ERRO for p in problems) else "alerta",
        )
    )


def cmd_run(args: argparse.Namespace, config: SandboxConfig, palette: Palette) -> int:
    """Executa o comando ``run``.

    Args:
        args: Namespace do comando.
        config: Configuração em vigor (limites de instruções e de tempo).
        palette: Paleta de cores da saída.

    Returns:
        :data:`EXIT_OK` quando a execução termina limpa, :data:`EXIT_PROBLEMS`
        quando acusa problema e :data:`EXIT_TIMEOUT` quando estoura o tempo.

    Raises:
        EmulationError: Se ``--entry`` aponta para um rótulo inexistente.
        SourceNotFoundError: Se o arquivo não existe.
    """
    fonte = read_source(args.file, suffixes=SOURCE_SUFFIXES)
    analise = analyze(fonte.text)
    if args.entry and args.entry not in analise.label_at:
        raise EmulationError("rótulo não encontrado: %s" % args.entry)
    maquina = Machine(analise, stdin=args.stdin, entry=args.entry)
    passos = maquina.run(
        limit=args.limit or config.max_steps,
        timeout=args.timeout,
        raise_on_timeout=args.timeout is not None,
    )
    problemas = list(maquina.issues)

    log_event(
        logger,
        "run_finished",
        path=fonte.path,
        steps=passos,
        exit_code=maquina.exit_code,
        issues=len(problemas),
        timed_out=maquina.timed_out,
    )

    if args.json:
        payload: Dict[str, Any] = {
            "schema": "asmx-run/1",
            "command": "run",
            "source": fonte.to_dict(),
            "entry": args.entry or "entrada do programa",
            "exit_code": maquina.exit_code,
            "output": maquina.output,
            "steps": passos,
            "halted": maquina.halted,
            "timed_out": maquina.timed_out,
            "issues": problemas,
            "registers": {chave: hexs(valor) for chave, valor in maquina.regs.items() if valor},
            "flags": dict(maquina.flags),
        }
        if args.trace:
            payload["trace"] = [
                {"line": passo.line, "text": passo.text, "note": passo.note}
                for passo in maquina.trace[-args.max_trace :]
            ]
        _emit_json(payload)
    else:
        _write(
            "%s %s"
            % (
                palette.paint(fonte.name, "forte"),
                palette.paint(
                    "· entrada: %s" % (args.entry or "ponto de entrada do programa"), "fraco"
                ),
            )
        )
        if maquina.output:
            _write("  saída:")
            for linha in maquina.output.splitlines() or [""]:
                _write("    %s" % linha)
        else:
            _write("  saída: %s" % palette.paint("(vazia)", "fraco"))
        _write(
            "  %d instruções · código de saída %s"
            % (passos, maquina.exit_code if maquina.exit_code is not None else "não definido")
        )
        _write("  RAX=%s  RSP=%s" % (hexs(maquina.regs["rax"]), hexs(maquina.regs["rsp"])))
        for problema in problemas:
            _write("  %s" % palette.paint("⚠ " + problema, "alerta"))
        if not problemas:
            _write("  %s" % palette.paint("execução sem problemas", "bom"))
        if args.trace:
            _write("")
            _write("  histórico:")
            for passo in maquina.trace[-args.max_trace :]:
                _write("    L%-4d %-46s %s" % (passo.line, passo.text[:46], passo.note))

    if maquina.timed_out:
        return EXIT_TIMEOUT
    return EXIT_PROBLEMS if problemas else EXIT_OK


def cmd_explain(args: argparse.Namespace, config: SandboxConfig, palette: Palette) -> int:
    """Executa o comando ``explain``.

    Args:
        args: Namespace do comando.
        config: Configuração em vigor.
        palette: Paleta de cores da saída.

    Returns:
        :data:`EXIT_OK` sempre que a explicação é produzida.

    Raises:
        UnknownMnemonicError: Mnemônico fora do acervo.
        LineNotFoundError: Linha inexistente no arquivo.
    """
    if args.mnemonic and args.line is None:
        return _explain_mnemonic(args.mnemonic, args.json, palette)

    fonte = read_source(args.file, suffixes=SOURCE_SUFFIXES)
    analise = analyze(fonte.text)
    linha = next((linha for linha in analise.program.lines if linha.n == args.line), None)
    if linha is None:
        raise LineNotFoundError(int(args.line), fonte.lines)
    if linha.kind == "instruction":
        ficha = describe_instruction(linha)
        if args.json:
            _emit_json(
                {
                    "schema": "asmx-explain/1",
                    "command": "explain",
                    "source": fonte.to_dict(),
                    "kind": "instruction",
                    **ficha,
                }
            )
        else:
            _print_instruction(ficha, palette)
        return EXIT_OK

    detalhe = {
        "line": linha.n,
        "kind": linha.kind,
        "text": linha.text,
        "label": linha.label,
        "directive": linha.directive,
        "args": list(linha.args),
        "section": linha.section,
        "func": linha.func,
    }
    if args.json:
        _emit_json(
            {"schema": "asmx-explain/1", "command": "explain", "source": fonte.to_dict(), **detalhe}
        )
    else:
        _write(
            "%s %s"
            % (
                palette.paint("linha %d" % linha.n, "titulo"),
                palette.paint("(%s)" % linha.kind, "fraco"),
            )
        )
        _write("  %s" % linha.text)
        if linha.label:
            _write("  rótulo %s%s" % (linha.label, " (local)" if linha.local_label else ""))
        if linha.directive:
            _write(
                "  diretiva %s%s"
                % (
                    linha.directive.upper(),
                    (
                        " · reserva %s byte(s)" % linha.unit
                        if linha.reserve
                        else " · %d byte(s) por item" % linha.unit
                    ),
                )
            )
    return EXIT_OK


def _explain_mnemonic(mnemonic: str, as_json: bool, palette: Palette) -> int:
    """Mostra a documentação de um mnemônico do acervo.

    Args:
        mnemonic: Nome da instrução (``mov``, ``syscall``...).
        as_json: Se a saída deve ser JSON.
        palette: Paleta de cores.

    Returns:
        :data:`EXIT_OK`.

    Raises:
        UnknownMnemonicError: Quando o acervo não documenta a instrução.
    """
    chave = mnemonic.strip().lower()
    doc = ISA.get(chave)
    if doc is None:
        raise UnknownMnemonicError(mnemonic, len(ISA))
    if as_json:
        _emit_json(
            {
                "schema": "asmx-explain/1",
                "command": "explain",
                "kind": "mnemonic",
                "mnemonic": chave,
                "documentation": doc,
            }
        )
        return EXIT_OK
    categoria = CATEGORIES.get(doc["cat"], {"label": doc["cat"]})
    _write(
        "%s  %s"
        % (
            palette.paint(chave.upper(), "titulo"),
            palette.paint("· %s · %s" % (doc["name"], categoria["label"]), "fraco"),
        )
    )
    _write("  sintaxe  %s" % doc["syntax"])
    _write("  %s" % doc["desc"])
    if doc.get("ex"):
        _write("  exemplo")
        for exemplo in doc["ex"]:
            _write("    %s" % exemplo)
    _write("  flags    %s" % doc["flags"])
    if doc.get("note"):
        _write("  %s" % palette.paint(doc["note"], "fraco"))
    return EXIT_OK


def _print_instruction(ficha: Dict[str, Any], palette: Palette) -> None:
    """Imprime a ficha de uma instrução analisada.

    Args:
        ficha: Dicionário devolvido por :func:`describe_instruction`.
        palette: Paleta de cores.
    """
    _write(
        "%s %s"
        % (
            palette.paint("linha %d" % ficha["line"], "titulo"),
            palette.paint(str(ficha["mnemonic"]).upper(), "forte"),
        )
    )
    _write("  %s" % ficha["text"])
    _write("  %s — %s" % (palette.paint(ficha["label"], "bom"), ficha["detail"]))
    doc = ficha.get("documentation")
    if doc:
        _write("  sintaxe  %s" % doc["syntax"])
        _write("  flags    %s" % doc["flags"])
        if doc.get("note"):
            _write("  %s" % palette.paint(doc["note"], "fraco"))


def cmd_info(args: argparse.Namespace, config: SandboxConfig, palette: Palette) -> int:
    """Executa o comando ``info``.

    Args:
        args: Namespace do comando.
        config: Configuração em vigor.
        palette: Paleta de cores da saída.

    Returns:
        :data:`EXIT_OK`.
    """
    try:
        import tkinter  # noqa: F401

        tem_tk = True
        versao_tk: Optional[str] = str(tkinter.TkVersion)
    except ImportError:
        tem_tk = False
        versao_tk = None
    estado: LoggingState = configure_logging()
    dados = {
        "schema": "asmx-info/1",
        "command": "info",
        "version": __version__,
        "python": _platform.python_version(),
        "tkinter": {"available": tem_tk, "version": versao_tk},
        "platform": _platform.system().lower(),
        "isa": {
            "mnemonics": len(ISA),
            "categories": len(CATEGORIES),
            "linux_syscalls": len(LINUX_SYSCALLS),
            "windows_apis": len(WIN_APIS),
            "validation_rules": len(ALL_CHECKS),
            "examples": len(EXAMPLES),
        },
        "config": config.to_dict(),
        "logging": estado.to_dict(),
    }
    if args.json:
        _emit_json(dados)
        return EXIT_OK
    _write("%s %s" % (palette.paint("ASM X", "titulo"), __version__))
    _write(
        "  python %s · tkinter %s"
        % (
            dados["python"],
            (
                versao_tk
                if tem_tk
                else palette.paint("indisponível (só a linha de comando funciona)", "alerta")
            ),
        )
    )
    _write(
        "  acervo: %d instruções · %d categorias · %d syscalls Linux · %d APIs do Windows"
        % (len(ISA), len(CATEGORIES), len(LINUX_SYSCALLS), len(WIN_APIS))
    )
    _write("  validação: %d regras · exemplos: %d" % (len(ALL_CHECKS), len(EXAMPLES)))
    _write("  configuração: %s" % config.describe())
    _write("  log: %s · json=%s" % (estado.level, estado.json_output))
    return EXIT_OK


def cmd_examples(args: argparse.Namespace, config: SandboxConfig, palette: Palette) -> int:
    """Executa o comando ``examples``.

    Args:
        args: Namespace do comando.
        config: Configuração em vigor.
        palette: Paleta de cores da saída.

    Returns:
        :data:`EXIT_OK`.

    Raises:
        EmulationError: Nome de exemplo inexistente.
    """
    nomes = sorted(EXAMPLES)
    if args.show:
        if args.show not in EXAMPLES:
            raise EmulationError(
                "exemplo desconhecido: %s (disponíveis: %s)" % (args.show, ", ".join(nomes))
            )
        _write(EXAMPLES[args.show]["code"])
        return EXIT_OK
    if args.dump:
        os.makedirs(args.dump, exist_ok=True)
        caminhos = []
        for nome in nomes:
            caminho = os.path.join(args.dump, "%s.asm" % nome)
            with open(caminho, "w", encoding="utf-8") as arquivo:
                arquivo.write(render(nome))
            caminhos.append(caminho)
        log_event(logger, "examples_dumped", directory=args.dump, count=len(nomes))
        if args.json:
            _emit_json(
                {
                    "schema": "asmx-examples/1",
                    "command": "examples",
                    "directory": args.dump,
                    "files": caminhos,
                }
            )
        else:
            _write(palette.paint("%d exemplos gravados em %s" % (len(nomes), args.dump), "bom"))
        return EXIT_OK
    if args.json:
        _emit_json(
            {
                "schema": "asmx-examples/1",
                "command": "examples",
                "examples": [
                    {
                        "name": n,
                        "title": EXAMPLES[n]["title"],
                        "lines": EXAMPLES[n]["code"].count("\n") + 1,
                    }
                    for n in nomes
                ],
            }
        )
        return EXIT_OK
    for nome in nomes:
        _write("%s %s" % (palette.paint("%-14s" % nome, "forte"), EXAMPLES[nome]["title"]))
    _write("")
    _write(
        palette.paint(
            "use --show NOME para ver o código ou --dump DIRETÓRIO " "para gravar todos", "fraco"
        )
    )
    return EXIT_OK


def cmd_version(args: argparse.Namespace, config: SandboxConfig, palette: Palette) -> int:
    """Executa o comando ``version``.

    Args:
        args: Namespace do comando.
        config: Configuração em vigor.
        palette: Paleta de cores da saída.

    Returns:
        :data:`EXIT_OK`.
    """
    if getattr(args, "json", False):
        _emit_json(
            {
                "schema": "asmx-version/1",
                "command": "version",
                "version": __version__,
                "python": _platform.python_version(),
            }
        )
    else:
        _write("ASM X %s" % __version__)
    return EXIT_OK


#: Comandos disponíveis, ligados às funções que os executam.
COMMANDS: Dict[str, Callable[[argparse.Namespace, SandboxConfig, Palette], int]] = {
    "check": cmd_check,
    "run": cmd_run,
    "explain": cmd_explain,
    "info": cmd_info,
    "examples": cmd_examples,
    "version": cmd_version,
}


def launch_gui() -> int:
    """Abre a interface gráfica, se o Tkinter e um display existirem.

    Returns:
        :data:`EXIT_OK` quando a janela fecha normalmente,
        :data:`EXIT_INPUT` quando não há Tkinter ou display.
    """
    try:
        from .ui import main as ui_main
    except ImportError as erro:
        sys.stderr.write(
            "a interface gráfica precisa do Tkinter, que não está instalado (%s).\n"
            "  Debian/Ubuntu:  sudo apt install python3-tk\n"
            "  Fedora:         sudo dnf install python3-tkinter\n"
            "  Windows/macOS:  reinstale o Python marcando 'tcl/tk'\n"
            "os comandos de linha de comando continuam disponíveis: asmx --help\n" % erro
        )
        return EXIT_INPUT
    try:
        ui_main()
    except Exception as erro:  # pragma: no cover - depende de display real
        sys.stderr.write("não consegui abrir a janela: %s\n" % erro)
        return EXIT_INPUT
    return EXIT_OK


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Ponto de entrada da linha de comando.

    Sem argumentos (chamada real do sistema) abre a interface gráfica; com
    ``argv`` explícito, exige um comando — o que mantém os testes previsíveis.

    Args:
        argv: Argumentos sem o nome do programa; ``None`` usa ``sys.argv[1:]``.

    Returns:
        O código de saída do processo (veja o topo do módulo).
    """
    chamada_real = argv is None
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if getattr(args, "gui", False) or (chamada_real and not args.command):
        return launch_gui()
    if not args.command:
        parser.print_help()
        return EXIT_USAGE

    palette = _palette(args)
    try:
        config = load_config(args)
    except AsmxError as erro:
        sys.stderr.write("%s\n" % palette.paint(str(erro), "erro"))
        return EXIT_INPUT
    # No terminal o padrão é falar pouco: o resultado é a saída do comando.
    # -v traz INFO/DEBUG, -q cala até os erros.
    config.apply_logging(force=True)
    configure_logging(
        "DEBUG" if args.verbose else ("ERROR" if args.quiet else "WARNING"),
        json_output=config.log_json,
        log_file=config.log_file,
        force=True,
    )

    log_event(logger, "command_started", level=10, **build_payload(args))
    try:
        codigo = COMMANDS[args.command](args, config, palette)
    except (
        SourceNotFoundError,
        SourceReadError,
        UnsupportedSourceError,
        ConfigError,
        UnknownMnemonicError,
        LineNotFoundError,
        EmulationError,
    ) as erro:
        log_event(logger, "command_input_error", level=40, code=erro.code, detail=erro.message)
        sys.stderr.write("%s\n" % palette.paint(str(erro), "erro"))
        return EXIT_INPUT
    except AnalysisTimeoutError as erro:
        log_event(logger, "command_timeout", level=40, timeout=erro.timeout, steps=erro.steps)
        sys.stderr.write("%s\n" % palette.paint(str(erro), "erro"))
        return EXIT_TIMEOUT
    except AsmxError as erro:
        log_event(logger, "command_failed", level=40, code=erro.code, detail=erro.message)
        sys.stderr.write("%s\n" % palette.paint(str(erro), "erro"))
        return EXIT_INPUT
    except KeyboardInterrupt:  # pragma: no cover - interação do usuário
        sys.stderr.write("\ninterrompido\n")
        return 130
    log_event(logger, "command_finished", exit_code=codigo)
    return codigo
