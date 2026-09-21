"""ASM X — ambiente de estudo e depuração de assembly x86-64.

A ideia é simples: ler o assembly e explicar o que ele faz antes de qualquer
ferramenta pesada entrar no caminho. O pacote é dividido em camadas que não
dependem uma da outra de baixo para cima:

    isa        base de instruções, registradores, flags, syscalls
    parser     leitura do fonte (NASM/Intel, MASM, GAS/AT&T)
    analyzer   plataforma, semântica por instrução, blocos e fluxo
    emulator   máquina virtual passo a passo
    linter     validação estática (o que pode quebrar antes de rodar)
    workspace  projeto, branches, anotações e cenários de teste
    config     configuração (arquivo, ambiente, padrões)
    errors     exceções com código estável
    source     leitura de arquivos com hash e codificação
    cli        linha de comando
    ui         interface gráfica em Tkinter

Nada aqui depende de biblioteca externa: só a biblioteca padrão do Python.

Example:
    >>> import asmx
    >>> analise = asmx.analyze("mov rax, 1\\nsyscall")
    >>> analise.stats["instructions"]
    2
    >>> asmx.summary(asmx.validate(analise))
    '0 erro(s), 2 alerta(s), 0 informação(ões)'
"""

from __future__ import annotations

from typing import Tuple

__version__ = "1.0.0"

#: Versão quebrada em números, para comparação.
__version_info__: Tuple[int, int, int] = (1, 0, 0)

from .analyzer import Analysis, analyze, callers_of, functions  # noqa: E402
from .config import SandboxConfig  # noqa: E402
from .emulator import Machine, Step  # noqa: E402
from .errors import ERROR_CODES, AsmxError  # noqa: E402
from .linter import Problem, summary, validate  # noqa: E402
from .logging_setup import configure_logging, get_logger, log_event  # noqa: E402
from .parser import Line, Operand, Program, parse  # noqa: E402
from .source import SourceFile, read_source  # noqa: E402
from .workspace import (  # noqa: E402
    Branch,
    Project,
    Scenario,
    ScenarioResult,
    run_all_scenarios,
    run_scenario,
)

__all__ = [
    "__version__",
    "__version_info__",
    "Analysis",
    "AsmxError",
    "Branch",
    "ERROR_CODES",
    "Line",
    "Machine",
    "Operand",
    "Problem",
    "Program",
    "Project",
    "SandboxConfig",
    "Scenario",
    "ScenarioResult",
    "SourceFile",
    "Step",
    "analyze",
    "callers_of",
    "configure_logging",
    "functions",
    "get_logger",
    "log_event",
    "parse",
    "read_source",
    "run_all_scenarios",
    "run_scenario",
    "summary",
    "validate",
]
