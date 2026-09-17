"""ASM X — ambiente de estudo e depuração de assembly x86-64.

Módulos:
    isa        base de instruções, registradores, flags, syscalls
    parser     leitura do fonte (NASM/Intel, MASM, GAS/AT&T)
    analyzer   plataforma, semântica por instrução, blocos e fluxo
    emulator   máquina virtual passo a passo
    linter     validação estática (o que pode quebrar)
    workspace  projeto, branches, anotações e cenários de teste
    ui         interface gráfica em Tkinter
"""

__version__ = "1.0.0"

from .analyzer import analyze                      # noqa: F401
from .emulator import Machine                      # noqa: F401
from .linter import validate, summary              # noqa: F401
from .workspace import Project, Scenario, run_scenario, run_all_scenarios  # noqa: F401
