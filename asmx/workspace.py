"""Gerenciamento de projeto: branches do mesmo assembly, anotações e cenários.

Um projeto é um único arquivo ``.asmproj`` (JSON) que guarda todas as variações
do código, as anotações de cada linha, os breakpoints e os cenários de teste.
Nada disso vive dentro do ``.asm``: o fonte continua limpo, pronto para o
montador de verdade, e o histórico de estudo fica no projeto.

Example:
    >>> from asmx.workspace import Project, Scenario
    >>> projeto = Project.new(code="mov rax, 1", name="teste")
    >>> projeto.fork("experimento").parent
    'principal'
    >>> projeto.set_note(1, "aqui começa")
    >>> projeto.note(1)
    'aqui começa'
"""

from __future__ import annotations

import copy
import datetime
import difflib
import json
import os
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from .analyzer import analyze
from .emulator import Machine
from .errors import (
    BranchExistsError,
    BranchNotFoundError,
    EmptyBranchNameError,
    LastBranchError,
    ProjectError,
    ProjectFormatError,
    ScenarioError,
    SourceNotFoundError,
    SourceReadError,
    SourceWriteError,
)
from .isa import REG_INFO
from .logging_setup import get_logger, log_event
from .parser import parse_number

logger = get_logger(__name__)

#: Marca gravada no arquivo de projeto, para recusar arquivo de outro programa.
FORMAT = "asmx-project/1"


def _now() -> str:
    """Devolve a data e hora atuais no formato usado no projeto.

    Returns:
        Texto como ``2026-09-21 18:04:11``.
    """
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


@dataclass
class Scenario:
    """Um teste: estado inicial + expectativa de resultado.

    Attributes:
        name: Nome do cenário, único dentro da branch.
        entry: Rótulo onde a execução começa (``""`` = ponto de entrada).
        regs: Registradores iniciais, como texto (``{"rdi": "0x20"}``).
        stdin: Entrada simulada entregue à syscall ``read``.
        expect_output: Saída esperada; ``None`` não verifica.
        expect_exit: Código de saída esperado; ``None`` não verifica.
        expect_issue: Quando ``True``, o teste passa se a execução acusar
            algum problema (estouro, laço infinito, divisão por zero...).
        max_steps: Limite de instruções executadas.
        timeout: Tempo máximo de parede em segundos; ``None`` não limita.
    """

    name: str
    entry: str = ""  # rótulo onde começar ("" = ponto de entrada)
    regs: Dict[str, str] = field(default_factory=dict)
    stdin: str = ""
    expect_output: Optional[str] = None
    expect_exit: Optional[int] = None
    expect_issue: bool = False  # o teste passa se a execução acusar problema
    max_steps: int = 200000
    timeout: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        """Converte o cenário em dicionário pronto para JSON.

        Returns:
            Todos os campos do cenário em tipos simples.
        """
        return asdict(self)

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Scenario":
        """Recria o cenário a partir do dicionário gravado no projeto.

        Campos desconhecidos (de versões futuras) são ignorados, o que permite
        abrir um projeto mais novo sem quebrar.

        Args:
            d: Dicionário lido do arquivo ``.asmproj``.

        Returns:
            O :class:`Scenario` correspondente.
        """
        return Scenario(**{k: v for k, v in d.items() if k in Scenario.__annotations__})


@dataclass
class ScenarioResult:
    """Resultado da execução de um cenário.

    Attributes:
        scenario: Nome do cenário executado.
        passed: Se o resultado bateu com o esperado.
        output: Saída produzida pelo programa.
        exit_code: Código de saída, quando houve.
        steps: Quantas instruções foram executadas.
        issues: Problemas detectados durante a execução.
        reason: Explicação legível, principalmente quando falhou.
    """

    scenario: str
    passed: bool
    output: str
    exit_code: Optional[int]
    steps: int
    issues: List[str]
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Converte o resultado em dicionário pronto para JSON.

        Returns:
            Todos os campos do resultado em tipos simples.
        """
        return asdict(self)


@dataclass
class Branch:
    """Uma variação do programa dentro do projeto.

    Attributes:
        name: Nome da branch.
        code: Código fonte desta variação.
        parent: Nome da branch de onde ela nasceu (``None`` na raiz).
        created: Data de criação, como texto.
        notes: Anotações por linha (``"12"`` -> texto).
        breakpoints: Linhas marcadas como breakpoint.
        scenarios: Cenários de teste desta branch.
    """

    name: str
    code: str = ""
    parent: Optional[str] = None
    created: str = field(default_factory=_now)
    notes: Dict[str, str] = field(default_factory=dict)  # "12" -> texto
    breakpoints: List[int] = field(default_factory=list)
    scenarios: List[Scenario] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Converte a branch (com os cenários) em dicionário.

        Returns:
            Dicionário com todos os campos da branch.
        """
        d = asdict(self)
        d["scenarios"] = [s.to_dict() for s in self.scenarios]
        return d

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Branch":
        """Recria a branch a partir do dicionário do projeto.

        Args:
            d: Dicionário lido do arquivo ``.asmproj``.

        Returns:
            O :class:`Branch` correspondente, com notas e breakpoints normais.
        """
        b = Branch(
            name=d.get("name", "principal"),
            code=d.get("code", ""),
            parent=d.get("parent"),
            created=d.get("created", _now()),
            notes={str(k): v for k, v in (d.get("notes") or {}).items()},
            breakpoints=list(d.get("breakpoints") or []),
        )
        b.scenarios = [Scenario.from_dict(s) for s in (d.get("scenarios") or [])]
        return b


class Project:
    """Coleção de branches do mesmo programa.

    Attributes:
        name: Nome do projeto (vem do nome do arquivo ao salvar).
        path: Caminho do ``.asmproj``; ``None`` enquanto nunca foi salvo.
        branches: Branches por nome.
        active: Nome da branch em edição.
        dirty: Se há alteração ainda não salva.
    """

    FORMAT = FORMAT

    def __init__(self, name: str = "projeto", path: Optional[str] = None) -> None:
        """Cria um projeto vazio.

        Args:
            name: Nome do projeto.
            path: Caminho do arquivo de projeto, quando já se sabe qual é.
        """
        self.name = name
        self.path = path
        self.branches: Dict[str, Branch] = {}
        self.active: str = "principal"
        self.dirty = False

    # ------------------------------------------------------------ básico --
    @classmethod
    def new(cls, code: str = "", name: str = "projeto") -> "Project":
        """Cria um projeto com uma branch ``principal``.

        Args:
            code: Código inicial.
            name: Nome do projeto.

        Returns:
            O projeto pronto para uso, sem alterações pendentes.

        Example:
            >>> Project.new(code="mov rax, 1").code
            'mov rax, 1'
        """
        p = cls(name=name)
        p.branches["principal"] = Branch(name="principal", code=code)
        p.active = "principal"
        return p

    @property
    def branch(self) -> Branch:
        """Branch em edição.

        Returns:
            A :class:`Branch` ativa; se o nome ativo sumiu, devolve a primeira.
        """
        if self.active not in self.branches:
            self.active = next(iter(self.branches))
        return self.branches[self.active]

    @property
    def code(self) -> str:
        """Código da branch em edição.

        Returns:
            O texto do fonte da branch ativa.
        """
        return self.branch.code

    def set_code(self, code: str) -> None:
        """Troca o código da branch ativa e marca o projeto como alterado.

        Args:
            code: Novo texto do fonte.
        """
        if self.branch.code != code:
            self.branch.code = code
            self.dirty = True

    # ---------------------------------------------------------- branches --
    def fork(self, new_name: str, from_branch: Optional[str] = None) -> Branch:
        """Cria uma branch copiando outra.

        Args:
            new_name: Nome da branch nova.
            from_branch: Branch de origem (padrão: a ativa).

        Returns:
            A branch recém-criada.

        Raises:
            BranchNotFoundError: Se a origem não existe.
            EmptyBranchNameError: Se o nome está vazio.
            BranchExistsError: Se já existe branch com esse nome.

        Example:
            >>> projeto = Project.new(code="mov rax, 1")
            >>> projeto.fork("alt").code
            'mov rax, 1'
        """
        src_name = from_branch or self.active
        if src_name not in self.branches:
            raise BranchNotFoundError(src_name)
        if not new_name.strip():
            raise EmptyBranchNameError()
        if new_name in self.branches:
            raise BranchExistsError(new_name)
        src = self.branches[src_name]
        b = Branch(
            name=new_name,
            code=src.code,
            parent=src_name,
            notes=dict(src.notes),
            breakpoints=list(src.breakpoints),
            scenarios=copy.deepcopy(src.scenarios),
        )
        self.branches[new_name] = b
        self.dirty = True
        log_event(
            logger,
            "branch_forked",
            branch=new_name,
            parent=src_name,
            lines=src.code.count("\n") + 1,
        )
        return b

    def switch(self, name: str) -> None:
        """Passa a editar outra branch.

        Args:
            name: Nome da branch de destino.

        Raises:
            BranchNotFoundError: Se a branch não existe.
        """
        if name not in self.branches:
            raise BranchNotFoundError(name)
        self.active = name
        log_event(logger, "branch_switched", level=10, branch=name)

    def delete_branch(self, name: str) -> None:
        """Apaga uma branch, deixando as filhas sem pai.

        Args:
            name: Nome da branch a apagar.

        Raises:
            BranchNotFoundError: Se a branch não existe.
            LastBranchError: Se é a única branch do projeto.
        """
        if name not in self.branches:
            raise BranchNotFoundError(name)
        if len(self.branches) == 1:
            raise LastBranchError()
        del self.branches[name]
        for b in self.branches.values():
            if b.parent == name:
                b.parent = None
        if self.active == name:
            self.active = next(iter(self.branches))
        self.dirty = True
        log_event(logger, "branch_deleted", branch=name, remaining=len(self.branches))

    def rename_branch(self, old: str, new: str) -> None:
        """Renomeia uma branch e reaponta as filhas.

        Args:
            old: Nome atual.
            new: Nome novo.

        Raises:
            BranchNotFoundError: Se ``old`` não existe.
            BranchExistsError: Se ``new`` já está em uso.
        """
        if old not in self.branches:
            raise BranchNotFoundError(old)
        if new in self.branches:
            raise BranchExistsError(new)
        b = self.branches.pop(old)
        b.name = new
        self.branches[new] = b
        for other in self.branches.values():
            if other.parent == old:
                other.parent = new
        if self.active == old:
            self.active = new
        self.dirty = True
        log_event(logger, "branch_renamed", old=old, new=new)

    def diff(self, a: str, b: str) -> str:
        """Compara o código de duas branches.

        Args:
            a: Nome da branch de origem.
            b: Nome da branch de destino.

        Returns:
            O diff unificado, como o de ``diff -u``.

        Raises:
            BranchNotFoundError: Se alguma das branches não existe.

        Example:
            >>> projeto = Project.new(code="mov rax, 1")
            >>> _ = projeto.fork("alt")
            >>> projeto.switch("alt")
            >>> projeto.set_code("mov rax, 2")
            >>> "+mov rax, 2" in projeto.diff("principal", "alt")
            True
        """
        for nome in (a, b):
            if nome not in self.branches:
                raise BranchNotFoundError(nome)
        ca = self.branches[a].code.splitlines()
        cb = self.branches[b].code.splitlines()
        return "\n".join(difflib.unified_diff(ca, cb, fromfile=a, tofile=b, lineterm=""))

    # ---------------------------------------------------------- anotações -
    def set_note(self, line: int, text: str) -> None:
        """Grava (ou apaga) a anotação de uma linha da branch ativa.

        Args:
            line: Número da linha anotada.
            text: Texto da anotação; vazio remove a anotação.
        """
        key = str(line)
        if text.strip():
            self.branch.notes[key] = text.strip()
        else:
            self.branch.notes.pop(key, None)
        self.dirty = True

    def note(self, line: int) -> str:
        """Devolve a anotação de uma linha.

        Args:
            line: Número da linha.

        Returns:
            O texto anotado, ou string vazia.
        """
        return self.branch.notes.get(str(line), "")

    def toggle_breakpoint(self, line: int) -> bool:
        """Liga ou desliga o breakpoint de uma linha.

        Args:
            line: Número da linha.

        Returns:
            ``True`` se o breakpoint ficou ligado, ``False`` se saiu.
        """
        bps = self.branch.breakpoints
        if line in bps:
            bps.remove(line)
            active = False
        else:
            bps.append(line)
            bps.sort()
            active = True
        self.dirty = True
        return active

    # ----------------------------------------------------------- cenários -
    def add_scenario(self, scenario: Scenario) -> None:
        """Adiciona (ou substitui, pelo nome) um cenário na branch ativa.

        Args:
            scenario: Cenário a guardar.
        """
        nomes = [s.name for s in self.branch.scenarios]
        if scenario.name in nomes:
            self.branch.scenarios[nomes.index(scenario.name)] = scenario
        else:
            self.branch.scenarios.append(scenario)
        self.dirty = True
        log_event(logger, "scenario_saved", scenario=scenario.name, branch=self.active)

    def remove_scenario(self, name: str) -> None:
        """Remove um cenário da branch ativa.

        Args:
            name: Nome do cenário.
        """
        self.branch.scenarios = [s for s in self.branch.scenarios if s.name != name]
        self.dirty = True

    def scenario(self, name: str) -> Scenario:
        """Busca um cenário pelo nome.

        Args:
            name: Nome do cenário.

        Returns:
            O cenário encontrado.

        Raises:
            ScenarioError: Se a branch ativa não tem cenário com esse nome.
        """
        for s in self.branch.scenarios:
            if s.name == name:
                return s
        raise ScenarioError("cenário não encontrado: %s" % name, scenario=name)

    # ----------------------------------------------------- persistência ---
    def to_dict(self) -> Dict[str, Any]:
        """Converte o projeto inteiro em dicionário.

        Returns:
            Dicionário com formato, nome, branch ativa e todas as branches.
        """
        return {
            "format": self.FORMAT,
            "name": self.name,
            "active": self.active,
            "saved": _now(),
            "branches": {k: v.to_dict() for k, v in self.branches.items()},
        }

    def save(self, path: Optional[str] = None) -> str:
        """Grava o projeto em disco.

        Args:
            path: Destino; sem ele, usa o caminho já conhecido.

        Returns:
            O caminho gravado.

        Raises:
            ProjectError: Se nenhum caminho foi definido.
            SourceWriteError: Se a gravação falhou.
        """
        target = path or self.path
        if not target:
            raise ProjectError("nenhum caminho definido para salvar")
        try:
            with open(target, "w", encoding="utf-8") as f:
                json.dump(self.to_dict(), f, ensure_ascii=False, indent=1)
        except OSError as erro:
            raise SourceWriteError(target, str(erro)) from erro
        self.path = target
        self.name = os.path.splitext(os.path.basename(target))[0]
        self.dirty = False
        log_event(logger, "project_saved", path=target, branches=len(self.branches))
        return target

    @classmethod
    def load(cls, path: str) -> "Project":
        """Lê um projeto gravado.

        Args:
            path: Caminho do arquivo ``.asmproj``.

        Returns:
            O projeto carregado, com a branch ativa restaurada.

        Raises:
            SourceNotFoundError: Se o arquivo não existe.
            SourceReadError: Se não pôde ser lido.
            ProjectFormatError: Se o JSON é inválido ou não é um projeto do
                ASM X.
        """
        if not os.path.exists(path):
            raise SourceNotFoundError(path)
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except OSError as erro:
            raise SourceReadError(path, str(erro)) from erro
        except json.JSONDecodeError as erro:
            raise ProjectFormatError(
                path, "JSON inválido na linha %d: %s" % (erro.lineno, erro.msg)
            ) from erro
        if not isinstance(data, dict):
            raise ProjectFormatError(path, "o conteúdo precisa ser um objeto JSON")
        marca = data.get("format")
        if marca and not str(marca).startswith("asmx-project/"):
            raise ProjectFormatError(path, "formato desconhecido: %s" % marca)

        p = cls(name=data.get("name") or os.path.splitext(os.path.basename(path))[0], path=path)
        for key, bd in (data.get("branches") or {}).items():
            if not isinstance(bd, dict):
                raise ProjectFormatError(path, "branch %s não é um objeto" % key)
            bd.setdefault("name", key)
            p.branches[key] = Branch.from_dict(bd)
        if not p.branches:
            p.branches["principal"] = Branch(name="principal")
        p.active = data.get("active") or next(iter(p.branches))
        if p.active not in p.branches:
            p.active = next(iter(p.branches))
        p.dirty = False
        log_event(logger, "project_loaded", path=path, branches=len(p.branches), active=p.active)
        return p

    @classmethod
    def from_asm_file(cls, path: str) -> "Project":
        """Cria um projeto a partir de um arquivo ``.asm`` solto.

        Args:
            path: Caminho do fonte.

        Returns:
            Projeto novo com uma branch ``principal`` contendo o código.

        Raises:
            SourceNotFoundError: Se o arquivo não existe.
            SourceReadError: Se não pôde ser lido.
        """
        with open(path, encoding="utf-8", errors="replace") as f:
            code = f.read()
        p = cls.new(code=code, name=os.path.splitext(os.path.basename(path))[0])
        log_event(logger, "project_imported", path=path, lines=code.count("\n") + 1)
        return p

    def export_asm(self, path: str) -> str:
        """Grava o código da branch ativa como ``.asm`` comum.

        Args:
            path: Destino.

        Returns:
            O caminho gravado.

        Raises:
            SourceWriteError: Se a gravação falhou.
        """
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.code)
        except OSError as erro:
            raise SourceWriteError(path, str(erro)) from erro
        log_event(logger, "branch_exported", path=path, branch=self.active)
        return path


# ------------------------------------------------------ execução de teste -
def parse_reg_values(text: str) -> Dict[str, int]:
    """Lê valores de registradores escritos como texto.

    Aceita ``rax=10, rbx=0x20``, separados por vírgula, ponto e vírgula ou
    quebra de linha. Nomes que não são registradores são ignorados.

    Args:
        text: Texto digitado pelo usuário.

    Returns:
        Dicionário ``nome -> valor`` com os registradores reconhecidos.

    Example:
        >>> parse_reg_values("rax=10, rbx=0x20")
        {'rax': 10, 'rbx': 32}
        >>> parse_reg_values("naoexiste=1")
        {}
    """
    out: Dict[str, int] = {}
    for part in re.split(r"[,;\n]", text or ""):
        m = re.match(r"^\s*(\w+)\s*=\s*(-?[\w]+)\s*$", part)
        if m and m.group(1).lower() in REG_INFO:
            out[m.group(1).lower()] = parse_number(m.group(2))
    return out


def run_scenario(code: str, scenario: Scenario) -> ScenarioResult:
    """Executa um cenário sobre um código e compara com o esperado.

    Args:
        code: Código fonte a executar.
        scenario: Cenário com estado inicial e expectativas.

    Returns:
        O :class:`ScenarioResult` com o que aconteceu e o motivo da reprovação.

    Raises:
        ScenarioError: Se o cenário aponta para um rótulo que não existe.

    Example:
        >>> from asmx.examples import EXAMPLES
        >>> cenario = Scenario(name="ola", expect_output="Ola, mundo!\\n")
        >>> run_scenario(EXAMPLES["linux-hello"]["code"], cenario).passed
        True
    """
    analysis = analyze(code)
    if scenario.entry and scenario.entry not in analysis.label_at:
        raise ScenarioError(
            "o cenário %s começa em %s, que não existe neste código"
            % (scenario.name, scenario.entry),
            scenario=scenario.name,
        )
    machine = Machine(analysis, stdin=scenario.stdin, entry=scenario.entry or None)
    for reg, value in scenario.regs.items():
        machine.set_reg(reg.lower(), parse_number(value) if isinstance(value, str) else value)
    machine.run(limit=scenario.max_steps, timeout=scenario.timeout)

    passed, reason = True, "estado final dentro do esperado"
    if machine.timed_out:
        passed = False
        reason = "a execução passou de %gs (timeout)" % (scenario.timeout or 0.0)
    elif scenario.expect_output is not None and machine.output != scenario.expect_output:
        passed = False
        reason = "saída diferente: esperava %r, obteve %r" % (
            scenario.expect_output,
            machine.output,
        )
    elif scenario.expect_exit is not None and machine.exit_code != scenario.expect_exit:
        passed = False
        reason = "código de saída %s, esperava %s" % (machine.exit_code, scenario.expect_exit)
    elif scenario.expect_issue and not machine.issues:
        passed = False
        reason = "esperava que a execução acusasse algum problema, mas nada foi detectado"
    elif not scenario.expect_issue and machine.issues:
        passed = False
        reason = "a execução acusou: " + "; ".join(machine.issues[:3])

    log_event(
        logger,
        "scenario_finished",
        level=10,
        scenario=scenario.name,
        passed=passed,
        steps=machine.steps,
        exit_code=machine.exit_code,
    )
    return ScenarioResult(
        scenario=scenario.name,
        passed=passed,
        output=machine.output,
        exit_code=machine.exit_code,
        steps=machine.steps,
        issues=list(machine.issues),
        reason=reason,
    )


def run_all_scenarios(code: str, scenarios: List[Scenario]) -> List[ScenarioResult]:
    """Executa uma lista de cenários em ordem.

    Args:
        code: Código fonte a executar.
        scenarios: Cenários a rodar.

    Returns:
        A lista de resultados, na mesma ordem dos cenários.

    Example:
        >>> from asmx.examples import EXAMPLES
        >>> cenarios = [Scenario(name="ok", expect_exit=0)]
        >>> run_all_scenarios(EXAMPLES["linux-hello"]["code"], cenarios)[0].passed
        True
    """
    resultados = [run_scenario(code, s) for s in scenarios]
    log_event(
        logger,
        "scenarios_finished",
        scenarios=len(resultados),
        passed=sum(1 for r in resultados if r.passed),
    )
    return resultados
