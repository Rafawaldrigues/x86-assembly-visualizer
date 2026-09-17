"""Gerenciamento de projeto: branches do mesmo assembly, anotações e cenários.

Um projeto é um único arquivo .asmproj (JSON) que guarda todas as variações do
código, as anotações de cada linha, os breakpoints e os cenários de teste.
"""

import copy
import datetime
import difflib
import json
import os
import re
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

from .analyzer import analyze
from .emulator import Machine
from .isa import REG_INFO
from .parser import parse_number


def _now() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


@dataclass
class Scenario:
    """Um teste: estado inicial + expectativa de resultado."""
    name: str
    entry: str = ""                       # rótulo onde começar ("" = ponto de entrada)
    regs: Dict[str, str] = field(default_factory=dict)
    stdin: str = ""
    expect_output: Optional[str] = None
    expect_exit: Optional[int] = None
    expect_issue: bool = False            # o teste passa se a execução acusar problema
    max_steps: int = 200000

    def to_dict(self):
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "Scenario":
        return Scenario(**{k: v for k, v in d.items() if k in Scenario.__annotations__})


@dataclass
class ScenarioResult:
    scenario: str
    passed: bool
    output: str
    exit_code: Optional[int]
    steps: int
    issues: List[str]
    reason: str = ""


@dataclass
class Branch:
    name: str
    code: str = ""
    parent: Optional[str] = None
    created: str = field(default_factory=_now)
    notes: Dict[str, str] = field(default_factory=dict)      # "12" -> texto
    breakpoints: List[int] = field(default_factory=list)
    scenarios: List[Scenario] = field(default_factory=list)

    def to_dict(self):
        d = asdict(self)
        d["scenarios"] = [s.to_dict() for s in self.scenarios]
        return d

    @staticmethod
    def from_dict(d: dict) -> "Branch":
        b = Branch(name=d.get("name", "principal"), code=d.get("code", ""),
                   parent=d.get("parent"), created=d.get("created", _now()),
                   notes={str(k): v for k, v in (d.get("notes") or {}).items()},
                   breakpoints=list(d.get("breakpoints") or []))
        b.scenarios = [Scenario.from_dict(s) for s in (d.get("scenarios") or [])]
        return b


class Project:
    """Coleção de branches do mesmo programa."""

    FORMAT = "asmx-project/1"

    def __init__(self, name: str = "projeto", path: Optional[str] = None):
        self.name = name
        self.path = path
        self.branches: Dict[str, Branch] = {}
        self.active: str = "principal"
        self.dirty = False

    # ------------------------------------------------------------ básico --
    @classmethod
    def new(cls, code: str = "", name: str = "projeto") -> "Project":
        p = cls(name=name)
        p.branches["principal"] = Branch(name="principal", code=code)
        p.active = "principal"
        return p

    @property
    def branch(self) -> Branch:
        if self.active not in self.branches:
            self.active = next(iter(self.branches))
        return self.branches[self.active]

    @property
    def code(self) -> str:
        return self.branch.code

    def set_code(self, code: str):
        if self.branch.code != code:
            self.branch.code = code
            self.dirty = True

    # ---------------------------------------------------------- branches --
    def fork(self, new_name: str, from_branch: Optional[str] = None) -> Branch:
        src_name = from_branch or self.active
        if src_name not in self.branches:
            raise KeyError("branch de origem inexistente: %s" % src_name)
        if not new_name.strip():
            raise ValueError("a branch precisa de um nome")
        if new_name in self.branches:
            raise ValueError("já existe uma branch chamada %s" % new_name)
        src = self.branches[src_name]
        b = Branch(name=new_name, code=src.code, parent=src_name,
                   notes=dict(src.notes), breakpoints=list(src.breakpoints),
                   scenarios=copy.deepcopy(src.scenarios))
        self.branches[new_name] = b
        self.dirty = True
        return b

    def switch(self, name: str):
        if name not in self.branches:
            raise KeyError("branch inexistente: %s" % name)
        self.active = name

    def delete_branch(self, name: str):
        if name not in self.branches:
            raise KeyError("branch inexistente: %s" % name)
        if len(self.branches) == 1:
            raise ValueError("o projeto precisa de pelo menos uma branch")
        del self.branches[name]
        for b in self.branches.values():
            if b.parent == name:
                b.parent = None
        if self.active == name:
            self.active = next(iter(self.branches))
        self.dirty = True

    def rename_branch(self, old: str, new: str):
        if old not in self.branches:
            raise KeyError("branch inexistente: %s" % old)
        if new in self.branches:
            raise ValueError("já existe uma branch chamada %s" % new)
        b = self.branches.pop(old)
        b.name = new
        self.branches[new] = b
        for other in self.branches.values():
            if other.parent == old:
                other.parent = new
        if self.active == old:
            self.active = new
        self.dirty = True

    def diff(self, a: str, b: str) -> str:
        ca = self.branches[a].code.splitlines()
        cb = self.branches[b].code.splitlines()
        return "\n".join(difflib.unified_diff(ca, cb, fromfile=a, tofile=b, lineterm=""))

    # ---------------------------------------------------------- anotações -
    def set_note(self, line: int, text: str):
        key = str(line)
        if text.strip():
            self.branch.notes[key] = text.strip()
        else:
            self.branch.notes.pop(key, None)
        self.dirty = True

    def note(self, line: int) -> str:
        return self.branch.notes.get(str(line), "")

    def toggle_breakpoint(self, line: int) -> bool:
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
    def add_scenario(self, scenario: Scenario):
        nomes = [s.name for s in self.branch.scenarios]
        if scenario.name in nomes:
            self.branch.scenarios[nomes.index(scenario.name)] = scenario
        else:
            self.branch.scenarios.append(scenario)
        self.dirty = True

    def remove_scenario(self, name: str):
        self.branch.scenarios = [s for s in self.branch.scenarios if s.name != name]
        self.dirty = True

    # ----------------------------------------------------- persistência ---
    def to_dict(self) -> dict:
        return {"format": self.FORMAT, "name": self.name, "active": self.active,
                "saved": _now(),
                "branches": {k: v.to_dict() for k, v in self.branches.items()}}

    def save(self, path: Optional[str] = None) -> str:
        target = path or self.path
        if not target:
            raise ValueError("nenhum caminho definido para salvar")
        with open(target, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, ensure_ascii=False, indent=1)
        self.path = target
        self.name = os.path.splitext(os.path.basename(target))[0]
        self.dirty = False
        return target

    @classmethod
    def load(cls, path: str) -> "Project":
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        p = cls(name=data.get("name") or os.path.splitext(os.path.basename(path))[0], path=path)
        for key, bd in (data.get("branches") or {}).items():
            bd.setdefault("name", key)
            p.branches[key] = Branch.from_dict(bd)
        if not p.branches:
            p.branches["principal"] = Branch(name="principal")
        p.active = data.get("active") or next(iter(p.branches))
        if p.active not in p.branches:
            p.active = next(iter(p.branches))
        p.dirty = False
        return p

    @classmethod
    def from_asm_file(cls, path: str) -> "Project":
        with open(path, encoding="utf-8", errors="replace") as f:
            code = f.read()
        p = cls.new(code=code, name=os.path.splitext(os.path.basename(path))[0])
        return p

    def export_asm(self, path: str) -> str:
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.code)
        return path


# ------------------------------------------------------ execução de teste -
def parse_reg_values(text: str) -> Dict[str, int]:
    """Aceita 'rax=10, rbx=0x20' e devolve {'rax': 10, 'rbx': 32}."""
    out = {}
    for part in re.split(r"[,;\n]", text or ""):
        m = re.match(r"^\s*(\w+)\s*=\s*(-?[\w]+)\s*$", part)
        if m and m.group(1).lower() in REG_INFO:
            out[m.group(1).lower()] = parse_number(m.group(2))
    return out


def run_scenario(code: str, scenario: Scenario) -> ScenarioResult:
    analysis = analyze(code)
    machine = Machine(analysis, stdin=scenario.stdin,
                      entry=scenario.entry or None)
    for reg, value in scenario.regs.items():
        if isinstance(value, str):
            value = parse_number(value)
        machine.set_reg(reg.lower(), value)
    machine.run(limit=scenario.max_steps)

    passed, reason = True, "estado final dentro do esperado"
    if scenario.expect_output is not None and machine.output != scenario.expect_output:
        passed = False
        reason = "saída diferente: esperava %r, obteve %r" % (scenario.expect_output, machine.output)
    elif scenario.expect_exit is not None and machine.exit_code != scenario.expect_exit:
        passed = False
        reason = "código de saída %s, esperava %s" % (machine.exit_code, scenario.expect_exit)
    elif scenario.expect_issue and not machine.issues:
        passed = False
        reason = "esperava que a execução acusasse algum problema, mas nada foi detectado"
    elif not scenario.expect_issue and machine.issues:
        passed = False
        reason = "a execução acusou: " + "; ".join(machine.issues[:3])

    return ScenarioResult(scenario=scenario.name, passed=passed, output=machine.output,
                          exit_code=machine.exit_code, steps=machine.steps,
                          issues=list(machine.issues), reason=reason)


def run_all_scenarios(code: str, scenarios: List[Scenario]) -> List[ScenarioResult]:
    return [run_scenario(code, s) for s in scenarios]
