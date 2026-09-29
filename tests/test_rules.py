"""Tests for the signature rule engine (:mod:`asmx.rules`).

The engine is data-driven, so most of the work here is checking that bad rule
files are rejected with a useful message, that every condition type really
matches (and really refuses to match), and that the rule set shipped with the
package stays sane — an id typo or a rule without a description would otherwise
only show up when a user ran it.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from asmx.analyzer import analyze
from asmx.errors import ConfigError, ProjectError
from asmx.examples import EXAMPLES
from asmx.linter import validate
from asmx.rules import (
    RULES_SCHEMA,
    SEVERITIES,
    Rule,
    RuleMatch,
    default_rules_dir,
    known_mnemonics,
    load_rule_file,
    load_rules,
    match_rules,
    match_text,
    rule_files,
    severity_rank,
    summary,
    validate_rule,
)

CONDICAO_MINIMA = {"strings": ["nop"]}


def regra(**campos: object) -> dict:
    """Builds a raw rule mapping with sensible defaults."""
    base = {"id": "TST001", "name": "Test rule", "severity": "medium", "match": CONDICAO_MINIMA}
    base.update(campos)
    return base


def escrever(tmp: str, nome: str, dados: object) -> str:
    """Writes a rule file inside a temporary directory and returns its path."""
    caminho = os.path.join(tmp, nome)
    with open(caminho, "w", encoding="utf-8") as arquivo:
        if isinstance(dados, str):
            arquivo.write(dados)
        else:
            json.dump(dados, arquivo)
    return caminho


class TestValidacao(unittest.TestCase):
    """A bad rule file must fail loudly, naming the rule and the field."""

    def test_regra_minima_valida(self) -> None:
        regra_pronta = validate_rule(regra(), source="memoria.json")
        self.assertEqual(regra_pronta.id, "TST001")
        self.assertEqual(regra_pronta.severity, "medium")
        self.assertEqual(regra_pronta.source, "memoria.json")

    def test_severidade_padrao_e_medium(self) -> None:
        self.assertEqual(
            validate_rule({"id": "X", "name": "Y", "match": CONDICAO_MINIMA}).severity, "medium"
        )

    def test_sem_id_ou_nome(self) -> None:
        for campo in ("id", "name"):
            with self.subTest(campo=campo):
                with self.assertRaises(ConfigError) as capturado:
                    validate_rule(regra(**{campo: "   "}))
                self.assertIn("id or name", str(capturado.exception))

    def test_severidade_desconhecida(self) -> None:
        with self.assertRaises(ConfigError) as capturado:
            validate_rule(regra(severity="urgente"))
        self.assertIn("unknown severity", str(capturado.exception))
        self.assertIn("high", str(capturado.exception))

    def test_match_precisa_ser_objeto(self) -> None:
        with self.assertRaises(ConfigError) as capturado:
            validate_rule(regra(match=["strings"]))
        self.assertIn("'match' must be an object", str(capturado.exception))

    def test_chave_desconhecida_no_match(self) -> None:
        with self.assertRaises(ConfigError) as capturado:
            validate_rule(regra(match={"syscall": ["open"]}))
        self.assertIn("unknown match key syscall", str(capturado.exception))

    def test_match_vazio_nunca_dispararia(self) -> None:
        with self.assertRaises(ConfigError) as capturado:
            validate_rule(regra(match={"require_all": True}))
        self.assertIn("no usable condition", str(capturado.exception))

    def test_any_of_precisa_de_lista_de_objetos(self) -> None:
        with self.assertRaises(ConfigError) as capturado:
            validate_rule(regra(match={"any_of": []}))
        self.assertIn("non-empty list", str(capturado.exception))
        with self.assertRaises(ConfigError) as capturado:
            validate_rule(regra(match={"any_of": [{"syscalls": ["open"]}, "connect"]}))
        self.assertIn("at least one condition", str(capturado.exception))

    def test_any_of_aceita_chave_desconhecida(self) -> None:
        with self.assertRaises(ConfigError) as capturado:
            validate_rule(regra(match={"any_of": [{"syscall": ["open"]}]}))
        self.assertIn("inside 'any_of'", str(capturado.exception))

    def test_any_of_sozinho_e_valido(self) -> None:
        pronta = validate_rule(
            regra(match={"any_of": [{"syscalls": ["open"]}, {"apis": ["CreateFileA"]}]})
        )
        self.assertIn("any_of", pronta.match)

    def test_tags_e_mitre_viram_tuplas(self) -> None:
        pronta = validate_rule(regra(tags=["network"], mitre=["t1071"]))
        self.assertEqual(pronta.tags, ("network",))
        self.assertEqual(pronta.mitre, ("T1071",))

    def test_to_dict_serializa(self) -> None:
        dados = validate_rule(regra(tags=["a"], mitre=["T1"]), source="x.json").to_dict()
        self.assertEqual(dados["tags"], ["a"])
        self.assertEqual(dados["mitre"], ["T1"])
        self.assertEqual(dados["source"], "x.json")
        self.assertIn("match", dados)


class TestArquivos(unittest.TestCase):
    """Reading rule files: JSON always, YAML when PyYAML is around."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_le_json(self) -> None:
        caminho = escrever(self.tmp.name, "a.json", {"rules": [regra()]})
        self.assertEqual([r.id for r in load_rule_file(caminho)], ["TST001"])

    def test_lista_solta_e_aceita(self) -> None:
        caminho = escrever(self.tmp.name, "a.json", [regra(id="A"), regra(id="B")])
        self.assertEqual([r.id for r in load_rule_file(caminho)], ["A", "B"])

    def test_json_invalido(self) -> None:
        caminho = escrever(self.tmp.name, "a.json", "{ this is not json }")
        with self.assertRaises(ConfigError) as capturado:
            load_rule_file(caminho)
        self.assertIn("invalid rule file", str(capturado.exception))

    def test_arquivo_sem_lista_rules(self) -> None:
        caminho = escrever(self.tmp.name, "a.json", {"schema": RULES_SCHEMA})
        with self.assertRaises(ConfigError) as capturado:
            load_rule_file(caminho)
        self.assertIn("no 'rules' list", str(capturado.exception))

    def test_rules_precisa_ser_lista(self) -> None:
        caminho = escrever(self.tmp.name, "a.json", {"rules": {"id": "X"}})
        with self.assertRaises(ConfigError) as capturado:
            load_rule_file(caminho)
        self.assertIn("must be a list", str(capturado.exception))

    def test_arquivo_inexistente(self) -> None:
        with self.assertRaises(ConfigError) as capturado:
            load_rule_file(os.path.join(self.tmp.name, "nao-existe.json"))
        self.assertIn("rule file not found", str(capturado.exception))

    def test_arquivo_vazio_e_erro(self) -> None:
        """A truncated file must fail loudly instead of silently loading nothing."""
        caminho = escrever(self.tmp.name, "vazio.json", "")
        with self.assertRaises(ConfigError) as capturado:
            load_rule_file(caminho)
        self.assertIn("invalid rule file", str(capturado.exception))

    def test_documento_que_nao_e_objeto(self) -> None:
        caminho = escrever(self.tmp.name, "numero.json", "42")
        with self.assertRaises(ConfigError) as capturado:
            load_rule_file(caminho)
        self.assertIn("must contain an object or a list", str(capturado.exception))

    def test_yaml_depende_do_pyyaml(self) -> None:
        try:
            import yaml  # noqa: F401
        except ImportError:
            caminho = escrever(self.tmp.name, "a.yaml", "rules: []\n")
            with self.assertRaises(ConfigError) as capturado:
                load_rule_file(caminho)
            self.assertIn("PyYAML", str(capturado.exception))
        else:
            caminho = escrever(
                self.tmp.name,
                "a.yaml",
                "rules:\n  - id: Y1\n    name: Y\n    match:\n      strings: [nop]\n",
            )
            self.assertEqual([r.id for r in load_rule_file(caminho)], ["Y1"])

    def test_rule_files_lista_e_ignora_pasta_ausente(self) -> None:
        escrever(self.tmp.name, "a.json", {"rules": []})
        escrever(self.tmp.name, "b.txt", "nada")
        self.assertEqual([os.path.basename(p) for p in rule_files(self.tmp.name)], ["a.json"])
        self.assertEqual(rule_files(os.path.join(self.tmp.name, "nao-existe")), [])

    def test_load_rules_de_pasta(self) -> None:
        escrever(self.tmp.name, "a.json", {"rules": [regra(id="A")]})
        escrever(self.tmp.name, "b.json", {"rules": [regra(id="B")]})
        self.assertEqual([r.id for r in load_rules(directory=self.tmp.name)], ["A", "B"])

    def test_id_repetido_fica_com_o_primeiro(self) -> None:
        escrever(self.tmp.name, "a.json", {"rules": [regra(id="A", name="first")]})
        escrever(self.tmp.name, "b.json", {"rules": [regra(id="A", name="second")]})
        regras = load_rules(directory=self.tmp.name)
        self.assertEqual(len(regras), 1)
        self.assertEqual(regras[0].name, "first")

    def test_pasta_sem_regras(self) -> None:
        with self.assertRaises(ProjectError) as capturado:
            load_rules(directory=self.tmp.name)
        self.assertIn("no rule file found", str(capturado.exception))

    def test_lista_explicita_de_arquivos(self) -> None:
        caminho = escrever(self.tmp.name, "a.json", {"rules": [regra(id="A")]})
        self.assertEqual([r.id for r in load_rules([caminho])], ["A"])


class TestCasamento(unittest.TestCase):
    """Every condition type must match when it should and refuse when it should not."""

    def rodar(self, condicao: dict, codigo: str) -> list:
        """Runs a single ad-hoc rule against a source and returns the matches."""
        pronta = validate_rule(regra(match=condicao))
        return match_rules([pronta], analyze(codigo), text=codigo)

    def test_casa_por_syscall(self) -> None:
        codigo = "mov rax, 41\nsyscall"
        self.assertTrue(self.rodar({"syscalls": ["socket"]}, codigo))
        self.assertFalse(self.rodar({"syscalls": ["connect"]}, codigo))

    def test_casa_por_api_externa(self) -> None:
        codigo = "extern ExitProcess\ncall ExitProcess"
        self.assertTrue(self.rodar({"apis": ["ExitProcess"]}, codigo))
        self.assertFalse(self.rodar({"apis": ["CreateFileA"]}, codigo))

    def test_casa_por_mnemonico(self) -> None:
        self.assertTrue(self.rodar({"mnemonics": ["div"]}, "mov rax, 4\nxor rdx, rdx\ndiv rbx"))

    def test_casa_por_secao(self) -> None:
        codigo = "section .data\nsection .text\n_start:"
        self.assertTrue(self.rodar({"sections": [".data"]}, codigo))
        self.assertTrue(self.rodar({"sections": ["data"]}, codigo))
        self.assertFalse(self.rodar({"sections": [".bss"]}, codigo))

    def test_casa_por_comportamento(self) -> None:
        codigo = EXAMPLES["suspicious"]["code"]
        self.assertTrue(self.rodar({"behaviors": ["network"]}, codigo))
        self.assertFalse(self.rodar({"behaviors": ["self-modifying"]}, codigo))

    def test_casa_por_codigo_de_problema(self) -> None:
        codigo = EXAMPLES["broken"]["code"]
        self.assertTrue(self.rodar({"problems": ["DIV001"]}, codigo))
        self.assertFalse(self.rodar({"problems": ["STR002"]}, codigo))

    def test_expressao_regular_e_sensivel_a_caixa_quando_pedido(self) -> None:
        codigo = 'msg db "MALWARE", 0'
        self.assertTrue(self.rodar({"strings": ["malware"]}, codigo))
        self.assertFalse(self.rodar({"strings": ["malware"], "case_sensitive": True}, codigo))

    def test_strings_min(self) -> None:
        codigo = 'a db "alpha", 0'
        self.assertFalse(self.rodar({"strings": ["alpha", "beta"], "strings_min": 2}, codigo))
        self.assertTrue(self.rodar({"strings": ["alpha", "beta"], "strings_min": 1}, codigo))

    def test_require_all(self) -> None:
        codigo = "mov rax, 41\nsyscall\nmov rax, 42\nsyscall"
        # socket is used, connect is not: require_all refuses, the default accepts
        self.assertFalse(
            self.rodar({"syscalls": ["socket", "ptrace"], "require_all": True}, codigo)
        )
        self.assertTrue(self.rodar({"syscalls": ["socket", "ptrace"]}, codigo))
        self.assertTrue(
            self.rodar({"syscalls": ["socket", "connect"], "require_all": True}, codigo)
        )

    def test_limiares_numericos(self) -> None:
        codigo = "nop\nnop\nnop"
        self.assertTrue(self.rodar({"min_instructions": 3, "strings": ["nop"]}, codigo))
        self.assertFalse(self.rodar({"min_instructions": 4, "strings": ["nop"]}, codigo))

    def test_min_blocks_e_min_syscalls(self) -> None:
        codigo = "cmp rax, 1\nje fim\nmov rax, 60\nsyscall\nfim:\nret"
        self.assertTrue(self.rodar({"min_blocks": 2, "min_syscalls": 1}, codigo))
        self.assertFalse(self.rodar({"min_blocks": 9, "min_syscalls": 1}, codigo))

    def test_min_strings_conta_declaracoes_de_dados(self) -> None:
        codigo = 'section .data\na db "x", 0\nb db "y", 0\nsection .text\n_start:'
        self.assertTrue(self.rodar({"min_strings": 2}, codigo))
        self.assertFalse(self.rodar({"min_strings": 3}, codigo))

    def test_limiar_invalido(self) -> None:
        with self.assertRaises(ConfigError):
            self.rodar({"min_instructions": "muitas", "strings": ["nop"]}, "nop")

    def test_regex_invalida(self) -> None:
        with self.assertRaises(ConfigError):
            self.rodar({"strings": ["[sem-fechar"]}, "nop")

    def test_any_of_casa_um_dos_grupos(self) -> None:
        codigo = "mov rax, 41\nsyscall"
        condicao = {"any_of": [{"apis": ["CreateFileA"]}, {"syscalls": ["socket"]}]}
        self.assertTrue(self.rodar(condicao, codigo))

    def test_any_of_recusa_quando_nenhum_grupo_casa(self) -> None:
        condicao = {"any_of": [{"apis": ["CreateFileA"]}, {"syscalls": ["ptrace"]}]}
        self.assertFalse(self.rodar(condicao, "mov rax, 41\nsyscall"))

    def test_any_of_combina_com_and(self) -> None:
        codigo = "mov rax, 41\nsyscall"
        condicao = {"mnemonics": ["syscall"], "any_of": [{"syscalls": ["socket"]}]}
        self.assertTrue(self.rodar(condicao, codigo))
        condicao = {"mnemonics": ["div"], "any_of": [{"syscalls": ["socket"]}]}
        self.assertFalse(self.rodar(condicao, codigo))

    def test_evidencia_traz_linha(self) -> None:
        codigo = "nop\nnop\nmov rax, 41\nsyscall"
        achados = self.rodar({"syscalls": ["socket"]}, codigo)
        self.assertIn(4, achados[0].lines)
        self.assertTrue(any("line 4" in e for e in achados[0].evidence))

    def test_linhas_unicas_e_ordenadas(self) -> None:
        codigo = 'section .data\na db "socket", 0\nsection .text\nmov rax, 41\nsyscall'
        achados = self.rodar({"strings": ["socket"], "syscalls": ["socket"]}, codigo)
        self.assertEqual(list(achados[0].lines), sorted(set(achados[0].lines)))

    def test_ordena_por_severidade(self) -> None:
        baixa = validate_rule(regra(id="Z", severity="low", match={"strings": ["nop"]}))
        alta = validate_rule(regra(id="A", severity="high", match={"strings": ["nop"]}))
        achados = match_rules([baixa, alta], analyze("nop"), text="nop")
        self.assertEqual([m.rule_id for m in achados], ["A", "Z"])

    def test_to_dict_do_match(self) -> None:
        achados = self.rodar({"strings": ["nop"]}, "nop")
        dados = achados[0].to_dict()
        self.assertEqual(dados["evidence"], list(achados[0].evidence))
        self.assertEqual(dados["lines"], list(achados[0].lines))

    def test_deterministico(self) -> None:
        codigo = EXAMPLES["suspicious"]["code"]
        regras = load_rules()
        primeira = [
            (m.rule_id, m.evidence) for m in match_rules(regras, analyze(codigo), text=codigo)
        ]
        segunda = [
            (m.rule_id, m.evidence) for m in match_rules(regras, analyze(codigo), text=codigo)
        ]
        self.assertEqual(primeira, segunda)


class TestAPI(unittest.TestCase):
    """The convenience layer used by the CLI, the report and the library."""

    def test_match_text_com_regras_proprias(self) -> None:
        pronta = validate_rule(regra(id="X", match={"strings": ["beacon"]}))
        achados = match_text('url db "beacon"', [pronta])
        self.assertEqual([m.rule_id for m in achados], ["X"])

    def test_match_text_sem_regras(self) -> None:
        self.assertEqual(match_text("nop", []), [])

    def test_match_text_com_pasta_inexistente(self) -> None:
        self.assertEqual(match_text("nop", directory="/caminho/que/nao/existe"), [])

    def test_match_text_usa_o_ruleset_padrao(self) -> None:
        achados = match_text(EXAMPLES["suspicious"]["code"])
        self.assertTrue(any(m.rule_id.startswith("NET") for m in achados))

    def test_summary(self) -> None:
        self.assertEqual(summary([]), "0 rule(s) matched")
        alta = RuleMatch("A", "a", "high")
        baixa = RuleMatch("B", "b", "low")
        self.assertEqual(summary([alta, baixa]), "2 rule(s) matched: 1 high, 1 low")

    def test_severity_rank(self) -> None:
        self.assertLess(severity_rank("high"), severity_rank("medium"))
        self.assertLess(severity_rank("medium"), severity_rank("low"))
        self.assertEqual(severity_rank("desconhecida"), 3)
        self.assertEqual(severity_rank("HIGH"), 0)

    def test_known_mnemonics(self) -> None:
        mnemonics = list(known_mnemonics())
        self.assertIn("mov", mnemonics)
        self.assertIn("syscall", mnemonics)

    def test_problemas_podem_ser_passados_prontos(self) -> None:
        codigo = EXAMPLES["broken"]["code"]
        analise = analyze(codigo)
        problemas = validate(analise)
        pronta = validate_rule(regra(id="P", match={"problems": ["DIV001"]}))
        self.assertTrue(match_rules([pronta], analise, problems=problemas, text=codigo))

    def test_rule_to_dict_redondo(self) -> None:
        dados = validate_rule(regra()).to_dict()
        self.assertEqual(
            set(dados),
            {"id", "name", "severity", "description", "tags", "mitre", "match", "source"},
        )
        self.assertIsInstance(
            Rule(**{**{k: v for k, v in dados.items() if k != "tags"}}, tags=()), Rule
        )

    def test_objeto_rule_aceita_campos_minimos(self) -> None:
        self.assertEqual(Rule("A", "a", "low").severity, "low")


class TestRulesetEmpacotado(unittest.TestCase):
    """The rules that ship with the package must be usable and honest."""

    def setUp(self) -> None:
        self.regras = load_rules()

    def test_carrega_o_ruleset_do_pacote(self) -> None:
        self.assertTrue(os.path.isdir(default_rules_dir()))
        self.assertGreaterEqual(len(self.regras), 20)

    def test_ids_unicos_e_severidade_valida(self) -> None:
        ids = [r.id for r in self.regras]
        self.assertEqual(len(ids), len(set(ids)))
        for regra_pronta in self.regras:
            with self.subTest(regra=regra_pronta.id):
                self.assertIn(regra_pronta.severity, SEVERITIES)

    def test_toda_regra_explica_o_que_faz(self) -> None:
        for regra_pronta in self.regras:
            with self.subTest(regra=regra_pronta.id):
                self.assertGreater(len(regra_pronta.description), 40)
                self.assertTrue(regra_pronta.tags)
                self.assertTrue(regra_pronta.source.endswith(".json"))

    def test_mitre_bem_formado(self) -> None:
        for regra_pronta in self.regras:
            for tecnica in regra_pronta.mitre:
                with self.subTest(regra=regra_pronta.id, tecnica=tecnica):
                    self.assertRegex(tecnica, r"^T\d{4}(\.\d{3})?$")

    def test_mnemonics_das_regras_existem(self) -> None:
        catalogo = set(known_mnemonics())
        for regra_pronta in self.regras:
            for mnemonic in regra_pronta.match.get("mnemonics", []):
                with self.subTest(regra=regra_pronta.id, mnemonic=mnemonic):
                    self.assertIn(mnemonic, catalogo)

    def test_exemplos_limpos_nao_disparam(self) -> None:
        for nome in ("linux-hello", "linux-loop", "windows-hello", "bubble", "gcc-att"):
            with self.subTest(exemplo=nome):
                self.assertEqual(match_text(EXAMPLES[nome]["code"], self.regras), [])

    def test_exemplo_suspeito_dispara_rede_e_impacto(self) -> None:
        achados = match_text(EXAMPLES["suspicious"]["code"], self.regras)
        ids = {m.rule_id for m in achados}
        self.assertIn("NET001", ids)
        self.assertIn("NET002", ids)
        severidades = {m.severity for m in achados}
        self.assertIn("high", severidades)

    def test_comentario_nao_conta_como_string(self) -> None:
        codigo = "; socket connect /etc/passwd\nnop"
        self.assertEqual(match_text(codigo, self.regras), [])

    def test_json_do_ruleset_tem_schema(self) -> None:
        for caminho in rule_files():
            with open(caminho, encoding="utf-8") as arquivo:
                self.assertEqual(json.load(arquivo)["schema"], RULES_SCHEMA)


if __name__ == "__main__":
    unittest.main()
