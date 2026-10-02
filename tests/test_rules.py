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

MINIMAL_CONDITION = {"strings": ["nop"]}


def rule_item(**fields: object) -> dict:
    """Builds a raw rule mapping with sensible defaults."""
    base = {"id": "TST001", "name": "Test rule", "severity": "medium", "match": MINIMAL_CONDITION}
    base.update(fields)
    return base


def write_fixture(tmp: str, item_name: str, values_data: object) -> str:
    """Writes a rule file inside a temporary directory and returns its path."""
    file_path = os.path.join(tmp, item_name)
    with open(file_path, "w", encoding="utf-8") as source_file:
        if isinstance(values_data, str):
            source_file.write(values_data)
        else:
            json.dump(values_data, source_file)
    return file_path


class TestValidation(unittest.TestCase):
    """A bad rule file must fail loudly, naming the rule and the field."""

    def test_minimal_rule_validates(self) -> None:
        validated_rule = validate_rule(rule_item(), source="memory.json")
        self.assertEqual(validated_rule.id, "TST001")
        self.assertEqual(validated_rule.severity, "medium")
        self.assertEqual(validated_rule.source, "memory.json")

    def test_default_severity_is_medium(self) -> None:
        self.assertEqual(
            validate_rule({"id": "X", "name": "Y", "match": MINIMAL_CONDITION}).severity, "medium"
        )

    def test_missing_id_or_name(self) -> None:
        for field in ("id", "name"):
            with self.subTest(field=field):
                with self.assertRaises(ConfigError) as caught:
                    validate_rule(rule_item(**{field: "   "}))
                self.assertIn("id or name", str(caught.exception))

    def test_unknown_severity(self) -> None:
        with self.assertRaises(ConfigError) as caught:
            validate_rule(rule_item(severity="urgent"))
        self.assertIn("unknown severity", str(caught.exception))
        self.assertIn("high", str(caught.exception))

    def test_match_must_be_object(self) -> None:
        with self.assertRaises(ConfigError) as caught:
            validate_rule(rule_item(match=["strings"]))
        self.assertIn("'match' must be an object", str(caught.exception))

    def test_unknown_match_key(self) -> None:
        with self.assertRaises(ConfigError) as caught:
            validate_rule(rule_item(match={"syscall": ["open"]}))
        self.assertIn("unknown match key syscall", str(caught.exception))

    def test_empty_match_is_rejected(self) -> None:
        with self.assertRaises(ConfigError) as caught:
            validate_rule(rule_item(match={"require_all": True}))
        self.assertIn("no usable condition", str(caught.exception))

    def test_any_of_requires_object_list(self) -> None:
        with self.assertRaises(ConfigError) as caught:
            validate_rule(rule_item(match={"any_of": []}))
        self.assertIn("non-empty list", str(caught.exception))
        with self.assertRaises(ConfigError) as caught:
            validate_rule(rule_item(match={"any_of": [{"syscalls": ["open"]}, "connect"]}))
        self.assertIn("at least one condition", str(caught.exception))

    def test_any_of_rejects_unknown_key(self) -> None:
        with self.assertRaises(ConfigError) as caught:
            validate_rule(rule_item(match={"any_of": [{"syscall": ["open"]}]}))
        self.assertIn("inside 'any_of'", str(caught.exception))

    def test_any_of_alone_is_valid(self) -> None:
        validated = validate_rule(
            rule_item(match={"any_of": [{"syscalls": ["open"]}, {"apis": ["CreateFileA"]}]})
        )
        self.assertIn("any_of", validated.match)

    def test_tags_and_mitre_become_tuples(self) -> None:
        validated = validate_rule(rule_item(tags=["network"], mitre=["t1071"]))
        self.assertEqual(validated.tags, ("network",))
        self.assertEqual(validated.mitre, ("T1071",))

    def test_to_dict_serializes(self) -> None:
        values_data = validate_rule(rule_item(tags=["a"], mitre=["T1"]), source="x.json").to_dict()
        self.assertEqual(values_data["tags"], ["a"])
        self.assertEqual(values_data["mitre"], ["T1"])
        self.assertEqual(values_data["source"], "x.json")
        self.assertIn("match", values_data)


class TestFiles(unittest.TestCase):
    """Reading rule files: JSON always, YAML when PyYAML is around."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_reads_json(self) -> None:
        file_path = write_fixture(self.tmp.name, "a.json", {"rules": [rule_item()]})
        self.assertEqual([r.id for r in load_rule_file(file_path)], ["TST001"])

    def test_bare_list_is_accepted(self) -> None:
        file_path = write_fixture(self.tmp.name, "a.json", [rule_item(id="A"), rule_item(id="B")])
        self.assertEqual([r.id for r in load_rule_file(file_path)], ["A", "B"])

    def test_invalid_json(self) -> None:
        file_path = write_fixture(self.tmp.name, "a.json", "{ this is not json }")
        with self.assertRaises(ConfigError) as caught:
            load_rule_file(file_path)
        self.assertIn("invalid rule file", str(caught.exception))

    def test_file_without_rules_list(self) -> None:
        file_path = write_fixture(self.tmp.name, "a.json", {"schema": RULES_SCHEMA})
        with self.assertRaises(ConfigError) as caught:
            load_rule_file(file_path)
        self.assertIn("no 'rules' list", str(caught.exception))

    def test_rules_must_be_list(self) -> None:
        file_path = write_fixture(self.tmp.name, "a.json", {"rules": {"id": "X"}})
        with self.assertRaises(ConfigError) as caught:
            load_rule_file(file_path)
        self.assertIn("must be a list", str(caught.exception))

    def test_missing_file(self) -> None:
        with self.assertRaises(ConfigError) as caught:
            load_rule_file(os.path.join(self.tmp.name, "does-not-exist.json"))
        self.assertIn("rule file not found", str(caught.exception))

    def test_empty_file_is_error(self) -> None:
        """A truncated file must fail loudly instead of silently loading nothing."""
        file_path = write_fixture(self.tmp.name, "empty_state.json", "")
        with self.assertRaises(ConfigError) as caught:
            load_rule_file(file_path)
        self.assertIn("invalid rule file", str(caught.exception))

    def test_non_object_document(self) -> None:
        file_path = write_fixture(self.tmp.name, "numero.json", "42")
        with self.assertRaises(ConfigError) as caught:
            load_rule_file(file_path)
        self.assertIn("must contain an object or a list", str(caught.exception))

    def test_yaml_requires_pyyaml(self) -> None:
        try:
            import yaml  # noqa: F401
        except ImportError:
            file_path = write_fixture(self.tmp.name, "a.yaml", "rules: []\n")
            with self.assertRaises(ConfigError) as caught:
                load_rule_file(file_path)
            self.assertIn("PyYAML", str(caught.exception))
        else:
            file_path = write_fixture(
                self.tmp.name,
                "a.yaml",
                "rules:\n  - id: Y1\n    name: Y\n    match:\n      strings: [nop]\n",
            )
            self.assertEqual([r.id for r in load_rule_file(file_path)], ["Y1"])

    def test_rule_files_ignores_missing_directory(self) -> None:
        write_fixture(self.tmp.name, "a.json", {"rules": []})
        write_fixture(self.tmp.name, "b.txt", "nothing")
        self.assertEqual([os.path.basename(p) for p in rule_files(self.tmp.name)], ["a.json"])
        self.assertEqual(rule_files(os.path.join(self.tmp.name, "does-not-exist")), [])

    def test_load_rules_from_directory(self) -> None:
        write_fixture(self.tmp.name, "a.json", {"rules": [rule_item(id="A")]})
        write_fixture(self.tmp.name, "b.json", {"rules": [rule_item(id="B")]})
        self.assertEqual([r.id for r in load_rules(directory=self.tmp.name)], ["A", "B"])

    def test_duplicate_id_keeps_first(self) -> None:
        write_fixture(self.tmp.name, "a.json", {"rules": [rule_item(id="A", name="first")]})
        write_fixture(self.tmp.name, "b.json", {"rules": [rule_item(id="A", name="second")]})
        rule_items = load_rules(directory=self.tmp.name)
        self.assertEqual(len(rule_items), 1)
        self.assertEqual(rule_items[0].name, "first")

    def test_directory_without_rules(self) -> None:
        with self.assertRaises(ProjectError) as caught:
            load_rules(directory=self.tmp.name)
        self.assertIn("no rule file found", str(caught.exception))

    def test_explicit_file_list(self) -> None:
        file_path = write_fixture(self.tmp.name, "a.json", {"rules": [rule_item(id="A")]})
        self.assertEqual([r.id for r in load_rules([file_path])], ["A"])


class TestMatching(unittest.TestCase):
    """Every condition type must match when it should and refuse when it should not."""

    def match_source(self, condition_data: dict, status_code: str) -> list:
        """Runs a single ad-hoc rule against a source and returns the matches."""
        validated = validate_rule(rule_item(match=condition_data))
        return match_rules([validated], analyze(status_code), text=status_code)

    def test_matches_syscall(self) -> None:
        status_code = "mov rax, 41\nsyscall"
        self.assertTrue(self.match_source({"syscalls": ["socket"]}, status_code))
        self.assertFalse(self.match_source({"syscalls": ["connect"]}, status_code))

    def test_matches_external_api(self) -> None:
        status_code = "extern ExitProcess\ncall ExitProcess"
        self.assertTrue(self.match_source({"apis": ["ExitProcess"]}, status_code))
        self.assertFalse(self.match_source({"apis": ["CreateFileA"]}, status_code))

    def test_matches_mnemonic(self) -> None:
        self.assertTrue(
            self.match_source({"mnemonics": ["div"]}, "mov rax, 4\nxor rdx, rdx\ndiv rbx")
        )

    def test_matches_section(self) -> None:
        status_code = "section .data\nsection .text\n_start:"
        self.assertTrue(self.match_source({"sections": [".data"]}, status_code))
        self.assertTrue(self.match_source({"sections": ["data"]}, status_code))
        self.assertFalse(self.match_source({"sections": [".bss"]}, status_code))

    def test_matches_behavior(self) -> None:
        status_code = EXAMPLES["suspicious"]["code"]
        self.assertTrue(self.match_source({"behaviors": ["network"]}, status_code))
        self.assertFalse(self.match_source({"behaviors": ["self-modifying"]}, status_code))

    def test_matches_problem_code(self) -> None:
        status_code = EXAMPLES["broken"]["code"]
        self.assertTrue(self.match_source({"problems": ["DIV001"]}, status_code))
        self.assertFalse(self.match_source({"problems": ["STR002"]}, status_code))

    def test_regex_case_sensitivity(self) -> None:
        status_code = 'msg db "MALWARE", 0'
        self.assertTrue(self.match_source({"strings": ["malware"]}, status_code))
        self.assertFalse(
            self.match_source({"strings": ["malware"], "case_sensitive": True}, status_code)
        )

    def test_strings_min(self) -> None:
        status_code = 'a db "alpha", 0'
        self.assertFalse(
            self.match_source({"strings": ["alpha", "beta"], "strings_min": 2}, status_code)
        )
        self.assertTrue(
            self.match_source({"strings": ["alpha", "beta"], "strings_min": 1}, status_code)
        )

    def test_require_all(self) -> None:
        status_code = "mov rax, 41\nsyscall\nmov rax, 42\nsyscall"
        # socket is used, connect is not: require_all refuses, the default accepts
        self.assertFalse(
            self.match_source({"syscalls": ["socket", "ptrace"], "require_all": True}, status_code)
        )
        self.assertTrue(self.match_source({"syscalls": ["socket", "ptrace"]}, status_code))
        self.assertTrue(
            self.match_source({"syscalls": ["socket", "connect"], "require_all": True}, status_code)
        )

    def test_numeric_thresholds(self) -> None:
        status_code = "nop\nnop\nnop"
        self.assertTrue(self.match_source({"min_instructions": 3, "strings": ["nop"]}, status_code))
        self.assertFalse(
            self.match_source({"min_instructions": 4, "strings": ["nop"]}, status_code)
        )

    def test_block_and_syscall_minimums(self) -> None:
        status_code = "cmp rax, 1\nje fim\nmov rax, 60\nsyscall\nfim:\nret"
        self.assertTrue(self.match_source({"min_blocks": 2, "min_syscalls": 1}, status_code))
        self.assertFalse(self.match_source({"min_blocks": 9, "min_syscalls": 1}, status_code))

    def test_min_strings_counts_data_declarations(self) -> None:
        status_code = 'section .data\na db "x", 0\nb db "y", 0\nsection .text\n_start:'
        self.assertTrue(self.match_source({"min_strings": 2}, status_code))
        self.assertFalse(self.match_source({"min_strings": 3}, status_code))

    def test_invalid_threshold(self) -> None:
        with self.assertRaises(ConfigError):
            self.match_source({"min_instructions": "muitas", "strings": ["nop"]}, "nop")

    def test_invalid_regex(self) -> None:
        with self.assertRaises(ConfigError):
            self.match_source({"strings": ["[sem-fechar"]}, "nop")

    def test_any_of_matches_one_group(self) -> None:
        status_code = "mov rax, 41\nsyscall"
        condition_data = {"any_of": [{"apis": ["CreateFileA"]}, {"syscalls": ["socket"]}]}
        self.assertTrue(self.match_source(condition_data, status_code))

    def test_any_of_rejects_when_no_group_matches(self) -> None:
        condition_data = {"any_of": [{"apis": ["CreateFileA"]}, {"syscalls": ["ptrace"]}]}
        self.assertFalse(self.match_source(condition_data, "mov rax, 41\nsyscall"))

    def test_any_of_combines_with_and(self) -> None:
        status_code = "mov rax, 41\nsyscall"
        condition_data = {"mnemonics": ["syscall"], "any_of": [{"syscalls": ["socket"]}]}
        self.assertTrue(self.match_source(condition_data, status_code))
        condition_data = {"mnemonics": ["div"], "any_of": [{"syscalls": ["socket"]}]}
        self.assertFalse(self.match_source(condition_data, status_code))

    def test_evidence_includes_line(self) -> None:
        status_code = "nop\nnop\nmov rax, 41\nsyscall"
        found_matches = self.match_source({"syscalls": ["socket"]}, status_code)
        self.assertIn(4, found_matches[0].lines)
        self.assertTrue(any("line 4" in e for e in found_matches[0].evidence))

    def test_unique_sorted_lines(self) -> None:
        status_code = 'section .data\na db "socket", 0\nsection .text\nmov rax, 41\nsyscall'
        found_matches = self.match_source(
            {"strings": ["socket"], "syscalls": ["socket"]}, status_code
        )
        self.assertEqual(list(found_matches[0].lines), sorted(set(found_matches[0].lines)))

    def test_sorts_by_severity(self) -> None:
        low_rule = validate_rule(rule_item(id="Z", severity="low", match={"strings": ["nop"]}))
        high_rule = validate_rule(rule_item(id="A", severity="high", match={"strings": ["nop"]}))
        found_matches = match_rules([low_rule, high_rule], analyze("nop"), text="nop")
        self.assertEqual([m.rule_id for m in found_matches], ["A", "Z"])

    def test_match_to_dict(self) -> None:
        found_matches = self.match_source({"strings": ["nop"]}, "nop")
        values_data = found_matches[0].to_dict()
        self.assertEqual(values_data["evidence"], list(found_matches[0].evidence))
        self.assertEqual(values_data["lines"], list(found_matches[0].lines))

    def test_deterministic(self) -> None:
        status_code = EXAMPLES["suspicious"]["code"]
        rule_items = load_rules()
        first_item = [
            (m.rule_id, m.evidence)
            for m in match_rules(rule_items, analyze(status_code), text=status_code)
        ]
        second_result = [
            (m.rule_id, m.evidence)
            for m in match_rules(rule_items, analyze(status_code), text=status_code)
        ]
        self.assertEqual(first_item, second_result)


class TestAPI(unittest.TestCase):
    """The convenience layer used by the CLI, the report and the library."""

    def test_match_text_with_custom_rules(self) -> None:
        validated = validate_rule(rule_item(id="X", match={"strings": ["beacon"]}))
        found_matches = match_text('url db "beacon"', [validated])
        self.assertEqual([m.rule_id for m in found_matches], ["X"])

    def test_match_text_without_rules(self) -> None:
        self.assertEqual(match_text("nop", []), [])

    def test_match_text_with_missing_directory(self) -> None:
        self.assertEqual(match_text("nop", directory="/nonexistent/rule-directory"), [])

    def test_match_text_uses_default_rules(self) -> None:
        found_matches = match_text(EXAMPLES["suspicious"]["code"])
        self.assertTrue(any(m.rule_id.startswith("NET") for m in found_matches))

    def test_summary(self) -> None:
        self.assertEqual(summary([]), "0 rule(s) matched")
        high_rule = RuleMatch("A", "a", "high")
        low_rule = RuleMatch("B", "b", "low")
        self.assertEqual(summary([high_rule, low_rule]), "2 rule(s) matched: 1 high, 1 low")

    def test_severity_rank(self) -> None:
        self.assertLess(severity_rank("high"), severity_rank("medium"))
        self.assertLess(severity_rank("medium"), severity_rank("low"))
        self.assertEqual(severity_rank("desconhecida"), 3)
        self.assertEqual(severity_rank("HIGH"), 0)

    def test_known_mnemonics(self) -> None:
        mnemonics = list(known_mnemonics())
        self.assertIn("mov", mnemonics)
        self.assertIn("syscall", mnemonics)

    def test_precomputed_problems(self) -> None:
        status_code = EXAMPLES["broken"]["code"]
        analysis_result = analyze(status_code)
        problems = validate(analysis_result)
        validated = validate_rule(rule_item(id="P", match={"problems": ["DIV001"]}))
        self.assertTrue(
            match_rules([validated], analysis_result, problems=problems, text=status_code)
        )

    def test_rule_to_dict_roundtrip(self) -> None:
        values_data = validate_rule(rule_item()).to_dict()
        self.assertEqual(
            set(values_data),
            {"id", "name", "severity", "description", "tags", "mitre", "match", "source"},
        )
        self.assertIsInstance(
            Rule(**{**{k: v for k, v in values_data.items() if k != "tags"}}, tags=()), Rule
        )

    def test_rule_accepts_minimal_fields(self) -> None:
        self.assertEqual(Rule("A", "a", "low").severity, "low")


class TestPackagedRules(unittest.TestCase):
    """The rules that ship with the package must be usable and honest."""

    def setUp(self) -> None:
        self.rule_items = load_rules()

    def test_loads_packaged_rules(self) -> None:
        self.assertTrue(os.path.isdir(default_rules_dir()))
        self.assertGreaterEqual(len(self.rule_items), 20)

    def test_unique_ids_valid_severity(self) -> None:
        ids = [r.id for r in self.rule_items]
        self.assertEqual(len(ids), len(set(ids)))
        for validated_rule in self.rule_items:
            with self.subTest(rule_item=validated_rule.id):
                self.assertIn(validated_rule.severity, SEVERITIES)

    def test_rules_have_descriptions(self) -> None:
        for validated_rule in self.rule_items:
            with self.subTest(rule_item=validated_rule.id):
                self.assertGreater(len(validated_rule.description), 40)
                self.assertTrue(validated_rule.tags)
                self.assertTrue(validated_rule.source.endswith(".json"))

    def test_mitre_identifiers(self) -> None:
        for validated_rule in self.rule_items:
            for technique in validated_rule.mitre:
                with self.subTest(rule_item=validated_rule.id, technique=technique):
                    self.assertRegex(technique, r"^T\d{4}(\.\d{3})?$")

    def test_rule_mnemonics_exist(self) -> None:
        catalog = set(known_mnemonics())
        for validated_rule in self.rule_items:
            for mnemonic in validated_rule.match.get("mnemonics", []):
                with self.subTest(rule_item=validated_rule.id, mnemonic=mnemonic):
                    self.assertIn(mnemonic, catalog)

    def test_clean_examples_do_not_match(self) -> None:
        for item_name in ("linux-hello", "linux-loop", "windows-hello", "bubble", "gcc-att"):
            with self.subTest(sample_example=item_name):
                self.assertEqual(match_text(EXAMPLES[item_name]["code"], self.rule_items), [])

    def test_suspicious_example_matches_network_and_impact(self) -> None:
        found_matches = match_text(EXAMPLES["suspicious"]["code"], self.rule_items)
        ids = {m.rule_id for m in found_matches}
        self.assertIn("NET001", ids)
        self.assertIn("NET002", ids)
        severities = {m.severity for m in found_matches}
        self.assertIn("high", severities)

    def test_comments_do_not_count_as_strings(self) -> None:
        status_code = "; socket connect /etc/passwd\nnop"
        self.assertEqual(match_text(status_code, self.rule_items), [])

    def test_rules_json_has_schema(self) -> None:
        for file_path in rule_files():
            with open(file_path, encoding="utf-8") as source_file:
                self.assertEqual(json.load(source_file)["schema"], RULES_SCHEMA)


if __name__ == "__main__":
    unittest.main()
