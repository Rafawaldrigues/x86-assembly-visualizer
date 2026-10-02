"""Corner case tests of the project: branches, scenarios, persistence and errors."""

import json
import os
import tempfile
import unittest

from asmx.errors import (
    BranchExistsError,
    BranchNotFoundError,
    EmptyBranchNameError,
    LastBranchError,
    ProjectError,
    ProjectFormatError,
    ScenarioError,
    SourceNotFoundError,
    SourceWriteError,
)
from asmx.examples import EXAMPLES
from asmx.workspace import (
    FORMAT,
    Branch,
    Project,
    Scenario,
    ScenarioResult,
    parse_reg_values,
    run_all_scenarios,
    run_scenario,
)

HELLO = EXAMPLES["linux-hello"]["code"]


class BaseProject(unittest.TestCase):
    """Project with two branches and a temporary directory at hand."""

    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.project = Project.new(code=HELLO, name="test")

    def tearDown(self) -> None:
        self.dir.cleanup()

    def path(self, name: str) -> str:
        return os.path.join(self.dir.name, name)


class TestBranches(BaseProject):
    """Error paths and branch operations."""

    def test_existing_nonenglish_branch_name_is_preserved(self) -> None:
        project = Project.new(code="nop")
        project.rename_branch("main", "principal")
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "legacy.asmproj")
            project.save(path)
            loaded = Project.load(path)
        self.assertEqual(loaded.active, "principal")
        self.assertEqual(loaded.code, "nop")

    def test_fork_from_a_nonexistent_source(self) -> None:
        with self.assertRaises(BranchNotFoundError):
            self.project.fork("new", from_branch="does_not_exist")

    def test_repeated_name(self) -> None:
        self.project.fork("a")
        with self.assertRaises(BranchExistsError):
            self.project.fork("a")

    def test_empty_name(self) -> None:
        with self.assertRaises(EmptyBranchNameError):
            self.project.fork("   ")

    def test_switch_to_a_nonexistent_branch(self) -> None:
        with self.assertRaises(BranchNotFoundError):
            self.project.switch("does_not_exist")

    def test_delete_a_nonexistent_branch(self) -> None:
        with self.assertRaises(BranchNotFoundError):
            self.project.delete_branch("does_not_exist")

    def test_delete_the_last_branch(self) -> None:
        with self.assertRaises(LastBranchError):
            self.project.delete_branch("main")

    def test_delete_leaves_the_children_without_a_parent(self) -> None:
        self.project.fork("child")
        self.project.delete_branch("main")
        self.assertIsNone(self.project.branches["child"].parent)

    def test_rename_a_nonexistent_branch(self) -> None:
        with self.assertRaises(BranchNotFoundError):
            self.project.rename_branch("does_not_exist", "new")

    def test_rename_to_an_existing_name(self) -> None:
        self.project.fork("b")
        with self.assertRaises(BranchExistsError):
            self.project.rename_branch("main", "b")

    def test_diff_of_a_nonexistent_branch(self) -> None:
        with self.assertRaises(BranchNotFoundError):
            self.project.diff("main", "does_not_exist")

    def test_nonexistent_active_branch_falls_back_to_the_first_one(self) -> None:
        self.project.active = "vanished"
        self.assertEqual(self.project.branch.name, "main")

    def test_fork_copies_notes_and_breakpoints(self) -> None:
        self.project.set_note(1, "note")
        self.project.toggle_breakpoint(3)
        copy = self.project.fork("copy")
        self.assertEqual(copy.notes["1"], "note")
        self.assertEqual(copy.breakpoints, [3])

    def test_branch_dataclass(self) -> None:
        branch = Branch(name="x", code="nop")
        self.assertEqual(branch.to_dict()["name"], "x")
        self.assertIn("created", branch.to_dict())


class TestScenarios(BaseProject):
    """Scenarios: add, remove, search and run."""

    def test_add_and_replace(self) -> None:
        self.project.add_scenario(Scenario(name="a", expect_exit=0))
        self.project.add_scenario(Scenario(name="a", expect_exit=1))
        self.assertEqual(len(self.project.branch.scenarios), 1)
        self.assertEqual(self.project.scenario("a").expect_exit, 1)

    def test_remove(self) -> None:
        self.project.add_scenario(Scenario(name="a"))
        self.project.remove_scenario("a")
        self.assertEqual(self.project.branch.scenarios, [])

    def test_search_for_a_nonexistent_scenario(self) -> None:
        with self.assertRaises(ScenarioError):
            self.project.scenario("does_not_exist")

    def test_nonexistent_entry(self) -> None:
        with self.assertRaises(ScenarioError):
            run_scenario(HELLO, Scenario(name="x", entry="does_not_exist"))

    def test_wrong_expected_output(self) -> None:
        result = run_scenario(HELLO, Scenario(name="x", expect_output="other"))
        self.assertFalse(result.passed)
        self.assertIn("output differs", result.reason)

    def test_wrong_exit_code(self) -> None:
        result = run_scenario(HELLO, Scenario(name="x", expect_exit=7))
        self.assertFalse(result.passed)
        self.assertIn("exit code", result.reason)

    def test_expects_a_problem_that_does_not_happen(self) -> None:
        result = run_scenario(HELLO, Scenario(name="x", expect_issue=True))
        self.assertFalse(result.passed)
        self.assertIn("expected", result.reason)

    def test_unexpected_problem_fails_the_scenario(self) -> None:
        result = run_scenario("start:\njmp start", Scenario(name="x", max_steps=500))
        self.assertFalse(result.passed)
        self.assertIn("the run reported:", result.reason)

    def test_timeout_fails_with_a_reason(self) -> None:
        code = "start:\njmp start"
        result = run_scenario(code, Scenario(name="x", max_steps=100000, timeout=0.0))
        self.assertFalse(result.passed)
        self.assertIn("timeout", result.reason)

    def test_all_scenarios(self) -> None:
        scenarios = [Scenario(name="a", expect_exit=0), Scenario(name="b", expect_exit=9)]
        results = run_all_scenarios(HELLO, scenarios)
        self.assertEqual([r.passed for r in results], [True, False])
        self.assertEqual(results[0].scenario, "a")

    def test_result_serializes(self) -> None:
        result = run_scenario(HELLO, Scenario(name="x", expect_exit=0))
        data = result.to_dict()
        self.assertEqual(data["scenario"], "x")
        self.assertTrue(data["passed"])
        self.assertIsInstance(result, ScenarioResult)

    def test_scenario_from_dict_ignores_new_fields(self) -> None:
        scenario = Scenario.from_dict({"name": "a", "field_from_the_future": 1, "max_steps": 10})
        self.assertEqual(scenario.name, "a")
        self.assertEqual(scenario.max_steps, 10)

    def test_initial_registers_accept_text_and_number(self) -> None:
        code = EXAMPLES["overflow"]["code"]
        result = run_scenario(code, Scenario(name="x", entry="sum_until", regs={"rdi": "0x10"}))
        self.assertTrue(result.passed, result.reason)
        self.assertGreater(result.steps, 0)

    def test_parse_reg_values_variants(self) -> None:
        self.assertEqual(parse_reg_values("rax=1;rbx=2\nrcx=3"), {"rax": 1, "rbx": 2, "rcx": 3})
        self.assertEqual(parse_reg_values(""), {})
        self.assertEqual(parse_reg_values("junk"), {})


class TestPersistence(BaseProject):
    """Write, load and refuse strange files."""

    def test_to_dict(self) -> None:
        data = self.project.to_dict()
        self.assertEqual(data["format"], FORMAT)
        self.assertEqual(data["active"], "main")
        self.assertIn("saved", data)
        self.assertIn("main", data["branches"])

    def test_save_without_a_path(self) -> None:
        with self.assertRaises(ProjectError):
            self.project.save()

    def test_save_into_a_directory(self) -> None:
        with self.assertRaises(SourceWriteError):
            self.project.save(self.dir.name)

    def test_load_a_nonexistent_file(self) -> None:
        with self.assertRaises(SourceNotFoundError):
            Project.load(self.path("nothing.asmproj"))

    def test_load_invalid_json(self) -> None:
        path = self.path("bad.asmproj")
        with open(path, "w", encoding="utf-8") as file:
            file.write("{not json}")
        with self.assertRaises(ProjectFormatError):
            Project.load(path)

    def test_load_a_list_instead_of_an_object(self) -> None:
        path = self.path("list.asmproj")
        with open(path, "w", encoding="utf-8") as file:
            json.dump([1, 2], file)
        with self.assertRaises(ProjectFormatError):
            Project.load(path)

    def test_load_a_format_from_another_program(self) -> None:
        path = self.path("other.asmproj")
        with open(path, "w", encoding="utf-8") as file:
            json.dump({"format": "other-tool/9", "branches": {}}, file)
        with self.assertRaises(ProjectFormatError):
            Project.load(path)

    def test_load_a_branch_that_is_not_an_object(self) -> None:
        path = self.path("strange.asmproj")
        with open(path, "w", encoding="utf-8") as file:
            json.dump({"format": FORMAT, "branches": {"a": 3}}, file)
        with self.assertRaises(ProjectFormatError):
            Project.load(path)

    def test_load_without_branches_creates_the_main_one(self) -> None:
        path = self.path("empty.asmproj")
        with open(path, "w", encoding="utf-8") as file:
            json.dump({"name": "empty", "branches": {}}, file)
        project = Project.load(path)
        self.assertEqual(list(project.branches), ["main"])
        self.assertFalse(project.dirty)

    def test_invalid_active_branch_in_the_file(self) -> None:
        path = self.path("active.asmproj")
        with open(path, "w", encoding="utf-8") as file:
            json.dump({"active": "vanished", "branches": {"main": {"code": "nop"}}}, file)
        self.assertEqual(Project.load(path).active, "main")

    def test_import_asm(self) -> None:
        path = self.path("source.asm")
        with open(path, "w", encoding="utf-8") as file:
            file.write(HELLO)
        project = Project.from_asm_file(path)
        self.assertEqual(project.name, "source")
        self.assertEqual(project.code, HELLO)

    def test_export_to_an_invalid_path(self) -> None:
        with self.assertRaises(SourceWriteError):
            self.project.export_asm(self.dir.name)

    def test_export_and_reimport(self) -> None:
        destination = self.path("output.asm")
        self.project.export_asm(destination)
        with open(destination, encoding="utf-8") as file:
            self.assertEqual(file.read(), HELLO)


class TestMarks(BaseProject):
    """Notes, breakpoints and the change mark."""

    def test_empty_note_removes_it(self) -> None:
        self.project.set_note(2, "something")
        self.project.set_note(2, "   ")
        self.assertEqual(self.project.note(2), "")

    def test_note_is_trimmed(self) -> None:
        self.project.set_note(2, "  look at this  ")
        self.assertEqual(self.project.note(2), "look at this")

    def test_breakpoints_are_sorted(self) -> None:
        self.project.toggle_breakpoint(9)
        self.project.toggle_breakpoint(3)
        self.assertEqual(self.project.branch.breakpoints, [3, 9])

    def test_dirty_on_note_and_on_breakpoint(self) -> None:
        self.project.dirty = False
        self.project.set_note(1, "x")
        self.assertTrue(self.project.dirty)
        self.project.dirty = False
        self.project.toggle_breakpoint(1)
        self.assertTrue(self.project.dirty)

    def test_same_code_does_not_make_it_dirty(self) -> None:
        self.project.set_code(HELLO)
        self.assertFalse(self.project.dirty)

    def test_saving_marks_it_clean_and_renames_it(self) -> None:
        self.project.set_code("nop")
        path = self.project.save(self.path("mine.asmproj"))
        self.assertEqual(path, self.path("mine.asmproj"))
        self.assertFalse(self.project.dirty)
        self.assertEqual(self.project.name, "mine")


if __name__ == "__main__":
    unittest.main()
