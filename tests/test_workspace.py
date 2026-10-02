"""Tests of the project workspace: branches, notes and scenarios."""

import os
import tempfile
import unittest

from asmx.examples import EXAMPLES
from asmx.workspace import Project, Scenario, parse_reg_values, run_all_scenarios, run_scenario

HELLO = EXAMPLES["linux-hello"]["code"]


class TestProject(unittest.TestCase):
    """Branches, notes and breakpoints of a project."""

    def setUp(self) -> None:
        self.p = Project.new(code=HELLO, name="test")

    def test_new_project_has_a_main_branch(self) -> None:
        self.assertEqual(self.p.active, "main")
        self.assertEqual(self.p.code, HELLO)

    def test_fork_copies_the_code(self) -> None:
        b = self.p.fork("experiment")
        self.assertEqual(b.code, HELLO)
        self.assertEqual(b.parent, "main")
        self.assertIn("experiment", self.p.branches)

    def test_branches_are_independent(self) -> None:
        self.p.fork("experiment")
        self.p.switch("experiment")
        self.p.set_code("mov rax, 1")
        self.assertEqual(self.p.code, "mov rax, 1")
        self.p.switch("main")
        self.assertEqual(self.p.code, HELLO)

    def test_fork_with_a_repeated_name_fails(self) -> None:
        self.p.fork("x")
        with self.assertRaises(ValueError):
            self.p.fork("x")

    def test_fork_without_a_name_fails(self) -> None:
        with self.assertRaises(ValueError):
            self.p.fork("   ")

    def test_does_not_delete_the_last_branch(self) -> None:
        with self.assertRaises(ValueError):
            self.p.delete_branch("main")

    def test_deleting_the_active_branch_switches_to_another_one(self) -> None:
        self.p.fork("b2")
        self.p.switch("b2")
        self.p.delete_branch("b2")
        self.assertEqual(self.p.active, "main")

    def test_renaming_a_branch_keeps_the_children(self) -> None:
        self.p.fork("child")
        self.p.rename_branch("main", "base")
        self.assertEqual(self.p.branches["child"].parent, "base")
        self.assertEqual(self.p.active, "base")

    def test_diff_between_branches(self) -> None:
        self.p.fork("alt")
        self.p.switch("alt")
        self.p.set_code(HELLO.replace("Hello, world!", "Another text"))
        d = self.p.diff("main", "alt")
        self.assertIn("Another text", d)
        self.assertIn("-", d)

    def test_notes_by_line(self) -> None:
        self.p.set_note(3, "the text starts here")
        self.assertEqual(self.p.note(3), "the text starts here")
        self.p.set_note(3, "")
        self.assertEqual(self.p.note(3), "")

    def test_note_does_not_leak_to_a_new_branch_after_the_fork(self) -> None:
        self.p.set_note(1, "note from main")
        self.p.fork("b")
        self.p.switch("b")
        self.assertEqual(self.p.note(1), "note from main")
        self.p.set_note(1, "only from b")
        self.p.switch("main")
        self.assertEqual(self.p.note(1), "note from main")

    def test_breakpoints(self) -> None:
        self.assertTrue(self.p.toggle_breakpoint(10))
        self.assertIn(10, self.p.branch.breakpoints)
        self.assertFalse(self.p.toggle_breakpoint(10))
        self.assertNotIn(10, self.p.branch.breakpoints)

    def test_save_and_load(self) -> None:
        self.p.set_note(2, "look at this")
        self.p.fork("other")
        self.p.toggle_breakpoint(4)
        self.p.add_scenario(Scenario(name="basic", expect_exit=0))
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "proj.asmproj")
            self.p.save(path)
            self.assertTrue(os.path.exists(path))
            q = Project.load(path)
        self.assertEqual(set(q.branches), {"main", "other"})
        self.assertEqual(q.code, HELLO)
        self.assertEqual(q.note(2), "look at this")
        self.assertIn(4, q.branch.breakpoints)
        self.assertEqual(q.branch.scenarios[0].name, "basic")
        self.assertFalse(q.dirty)

    def test_import_asm_and_export(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            origin = os.path.join(d, "a.asm")
            with open(origin, "w", encoding="utf-8") as f:
                f.write(HELLO)
            p = Project.from_asm_file(origin)
            self.assertEqual(p.code, HELLO)
            destination = os.path.join(d, "b.asm")
            p.export_asm(destination)
            with open(destination, encoding="utf-8") as f:
                self.assertEqual(f.read(), HELLO)

    def test_change_mark(self) -> None:
        self.assertFalse(self.p.dirty)
        self.p.set_code("mov rax, 1")
        self.assertTrue(self.p.dirty)


class TestScenarios(unittest.TestCase):
    """Running scenarios and the reason of each result."""

    def test_parse_reg_values(self) -> None:
        d = parse_reg_values("rax=10, rbx=0x20; rcx = 5")
        self.assertEqual(d, {"rax": 10, "rbx": 32, "rcx": 5})
        self.assertEqual(parse_reg_values("nonexistent=1"), {})

    def test_scenario_passed(self) -> None:
        r = run_scenario(
            HELLO, Scenario(name="output", expect_output="Hello, world!\n", expect_exit=0)
        )
        self.assertTrue(r.passed, r.reason)
        self.assertEqual(r.exit_code, 0)

    def test_failed_scenario_shows_the_reason(self) -> None:
        r = run_scenario(HELLO, Scenario(name="wrong", expect_output="something else"))
        self.assertFalse(r.passed)
        self.assertIn("output differs", r.reason)

    def test_scenario_with_entry_in_a_function_and_registers(self) -> None:
        code = EXAMPLES["overflow"]["code"]
        r = run_scenario(code, Scenario(name="sum to 10", entry="sum_until", regs={"rdi": 10}))
        self.assertTrue(r.passed, r.reason)
        r2 = run_scenario(code, Scenario(name="sum to 100", entry="sum_until", regs={"rdi": 100}))
        self.assertTrue(r2.passed, r2.reason)
        self.assertGreater(r2.steps, r.steps)

    def test_absurd_value_detects_a_problem(self) -> None:
        """It is the "what if I use a very high number?" case."""
        code = EXAMPLES["overflow"]["code"]
        r = run_scenario(
            code,
            Scenario(
                name="giant N",
                entry="sum_until",
                regs={"rdi": "0xFFFFFFFFFFFFFFFF"},
                max_steps=5000,
                expect_issue=True,
            ),
        )
        self.assertTrue(r.passed, r.reason)
        self.assertTrue(r.issues)

    def test_scenario_expects_a_problem_but_there_is_none(self) -> None:
        r = run_scenario(HELLO, Scenario(name="false alarm", expect_issue=True))
        self.assertFalse(r.passed)
        self.assertIn("expected", r.reason)

    def test_run_all_scenarios(self) -> None:
        scenarios = [Scenario(name="a", expect_exit=0), Scenario(name="b", expect_exit=99)]
        rs = run_all_scenarios(HELLO, scenarios)
        self.assertEqual([r.passed for r in rs], [True, False])

    def test_scenario_serializes(self) -> None:
        s = Scenario(name="x", regs={"rax": 1}, expect_exit=0)
        d = s.to_dict()
        s2 = Scenario.from_dict(d)
        self.assertEqual(s2.name, "x")
        self.assertEqual(s2.regs, {"rax": 1})


if __name__ == "__main__":
    unittest.main()
