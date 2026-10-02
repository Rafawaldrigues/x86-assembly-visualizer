"""GUI tests. They need Tkinter and a display (use xvfb-run)."""

import os
import tempfile
import unittest

try:
    import tkinter as tk

    TK_OK = True
except ImportError:  # pragma: no cover
    TK_OK = False

HAS_DISPLAY = bool(os.environ.get("DISPLAY")) or os.name == "nt"


@unittest.skipUnless(TK_OK and HAS_DISPLAY, "no Tkinter or no display")
class TestGUI(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        from asmx.ui.app import AsmXApp

        cls.AsmXApp = AsmXApp

    def setUp(self) -> None:
        self.app = self.AsmXApp()
        self.app.update()

    def tearDown(self) -> None:
        try:
            self.app.destroy()
        except tk.TclError:
            pass

    def pump(self) -> None:
        for _ in range(3):
            self.app.update_idletasks()
            self.app.update()

    def set_code(self, code: str) -> None:
        self.app.editor.set_code(code)
        self.app.on_code_change()
        self.pump()

    def test_memory_fault_and_usage_are_visible(self) -> None:
        self.app.sandbox_config.max_memory = 16
        self.set_code("buffer resb 16777217\nmov rax, 7")
        self.app.reset_machine()
        self.assertTrue(self.app.machine.out_of_memory)
        self.assertIn("MEM_LIMIT", self.app.exec_label.cget("text"))
        self.assertIn("16 MiB", self.app.memory_label.cget("text"))
        self.assertEqual(self.app.machine.steps, 0)

    def test_inspector_does_not_warn_on_uninitialized_stack(self) -> None:
        self.set_code("sub rsp, 8\nhlt")
        self.app.reset_machine()
        self.app.step()
        before = list(self.app.machine.issues)
        self.app.refresh_machine()
        self.assertEqual(self.app.machine.issues, before)
        self.assertEqual(before, [])

    # ------------------------------------------------------------ basic ---
    def test_opens_with_sample_and_analyzes(self) -> None:
        self.assertIn("Hello, world!", self.app.editor.get_code())
        self.assertIsNotNone(self.app.analysis)
        self.assertIn("Linux", self.app.platform_label.cget("text"))
        self.assertTrue(self.app.tree.get_children(), "the structure tree should have items")

    def test_status_shows_branch_and_counts(self) -> None:
        self.app.set_status()
        text = self.app.status.cget("text")
        self.assertIn("branch: %s" % self.app.project.active, text)
        self.assertIn("instructions", text)

    def test_switching_sample_reanalyzes(self) -> None:
        from asmx.examples import EXAMPLES

        self.set_code(EXAMPLES["windows-hello"]["code"])
        self.assertIn("Windows", self.app.platform_label.cget("text"))

    # -------------------------------------------------------- problems ----
    def test_validation_lists_problems_and_marks_lines(self) -> None:
        from asmx.examples import EXAMPLES

        self.set_code(EXAMPLES["broken"]["code"])
        self.app.validate_now()
        self.pump()
        items = self.app.problem_tree.get_children()
        self.assertTrue(items, "the broken sample should list problems")
        codes = {self.app.problem_tree.item(i, "values")[1] for i in items}
        self.assertIn("DIV001", codes)
        self.assertIn("IMM001", codes)
        ranges = self.app.editor.text.tag_ranges("errorline")
        self.assertTrue(ranges, "the error lines should be marked in the editor")

    def test_problem_click_jumps_to_line(self) -> None:
        from asmx.examples import EXAMPLES

        self.set_code(EXAMPLES["broken"]["code"])
        self.app.validate_now()
        self.pump()
        first = self.app.problem_tree.get_children()[0]
        expected_line = int(self.app.problem_tree.item(first, "values")[0])
        self.app.problem_tree.selection_set(first)
        self.app.on_problem_open()
        self.pump()
        self.assertEqual(self.app.editor.cursor_line(), expected_line)

    def test_clean_code_lists_no_errors(self) -> None:
        self.app.validate_now()
        self.pump()
        severities = [
            self.app.problem_tree.item(i, "tags")[0] for i in self.app.problem_tree.get_children()
        ]
        self.assertNotIn("error", severities)

    # ------------------------------------------------------- execution ----
    def test_step_updates_registers(self) -> None:
        self.app.reset_machine()
        self.app.step()
        self.pump()
        values = self.app.reg_tree.item("rax", "values")
        self.assertEqual(values[1], "1")
        self.assertIn("Next", self.app.exec_label.cget("text"))

    def test_run_shows_output(self) -> None:
        self.app.reset_machine()
        self.app.run()
        self.pump()
        output = self.app.output_text.get("1.0", "end-1c")
        self.assertIn("Hello, world!", output)
        self.assertTrue(self.app.trace_tree.get_children())

    def test_breakpoint_stops_execution(self) -> None:
        self.app.reset_machine()
        syscall_line = next(i.n for i in self.app.analysis.instrs if i.mnemonic == "syscall")
        self.app.editor.breakpoints = {syscall_line}
        self.app.run()
        self.pump()
        self.assertFalse(self.app.machine.halted)
        self.assertEqual(self.app.machine.current.n, syscall_line)

    def test_run_to_cursor(self) -> None:
        self.app.reset_machine()
        target = self.app.analysis.instrs[2].n
        self.app.editor.goto_line(target)
        self.app.run_to_cursor()
        self.pump()
        self.assertEqual(self.app.machine.current.n, target)

    def test_reset_clears_state(self) -> None:
        self.app.run()
        self.app.reset_machine()
        self.pump()
        self.assertEqual(self.app.machine.regs["rax"], 0)
        self.assertEqual(self.app.output_text.get("1.0", "end-1c"), "")

    def test_debug_single_function(self) -> None:
        from asmx.examples import EXAMPLES
        from asmx.ui import app as appmod

        self.set_code(EXAMPLES["overflow"]["code"])

        class FakeDialog:
            def __init__(self, *a: object, **k: object) -> None:
                pass

            def show(self) -> str:
                return "sum_until"

        original = appmod.TextPromptDialog
        appmod.TextPromptDialog = FakeDialog
        try:
            self.app.debug_function()
        finally:
            appmod.TextPromptDialog = original
        self.pump()
        self.assertEqual(
            self.app.machine.current.n,
            next(i.n for i in self.app.analysis.instrs if i.func == "sum_until"),
        )

    # ---------------------------------------------------------- branches --
    def test_create_branch_from_interface(self) -> None:
        from asmx.ui import app as appmod

        class FakeDialog:
            def __init__(self, *a: object, **k: object) -> None:
                pass

            def show(self) -> str:
                return "experiment"

        original = appmod.TextPromptDialog
        appmod.TextPromptDialog = FakeDialog
        try:
            self.app.branch_new()
        finally:
            appmod.TextPromptDialog = original
        self.pump()
        self.assertEqual(self.app.project.active, "experiment")
        self.assertIn("experiment", self.app.branch_box.cget("values"))

    def test_branches_keep_different_code(self) -> None:
        first = self.app.project.active
        self.app.project.fork("alt")
        self.app.project.switch("alt")
        self.app.load_branch_into_editor()
        self.set_code("mov rax, 99")
        self.app.branch_switch(first)
        self.pump()
        self.assertIn("Hello, world!", self.app.editor.get_code())
        self.app.branch_switch("alt")
        self.pump()
        self.assertIn("mov rax, 99", self.app.editor.get_code())

    # ------------------------------------------------------------- notes --
    def test_note_appears_in_list(self) -> None:
        self.app.project.set_note(4, "the string lives here")
        self.app.refresh_notes()
        self.pump()
        items = self.app.note_tree.get_children()
        self.assertIn("4", items)
        self.assertEqual(self.app.note_tree.item("4", "values")[0], "the string lives here")

    def test_comment_line_with_shortcut(self) -> None:
        self.set_code("mov rax, 1\nmov rbx, 2")
        self.app.editor.goto_line(1)
        self.app.editor_toggle_comment()
        self.pump()
        self.assertTrue(self.app.editor.get_code().startswith("; mov rax, 1"))
        self.app.editor.goto_line(1)
        self.app.editor_toggle_comment()
        self.pump()
        self.assertTrue(self.app.editor.get_code().startswith("mov rax, 1"))

    # ------------------------------------------------------------ tests ---
    def test_scenarios_run_and_show_result(self) -> None:
        from asmx.workspace import Scenario

        self.app.project.add_scenario(
            Scenario(name="right output", expect_output="Hello, world!\n")
        )
        self.app.project.add_scenario(Scenario(name="wrong output", expect_output="anything"))
        self.app.run_all_scenarios()
        self.pump()
        self.assertEqual(self.app.scenario_tree.item("right output", "tags"), ("ok",))
        self.assertEqual(self.app.scenario_tree.item("wrong output", "tags"), ("failed",))
        self.assertIn("1 of 2", self.app.status.cget("text"))

    def test_scenario_created_by_dialog(self) -> None:
        from asmx.ui import app as appmod
        from asmx.workspace import Scenario

        class FakeDialog:
            def __init__(self, *a: object, **k: object) -> None:
                pass

            def show(self) -> Scenario:
                return Scenario(
                    name="huge value",
                    entry="_start",
                    regs={"rdi": "0xFFFFFFFF"},
                    expect_issue=True,
                )

        original = appmod.ScenarioDialog
        appmod.ScenarioDialog = FakeDialog
        try:
            self.app.scenario_new()
        finally:
            appmod.ScenarioDialog = original
        self.pump()
        self.assertIn("huge value", self.app.scenario_tree.get_children())

    # ------------------------------------------------------ persistence ---
    def test_save_and_reopen_project(self) -> None:
        from asmx.workspace import Project

        self.app.project.set_note(2, "note")
        self.app.project.fork("b2")
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "p.asmproj")
            self.app.project.save(path)
            reloaded = Project.load(path)
        self.assertEqual(set(reloaded.branches), {self.app.project.active, "b2"})
        self.assertEqual(reloaded.note(2), "note")

    # ----------------------------------------------------- documentation --
    def test_documentation_follows_cursor(self) -> None:
        line = next(i.n for i in self.app.analysis.instrs if i.mnemonic == "syscall")
        self.app.editor.goto_line(line)
        self.app.on_cursor(line, 1)
        self.pump()
        text = self.app.doc_text.get("1.0", "end-1c")
        self.assertIn("SYSCALL", text)
        self.assertIn("kernel", text.lower())

    def test_documentation_search(self) -> None:
        self.app.doc_query.insert(0, "jn")
        self.app.refresh_doc_list()
        self.pump()
        items = self.app.doc_list.get(0, "end")
        self.assertTrue(all(i.startswith("jn") for i in items))
        self.assertIn("jne", items)

    # -------------------------------------------------------- robustness --
    def test_invalid_code_does_not_crash_interface(self) -> None:
        for junk in ("", "   ", "???", "mov", "[[[", '"', "section"):
            with self.subTest(code=junk):
                self.set_code(junk)
                self.app.validate_now()
                self.app.reset_machine()
                self.app.step()
                self.pump()
        self.assertTrue(self.app.winfo_exists())


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(TK_OK and HAS_DISPLAY, "no Tkinter or no display")
class TestGUIExtra(unittest.TestCase):
    """Cases that came out of defects found in the visual review."""

    @classmethod
    def setUpClass(cls) -> None:
        from asmx.ui.app import AsmXApp

        cls.AsmXApp = AsmXApp

    def setUp(self) -> None:
        self.app = self.AsmXApp()
        self.app.update()

    def tearDown(self) -> None:
        try:
            self.app.destroy()
        except tk.TclError:
            pass

    def test_block_column_stays_one_value(self) -> None:
        """values must be a tuple, otherwise Tcl splits the text into words."""
        roots = [
            i
            for i in self.app.tree.get_children()
            if self.app.tree.item(i, "tags") and "fn" in self.app.tree.item(i, "tags")
        ]
        self.assertTrue(roots)
        block = self.app.tree.get_children(roots[0])[0]
        info = self.app.tree.item(block, "values")[0]
        self.assertIn("instr", info, "the block description was truncated: %r" % info)

    def test_large_register_hides_unreadable_decimal(self) -> None:
        self.app.reset_machine()
        self.app.refresh_machine()
        self.assertEqual(self.app.reg_tree.item("rsp", "values")[1], "")
        self.assertNotEqual(self.app.reg_tree.item("rsp", "values")[0], "")

    def test_cursor_on_label_explains_label(self) -> None:
        line = next(line.n for line in self.app.analysis.program.lines if line.kind == "label")
        self.app.on_cursor(line, 1)
        self.app.update()
        text = self.app.doc_text.get("1.0", "end-1c")
        self.assertIn("Label", text)

    def test_cursor_on_data_explains_data(self) -> None:
        line = next(line.n for line in self.app.analysis.program.lines if line.kind == "data")
        self.app.on_cursor(line, 1)
        self.app.update()
        text = self.app.doc_text.get("1.0", "end-1c")
        self.assertTrue(
            "Initialized data" in text or "Assembler constant" in text or "Space" in text
        )

    def test_platform_has_full_explanation(self) -> None:
        self.assertTrue(hasattr(self.app, "platform_detail"))
        self.assertIn("System V", self.app.platform_detail)

    def test_scenario_detail_shows_reason(self) -> None:
        from asmx.workspace import Scenario

        self.app.project.add_scenario(Scenario(name="failure", expect_exit=42))
        self.app.run_all_scenarios()
        self.app.scenario_tree.selection_set("failure")
        self.app.on_scenario_select()
        self.app.update()
        text = self.app.scenario_detail.cget("text")
        self.assertIn("FAILED", text)
        self.assertIn("instructions executed", text)

    def test_machine_follows_new_code_when_stopped(self) -> None:
        self.app.editor.set_code("mov rax, 7")
        self.app.on_code_change()
        self.app.update()
        self.app.step()
        self.assertEqual(self.app.machine.regs["rax"], 7)

    def test_machine_warns_when_code_changes_midway(self) -> None:
        self.app.reset_machine()
        self.app.step()
        self.app.editor.set_code("mov rbx, 1\nmov rcx, 2")
        self.app.on_code_change()
        self.app.update()
        self.assertIn("reset", self.app.exec_label.cget("text"))
