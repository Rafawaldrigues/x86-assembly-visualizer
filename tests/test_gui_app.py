"""Tests of the main window, the code editor and the theme (asmx.ui.app).

No real modal window is opened: the dialogs of the module and the boxes of
``tkinter.messagebox``/``tkinter.filedialog`` are replaced by doubles.
"""

from __future__ import annotations

import os
import tempfile
import time
import unittest
from typing import Any, List, Tuple
from unittest import mock

try:
    import tkinter as tk

    TK_OK = True
except ImportError:  # pragma: no cover
    TK_OK = False

HAS_DISPLAY = bool(os.environ.get("DISPLAY")) or os.name == "nt"

#: Code with every line kind the documentation explains.
FULL_CODE = """section .data
msg: db "Hi", 0
buf: resb 16
SIZE equ 4
tab: times 4 db 0

section .text
    global _start
_start:
.loop:
    mov rax, [msg]
    nop
"""

#: Code that pushes values and keeps a return address on the stack.
STACK_CODE = """section .text
    global _start
_start:
    call helper
    mov rax, 1
helper:
    push 1
    push 2
    push 3
    push 4
    push 5
    nop
"""


def fake_dialog(value: Any) -> type:
    """Create a fake dialog (no Tk) that always returns the same value.

    Args:
        value: Value returned by :meth:`show`.

    Returns:
        A class compatible with the constructor of the real dialogs.
    """

    class FakeDialog:
        """Fake dialog: it accepts the arguments and returns a fixed value."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            """Keep the received arguments without opening any window.

            Args:
                *args: Positional arguments of the real dialog.
                **kwargs: Keyword arguments of the real dialog.
            """
            self.args = args
            self.kwargs = kwargs

        def show(self) -> Any:
            """Return the arranged value without waiting for the user.

            Returns:
                The value passed to :func:`fake_dialog`.
            """
            return value

    return FakeDialog


class FakeEvent:
    """Fake Tk event, to call the handlers without mouse or keyboard."""

    def __init__(self, num: int = 0, delta: int = 0, y: int = 0) -> None:
        """Keep the fields read by the editor handlers.

        Args:
            num: Button number, as Tk delivers it on Linux (4/5 = wheel).
            delta: Wheel offset on the systems that use delta.
            y: Vertical coordinate of the click.
        """
        self.num = num
        self.delta = delta
        self.y = y


class AppTestCase(unittest.TestCase):
    """Base with the main window created and destroyed for each test."""

    @classmethod
    def setUpClass(cls) -> None:
        from asmx.ui.app import AsmXApp

        cls.AsmXApp = AsmXApp

    def setUp(self) -> None:
        self.app = self.AsmXApp()
        self.app.update()
        self.project_name = self.app.project.name
        self.default_branch = self.app.project.active

    def tearDown(self) -> None:
        self.cancel_pending_highlights()
        try:
            self.app.destroy()
        except tk.TclError:
            pass

    def cancel_pending_highlights(self) -> None:
        """Cancel scheduled highlights that would be left orphaned on close.

        ``toggle_comment`` calls ``highlight()`` directly and leaves the
        scheduled job behind; when it fires after the destroy the Tk prints
        ``invalid command name ...highlight`` in the middle of the suite.
        """
        try:
            for job in self.app.tk.call("after", "info"):
                if "highlight" in str(self.app.tk.call("after", "info", job)):
                    self.app.after_cancel(job)
        except tk.TclError:
            pass

    def pump(self) -> None:
        """Let Tk process whatever is pending."""
        for _ in range(3):
            self.app.update_idletasks()
            self.app.update()

    def set_code(self, code: str) -> None:
        """Replace the editor code and wait for the reanalysis.

        Args:
            code: Code that goes into the editor.
        """
        self.app.editor.set_code(code)
        self.app.on_code_change()
        self.pump()

    def items(self, tree: Any, parent: str = "") -> List[str]:
        """List the iids of a tree, in depth.

        Args:
            tree: Tree to walk.
            parent: Starting item; empty starts at the root.

        Returns:
            The iids in visit order.
        """
        output: List[str] = []
        for iid in tree.get_children(parent):
            output.append(iid)
            output.extend(self.items(tree, iid))
        return output

    def item_with_line(self, tree: Any) -> Tuple[str, int]:
        """Find a tree item whose tags point to a line.

        Args:
            tree: Tree to search.

        Returns:
            The iid and the line number it points to.
        """
        for iid in self.items(tree):
            line = self.app._tag_line(tree.item(iid, "tags"))
            if line:
                return iid, line
        raise AssertionError("no tree item points to a line")

    def item_without_line(self, tree: Any) -> str:
        """Find a tree item that does not point to any line.

        Args:
            tree: Tree to search.

        Returns:
            The iid of the item.
        """
        for iid in self.items(tree):
            if not self.app._tag_line(tree.item(iid, "tags")):
                return iid
        raise AssertionError("every tree item points to a line")


@unittest.skipUnless(TK_OK and HAS_DISPLAY, "no Tkinter or no display")
class TestAppFile(AppTestCase):
    """File menu commands and the discard of changes."""

    def test_load_sample_switches_project(self) -> None:
        from asmx.examples import EXAMPLES

        self.app.load_example("linux-loop")
        self.pump()
        self.assertEqual(self.app.project.name, "linux-loop")
        self.assertIn(EXAMPLES["linux-loop"]["title"], self.app.title())
        self.assertEqual(self.app.editor.get_code(), EXAMPLES["linux-loop"]["code"])

    def test_cancelled_sample_load_keeps_project(self) -> None:
        from asmx.ui import app as appmod

        self.app.project.dirty = True
        with mock.patch.object(appmod.messagebox, "askyesnocancel", return_value=None):
            self.app.load_example("linux-loop")
        self.assertEqual(self.app.project.name, self.project_name)

    def test_new_project_creates_empty_code(self) -> None:
        self.app.new_project()
        self.pump()
        self.assertIn("new program", self.app.editor.get_code())
        self.assertEqual(self.app.title(), "ASM X")

    def test_cancelled_new_project_keeps_code(self) -> None:
        from asmx.ui import app as appmod

        self.app.project.dirty = True
        with mock.patch.object(appmod.messagebox, "askyesnocancel", return_value=None):
            self.app.new_project()
        self.assertIn("Hello, world!", self.app.editor.get_code())

    def test_open_saved_project(self) -> None:
        from asmx.ui import app as appmod
        from asmx.workspace import Project

        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "saved.asmproj")
            self.app.project.set_code("mov rax, 7")
            self.app.project.save(path)
            with mock.patch.object(appmod.filedialog, "askopenfilename", return_value=path):
                self.app.open_project()
        self.pump()
        self.assertIn("mov rax, 7", self.app.editor.get_code())
        self.assertTrue(self.app.title().endswith("saved.asmproj"))
        self.assertEqual(self.app.project.path, path)
        self.assertIsInstance(self.app.project, Project)

    def test_cancelled_open_does_nothing(self) -> None:
        from asmx.ui import app as appmod

        with mock.patch.object(appmod.filedialog, "askopenfilename", return_value=""):
            self.app.open_project()
        self.assertIn("Hello, world!", self.app.editor.get_code())

    def test_open_broken_project_shows_error(self) -> None:
        from asmx.ui import app as appmod

        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "bad.asmproj")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("{this is not json")
            with (
                mock.patch.object(appmod.filedialog, "askopenfilename", return_value=path),
                mock.patch.object(appmod.messagebox, "showerror") as error,
            ):
                self.app.open_project()
        error.assert_called_once()
        self.assertIn("Hello, world!", self.app.editor.get_code())
        self.assertEqual(self.app.title(), "ASM X")

    def test_save_project_as(self) -> None:
        from asmx.ui import app as appmod

        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "new.asmproj")
            self.app.editor.set_code("mov rax, 1")
            with mock.patch.object(appmod.filedialog, "asksaveasfilename", return_value=path):
                self.assertTrue(self.app.save_project_as())
            self.assertTrue(os.path.exists(path))
        self.assertTrue(self.app.title().endswith("new.asmproj"))
        self.assertIn("saved to", self.app.status.cget("text"))

    def test_cancelled_save_project_as(self) -> None:
        from asmx.ui import app as appmod

        self.assertFalse(self.app.project.dirty)
        with mock.patch.object(appmod.filedialog, "asksaveasfilename", return_value=""):
            self.assertFalse(self.app.save_project_as())

    def test_save_project_with_path_already_set(self) -> None:
        from asmx.ui import app as appmod

        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "p.asmproj")
            self.app.project.path = path
            self.app.project.dirty = True
            self.app.editor.set_code("mov rbx, 9")
            with mock.patch.object(appmod.filedialog, "asksaveasfilename") as ask:
                self.assertTrue(self.app.save_project())
            ask.assert_not_called()
            self.assertTrue(os.path.exists(path))
        self.assertFalse(self.app.project.dirty)

    def test_save_project_without_path_asks_for_destination(self) -> None:
        from asmx.ui import app as appmod

        self.assertIsNone(self.app.project.path)
        with mock.patch.object(appmod.filedialog, "asksaveasfilename", return_value="") as ask:
            self.assertFalse(self.app.save_project())
        ask.assert_called_once()

    def test_import_asm_creates_new_project(self) -> None:
        from asmx.ui import app as appmod

        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "loose.asm")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("mov rax, 3\n")
            with mock.patch.object(appmod.filedialog, "askopenfilename", return_value=path):
                self.app.import_asm()
        self.pump()
        self.assertIn("mov rax, 3", self.app.editor.get_code())
        self.assertTrue(self.app.title().endswith("loose.asm"))

    def test_cancelled_import_asm_does_nothing(self) -> None:
        from asmx.ui import app as appmod

        with mock.patch.object(appmod.filedialog, "askopenfilename", return_value=""):
            self.app.import_asm()
        self.assertEqual(self.app.project.name, self.project_name)

    def test_refused_import_asm_keeps_project(self) -> None:
        from asmx.ui import app as appmod

        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "loose.asm")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("mov rax, 3\n")
            self.app.project.dirty = True
            with (
                mock.patch.object(appmod.filedialog, "askopenfilename", return_value=path),
                mock.patch.object(appmod.messagebox, "askyesnocancel", return_value=None),
            ):
                self.app.import_asm()
        self.assertIn("Hello, world!", self.app.editor.get_code())

    def test_export_branch_as_asm(self) -> None:
        from asmx.ui import app as appmod

        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "output.asm")
            self.app.editor.set_code("mov rax, 42")
            with mock.patch.object(appmod.filedialog, "asksaveasfilename", return_value=path):
                self.app.export_asm()
            with open(path, encoding="utf-8") as handle:
                self.assertIn("mov rax, 42", handle.read())
        self.assertIn("exported to", self.app.status.cget("text"))

    def test_cancelled_export_branch(self) -> None:
        from asmx.ui import app as appmod

        with mock.patch.object(appmod.filedialog, "asksaveasfilename", return_value=""):
            self.app.export_asm()
        self.assertNotIn("exported", self.app.status.cget("text"))

    def test_confirm_discard_without_changes(self) -> None:
        self.app.project.dirty = False
        with mock.patch.object(self.app, "save_project") as save:
            self.assertTrue(self.app.confirm_discard())
        save.assert_not_called()

    def test_confirm_discard_saves_project(self) -> None:
        from asmx.ui import app as appmod

        self.app.project.dirty = True
        with (
            mock.patch.object(appmod.messagebox, "askyesnocancel", return_value=True),
            mock.patch.object(self.app, "save_project", return_value=True) as save,
        ):
            self.assertTrue(self.app.confirm_discard())
        save.assert_called_once()

    def test_confirm_discard_saves_but_fails(self) -> None:
        from asmx.ui import app as appmod

        self.app.project.dirty = True
        with (
            mock.patch.object(appmod.messagebox, "askyesnocancel", return_value=True),
            mock.patch.object(self.app, "save_project", return_value=False),
        ):
            self.assertFalse(self.app.confirm_discard())

    def test_confirm_discard_discards(self) -> None:
        from asmx.ui import app as appmod

        self.app.project.dirty = True
        with (
            mock.patch.object(appmod.messagebox, "askyesnocancel", return_value=False),
            mock.patch.object(self.app, "save_project") as save,
        ):
            self.assertTrue(self.app.confirm_discard())
        save.assert_not_called()

    def test_confirm_discard_cancels(self) -> None:
        from asmx.ui import app as appmod

        self.app.project.dirty = True
        with (
            mock.patch.object(appmod.messagebox, "askyesnocancel", return_value=None),
            mock.patch.object(self.app, "save_project") as save,
        ):
            self.assertFalse(self.app.confirm_discard())
        save.assert_not_called()

    def test_on_close_closes_window(self) -> None:
        with mock.patch.object(self.app, "destroy") as destroy:
            self.app.on_close()
        destroy.assert_called_once()

    def test_cancelled_on_close_does_not_close(self) -> None:
        from asmx.ui import app as appmod

        self.app.project.dirty = True
        with (
            mock.patch.object(appmod.messagebox, "askyesnocancel", return_value=None),
            mock.patch.object(self.app, "destroy") as destroy,
        ):
            self.app.on_close()
        destroy.assert_not_called()


@unittest.skipUnless(TK_OK and HAS_DISPLAY, "no Tkinter or no display")
class TestAppBranches(AppTestCase):
    """Branch menu commands."""

    def test_new_branch_through_dialog(self) -> None:
        from asmx.ui import app as appmod

        with mock.patch.object(appmod, "TextPromptDialog", fake_dialog("experiment")):
            self.app.branch_new()
        self.pump()
        self.assertEqual(self.app.project.active, "experiment")
        self.assertIn("experiment", self.app.branch_box.cget("values"))
        self.assertIn("created from %s" % self.default_branch, self.app.status.cget("text"))

    def test_cancelled_new_branch(self) -> None:
        from asmx.ui import app as appmod

        with mock.patch.object(appmod, "TextPromptDialog", fake_dialog("")):
            self.app.branch_new()
        self.assertEqual(sorted(self.app.project.branches), [self.default_branch])

    def test_new_branch_without_name_shows_error(self) -> None:
        from asmx.ui import app as appmod

        with (
            mock.patch.object(appmod, "TextPromptDialog", fake_dialog("   ")),
            mock.patch.object(appmod.messagebox, "showerror") as error,
        ):
            self.app.branch_new()
        error.assert_called_once()
        self.assertEqual(sorted(self.app.project.branches), [self.default_branch])

    def test_duplicate_new_branch_shows_error(self) -> None:
        from asmx.ui import app as appmod

        with (
            mock.patch.object(appmod, "TextPromptDialog", fake_dialog(self.default_branch)),
            mock.patch.object(appmod.messagebox, "showerror") as error,
        ):
            self.app.branch_new()
        error.assert_called_once()
        self.assertEqual(sorted(self.app.project.branches), [self.default_branch])

    def test_switching_branch_reloads_editor(self) -> None:
        self.app.project.fork("alt")
        self.app.project.switch("alt")
        self.app.project.set_code("mov rax, 99")
        self.app.project.switch(self.default_branch)
        self.app.refresh_branches()
        self.app.load_branch_into_editor()
        self.pump()
        self.app.branch_switch("alt")
        self.pump()
        self.assertEqual(self.app.project.active, "alt")
        self.assertIn("mov rax, 99", self.app.editor.get_code())
        self.assertIn("now editing branch alt", self.app.status.cget("text"))

    def test_switching_to_the_same_branch_does_nothing(self) -> None:
        self.app.editor.set_code("mov rax, 5")
        self.app.branch_switch(self.default_branch)
        self.assertNotIn("now editing", self.app.status.cget("text"))
        self.assertIn("mov rax, 5", self.app.editor.get_code())

    def test_rename_branch(self) -> None:
        from asmx.ui import app as appmod

        with mock.patch.object(appmod, "TextPromptDialog", fake_dialog("renamed")):
            self.app.branch_rename()
        self.assertEqual(self.app.project.active, "renamed")
        self.assertIn("renamed", self.app.branch_box.cget("values"))

    def test_cancelled_rename_branch(self) -> None:
        from asmx.ui import app as appmod

        with mock.patch.object(appmod, "TextPromptDialog", fake_dialog("")):
            self.app.branch_rename()
        self.assertEqual(self.app.project.active, self.default_branch)

    def test_rename_branch_to_existing_name_shows_error(self) -> None:
        from asmx.ui import app as appmod

        self.app.project.fork("alt")
        self.app.refresh_branches()
        with (
            mock.patch.object(appmod, "TextPromptDialog", fake_dialog("alt")),
            mock.patch.object(appmod.messagebox, "showerror") as error,
        ):
            self.app.branch_rename()
        error.assert_called_once()
        self.assertEqual(self.app.project.active, self.default_branch)

    def test_delete_branch_confirmed(self) -> None:
        from asmx.ui import app as appmod

        self.app.project.fork("alt")
        self.app.branch_switch("alt")
        self.pump()
        with mock.patch.object(appmod.messagebox, "askyesno", return_value=True):
            self.app.branch_delete()
        self.pump()
        self.assertNotIn("alt", self.app.project.branches)
        self.assertEqual(self.app.project.active, self.default_branch)

    def test_delete_branch_refused(self) -> None:
        from asmx.ui import app as appmod

        self.app.project.fork("alt")
        self.app.refresh_branches()
        with mock.patch.object(appmod.messagebox, "askyesno", return_value=False):
            self.app.branch_delete()
        self.assertIn("alt", self.app.project.branches)

    def test_delete_the_only_branch_shows_error(self) -> None:
        from asmx.ui import app as appmod

        with (
            mock.patch.object(appmod.messagebox, "askyesno", return_value=True),
            mock.patch.object(appmod.messagebox, "showerror") as error,
        ):
            self.app.branch_delete()
        error.assert_called_once()
        self.assertEqual(sorted(self.app.project.branches), [self.default_branch])

    def test_compare_branches_opens_window(self) -> None:
        from asmx.ui import app as appmod

        self.app.project.fork("alt")
        self.app.project.switch("alt")
        self.app.project.set_code("mov rax, 2")
        self.app.project.switch(self.default_branch)
        self.app.refresh_branches()
        with (
            mock.patch.object(appmod, "TextPromptDialog", fake_dialog("alt")),
            mock.patch.object(appmod, "DiffDialog") as window,
        ):
            self.app.branch_diff()
        window.assert_called_once()
        self.assertEqual(window.call_args[0][1], "%s ↔ alt" % self.default_branch)
        self.assertIn("+mov rax, 2", window.call_args[0][2])

    def test_compare_with_a_single_branch_warns(self) -> None:
        from asmx.ui import app as appmod

        with (
            mock.patch.object(appmod.messagebox, "showinfo") as warning,
            mock.patch.object(appmod, "DiffDialog") as window,
        ):
            self.app.branch_diff()
        warning.assert_called_once()
        window.assert_not_called()

    def test_compare_missing_branch_does_not_open(self) -> None:
        from asmx.ui import app as appmod

        self.app.project.fork("alt")
        with (
            mock.patch.object(appmod, "TextPromptDialog", fake_dialog("missing")),
            mock.patch.object(appmod, "DiffDialog") as window,
        ):
            self.app.branch_diff()
        window.assert_not_called()

    def test_cancelled_compare(self) -> None:
        from asmx.ui import app as appmod

        self.app.project.fork("alt")
        with (
            mock.patch.object(appmod, "TextPromptDialog", fake_dialog(None)),
            mock.patch.object(appmod, "DiffDialog") as window,
        ):
            self.app.branch_diff()
        window.assert_not_called()


@unittest.skipUnless(TK_OK and HAS_DISPLAY, "no Tkinter or no display")
class TestAppScenarios(AppTestCase):
    """Tests tab commands."""

    def test_create_scenario_through_dialog(self) -> None:
        from asmx.ui import app as appmod
        from asmx.workspace import Scenario

        new = Scenario(name="new", expect_output="Hello, world!\n")
        with mock.patch.object(appmod, "ScenarioDialog", fake_dialog(new)):
            self.app.scenario_new()
        self.pump()
        self.assertIn("new", self.app.scenario_tree.get_children())

    def test_cancelled_create_scenario(self) -> None:
        from asmx.ui import app as appmod

        with mock.patch.object(appmod, "ScenarioDialog", fake_dialog(None)):
            self.app.scenario_new()
        self.assertEqual(self.app.project.branch.scenarios, [])

    def test_edit_scenario_changing_name(self) -> None:
        from asmx.ui import app as appmod
        from asmx.workspace import Scenario

        self.app.project.add_scenario(Scenario(name="old"))
        self.app.refresh_scenarios()
        self.app.scenario_tree.selection_set("old")
        with mock.patch.object(
            appmod, "ScenarioDialog", fake_dialog(Scenario(name="new", expect_exit=0))
        ):
            self.app.scenario_edit()
        self.pump()
        self.assertEqual([s.name for s in self.app.project.branch.scenarios], ["new"])
        self.assertIn("new", self.app.scenario_tree.get_children())
        self.assertNotIn("old", self.app.scenario_tree.get_children())

    def test_edit_scenario_keeping_name(self) -> None:
        from asmx.ui import app as appmod
        from asmx.workspace import Scenario

        self.app.project.add_scenario(Scenario(name="only"))
        self.app.refresh_scenarios()
        self.app.scenario_tree.selection_set("only")
        with mock.patch.object(
            appmod, "ScenarioDialog", fake_dialog(Scenario(name="only", expect_exit=3))
        ):
            self.app.scenario_edit()
        self.pump()
        self.assertEqual([s.name for s in self.app.project.branch.scenarios], ["only"])
        self.assertEqual(self.app.project.branch.scenarios[0].expect_exit, 3)

    def test_edit_scenario_without_selection_warns(self) -> None:
        from asmx.ui import app as appmod

        with mock.patch.object(appmod, "ScenarioDialog") as window:
            self.app.scenario_edit()
        window.assert_not_called()
        self.assertIn("select a scenario", self.app.status.cget("text"))

    def test_cancelled_edit_scenario_changes_nothing(self) -> None:
        from asmx.ui import app as appmod
        from asmx.workspace import Scenario

        self.app.project.add_scenario(Scenario(name="stays"))
        self.app.refresh_scenarios()
        self.app.scenario_tree.selection_set("stays")
        with mock.patch.object(appmod, "ScenarioDialog", fake_dialog(None)):
            self.app.scenario_edit()
        self.assertEqual([s.name for s in self.app.project.branch.scenarios], ["stays"])

    def test_delete_scenario(self) -> None:
        from asmx.workspace import Scenario

        self.app.project.add_scenario(Scenario(name="disposable"))
        self.app.refresh_scenarios()
        self.app.scenario_tree.selection_set("disposable")
        self.app.scenario_delete()
        self.pump()
        self.assertEqual(self.app.project.branch.scenarios, [])
        self.assertNotIn("disposable", self.app.scenario_tree.get_children())

    def test_delete_scenario_without_selection_does_nothing(self) -> None:
        from asmx.workspace import Scenario

        self.app.project.add_scenario(Scenario(name="stays"))
        self.app.refresh_scenarios()
        self.app.scenario_delete()
        self.assertEqual([s.name for s in self.app.project.branch.scenarios], ["stays"])

    def test_run_selected_scenario(self) -> None:
        from asmx.workspace import Scenario

        self.app.project.add_scenario(Scenario(name="passes", expect_output="Hello, world!\n"))
        self.app.refresh_scenarios()
        self.app.scenario_tree.selection_set("passes")
        self.app.run_selected_scenario()
        self.pump()
        self.assertEqual(self.app.scenario_tree.item("passes", "tags"), ("ok",))
        self.assertIn("passed", self.app.status.cget("text"))

    def test_run_scenario_without_selection_warns(self) -> None:
        self.app.run_selected_scenario()
        self.assertIn("select a scenario", self.app.status.cget("text"))

    def test_run_all_without_scenarios_warns(self) -> None:
        self.app.run_all_scenarios()
        self.assertIn("no scenarios", self.app.status.cget("text"))

    def test_detail_of_scenario_that_never_ran(self) -> None:
        from asmx.workspace import Scenario

        self.app.project.add_scenario(Scenario(name="stopped", entry="_start", regs={"rdi": "1"}))
        self.app.refresh_scenarios()
        self.app.scenario_tree.selection_set("stopped")
        self.app.on_scenario_select()
        text = self.app.scenario_detail.cget("text")
        self.assertIn("has not run yet", text)
        self.assertIn("_start", text)

    def test_detail_of_scenario_without_selection(self) -> None:
        before = self.app.scenario_detail.cget("text")
        self.app.on_scenario_select()
        self.assertEqual(self.app.scenario_detail.cget("text"), before)

    def test_detail_of_scenario_that_passed(self) -> None:
        from asmx.ui import theme
        from asmx.workspace import Scenario

        self.app.project.add_scenario(Scenario(name="passes", expect_output="Hello, world!\n"))
        self.app.refresh_scenarios()
        self.app.run_all_scenarios()
        self.app.scenario_tree.selection_set("passes")
        self.app.on_scenario_select()
        text = self.app.scenario_detail.cget("text")
        self.assertIn("passed", text)
        self.assertIn("instructions executed", text)
        self.assertEqual(str(self.app.scenario_detail.cget("foreground")), theme.CALL)

    def test_detail_of_scenario_that_failed_with_problems(self) -> None:
        from asmx.examples import EXAMPLES
        from asmx.ui import theme
        from asmx.workspace import Scenario

        self.set_code(EXAMPLES["linux-loop"]["code"])
        self.app.project.add_scenario(Scenario(name="loop", max_steps=5))
        self.app.refresh_scenarios()
        self.app.run_all_scenarios()
        self.pump()
        self.app.scenario_tree.selection_set("loop")
        self.app.on_scenario_select()
        text = self.app.scenario_detail.cget("text")
        self.assertIn("FAILED", text)
        self.assertIn("problems detected", text)
        self.assertEqual(str(self.app.scenario_detail.cget("foreground")), theme.SEV_COLOR["error"])

    def test_run_all_counts_the_passed_ones(self) -> None:
        from asmx.workspace import Scenario

        self.app.project.add_scenario(Scenario(name="passes", expect_output="Hello, world!\n"))
        self.app.project.add_scenario(Scenario(name="fails", expect_output="nothing like it"))
        self.app.refresh_scenarios()
        self.app.run_all_scenarios()
        self.pump()
        self.assertEqual(self.app.scenario_tree.item("passes", "tags"), ("ok",))
        self.assertEqual(self.app.scenario_tree.item("fails", "tags"), ("failed",))
        self.assertIn("1 of 2", self.app.status.cget("text"))


@unittest.skipUnless(TK_OK and HAS_DISPLAY, "no Tkinter or no display")
class TestAppNotes(AppTestCase):
    """Per-line notes."""

    def test_note_cursor_line(self) -> None:
        from asmx.ui import app as appmod

        self.app.editor.goto_line(3)
        with mock.patch.object(appmod, "TextPromptDialog", fake_dialog("reminder")):
            self.app.edit_note()
        self.pump()
        self.assertEqual(self.app.project.note(3), "reminder")
        self.assertIn("3", self.app.note_tree.get_children())
        self.assertIn("note saved on line 3", self.app.status.cget("text"))

    def test_empty_note_removes_the_line(self) -> None:
        from asmx.ui import app as appmod

        self.app.editor.goto_line(3)
        self.app.project.set_note(3, "old")
        self.app.refresh_notes()
        with mock.patch.object(appmod, "TextPromptDialog", fake_dialog("")):
            self.app.edit_note()
        self.pump()
        self.assertEqual(self.app.project.note(3), "")
        self.assertNotIn("3", self.app.note_tree.get_children())
        self.assertIn("note removed on line 3", self.app.status.cget("text"))

    def test_cancelled_note_changes_nothing(self) -> None:
        from asmx.ui import app as appmod

        self.app.editor.goto_line(3)
        self.app.project.set_note(3, "old")
        self.app.refresh_notes()
        with mock.patch.object(appmod, "TextPromptDialog", fake_dialog(None)):
            self.app.edit_note()
        self.assertEqual(self.app.project.note(3), "old")

    def test_open_note_jumps_to_line(self) -> None:
        self.app.project.set_note(2, "come back here")
        self.app.refresh_notes()
        self.app.note_tree.selection_set("2")
        self.app.on_note_open()
        self.pump()
        self.assertEqual(self.app.editor.cursor_line(), 2)

    def test_open_note_without_selection(self) -> None:
        self.app.editor.goto_line(1)
        self.app.on_note_open()
        self.assertEqual(self.app.editor.cursor_line(), 1)

    def test_remove_selected_note(self) -> None:
        self.app.project.set_note(4, "goes away later")
        self.app.refresh_notes()
        self.app.note_tree.selection_set("4")
        self.app.delete_note()
        self.pump()
        self.assertEqual(self.app.project.note(4), "")
        self.assertEqual(self.app.note_tree.get_children(), ())

    def test_remove_note_without_selection(self) -> None:
        self.app.project.set_note(4, "stays")
        self.app.refresh_notes()
        self.app.delete_note()
        self.assertEqual(self.app.project.note(4), "stays")

    def test_notes_tab_is_clean_when_switching_branch(self) -> None:
        self.app.project.set_note(2, "note of the default branch")
        self.app.refresh_notes()
        self.assertEqual(len(self.app.note_tree.get_children()), 1)
        self.app.project.fork("alt")
        self.app.branch_switch("alt")
        self.pump()
        self.assertEqual(len(self.app.note_tree.get_children()), 1)


@unittest.skipUnless(TK_OK and HAS_DISPLAY, "no Tkinter or no display")
class TestAppDocumentation(AppTestCase):
    """Documentation panel and line explanation."""

    def test_explains_local_label(self) -> None:
        self.set_code(FULL_CODE)
        line = next(item.n for item in self.app.analysis.program.lines if item.local_label)
        self.app.on_cursor(line, 1)
        text = self.app.doc_text.get("1.0", "end-1c")
        self.assertIn("Label", text)
        self.assertIn("local label", text)

    def test_on_cursor_walks_every_line_kind(self) -> None:
        self.set_code(FULL_CODE)
        seen = set()
        for line in self.app.analysis.program.lines:
            self.app.on_cursor(line.n, 1)
            self.assertTrue(self.app.doc_text.get("1.0", "end-1c").strip())
            seen.add(line.kind)
        self.assertIn("empty", seen)
        self.assertIn("label", seen)
        self.assertIn("data", seen)
        self.assertIn("directive", seen)

    def test_describe_line_of_each_kind(self) -> None:
        from asmx.parser import Line

        cases = [
            (Line(n=9, raw=".loop:", kind="label", label=".loop", local_label=True), "Label"),
            (
                Line(
                    n=3,
                    raw="buf: resb 16",
                    kind="data",
                    label="buf",
                    directive="resb",
                    args=["16"],
                    reserve=True,
                ),
                "Space reservation",
            ),
            (
                Line(
                    n=2,
                    raw="msg: db 1",
                    kind="data",
                    label="msg",
                    directive="db",
                    args=["1"],
                    unit=1,
                ),
                "Initialized data",
            ),
            (
                Line(
                    n=4,
                    raw="SIZE equ 4",
                    kind="data",
                    label="SIZE",
                    directive="equ",
                    args=["4"],
                    unit=4,
                ),
                "Assembler constant",
            ),
            (
                Line(
                    n=5,
                    raw="tab: times 4 db 0",
                    kind="directive",
                    directive="times",
                    args=["4", "db", "0"],
                ),
                "Assembler directive",
            ),
        ]
        for line, expected in cases:
            with self.subTest(kind=line.kind, directive=line.directive):
                self.app.describe_line(line)
                self.assertIn(expected, self.app.doc_text.get("1.0", "end-1c"))

    def test_on_cursor_without_analysis_does_not_break(self) -> None:
        self.app.analysis = None
        self.app.on_cursor(1, 1)
        self.assertIn("Ln 1, Col 1", self.app.status.cget("text"))

    def test_documentation_list_with_and_without_search(self) -> None:
        self.app.doc_query.delete(0, "end")
        self.app.refresh_doc_list()
        every = self.app.doc_list.get(0, "end")
        self.assertGreater(len(every), 10)
        self.app.doc_query.insert(0, "jn")
        self.app.refresh_doc_list()
        filtered = self.app.doc_list.get(0, "end")
        self.assertTrue(filtered)
        self.assertTrue(all(name.startswith("jn") for name in filtered))
        self.assertLess(len(filtered), len(every))

    def test_choosing_mnemonic_in_the_list_shows_the_help(self) -> None:
        self.app.doc_query.delete(0, "end")
        self.app.refresh_doc_list()
        self.app.doc_list.selection_clear(0, "end")
        self.app.doc_list.selection_set(0)
        self.app.on_doc_select()
        chosen = self.app.doc_list.get(0)
        self.assertIn(chosen.upper(), self.app.doc_text.get("1.0", "end-1c"))

    def test_on_doc_select_without_selection_does_nothing(self) -> None:
        before = self.app.doc_text.get("1.0", "end-1c")
        self.app.doc_list.selection_clear(0, "end")
        self.app.on_doc_select()
        self.assertEqual(self.app.doc_text.get("1.0", "end-1c"), before)

    def test_documentation_of_known_and_unknown_mnemonic(self) -> None:
        self.app.show_doc("mov")
        self.assertIn("MOV", self.app.doc_text.get("1.0", "end-1c"))
        self.app.show_doc("doesnotexist")
        self.assertIn("No documentation", self.app.doc_text.get("1.0", "end-1c"))
        self.app.show_doc(None)
        self.assertIn("No documentation", self.app.doc_text.get("1.0", "end-1c"))

    def test_documentation_of_instruction_with_memory(self) -> None:
        self.set_code("section .text\n_start:\n    mov rax, [rbp - 8]\n")
        instruction = next(i for i in self.app.analysis.instrs if i.mnemonic == "mov")
        self.app.show_doc(instruction.mnemonic, instruction)
        text = self.app.doc_text.get("1.0", "end-1c")
        self.assertIn("MOV", text)
        self.assertIn("RAX", text)
        self.assertIn("RBP", text)

    def test_documentation_of_instruction_with_note(self) -> None:
        instruction = next(i for i in self.app.analysis.instrs if i.mnemonic == "syscall")
        self.app.show_doc(instruction.mnemonic, instruction)
        text = self.app.doc_text.get("1.0", "end-1c")
        self.assertIn("SYSCALL", text)
        self.assertIn("Processor flags", text)

    def test_documentation_of_mnemonic_with_note(self) -> None:
        from asmx.isa import ISA

        with_note = next(k for k, v in ISA.items() if v.get("note"))
        self.app.show_doc(with_note)
        self.assertIn(ISA[with_note]["note"], self.app.doc_text.get("1.0", "end-1c"))

    def test_documentation_of_instruction_with_registers_without_entries(self) -> None:
        self.set_code("section .text\n_start:\n    movups xmm0, [rbp - 8]\n")
        instruction = next(i for i in self.app.analysis.instrs if i.mnemonic == "movups")
        self.app.show_doc(instruction.mnemonic, instruction)
        text = self.app.doc_text.get("1.0", "end-1c")
        self.assertIn("RBP", text)
        self.assertIn("no documentation", text.lower())

    def test_selecting_register_explains_its_role(self) -> None:
        self.app.reg_tree.selection_set("rax")
        self.app.on_reg_select()
        self.assertIn("RAX", self.app.status.cget("text"))
        self.app.reg_tree.selection_remove("rax")
        before = self.app.status.cget("text")
        self.app.on_reg_select()
        self.assertEqual(self.app.status.cget("text"), before)


@unittest.skipUnless(TK_OK and HAS_DISPLAY, "no Tkinter or no display")
class TestAppStructureAndProblems(AppTestCase):
    """Structure tree, problem list and breakpoints."""

    def test_clicking_structure_jumps_to_line(self) -> None:
        iid, line = self.item_with_line(self.app.tree)
        self.app.tree.selection_set(iid)
        self.app.on_tree_select()
        self.pump()
        self.assertEqual(self.app.editor.cursor_line(), line)

    def test_clicking_structure_without_selection(self) -> None:
        self.app.editor.goto_line(1)
        self.app.tree.selection_remove(*self.app.tree.selection())
        self.app.on_tree_select()
        self.assertEqual(self.app.editor.cursor_line(), 1)

    def test_clicking_structure_without_line_does_not_jump(self) -> None:
        iid = self.item_without_line(self.app.tree)
        self.app.editor.goto_line(1)
        self.app.tree.selection_set(iid)
        self.app.on_tree_select()
        self.assertEqual(self.app.editor.cursor_line(), 1)

    def test_tag_line_returns_none_without_line_tag(self) -> None:
        self.assertIsNone(self.app._tag_line(("blk", "sec")))
        self.assertEqual(self.app._tag_line(("line:7", "no_mov")), 7)
        self.assertIsNone(self.app._tag_line(""))

    def test_selecting_problem_shows_the_hint(self) -> None:
        from asmx.examples import EXAMPLES

        self.set_code(EXAMPLES["broken"]["code"])
        self.app.validate_now()
        self.pump()
        first = self.app.problem_tree.get_children()[0]
        self.app.problem_tree.selection_set(first)
        self.app.on_problem_select()
        self.assertTrue(self.app.problem_hint.cget("text"))

    def test_selecting_problem_without_selection(self) -> None:
        self.app.problem_tree.selection_remove(*self.app.problem_tree.selection())
        self.app.on_problem_select()
        self.assertEqual(self.app.problem_hint.cget("text"), "")

    def test_selecting_problem_with_unknown_line(self) -> None:
        self.app.problem_tree.insert(
            "", "end", iid="extra", values=(0, "X", "no line"), tags=("error",)
        )
        self.app.problem_tree.selection_set("extra")
        self.app.on_problem_select()
        self.assertEqual(self.app.problem_hint.cget("text"), "")

    def test_open_problem_jumps_to_line(self) -> None:
        from asmx.examples import EXAMPLES

        self.set_code(EXAMPLES["broken"]["code"])
        self.app.validate_now()
        self.pump()
        first = self.app.problem_tree.get_children()[0]
        line = int(self.app.problem_tree.item(first, "values")[0])
        self.app.problem_tree.selection_set(first)
        self.app.on_problem_open()
        self.pump()
        self.assertEqual(self.app.editor.cursor_line(), line)

    def test_open_problem_without_selection(self) -> None:
        self.app.editor.goto_line(1)
        self.app.problem_tree.selection_remove(*self.app.problem_tree.selection())
        self.app.on_problem_open()
        self.assertEqual(self.app.editor.cursor_line(), 1)

    def test_open_problem_without_line_does_not_jump(self) -> None:
        self.app.problem_tree.insert("", "end", iid="noline", values=(0, "X", "?"))
        self.app.editor.goto_line(1)
        self.app.problem_tree.selection_set("noline")
        self.app.on_problem_open()
        self.assertEqual(self.app.editor.cursor_line(), 1)

    def test_structure_without_analysis_stays_empty(self) -> None:
        self.app.analysis = None
        self.app.refresh_structure()
        self.assertEqual(self.app.tree.get_children(), ())

    def test_refresh_of_the_panels_does_not_break(self) -> None:
        self.app.refresh_problems()
        self.app.refresh_scenarios()
        self.app.refresh_notes()
        self.assertIn("Problems", self.app.bottom.tab(self.app.bottom.select(), "text"))

    def test_breakpoint_is_stored_in_the_project(self) -> None:
        self.app.editor.breakpoints = {3}
        self.app.on_breakpoint(3, True)
        self.assertEqual(self.app.project.branch.breakpoints, [3])
        self.assertIn("breakpoint set on line 3", self.app.status.cget("text"))
        self.app.on_breakpoint(3, False)
        self.assertIn("cleared", self.app.status.cget("text"))


@unittest.skipUnless(TK_OK and HAS_DISPLAY, "no Tkinter or no display")
class TestAppExecution(AppTestCase):
    """Run menu: steps, execution, stack and isolated debugging."""

    def test_reset_without_analysis_does_nothing(self) -> None:
        machine = mock.MagicMock()
        self.app.analysis = None
        self.app.machine = machine
        self.app.reset_machine()
        self.assertIs(self.app.machine, machine)

    def test_ensure_machine_creates_the_missing_machine(self) -> None:
        self.app.machine = None
        machine = self.app._ensure_machine()
        self.assertIsNotNone(machine)
        self.assertIs(machine, self.app.machine)

    def test_step_after_halt_warns(self) -> None:
        self.app.run()
        self.pump()
        self.assertTrue(self.app.machine.halted)
        self.app.step()
        self.assertIn("already finished", self.app.status.cget("text"))

    def test_run_after_halt_restarts_by_itself(self) -> None:
        self.app.run()
        self.pump()
        first = self.app.machine
        self.app.run()
        self.pump()
        self.assertIsNot(self.app.machine, first)
        self.assertIn("Hello, world!", self.app.output_text.get("1.0", "end-1c"))
        self.assertIn("run finished", self.app.status.cget("text"))

    def test_run_to_cursor_without_instruction_warns(self) -> None:
        self.set_code("section .text\n_start:\n    nop\n")
        self.app.editor.goto_line(1)
        self.app.run_to_cursor()
        self.assertIn("no instruction", self.app.status.cget("text"))

    def test_debug_function_without_analysis(self) -> None:
        self.app.analysis = None
        self.app.debug_function()
        self.assertIn("machine reset", self.app.status.cget("text"))

    def test_debug_function_without_labels_warns(self) -> None:
        from asmx.ui import app as appmod

        self.set_code("    mov rax, 1\n    nop\n")
        with mock.patch.object(appmod.messagebox, "showinfo") as warning:
            self.app.debug_function()
        warning.assert_called_once()

    def test_debug_function_with_missing_label_does_nothing(self) -> None:
        from asmx.ui import app as appmod

        before = self.app.machine
        with mock.patch.object(appmod, "TextPromptDialog", fake_dialog("does_not_exist")):
            self.app.debug_function()
        self.assertIs(self.app.machine, before)

    def test_cancelled_debug_function_does_nothing(self) -> None:
        from asmx.ui import app as appmod

        before = self.app.machine
        with mock.patch.object(appmod, "TextPromptDialog", fake_dialog(None)):
            self.app.debug_function()
        self.assertIs(self.app.machine, before)

    def test_machine_panel_without_machine(self) -> None:
        before = self.app.reg_tree.get_children()
        self.app.machine = None
        self.app.refresh_machine()
        self.assertEqual(self.app.reg_tree.get_children(), before)

    def test_stack_shows_return_address(self) -> None:
        self.set_code(STACK_CODE)
        self.app.reset_machine()
        for _ in range(6):
            self.app.step()
        self.pump()
        root = self.app.mem_tree.get_children()[0]
        notes = [
            self.app.mem_tree.item(i, "values")[1] for i in self.app.mem_tree.get_children(root)
        ]
        self.assertEqual(len(notes), 6)
        self.assertEqual(notes[0], "RSP")
        self.assertIn("return address", notes[-1])

    def test_analysis_failure_warns_in_the_status_bar(self) -> None:
        from asmx.ui import app as appmod

        with mock.patch.object(appmod, "analyze", side_effect=ValueError("broke")):
            self.app.analyze_now()
        self.assertIn("analysis failed", self.app.status.cget("text"))

    def test_suspended_change_does_not_reanalyze(self) -> None:
        before = self.app.analysis
        self.app._suspend_change = True
        self.app.editor.set_code("mov rax, 123")
        self.app.on_code_change()
        self.assertIs(self.app.analysis, before)
        self.app._suspend_change = False


@unittest.skipUnless(TK_OK and HAS_DISPLAY, "no Tkinter or no display")
class TestAppStatus(AppTestCase):
    """Status line, validation and edit shortcuts."""

    def test_status_with_cursor_and_message(self) -> None:
        self.app.set_status("important note", cursor=(4, 5))
        text = self.app.status.cget("text")
        self.assertIn("Ln 4, Col 5", text)
        self.assertIn("branch: %s" % self.default_branch, text)
        self.assertIn("important note", text)

    def test_status_without_analysis_and_arguments(self) -> None:
        self.app.analysis = None
        self.app.set_status()
        text = self.app.status.cget("text")
        self.assertIn("Ln ", text)
        self.assertNotIn("instructions", text)

    def test_status_warns_that_it_was_not_saved(self) -> None:
        self.app.project.dirty = True
        self.app.set_status()
        self.assertIn("not saved", self.app.status.cget("text"))

    def test_validate_clean_code(self) -> None:
        self.app.validate_now()
        self.pump()
        self.assertIn("no problems found", self.app.status.cget("text"))

    def test_validate_broken_code(self) -> None:
        from asmx.examples import EXAMPLES

        self.set_code(EXAMPLES["broken"]["code"])
        self.app.validate_now()
        self.pump()
        self.assertTrue(self.app.problems)
        self.assertIn("Problems", self.app.bottom.tab(self.app.bottom.select(), "text"))

    def test_comment_from_the_menu(self) -> None:
        self.set_code("mov rax, 1\nmov rbx, 2")
        self.app.editor.goto_line(1)
        self.app.editor_toggle_comment()
        self.pump()
        self.assertTrue(self.app.editor.get_code().startswith("; mov rax, 1"))

    def test_find_with_and_without_success(self) -> None:
        from asmx.ui import app as appmod

        with mock.patch.object(appmod, "TextPromptDialog", fake_dialog("Hello")):
            self.app.find()
        self.assertTrue(self.app.editor.text.tag_ranges("found"))
        with mock.patch.object(appmod, "TextPromptDialog", fake_dialog("doesnotexist")):
            self.app.find()
        self.assertIn("could not find", self.app.status.cget("text"))

    def test_cancelled_find(self) -> None:
        from asmx.ui import app as appmod

        with mock.patch.object(appmod, "TextPromptDialog", fake_dialog(None)):
            self.app.find()
        self.assertFalse(self.app.editor.text.tag_ranges("found"))

    def test_go_to_line(self) -> None:
        from asmx.ui import app as appmod

        with mock.patch.object(appmod, "TextPromptDialog", fake_dialog("3")):
            self.app.goto_line()
        self.assertEqual(self.app.editor.cursor_line(), 3)

    def test_go_to_invalid_line_and_cancelled(self) -> None:
        from asmx.ui import app as appmod

        self.app.editor.goto_line(2)
        for answer in ("abc", "", None, "   "):
            with self.subTest(answer=answer):
                with mock.patch.object(appmod, "TextPromptDialog", fake_dialog(answer)):
                    self.app.goto_line()
                self.assertEqual(self.app.editor.cursor_line(), 2)

    def test_show_about(self) -> None:
        from asmx.ui import app as appmod

        window = mock.MagicMock()
        with mock.patch.object(appmod, "AboutDialog", window):
            self.app.show_about()
        window.assert_called_once()
        window.return_value.show.assert_called_once()


@unittest.skipUnless(TK_OK and HAS_DISPLAY, "no Tkinter or no display")
class TestEditorWidget(AppTestCase):
    """Editor methods that do not depend on real typing."""

    def test_set_code_keeping_the_scroll(self) -> None:
        ed = self.app.editor
        code = "\n".join("line %d" % i for i in range(300))
        ed.set_code(code)
        self.pump()
        ed.text.yview_moveto(0.6)
        self.pump()
        self.assertGreater(ed.text.yview()[0], 0.1)
        ed.set_code(code, keep_view=True)
        self.pump()
        self.assertGreater(ed.text.yview()[0], 0.1)

    def test_line_and_cursor_count(self) -> None:
        ed = self.app.editor
        ed.set_code("mov rax, 1\nmov rbx, 2\nmov rcx, 3")
        self.pump()
        self.assertEqual(ed.line_count(), 3)
        ed.goto_line(2, focus=False)
        self.assertEqual(ed.cursor_line(), 2)
        self.assertEqual(ed.cursor_col(), 1)
        ed.goto_line(3)
        self.assertEqual(ed.cursor_line(), 3)

    def test_insert_at_cursor(self) -> None:
        ed = self.app.editor
        ed.set_code("mov rax, 1")
        ed.goto_line(1)
        ed.insert_at_cursor("; note\n")
        self.pump()
        self.assertTrue(ed.get_code().startswith("; note\n"))
        self.assertIn("; note", ed.get_code())

    def test_find_hit_miss_and_empty_term(self) -> None:
        ed = self.app.editor
        ed.set_code("mov rax, 1\nmov rbx, 2")
        self.pump()
        self.assertTrue(ed.find("rbx"))
        self.assertTrue(ed.text.tag_ranges("found"))
        self.assertTrue(ed.find("mov"))
        self.assertTrue(ed.find("mov", from_start=True))
        self.assertFalse(ed.find("doesnotexist"))
        self.assertFalse(ed.find(""))

    def test_comment_and_uncomment_a_selection(self) -> None:
        ed = self.app.editor
        ed.set_code("mov rax, 1\n\nmov rbx, 2")
        self.pump()
        ed.text.tag_add("sel", "1.0", "3.end")
        ed.toggle_comment()
        self.pump()
        lines = ed.get_code().split("\n")
        self.assertEqual(lines[0], "; mov rax, 1")
        self.assertEqual(lines[1], "")
        self.assertEqual(lines[2], "; mov rbx, 2")
        ed.text.tag_add("sel", "1.0", "3.end")
        ed.toggle_comment()
        self.pump()
        self.assertEqual(ed.get_code(), "mov rax, 1\n\nmov rbx, 2")

    def test_uncomment_line_already_commented(self) -> None:
        ed = self.app.editor
        ed.set_code("; mov rax, 1")
        self.pump()
        ed.goto_line(1)
        ed.toggle_comment()
        self.pump()
        self.assertEqual(ed.get_code(), "mov rax, 1")

    def test_mark_lines_with_error(self) -> None:
        ed = self.app.editor
        ed.set_code("mov rax, 1\nmov rbx, 2\nmov rcx, 3")
        self.pump()
        ed.mark_error_lines([1, 3])
        self.assertEqual(len(ed.text.tag_ranges("errorline")) // 2, 2)
        with mock.patch.object(ed.text, "tag_add", side_effect=tk.TclError("invalid index")):
            ed.mark_error_lines([1])

    def test_mark_running_line(self) -> None:
        ed = self.app.editor
        ed.set_code("mov rax, 1\nmov rbx, 2")
        self.pump()
        ed.set_exec_line(2)
        self.assertTrue(ed.text.tag_ranges("exec"))
        ed.set_exec_line(None)
        self.assertFalse(ed.text.tag_ranges("exec"))

    def test_mark_cursor_line(self) -> None:
        ed = self.app.editor
        ed.set_code("mov rax, 1\nmov rbx, 2")
        ed.goto_line(2)
        self.pump()
        ed.mark_current_line()
        self.assertTrue(ed.text.tag_ranges("current"))

    def test_schedule_and_redo_the_highlight(self) -> None:
        ed = self.app.editor
        ed.set_code('; comment\nmsg: db "text", 0x10\n    mov rax, 0x10\n')
        self.pump()
        ed.schedule_highlight()
        ed.schedule_highlight()
        self.assertIsNotNone(ed._highlight_job)
        limit = time.time() + 3.0
        while ed._highlight_job and time.time() < limit:
            self.pump()
            time.sleep(0.02)
        self.assertIsNone(ed._highlight_job, "the scheduled highlight should have run")
        for tag in ("comment", "string", "directive", "label", "number", "register", "mnemonic"):
            with self.subTest(tag=tag):
                self.assertTrue(ed.text.tag_ranges(tag), "tag %s without marks" % tag)

    def test_highlight_does_not_mark_mnemonic_mid_line(self) -> None:
        ed = self.app.editor
        ed.set_code("mov rax, call")
        self.pump()
        ed.highlight()
        marks = ed.text.tag_ranges("mnemonic")
        self.assertEqual(len(marks), 2)
        self.assertEqual(ed.text.get(marks[0], marks[1]), "mov")

    def test_tab_inserts_four_spaces(self) -> None:
        ed = self.app.editor
        ed.set_code("")
        ed.goto_line(1)
        self.assertEqual(ed._tab(FakeEvent()), "break")
        self.assertEqual(ed.get_code(), "    ")

    def test_mouse_wheel_scrolls_both_ways(self) -> None:
        ed = self.app.editor
        ed.set_code("\n".join("line %d" % i for i in range(300)))
        self.pump()
        ed.text.yview_moveto(0.5)
        self.pump()
        middle = ed.text.yview()[0]
        self.assertEqual(ed._wheel(FakeEvent(num=4)), "break")
        above = ed.text.yview()[0]
        self.assertLess(above, middle)
        self.assertEqual(ed._wheel(FakeEvent(num=5)), "break")
        below = ed.text.yview()[0]
        self.assertGreater(below, above)
        ed._wheel(FakeEvent(delta=120))
        with_delta = ed.text.yview()[0]
        self.assertLess(with_delta, below)
        ed._wheel(FakeEvent(delta=-120))
        self.assertGreater(ed.text.yview()[0], with_delta)

    def test_gutter_click_toggles_breakpoint(self) -> None:
        ed = self.app.editor
        ed.set_code("\n".join("mov rax, %d" % i for i in range(20)))
        self.pump()
        info = ed.text.dlineinfo("3.0")
        self.assertIsNotNone(info)
        y = int(info[1]) + 3
        ed._gutter_click(FakeEvent(y=y))
        self.assertIn(3, ed.breakpoints)
        self.assertIn(3, self.app.project.branch.breakpoints)
        ed._gutter_click(FakeEvent(y=y))
        self.assertNotIn(3, ed.breakpoints)
        self.app.editor.on_breakpoint = None
        ed._gutter_click(FakeEvent(y=y))
        self.assertIn(3, ed.breakpoints)

    def test_click_outside_the_text_is_ignored(self) -> None:
        ed = self.app.editor
        ed.set_code("mov rax, 1\nmov rbx, 2")
        self.pump()
        ed.breakpoints = set()
        with mock.patch.object(ed, "line_count", return_value=0):
            ed._gutter_click(FakeEvent(y=5))
        self.assertEqual(ed.breakpoints, set())

    def test_clear_scheduled_jobs(self) -> None:
        ed = self.app.editor
        ed.schedule_highlight()
        ed._cleanup()
        self.assertIsNone(ed._highlight_job)
        self.assertIsNone(ed._change_job)
        ed.schedule_highlight()
        self.assertIsNone(ed._highlight_job, "a destroyed editor does not schedule a highlight")
        ed._highlight_job = "fake-job"
        with mock.patch.object(ed, "after_cancel", side_effect=tk.TclError("gone")):
            ed._cleanup()
        self.assertIsNone(ed._highlight_job)

    def test_scroll_forwarded_and_bar_synced(self) -> None:
        ed = self.app.editor
        ed.set_code("\n".join("line %d" % i for i in range(200)))
        self.pump()
        ed._yview("moveto", 0.25)
        self.assertGreater(ed.text.yview()[0], 0.0)
        ed._on_text_scroll(0.0, 1.0)
        first, last = ed.scroll.get()
        self.assertGreaterEqual(first, 0.0)
        self.assertGreater(last, first)

    def test_gutter_draws_marks(self) -> None:
        ed = self.app.editor
        ed.set_code("\n".join("mov rax, %d" % i for i in range(20)))
        self.pump()
        ed.breakpoints = {2}
        ed.notes = {"3": "note"}
        ed.set_exec_line(4)
        self.pump()
        self.assertTrue(ed.gutter.find_all())

    def test_gutter_survives_text_without_index(self) -> None:
        ed = self.app.editor
        with mock.patch.object(ed.text, "index", side_effect=tk.TclError("no widget")):
            ed.redraw_gutter()

    def test_edit_without_observers(self) -> None:
        ed = self.app.editor
        ed.set_code("mov rax, 1")
        ed.on_change = None
        ed.on_cursor = None
        ed._changed()
        ed._cursor_moved()
        ed._cleanup()
        self.assertTrue(ed.get_code())


@unittest.skipUnless(TK_OK and HAS_DISPLAY, "no Tkinter or no display")
class TestTheme(unittest.TestCase):
    """Fonts and ttk theme, including the emergency paths."""

    def setUp(self) -> None:
        self.root = tk.Tk()
        self.root.update()

    def tearDown(self) -> None:
        try:
            self.root.destroy()
        except tk.TclError:
            pass

    def test_normal_fonts(self) -> None:
        from asmx.ui import theme

        self.assertTrue(theme.mono(11).actual("family"))
        self.assertTrue(theme.mono(11, "bold").actual("family"))
        self.assertTrue(theme.ui(10).actual("family"))
        self.assertTrue(theme.ui(12, "bold").actual("family"))

    def test_mono_falls_back_to_courier_when_everything_fails(self) -> None:
        from asmx.ui import theme

        fallback = mock.MagicMock()
        fallback.actual.return_value = "Courier"

        def fake_font(*args: Any, **kwargs: Any) -> Any:
            if kwargs.get("family") == "Courier":
                return fallback
            raise tk.TclError("font unavailable")

        with mock.patch.object(theme.tkfont, "Font", side_effect=fake_font):
            self.assertIs(theme.mono(11), fallback)

    def test_mono_skips_font_without_family(self) -> None:
        from asmx.ui import theme

        empty = mock.MagicMock()
        empty.actual.return_value = ""
        good = mock.MagicMock()
        good.actual.return_value = "DejaVu Sans Mono"

        def fake_font(*args: Any, **kwargs: Any) -> Any:
            family = kwargs.get("family")
            if family == "JetBrains Mono":
                return empty
            if family == "DejaVu Sans Mono":
                return good
            raise tk.TclError("font unavailable")

        with mock.patch.object(theme.tkfont, "Font", side_effect=fake_font):
            self.assertIs(theme.mono(11), good)

    def test_ui_uses_the_default_font_when_everything_fails(self) -> None:
        from asmx.ui import theme

        fallback = mock.MagicMock()
        fallback.actual.return_value = "TkDefaultFont"

        def fake_font(*args: Any, **kwargs: Any) -> Any:
            if kwargs.get("family") is None:
                return fallback
            raise tk.TclError("font unavailable")

        with mock.patch.object(theme.tkfont, "Font", side_effect=fake_font):
            self.assertIs(theme.ui(10), fallback)

    def test_ui_skips_font_without_family(self) -> None:
        from asmx.ui import theme

        empty = mock.MagicMock()
        empty.actual.return_value = ""
        good = mock.MagicMock()
        good.actual.return_value = "DejaVu Sans"

        def fake_font(*args: Any, **kwargs: Any) -> Any:
            family = kwargs.get("family")
            if family == "Segoe UI":
                return empty
            if family == "DejaVu Sans":
                return good
            raise tk.TclError("font unavailable")

        with mock.patch.object(theme.tkfont, "Font", side_effect=fake_font):
            self.assertIs(theme.ui(10), good)

    def test_ttk_theme_survives_broken_theme_use(self) -> None:
        from tkinter import ttk
        from asmx.ui import theme

        with mock.patch.object(ttk.Style, "theme_use", side_effect=tk.TclError("no theme")):
            style = theme.apply_ttk_theme(self.root)
        self.assertIsInstance(style, ttk.Style)
        self.assertTrue(style.configure("TFrame", "background"))


if __name__ == "__main__":
    unittest.main()
