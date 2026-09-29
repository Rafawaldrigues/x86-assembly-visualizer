"""Tests of the auxiliary windows (asmx.ui.dialogs), without opening a real modal."""

from __future__ import annotations

import os
import unittest
from typing import Any, List, Optional

try:
    import tkinter as tk

    TK_OK = True
except ImportError:  # pragma: no cover
    TK_OK = False

HAS_DISPLAY = bool(os.environ.get("DISPLAY")) or os.name == "nt"


def close_window(window: tk.Misc) -> None:
    """Close a window ignoring the error of an application already destroyed.

    Args:
        window: Widget to destroy.
    """
    try:
        window.destroy()
    except tk.TclError:
        pass


def fake_modal(value: Any) -> type:
    """Create a ModalDialog subclass whose collect() always returns the value.

    Args:
        value: Value returned by :meth:`collect`.

    Returns:
        The class ready to be instantiated with ``(master, title)``.
    """
    from asmx.ui.dialogs import ModalDialog

    class FakeModal(ModalDialog):
        """Test modal: it does not wait for the user and returns a fixed value."""

        def collect(self) -> Any:
            """Return the arranged value, like an already filled form.

            Returns:
                The value passed to :func:`fake_modal`.
            """
            return value

    return FakeModal


def fake_prompt(value: Any) -> type:
    """Create a fake dialog (no Tk) that always returns the same value.

    Args:
        value: Value returned by :meth:`show`.

    Returns:
        The class, compatible with the constructor of the real dialogs.
    """

    class FakePrompt:
        """Fake dialog used in place of the modal windows."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            """Accept (and ignore) the same arguments as the real dialog."""

        def show(self) -> Any:
            """Return the arranged value without opening any window.

            Returns:
                The value passed to :func:`fake_prompt`.
            """
            return value

    return FakePrompt


@unittest.skipUnless(TK_OK and HAS_DISPLAY, "no Tkinter or no display")
class TestModalDialog(unittest.TestCase):
    """Base of the modals: buttons, confirm, cancel and show()."""

    def setUp(self) -> None:
        self.root = tk.Tk()
        self.root.geometry("320x240")
        self.root.update()

    def tearDown(self) -> None:
        try:
            self.root.destroy()
        except tk.TclError:
            pass

    def test_base_builds_body_buttons_and_collects_nothing(self) -> None:
        from asmx.ui.dialogs import ModalDialog

        dlg = ModalDialog(self.root, "base", 300, 200)
        self.addCleanup(close_window, dlg)
        self.root.update()
        self.assertTrue(dlg.body.winfo_exists())
        self.assertTrue(dlg.buttons.winfo_exists())
        self.assertEqual(dlg.title(), "base")
        self.assertIsNone(dlg.collect())
        self.assertIsNone(dlg.result)

    def test_add_buttons_creates_cancel_and_confirm(self) -> None:
        from asmx.ui.dialogs import ModalDialog

        dlg = ModalDialog(self.root, "base", 300, 200)
        self.addCleanup(close_window, dlg)
        dlg.add_buttons("Save scenario")
        self.root.update()
        texts = [w.cget("text") for w in dlg.buttons.winfo_children()]
        self.assertIn("Save scenario", texts)
        self.assertIn("Cancel", texts)

    def test_confirm_stores_result_and_closes(self) -> None:
        dlg = fake_modal("done")(self.root, "test")
        self.addCleanup(close_window, dlg)
        self.root.update()
        dlg.confirm()
        self.assertEqual(dlg.result, "done")
        self.assertEqual(dlg.winfo_exists(), 0)

    def test_confirm_without_result_keeps_window(self) -> None:
        from asmx.ui.dialogs import ModalDialog

        dlg = ModalDialog(self.root, "test")
        self.addCleanup(close_window, dlg)
        self.root.update()
        dlg.confirm()
        self.assertIsNone(dlg.result)
        self.assertEqual(dlg.winfo_exists(), 1)

    def test_cancel_clears_result_and_closes(self) -> None:
        dlg = fake_modal("anything")(self.root, "test")
        self.addCleanup(close_window, dlg)
        self.root.update()
        dlg.cancel()
        self.assertIsNone(dlg.result)
        self.assertEqual(dlg.winfo_exists(), 0)

    def test_show_returns_confirmed_result(self) -> None:
        dlg = fake_modal("result")(self.root, "test")
        self.addCleanup(close_window, dlg)
        self.root.update()
        dlg.after(10, dlg.confirm)
        self.assertEqual(dlg.show(), "result")

    def test_cancelled_show_returns_none(self) -> None:
        dlg = fake_modal("result")(self.root, "test")
        self.addCleanup(close_window, dlg)
        self.root.update()
        dlg.after(10, dlg.cancel)
        self.assertIsNone(dlg.show())


@unittest.skipUnless(TK_OK and HAS_DISPLAY, "no Tkinter or no display")
class TestScenarioDialog(unittest.TestCase):
    """Scenario form: filling, validation and collection."""

    def setUp(self) -> None:
        self.root = tk.Tk()
        self.root.geometry("640x520")
        self.root.update()

    def tearDown(self) -> None:
        try:
            self.root.destroy()
        except tk.TclError:
            pass

    def open_dialog(self, labels: Optional[List[str]] = None, scenario: Any = None) -> Any:
        """Open a ScenarioDialog and register its closing at the end of the test.

        Args:
            labels: Labels offered in the "Start at" field.
            scenario: Scenario to edit; None creates a new one.

        Returns:
            The dialog ready to use.
        """
        from asmx.ui.dialogs import ScenarioDialog

        dlg = ScenarioDialog(self.root, labels or [], scenario)
        self.addCleanup(close_window, dlg)
        self.root.update()
        return dlg

    def test_fields_come_filled_from_scenario(self) -> None:
        from asmx.workspace import Scenario

        scenario = Scenario(
            name="c1",
            entry="_start",
            regs={"rdi": "1000000"},
            stdin="abc",
            expect_output="Hello\n",
            expect_exit=3,
            expect_issue=True,
            max_steps=77,
        )
        dlg = self.open_dialog(["_start", "add_pair"], scenario)
        self.assertEqual(dlg.nome.get(), "c1")
        self.assertEqual(dlg.entrada.get(), "_start")
        self.assertEqual(dlg.entrada.cget("values")[0], "")
        self.assertIn("_start", dlg.entrada.cget("values"))
        self.assertEqual(dlg.regs.get(), "rdi=1000000")
        self.assertEqual(dlg.stdin.get(), "abc")
        self.assertEqual(dlg.saida.get("1.0", "end-1c"), "Hello\n")
        self.assertEqual(dlg.exit_code.get(), "3")
        self.assertTrue(dlg.espera_problema.get())
        self.assertEqual(dlg.max_steps.get(), "77")

    def test_collect_builds_the_typed_scenario(self) -> None:
        dlg = self.open_dialog(["_start"])
        dlg.nome.insert(0, "  huge value  ")
        dlg.entrada.set("_start")
        dlg.regs.insert(0, "rdi=1000000, rsi=0x20, missing=5")
        dlg.stdin.insert(0, "input\n")
        dlg.saida.insert("1.0", "expected output")
        dlg.exit_code.insert(0, "42")
        dlg.espera_problema.set(True)
        dlg.max_steps.delete(0, "end")
        dlg.max_steps.insert(0, "1234")
        scenario = dlg.collect()
        self.assertIsNotNone(scenario)
        self.assertEqual(scenario.name, "huge value")
        self.assertEqual(scenario.entry, "_start")
        self.assertEqual(scenario.regs, {"rdi": "1000000", "rsi": "32"})
        self.assertEqual(scenario.stdin, "input\n")
        self.assertEqual(scenario.expect_output, "expected output")
        self.assertEqual(scenario.expect_exit, 42)
        self.assertTrue(scenario.expect_issue)
        self.assertEqual(scenario.max_steps, 1234)

    def test_collect_without_name_warns_and_returns_none(self) -> None:
        dlg = self.open_dialog()
        dlg.nome.delete(0, "end")
        self.assertIsNone(dlg.collect())
        self.assertIn("name", dlg.error.cget("text"))

    def test_collect_with_non_numeric_limit_warns(self) -> None:
        dlg = self.open_dialog()
        dlg.nome.insert(0, "scenario")
        dlg.max_steps.delete(0, "end")
        dlg.max_steps.insert(0, "many")
        self.assertIsNone(dlg.collect())
        self.assertIn("number", dlg.error.cget("text"))

    def test_collect_with_non_numeric_exit_code_warns(self) -> None:
        dlg = self.open_dialog()
        dlg.nome.insert(0, "scenario")
        dlg.exit_code.insert(0, "zero")
        self.assertIsNone(dlg.collect())
        self.assertIn("number", dlg.error.cget("text"))

    def test_collect_uses_defaults_when_fields_are_empty(self) -> None:
        dlg = self.open_dialog()
        dlg.nome.insert(0, "scenario")
        self.assertEqual(dlg.max_steps.get(), "200000")
        dlg.max_steps.delete(0, "end")
        scenario = dlg.collect()
        self.assertIsNotNone(scenario)
        self.assertEqual(scenario.max_steps, 200000)
        self.assertIsNone(scenario.expect_output)
        self.assertIsNone(scenario.expect_exit)
        self.assertEqual(scenario.entry, "")
        self.assertFalse(scenario.expect_issue)

    def test_confirm_closes_and_stores_scenario(self) -> None:
        dlg = self.open_dialog()
        dlg.nome.insert(0, "scenario")
        dlg.confirm()
        self.assertIsNotNone(dlg.result)
        self.assertEqual(dlg.result.name, "scenario")
        self.assertEqual(dlg.winfo_exists(), 0)


@unittest.skipUnless(TK_OK and HAS_DISPLAY, "no Tkinter or no display")
class TestTextPromptDialog(unittest.TestCase):
    """Short text question, single line and multiline."""

    def setUp(self) -> None:
        self.root = tk.Tk()
        self.root.geometry("480x260")
        self.root.update()

    def tearDown(self) -> None:
        try:
            self.root.destroy()
        except tk.TclError:
            pass

    def open_dialog(self, **kwargs: Any) -> Any:
        """Open a TextPromptDialog and register its closing at the end of the test.

        Args:
            **kwargs: Arguments forwarded to the dialog.

        Returns:
            The dialog ready to use.
        """
        from asmx.ui.dialogs import TextPromptDialog

        dlg = TextPromptDialog(self.root, "Question", "What is the value?", **kwargs)
        self.addCleanup(close_window, dlg)
        self.root.update()
        return dlg

    def test_collect_single_line(self) -> None:
        dlg = self.open_dialog(value="initial", hint="help hint")
        self.assertFalse(dlg.multiline)
        self.assertEqual(dlg.collect(), "initial")
        dlg.entry.delete(0, "end")
        dlg.entry.insert(0, "typed")
        self.assertEqual(dlg.collect(), "typed")

    def test_collect_multiline(self) -> None:
        dlg = self.open_dialog(value="line 1\nline 2", multiline=True)
        self.assertTrue(dlg.multiline)
        self.assertEqual(dlg.collect(), "line 1\nline 2")
        dlg.entry.insert("end", "\nline 3")
        self.assertEqual(dlg.collect(), "line 1\nline 2\nline 3")

    def test_enter_of_short_field_confirms(self) -> None:
        """The Enter key must be bound to confirm the dialog.

        Under xvfb there is no window manager, so the focus never reaches the
        field and a generated key event would not be delivered; that is why the
        test checks the binding and calls the same method it calls.
        """
        dlg = self.open_dialog(value="text")
        self.assertTrue(dlg.entry.bind("<Return>"), "Enter must be bound to confirm")
        dlg.confirm()
        self.root.update()
        self.assertEqual(dlg.result, "text")
        self.assertEqual(dlg.winfo_exists(), 0)

    def test_without_hint_and_without_initial_value(self) -> None:
        dlg = self.open_dialog()
        self.assertEqual(dlg.collect(), "")
        self.assertEqual(dlg.error.cget("text"), "")
        self.assertTrue(dlg.entry.winfo_exists())


@unittest.skipUnless(TK_OK and HAS_DISPLAY, "no Tkinter or no display")
class TestDiffDialog(unittest.TestCase):
    """Window that compares two branches."""

    def setUp(self) -> None:
        self.root = tk.Tk()
        self.root.geometry("400x300")
        self.root.update()

    def tearDown(self) -> None:
        try:
            self.root.destroy()
        except tk.TclError:
            pass

    def open_dialog(self, diff_text: str) -> Any:
        """Open a DiffDialog and return the text widget with the diff.

        Args:
            diff_text: Unified diff shown in the window.

        Returns:
            The :class:`tkinter.Text` used to display the diff.
        """
        from asmx.ui.dialogs import DiffDialog

        dlg = DiffDialog(self.root, "main ↔ alt", diff_text)
        self.addCleanup(close_window, dlg)
        self.root.update()
        texts = [w for w in dlg.winfo_children() if isinstance(w, tk.Text)]
        self.assertEqual(len(texts), 1)
        return texts[0]

    def test_empty_diff_says_the_code_is_equal(self) -> None:
        text = self.open_dialog("")
        self.assertIn("exactly the same code", text.get("1.0", "end-1c"))
        self.assertEqual(text.cget("state"), "disabled")

    def test_blank_diff_is_also_empty(self) -> None:
        text = self.open_dialog("   \n\n")
        self.assertIn("exactly the same code", text.get("1.0", "end-1c"))

    def test_real_diff_colors_by_line_type(self) -> None:
        """Header, addition, removal and context get different colors.

        The diff header (`---`, `+++`, `@@`) has to be recognized before the
        addition and removal lines: `+++` starts with `+` and `---` starts with
        `-`, so the order of the checks is what separates header from content.
        """
        diff = "--- main\n+++ alt\n@@ -1,3 +1,3 @@\n-old line\n+new line\n" "equal line"
        text = self.open_dialog(diff)
        self.assertIn("new line", text.get("1.0", "end-1c"))
        # the three header lines stay contiguous, so Tk joins them into a
        # single marked range
        header = text.get(*text.tag_ranges("head")[0:2])
        for mark in ("---", "+++", "@@"):
            self.assertIn(mark, header)
        self.assertEqual(len(text.tag_ranges("add")) // 2, 1)
        self.assertEqual(len(text.tag_ranges("del")) // 2, 1)
        self.assertEqual(text.cget("state"), "disabled")

    def test_diff_header_is_not_an_addition(self) -> None:
        text = self.open_dialog("--- a\n+++ b\n@@ -1 +1 @@\n")
        additions = text.get(*text.tag_ranges("add")[0:2]) if text.tag_ranges("add") else ""
        removals = text.get(*text.tag_ranges("del")[0:2]) if text.tag_ranges("del") else ""
        self.assertNotIn("+++", additions)
        self.assertNotIn("---", removals)


@unittest.skipUnless(TK_OK and HAS_DISPLAY, "no Tkinter or no display")
class TestAboutDialog(unittest.TestCase):
    """The "About" window, with version and shortcuts."""

    def setUp(self) -> None:
        self.root = tk.Tk()
        self.root.geometry("400x300")
        self.root.update()

    def tearDown(self) -> None:
        try:
            self.root.destroy()
        except tk.TclError:
            pass

    def test_shows_version_and_shortcuts(self) -> None:
        from asmx.ui.dialogs import AboutDialog

        dlg = AboutDialog(self.root, "9.9.9")
        self.addCleanup(close_window, dlg)
        self.root.update()
        self.assertEqual(dlg.title(), "About")
        texts = []
        for child in dlg.body.winfo_children():
            try:
                texts.append(child.cget("text"))
            except tk.TclError:
                pass
        self.assertTrue(any("ASM X" == t for t in texts))
        self.assertTrue(any("9.9.9" in t for t in texts))
        boxes = [w for w in dlg.body.winfo_children() if isinstance(w, tk.Text)]
        self.assertEqual(len(boxes), 1)
        self.assertIn("F8", boxes[0].get("1.0", "end-1c"))

    def test_close_button_cancels_the_window(self) -> None:
        from asmx.ui.dialogs import AboutDialog

        dlg = AboutDialog(self.root, "1.0")
        self.addCleanup(close_window, dlg)
        self.root.update()
        buttons = [w for w in dlg.buttons.winfo_children() if isinstance(w, tk.Widget)]
        self.assertTrue(any(w.cget("text") == "Close" for w in buttons))
        dlg.after(10, dlg.cancel)
        self.assertIsNone(dlg.show())
        self.assertEqual(dlg.winfo_exists(), 0)


if __name__ == "__main__":
    unittest.main()
