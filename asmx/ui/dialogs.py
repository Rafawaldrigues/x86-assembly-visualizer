"""Auxiliary windows of the interface."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any, List, Optional, Union

from ..workspace import Scenario, parse_reg_values
from . import theme


class ModalDialog(tk.Toplevel):
    """Base of the modal windows, with the result in self.result."""

    def __init__(
        self, master: Union[tk.Tk, tk.Toplevel], title: str, width: int = 520, height: int = 420
    ) -> None:
        """Build the window with body, buttons and Esc to close.

        Args:
            master: Parent window.
            title: Window title.
            width: Initial width in pixels.
            height: Initial height in pixels.
        """
        super().__init__(master)
        self.result: Any = None
        self.title(title)
        self.configure(bg=theme.PANEL)
        self.transient(master)
        self.resizable(True, True)
        self.geometry("%dx%d" % (width, height))
        self.buttons: ttk.Frame = ttk.Frame(self, padding=(12, 0, 12, 12))
        self.buttons.pack(side="bottom", fill="x")
        self.body: ttk.Frame = ttk.Frame(self, padding=12)
        self.body.pack(fill="both", expand=True)
        self.bind("<Escape>", lambda e: self.cancel())
        self.protocol("WM_DELETE_WINDOW", self.cancel)

    def add_buttons(self, ok_text: str = "Save") -> None:
        """Create the Cancel and confirm buttons.

        Args:
            ok_text: Label of the confirmation button.
        """
        ttk.Button(self.buttons, text="Cancel", command=self.cancel).pack(side="right")
        ttk.Button(self.buttons, text=ok_text, style="Accent.TButton", command=self.confirm).pack(
            side="right", padx=(0, 8)
        )

    def confirm(self) -> None:
        """Store what collect() returned and close the window when there is a result."""
        self.result = self.collect()
        if self.result is not None:
            self.destroy()

    def cancel(self) -> None:
        """Close the window without a result."""
        self.result = None
        self.destroy()

    def collect(self) -> Any:
        """Return the window result; the base collects nothing.

        Returns:
            Always None in this base; the subclasses return the collected value.
        """
        return None

    def show(self) -> Any:
        """Show the window, wait for the user and return the result.

        Returns:
            The collected value, or None when the window was cancelled.
        """
        self.grab_set()
        self.wait_window()
        return self.result


class ScenarioDialog(ModalDialog):
    """Create or edit a test scenario."""

    def __init__(
        self,
        master: Union[tk.Tk, tk.Toplevel],
        labels: List[str],
        scenario: Optional[Scenario] = None,
    ) -> None:
        """Build the scenario form, filled from scenario.

        Args:
            master: Parent window.
            labels: Labels that can be used as the starting point.
            scenario: Scenario to edit; None creates a new scenario.
        """
        super().__init__(master, "Test scenario", 560, 470)
        s = scenario or Scenario(name="")
        self.error: ttk.Label = ttk.Label(self.body, text="", foreground=theme.SEV_COLOR["error"])

        fields = ttk.Frame(self.body)
        fields.pack(fill="both", expand=True)
        fields.columnconfigure(1, weight=1)
        row = 0

        def add(label: str, widget: tk.Widget, hint: str = "") -> None:
            """Place a label, the field and the hint on the form grid.

            Args:
                label: Label text.
                widget: Field to place.
                hint: Help shown below the field.
            """
            nonlocal row
            ttk.Label(fields, text=label).grid(row=row, column=0, sticky="w", pady=(6, 0))
            widget.grid(row=row, column=1, sticky="ew", pady=(6, 0))
            row += 1
            if hint:
                ttk.Label(
                    fields, text=hint, style="Dim.TLabel", wraplength=340, justify="left"
                ).grid(row=row, column=1, sticky="w")
                row += 1

        self.nome: ttk.Entry = ttk.Entry(fields)
        self.nome.insert(0, s.name)
        add("Name", self.nome)

        self.entrada: ttk.Combobox = ttk.Combobox(
            fields, values=[""] + list(labels), state="normal"
        )
        self.entrada.set(s.entry)
        add(
            "Start at",
            self.entrada,
            "empty = entry point; or a function to test alone",
        )

        self.regs: ttk.Entry = ttk.Entry(fields)
        self.regs.insert(0, ", ".join("%s=%s" % (k, v) for k, v in (s.regs or {}).items()))
        add("Initial registers", self.regs, "example: rdi=1000000, rsi=0x20")

        self.stdin: ttk.Entry = ttk.Entry(fields)
        self.stdin.insert(0, s.stdin)
        add("Simulated input (syscall read)", self.stdin)

        self.saida: tk.Text = tk.Text(
            fields,
            height=3,
            bg=theme.BG,
            fg=theme.FG,
            font=theme.mono(10),
            insertbackground=theme.ACCENT,
            borderwidth=0,
            highlightthickness=1,
            highlightbackground=theme.LINE,
        )
        if s.expect_output is not None:
            self.saida.insert("1.0", s.expect_output)
        add("Expected output", self.saida, "leave it empty to skip the output check")

        self.exit_code: ttk.Entry = ttk.Entry(fields)
        if s.expect_exit is not None:
            self.exit_code.insert(0, str(s.expect_exit))
        add("Expected exit code", self.exit_code, "empty = no check")

        self.espera_problema: tk.BooleanVar = tk.BooleanVar(value=s.expect_issue)
        ttk.Checkbutton(
            fields,
            text="Pass if the run reports a problem",
            variable=self.espera_problema,
        ).grid(row=row, column=1, sticky="w", pady=(8, 0))
        row += 1

        self.max_steps: ttk.Entry = ttk.Entry(fields)
        self.max_steps.insert(0, str(s.max_steps))
        add(
            "Instruction limit",
            self.max_steps,
            "stops an infinite loop and reports the problem",
        )

        self.error.pack(fill="x", pady=(8, 0))
        self.add_buttons("Save scenario")
        self.nome.focus_set()

    def collect(self) -> Optional[Scenario]:
        """Validate the fields and build the typed scenario.

        Returns:
            The ready scenario, or None when some field is invalid.
        """
        name = self.nome.get().strip()
        if not name:
            self.error.configure(text="give the scenario a name")
            return None
        output_text = self.saida.get("1.0", "end-1c")
        try:
            steps = int(self.max_steps.get() or 200000)
        except ValueError:
            self.error.configure(text="the instruction limit must be a number")
            return None
        exit_text = self.exit_code.get().strip()
        try:
            exit_code = int(exit_text) if exit_text else None
        except ValueError:
            self.error.configure(text="the exit code must be a number")
            return None
        return Scenario(
            name=name,
            entry=self.entrada.get().strip(),
            regs={k: str(v) for k, v in parse_reg_values(self.regs.get()).items()},
            stdin=self.stdin.get(),
            expect_output=output_text if output_text else None,
            expect_exit=exit_code,
            expect_issue=bool(self.espera_problema.get()),
            max_steps=steps,
        )


class TextPromptDialog(ModalDialog):
    """Ask for a short text (branch name, note)."""

    def __init__(
        self,
        master: Union[tk.Tk, tk.Toplevel],
        title: str,
        label: str,
        value: str = "",
        multiline: bool = False,
        hint: str = "",
    ) -> None:
        """Build the question with a single-line or multiline field.

        Args:
            master: Parent window.
            title: Window title.
            label: Question shown above the field.
            value: Initial value of the field.
            multiline: Use a multiline field when true.
            hint: Optional help shown below the question.
        """
        super().__init__(master, title, 460, 240 if multiline else 190)
        ttk.Label(self.body, text=label).pack(anchor="w")
        if hint:
            ttk.Label(
                self.body, text=hint, style="Dim.TLabel", wraplength=420, justify="left"
            ).pack(anchor="w", pady=(2, 6))
        self.multiline: bool = multiline
        if multiline:
            self.entry: Union[tk.Text, ttk.Entry] = tk.Text(
                self.body,
                height=5,
                bg=theme.BG,
                fg=theme.FG,
                font=theme.mono(10),
                insertbackground=theme.ACCENT,
                borderwidth=0,
                highlightthickness=1,
                highlightbackground=theme.LINE,
            )
            self.entry.insert("1.0", value)
        else:
            self.entry = ttk.Entry(self.body)
            self.entry.insert(0, value)
            self.entry.bind("<Return>", lambda e: self.confirm())
        self.entry.pack(fill="both", expand=True, pady=(4, 0))
        self.error: ttk.Label = ttk.Label(self.body, text="", foreground=theme.SEV_COLOR["error"])
        self.error.pack(fill="x")
        self.add_buttons("Confirm")
        self.entry.focus_set()

    def collect(self) -> str:
        """Return the typed text, without the trailing newline when it is multiline.

        Returns:
            The field content.
        """
        value = self.entry.get("1.0", "end-1c") if self.multiline else self.entry.get()
        return value


class DiffDialog(tk.Toplevel):
    """Show the difference between two branches."""

    def __init__(self, master: Union[tk.Tk, tk.Toplevel], title: str, diff_text: str) -> None:
        """Build the window with the diff already colored by line type.

        Args:
            master: Parent window.
            title: Window title.
            diff_text: Unified diff between the two branches.
        """
        super().__init__(master)
        self.title(title)
        self.configure(bg=theme.PANEL)
        self.geometry("720x520")
        self.transient(master)
        txt = tk.Text(
            self,
            bg=theme.BG,
            fg=theme.FG,
            font=theme.mono(10),
            borderwidth=0,
            highlightthickness=0,
            wrap="none",
        )
        scroll = ttk.Scrollbar(self, orient="vertical", command=txt.yview)
        txt.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        txt.pack(fill="both", expand=True)
        txt.tag_configure("add", foreground=theme.CALL)
        txt.tag_configure("del", foreground=theme.CMP)
        txt.tag_configure("head", foreground=theme.ACCENT)
        if not diff_text.strip():
            txt.insert("1.0", "Both branches have exactly the same code.")
        else:
            for line in diff_text.split("\n"):
                # The diff header (---, +++ and @@) has to be tested before "+"
                # and "-", otherwise it would fall into the add/remove colors.
                tag = ""
                if line.startswith(("@@", "---", "+++")):
                    tag = "head"
                elif line.startswith("+"):
                    tag = "add"
                elif line.startswith("-"):
                    tag = "del"
                txt.insert("end", line + "\n", tag)
        txt.configure(state="disabled")
        ttk.Button(self, text="Close", command=self.destroy).pack(pady=8)


class AboutDialog(ModalDialog):
    """The "About" window, with the version and the shortcut list."""

    def __init__(self, master: Union[tk.Tk, tk.Toplevel], version: str) -> None:
        """Build the window with the version and the main shortcuts.

        Args:
            master: Parent window.
            version: ASM X version shown in the text.
        """
        super().__init__(master, "About", 520, 360)
        ttk.Label(self.body, text="ASM X", style="Head.TLabel", font=theme.ui(16, "bold")).pack(
            anchor="w"
        )
        ttk.Label(
            self.body,
            text="x86-64 assembly study and debugging environment — version %s" % version,
            style="Dim.TLabel",
        ).pack(anchor="w", pady=(0, 10))
        text = (
            "Main shortcuts\n"
            "  F5   validate the code\n"
            "  F8   run one step\n"
            "  F9   run to the end or to the breakpoint\n"
            "  F10  reset the machine\n"
            "  F11  run all test scenarios\n"
            "  Ctrl+/   comment or uncomment the selection\n"
            "  Ctrl+S   save the project\n"
            "  Ctrl+B   new branch from the current one\n"
            "  Ctrl+F   find\n"
            "  Ctrl+G   go to line\n"
            "Set a breakpoint in the number gutter; double-click to jump to the line."
        )
        box = tk.Text(
            self.body,
            bg=theme.BG,
            fg=theme.FG,
            font=theme.mono(10),
            borderwidth=0,
            highlightthickness=0,
            height=14,
        )
        box.insert("1.0", text)
        box.configure(state="disabled")
        box.pack(fill="both", expand=True)
        ttk.Button(self.buttons, text="Close", command=self.cancel).pack(side="right")
