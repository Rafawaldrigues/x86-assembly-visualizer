"""Main window of ASM X."""

from __future__ import annotations

import os
import tkinter as tk
import webbrowser
from tkinter import filedialog, messagebox, ttk
from typing import Dict, List, Optional, Tuple, Union

from .. import __version__
from ..analyzer import Analysis, analyze, callers_of
from ..emulator import Machine, hexs, to_signed
from ..examples import EXAMPLES
from ..isa import CATEGORIES, FLAG_DOC, ISA, REGS64, REG_DOC, REG_INFO
from ..linter import Problem, summary, validate
from ..parser import Line
from ..workspace import Project, Scenario, ScenarioResult, run_all_scenarios, run_scenario
from . import theme
from .dialogs import AboutDialog, DiffDialog, ScenarioDialog, TextPromptDialog
from .editor import CodeEditor

PROJ_TYPES = [("ASM X project", "*.asmproj"), ("All files", "*.*")]
REPORT_TYPES = [
    ("HTML report", "*.html"),
    ("Markdown", "*.md"),
    ("JSON", "*.json"),
    ("All files", "*.*"),
]
ASM_TYPES = [("Assembly", "*.asm *.s *.S *.nasm"), ("All files", "*.*")]

#: Severity value that marks a problem as an error (see asmx.linter).
SEV_ERROR = "error"


class AsmXApp(tk.Tk):
    """Main window: editor, structure, problems, machine, docs and tests."""

    def __init__(self, project: Optional[Project] = None) -> None:
        """Build the window, load the project and run the first analysis.

        Args:
            project: Project to open; None creates a new project with the
                "linux-hello" sample.
        """
        super().__init__()
        self.title("ASM X")
        self.geometry("1360x820")
        self.minsize(900, 600)
        self.configure(bg=theme.PANEL)
        theme.apply_ttk_theme(self)

        self.project: Project = project or Project.new(code=EXAMPLES["linux-hello"]["code"])
        self.analysis: Optional[Analysis] = None
        self.machine: Optional[Machine] = None
        self.problems: List[Problem] = []
        self.results: List[ScenarioResult] = []
        self.last_regs: Dict[str, int] = {}
        self._suspend_change: bool = False

        self._build_menu()
        self._build_layout()
        self._bind_keys()

        self.editor.set_code(self.project.code)
        self.editor.breakpoints = set(self.project.branch.breakpoints)
        self.editor.notes = dict(self.project.branch.notes)
        self.refresh_branches()
        self.analyze_now()
        self.reset_machine()
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    # ======================================================= building =====
    def _build_menu(self) -> None:
        """Build the menu bar: File, Edit, Branch, Run and Help.

        The menu actions are registered as Tk commands, so each item calls the
        matching method of the window.
        """
        menubar = tk.Menu(
            self,
            bg=theme.PANEL,
            fg=theme.FG,
            activebackground=theme.SEL,
            activeforeground=theme.WHITE,
            borderwidth=0,
        )

        def menu() -> tk.Menu:
            """Create a drop-down menu with the theme colors.

            Returns:
                The newly created menu, still without items.
            """
            return tk.Menu(
                menubar,
                tearoff=0,
                bg=theme.PANEL,
                fg=theme.FG,
                activebackground=theme.SEL,
                activeforeground=theme.WHITE,
            )

        file_menu = menu()
        file_menu.add_command(label="New project", accelerator="Ctrl+N", command=self.new_project)
        file_menu.add_command(
            label="Open project...", accelerator="Ctrl+O", command=self.open_project
        )
        file_menu.add_command(label="Save project", accelerator="Ctrl+S", command=self.save_project)
        file_menu.add_command(label="Save project as...", command=self.save_project_as)
        file_menu.add_separator()
        file_menu.add_command(label="Import .asm file...", command=self.import_asm)
        file_menu.add_command(label="Export branch as .asm...", command=self.export_asm)
        samples = menu()
        for key, sample in EXAMPLES.items():
            samples.add_command(
                label=sample["title"], command=lambda chosen=key: self.load_example(chosen)
            )
        file_menu.add_cascade(label="Open sample", menu=samples)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_close)
        menubar.add_cascade(label="File", menu=file_menu)

        edit_menu = menu()
        edit_menu.add_command(
            label="Undo", accelerator="Ctrl+Z", command=lambda: self.editor.text.edit_undo()
        )
        edit_menu.add_command(
            label="Redo", accelerator="Ctrl+Y", command=lambda: self.editor.text.edit_redo()
        )
        edit_menu.add_separator()
        edit_menu.add_command(
            label="Comment/uncomment", accelerator="Ctrl+/", command=self.editor_toggle_comment
        )
        edit_menu.add_command(label="Note this line", accelerator="Ctrl+E", command=self.edit_note)
        edit_menu.add_separator()
        edit_menu.add_command(label="Find...", accelerator="Ctrl+F", command=self.find)
        edit_menu.add_command(label="Go to line...", accelerator="Ctrl+G", command=self.goto_line)
        menubar.add_cascade(label="Edit", menu=edit_menu)

        branch_menu = menu()
        branch_menu.add_command(
            label="New branch from this one", accelerator="Ctrl+B", command=self.branch_new
        )
        branch_menu.add_command(label="Rename current branch", command=self.branch_rename)
        branch_menu.add_command(label="Delete current branch", command=self.branch_delete)
        branch_menu.add_separator()
        branch_menu.add_command(label="Compare with another branch...", command=self.branch_diff)
        menubar.add_cascade(label="Branch", menu=branch_menu)

        run_menu = menu()
        run_menu.add_command(label="Validate code", accelerator="F5", command=self.validate_now)
        run_menu.add_separator()
        run_menu.add_command(label="Step", accelerator="F8", command=self.step)
        run_menu.add_command(label="Run", accelerator="F9", command=self.run)
        run_menu.add_command(label="Run to cursor", accelerator="F7", command=self.run_to_cursor)
        run_menu.add_command(label="Reset", accelerator="F10", command=self.reset_machine)
        run_menu.add_separator()
        run_menu.add_command(label="Debug single function...", command=self.debug_function)
        run_menu.add_command(
            label="Run all scenarios", accelerator="F11", command=self.run_all_scenarios
        )
        run_menu.add_separator()
        run_menu.add_command(
            label="Generate report...", accelerator="Ctrl+R", command=self.generate_report
        )
        menubar.add_cascade(label="Run", menu=run_menu)

        help_menu = menu()
        help_menu.add_command(label="Shortcuts and about", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.configure(menu=menubar)

    def _build_layout(self) -> None:
        """Build the top bar, the status line and the three columns."""
        top = ttk.Frame(self, padding=(8, 5))
        top.pack(fill="x")
        self.branch_var: tk.StringVar = tk.StringVar(value=self.project.active)
        ttk.Label(top, text="branch").pack(side="left")
        self.branch_box: ttk.Combobox = ttk.Combobox(
            top, textvariable=self.branch_var, width=22, state="readonly"
        )
        self.branch_box.pack(side="left", padx=(6, 10))
        self.branch_box.bind(
            "<<ComboboxSelected>>", lambda e: self.branch_switch(self.branch_var.get())
        )
        ttk.Button(top, text="New branch", command=self.branch_new).pack(side="left")
        ttk.Button(top, text="Validate", command=self.validate_now).pack(side="left", padx=6)
        ttk.Button(top, text="Step", command=self.step).pack(side="left")
        ttk.Button(top, text="Run", style="Accent.TButton", command=self.run).pack(
            side="left", padx=6
        )
        ttk.Button(top, text="Reset", command=self.reset_machine).pack(side="left")
        self.platform_label: ttk.Label = ttk.Label(top, text="—", style="Head.TLabel")
        self.platform_label.pack(side="right")

        self.status: ttk.Label = ttk.Label(self, text="", style="Status.TLabel", padding=(8, 3))
        self.status.pack(side="bottom", fill="x")

        main_pane = ttk.PanedWindow(self, orient="horizontal")
        main_pane.pack(fill="both", expand=True)

        # ------------------------------------------------------- column 1 ----
        left = ttk.Frame(main_pane, width=330)
        left.pack_propagate(False)
        main_pane.add(left, weight=0)
        ttk.Label(left, text="Code structure", style="Head.TLabel", padding=(8, 6)).pack(fill="x")
        self.tree: ttk.Treeview = ttk.Treeview(
            left, columns=("info",), show="tree headings", height=20
        )
        self.tree.heading("#0", text="program")
        self.tree.heading("info", text="what it does")
        self.tree.column("#0", width=140, stretch=True, minwidth=90)
        self.tree.column("info", width=175, stretch=True, minwidth=90)
        vs = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vs.set)
        vs.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)
        self.tree.bind("<Double-1>", self.on_tree_select)

        # ------------------------------------------------------- column 2 ----
        center = ttk.PanedWindow(main_pane, orient="vertical")
        main_pane.add(center, weight=3)

        editor_frame = ttk.Frame(center)
        center.add(editor_frame, weight=3)
        self.editor: CodeEditor = CodeEditor(
            editor_frame,
            on_change=self.on_code_change,
            on_breakpoint=self.on_breakpoint,
            on_cursor=self.on_cursor,
        )
        self.editor.pack(fill="both", expand=True)

        bottom_notebook = ttk.Notebook(center)
        center.add(bottom_notebook, weight=1)
        self.bottom: ttk.Notebook = bottom_notebook

        # problems
        problems_tab = ttk.Frame(bottom_notebook)
        bottom_notebook.add(problems_tab, text="Problems")
        self.problem_tree: ttk.Treeview = ttk.Treeview(
            problems_tab, columns=("line", "code", "msg"), show="headings", height=7
        )
        for col, txt, w in (
            ("line", "line", 55),
            ("code", "code", 70),
            ("msg", "problem", 700),
        ):
            self.problem_tree.heading(col, text=txt)
            self.problem_tree.column(col, width=w, anchor="w")
        for severity, color in theme.SEV_COLOR.items():
            self.problem_tree.tag_configure(severity, foreground=color)
        ps = ttk.Scrollbar(problems_tab, orient="vertical", command=self.problem_tree.yview)
        self.problem_tree.configure(yscrollcommand=ps.set)
        ps.pack(side="right", fill="y")
        self.problem_tree.pack(side="top", fill="both", expand=True)
        self.problem_hint: ttk.Label = ttk.Label(
            problems_tab,
            text="",
            style="Dim.TLabel",
            wraplength=900,
            justify="left",
            padding=(8, 4),
        )
        self.problem_hint.pack(fill="x")
        self.problem_tree.bind("<<TreeviewSelect>>", self.on_problem_select)
        self.problem_tree.bind("<Double-1>", self.on_problem_open)

        # output
        output_tab = ttk.Frame(bottom_notebook)
        bottom_notebook.add(output_tab, text="Output")
        self.output_text: tk.Text = tk.Text(
            output_tab,
            bg=theme.BG,
            fg=theme.LOGIC,
            height=7,
            font=theme.mono(10),
            borderwidth=0,
            highlightthickness=0,
        )
        self.output_text.pack(fill="both", expand=True)
        self.output_text.configure(state="disabled")

        # test scenarios
        tests_tab = ttk.Frame(bottom_notebook)
        bottom_notebook.add(tests_tab, text="Tests")
        actions = ttk.Frame(tests_tab, padding=(4, 4))
        actions.pack(fill="x")
        ttk.Button(actions, text="New", command=self.scenario_new).pack(side="left")
        ttk.Button(actions, text="Edit", command=self.scenario_edit).pack(side="left", padx=4)
        ttk.Button(actions, text="Delete", command=self.scenario_delete).pack(side="left")
        ttk.Button(actions, text="Run", command=self.run_selected_scenario).pack(
            side="left", padx=4
        )
        ttk.Button(
            actions, text="Run all", style="Accent.TButton", command=self.run_all_scenarios
        ).pack(side="left")

        self.scenario_tree: ttk.Treeview = ttk.Treeview(
            tests_tab, columns=("entry", "state", "result"), show="tree headings", height=6
        )
        self.scenario_tree.heading("#0", text="scenario")
        self.scenario_tree.heading("entry", text="starts at")
        self.scenario_tree.heading("state", text="registers")
        self.scenario_tree.heading("result", text="result")
        self.scenario_tree.column("#0", width=140, minwidth=80)
        self.scenario_tree.column("entry", width=100, minwidth=70)
        self.scenario_tree.column("state", width=120, minwidth=70)
        self.scenario_tree.column("result", width=110, minwidth=70)
        self.scenario_tree.tag_configure("ok", foreground=theme.CALL)
        self.scenario_tree.tag_configure("failed", foreground=theme.SEV_COLOR["error"])
        self.scenario_tree.pack(fill="both", expand=True)
        self.scenario_detail: ttk.Label = ttk.Label(
            tests_tab,
            text="A scenario stores the initial state "
            "(where to start, which registers) and what you expect "
            "to happen. Select one to see the full result.",
            style="Dim.TLabel",
            wraplength=900,
            justify="left",
            padding=(8, 4),
        )
        self.scenario_detail.pack(fill="x")
        self.scenario_tree.bind("<Double-1>", lambda e: self.scenario_edit())
        self.scenario_tree.bind("<<TreeviewSelect>>", self.on_scenario_select)

        # history
        history_tab = ttk.Frame(bottom_notebook)
        bottom_notebook.add(history_tab, text="Execution history")
        self.trace_tree: ttk.Treeview = ttk.Treeview(
            history_tab, columns=("line", "instr", "effect"), show="headings", height=7
        )
        for col, txt, w in (
            ("line", "line", 55),
            ("instr", "instruction", 220),
            ("effect", "what happened", 700),
        ):
            self.trace_tree.heading(col, text=txt)
            self.trace_tree.column(col, width=w, anchor="w")
        ts = ttk.Scrollbar(history_tab, orient="vertical", command=self.trace_tree.yview)
        self.trace_tree.configure(yscrollcommand=ts.set)
        ts.pack(side="right", fill="y")
        self.trace_tree.pack(fill="both", expand=True)

        # ------------------------------------------------------- column 3 ----
        right_box = ttk.Frame(main_pane, width=430)
        right_box.pack_propagate(False)
        main_pane.add(right_box, weight=0)
        right_notebook = ttk.Notebook(right_box)
        right_notebook.pack(fill="both", expand=True)
        self.right: ttk.Notebook = right_notebook

        machine_tab = ttk.Frame(right_notebook)
        right_notebook.add(machine_tab, text="Machine")
        self._build_inspector(machine_tab)

        docs_tab = ttk.Frame(right_notebook)
        right_notebook.add(docs_tab, text="Docs")
        self._build_docs(docs_tab)

        notes_tab = ttk.Frame(right_notebook)
        right_notebook.add(notes_tab, text="Notes")
        self._build_notes(notes_tab)

    def _build_inspector(self, parent: ttk.Frame) -> None:
        """Build the Machine tab: registers, flags, stack and variables.

        Args:
            parent: Frame that receives the widgets.
        """
        head = ttk.Frame(parent, padding=(6, 6))
        head.pack(fill="x")
        self.exec_label: ttk.Label = ttk.Label(
            head, text="machine stopped", style="Dim.TLabel", wraplength=340, justify="left"
        )
        self.exec_label.pack(fill="x")

        self.reg_tree: ttk.Treeview = ttk.Treeview(
            parent, columns=("hex", "dec"), show="tree headings", height=16
        )
        self.reg_tree.heading("#0", text="reg")
        self.reg_tree.heading("hex", text="hexadecimal")
        self.reg_tree.heading("dec", text="decimal")
        self.reg_tree.column("#0", width=48)
        self.reg_tree.column("hex", width=150, anchor="e")
        self.reg_tree.column("dec", width=140, anchor="e")
        self.reg_tree.tag_configure("changed", foreground=theme.ACCENT)
        self.reg_tree.tag_configure("zero", foreground=theme.DIM)
        self.reg_tree.pack(fill="x", padx=4)
        self.reg_tree.bind("<<TreeviewSelect>>", self.on_reg_select)

        self.flags_label: ttk.Label = ttk.Label(
            parent, text="", font=theme.mono(10), padding=(8, 6)
        )
        self.flags_label.pack(fill="x")

        ttk.Label(parent, text="Stack and variables", style="Head.TLabel", padding=(8, 2)).pack(
            fill="x"
        )
        self.mem_tree: ttk.Treeview = ttk.Treeview(
            parent, columns=("value", "note"), show="tree headings", height=10
        )
        self.mem_tree.heading("#0", text="where")
        self.mem_tree.heading("value", text="contents")
        self.mem_tree.heading("note", text="note")
        self.mem_tree.column("#0", width=95)
        self.mem_tree.column("value", width=180)
        self.mem_tree.column("note", width=120)
        self.mem_tree.pack(fill="both", expand=True, padx=4, pady=(0, 6))

    def _build_docs(self, parent: ttk.Frame) -> None:
        """Build the Docs tab: search, mnemonic list and the help text.

        Args:
            parent: Frame that receives the widgets.
        """
        search = ttk.Frame(parent, padding=(6, 6))
        search.pack(fill="x")
        self.doc_query: ttk.Entry = ttk.Entry(search)
        self.doc_query.pack(fill="x")
        self.doc_query.bind("<KeyRelease>", lambda e: self.refresh_doc_list())
        self.doc_list: tk.Listbox = tk.Listbox(
            parent,
            bg=theme.BG,
            fg=theme.FG,
            height=6,
            font=theme.mono(10),
            borderwidth=0,
            highlightthickness=0,
            selectbackground=theme.SEL,
        )
        self.doc_list.pack(fill="x", padx=6)
        self.doc_list.bind("<<ListboxSelect>>", self.on_doc_select)
        self.doc_text: tk.Text = tk.Text(
            parent,
            bg=theme.BG,
            fg=theme.FG,
            font=theme.ui(10),
            borderwidth=0,
            highlightthickness=0,
            wrap="word",
            padx=8,
            pady=6,
        )
        self.doc_text.pack(fill="both", expand=True, padx=6, pady=6)
        self.doc_text.tag_configure("titulo", foreground=theme.WHITE, font=theme.ui(12, "bold"))
        self.doc_text.tag_configure("sub", foreground=theme.ACCENT, font=theme.ui(10, "bold"))
        self.doc_text.tag_configure("code", foreground=theme.DATA, font=theme.mono(10))
        self.doc_text.tag_configure("dim", foreground=theme.DIM)
        self.doc_text.configure(state="disabled")
        self.refresh_doc_list()
        self.show_doc("mov")

    def _build_notes(self, parent: ttk.Frame) -> None:
        """Build the Notes tab with the list of notes of the branch.

        Args:
            parent: Frame that receives the widgets.
        """
        head = ttk.Frame(parent, padding=(6, 6))
        head.pack(fill="x")
        ttk.Label(head, text="Notes for this branch", style="Head.TLabel").pack(anchor="w")
        ttk.Label(
            head,
            text="Ctrl+E annotates the line where the cursor is. The notes are "
            "saved in the project and do not go into the .asm file.",
            style="Dim.TLabel",
            wraplength=340,
            justify="left",
        ).pack(anchor="w", pady=(2, 0))
        self.note_tree: ttk.Treeview = ttk.Treeview(
            parent, columns=("text",), show="tree headings", height=14
        )
        self.note_tree.heading("#0", text="line")
        self.note_tree.heading("text", text="note")
        self.note_tree.column("#0", width=60)
        self.note_tree.column("text", width=300)
        self.note_tree.pack(fill="both", expand=True, padx=6)
        self.note_tree.bind("<Double-1>", self.on_note_open)
        buttons = ttk.Frame(parent, padding=(6, 6))
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Note current line", command=self.edit_note).pack(side="left")
        ttk.Button(buttons, text="Remove", command=self.delete_note).pack(side="left", padx=4)

    def _bind_keys(self) -> None:
        """Bind the window shortcuts (F5-F11 and Ctrl+N/O/S/B/E/F/G)."""
        self.bind("<F5>", lambda e: self.validate_now())
        self.bind("<F7>", lambda e: self.run_to_cursor())
        self.bind("<F8>", lambda e: self.step())
        self.bind("<F9>", lambda e: self.run())
        self.bind("<F10>", lambda e: self.reset_machine())
        self.bind("<F11>", lambda e: self.run_all_scenarios())
        self.bind("<Control-s>", lambda e: self.save_project())
        self.bind("<Control-o>", lambda e: self.open_project())
        self.bind("<Control-n>", lambda e: self.new_project())
        self.bind("<Control-b>", lambda e: self.branch_new())
        self.bind("<Control-e>", lambda e: self.edit_note())
        self.bind("<Control-f>", lambda e: self.find())
        self.bind("<Control-g>", lambda e: self.goto_line())
        self.bind("<Control-r>", lambda e: self.generate_report())

    # ======================================================= analysis =====
    def on_code_change(self) -> None:
        """Store the text in the project and analyze the code again."""
        if self._suspend_change:
            return
        self.project.set_code(self.editor.get_code())
        self.analyze_now()

    def analyze_now(self) -> None:
        """Analyze the code, validate it and refresh every panel of the window."""
        code = self.editor.get_code()
        try:
            self.analysis = analyze(code)
        except Exception as exc:  # noqa: BLE001
            self.set_status("analysis failed: %s" % exc)
            return
        self.problems = validate(self.analysis)
        self.refresh_platform()
        self.refresh_structure()
        self.refresh_problems()
        self.refresh_scenarios()
        self.refresh_notes()
        self.sync_machine_with_code()
        self.set_status()

    def sync_machine_with_code(self) -> None:
        """The machine panel must not show the state of code that changed."""
        if self.machine is None or self.machine.analysis is self.analysis:
            return
        if self.machine.steps == 0:
            self.reset_machine()
        else:
            self.editor.set_exec_line(None)
            self.exec_label.configure(
                text="the code changed after the run started — reset (F10) to "
                "run the new version",
                foreground=theme.ACCENT,
            )

    def refresh_platform(self) -> None:
        """Refresh the detected system label and the hint text."""
        p = self.analysis.platform
        os_label = {"linux": "Linux", "windows": "Windows", "ambiguous": "Ambiguous"}
        name = os_label.get(p.os, "No OS hints" if not p.confidence else "Ambiguous")
        color = {"linux": theme.ACCENT, "windows": theme.STACK}.get(p.os, theme.DIM)
        label = "%s · %d bits" % (name, p.bits)
        if p.confidence:
            label += " · %d%%" % p.confidence
        self.platform_label.configure(text=label, foreground=color)
        hints = p.evidence["linux"] + p.evidence["windows"]
        self.platform_detail: str = "%s — %s. %s%s" % (
            name,
            p.abi["name"],
            p.abi["notes"],
            (
                ("  Hints: " + "; ".join(hints) + ".")
                if hints
                else "  No operating system hints: this code runs the same on both."
            ),
        )
        self.platform_label.bind("<Enter>", lambda e: self.set_status(self.platform_detail))
        self.platform_label.bind("<Button-1>", lambda e: self.set_status(self.platform_detail))

    def refresh_structure(self) -> None:
        """Rebuild the structure tree: data, functions, blocks and instructions."""
        self.tree.delete(*self.tree.get_children())
        analysis = self.analysis
        if not analysis:
            return
        self.tree.tag_configure("sec", foreground=theme.DATA)
        self.tree.tag_configure("fn", foreground=theme.CALL)
        self.tree.tag_configure("blk", foreground=theme.WHITE)
        self.tree.tag_configure("flow", foreground=theme.BRANCH)
        for tag, color in theme.TAG_COLOR.items():
            self.tree.tag_configure("sem_" + tag, foreground=color)

        data_lines = [line for line in analysis.program.lines if line.kind == "data"]
        if data_lines:
            node = self.tree.insert(
                "", "end", text="data", values=("declared variables",), open=True, tags=("sec",)
            )
            for line in data_lines:
                info = (
                    ("reserves %s" % (line.args[0] if line.args else "?"))
                    if line.reserve
                    else "%s" % (line.directive or "")
                )
                self.tree.insert(
                    node,
                    "end",
                    text=(line.label or line.directive or "?"),
                    values=(info,),
                    tags=("line:%d" % line.n, "sec"),
                )

        current_func, func_node = None, None
        for b in analysis.blocks:
            if b.func != current_func or func_node is None:
                current_func = b.func
                callers = callers_of(analysis, current_func) if current_func else []
                summary_text = (
                    ("called by %s" % ", ".join(callers))
                    if callers
                    else (
                        "entry point"
                        if current_func in ("_start", "main", "start", "WinMain")
                        else "nothing calls it in this file"
                    )
                )
                func_node = self.tree.insert(
                    "",
                    "end",
                    text=current_func or "code",
                    values=(summary_text,),
                    open=True,
                    tags=("fn",),
                )
            incoming = ", ".join(
                "%s (%s)" % (analysis.blocks[e.target].name, e.why) for e in b.pred
            ) or ("start" if b.id == 0 else "nothing leads here")
            outgoing = ", ".join(
                "%s (%s)" % (analysis.blocks[e.target].name, e.why) for e in b.succ
            )
            if b.exit:
                outgoing = (outgoing + ", " if outgoing else "") + b.exit
            block_node = self.tree.insert(
                func_node,
                "end",
                text=b.name,
                values=("%d instr · L%d-%d" % (len(b.instrs), b.instrs[0].n, b.instrs[-1].n),),
                tags=("blk", "line:%d" % b.instrs[0].n),
            )
            self.tree.insert(
                block_node, "end", text="comes from", values=(incoming,), tags=("flow",)
            )
            self.tree.insert(
                block_node, "end", text="goes to", values=(outgoing or "nothing",), tags=("flow",)
            )
            for ins in b.instrs:
                self.tree.insert(
                    block_node,
                    "end",
                    text="%d: %s" % (ins.n, ins.text[:34]),
                    values=(ins.sem.label,),
                    tags=("line:%d" % ins.n, "sem_" + ins.sem.tag),
                )

    def refresh_problems(self) -> None:
        """Rebuild the problem list and mark the error lines in the editor."""
        self.problem_tree.delete(*self.problem_tree.get_children())
        for p in self.problems:
            self.problem_tree.insert(
                "",
                "end",
                values=(p.line, p.code, p.message),
                tags=(p.severity, "line:%d" % p.line),
            )
        self.editor.mark_error_lines([p.line for p in self.problems if p.severity == SEV_ERROR])
        idx = self.bottom.index(self.bottom.tabs()[0])
        self.bottom.tab(idx, text="Problems (%d)" % len(self.problems))

    # ===================================================== interactions ====
    def on_cursor(self, line: int, col: int) -> None:
        """Show the instruction or the line under the cursor in the docs panel.

        Args:
            line: Line where the cursor is.
            col: Column where the cursor is.
        """
        self.set_status(cursor=(line, col))
        if not self.analysis:
            return
        ins = next((i for i in self.analysis.instrs if i.n == line), None)
        if ins:
            self.show_doc(ins.mnemonic, ins)
            return
        source_line = next((item for item in self.analysis.program.lines if item.n == line), None)
        if source_line is not None and source_line.kind in ("label", "data", "directive"):
            self.describe_line(source_line)

    def describe_line(self, line: Line) -> None:
        """Explain labels, data and directives in the documentation panel.

        Args:
            line: Program line to describe.
        """
        t = self.doc_text
        t.configure(state="normal")
        t.delete("1.0", "end")
        t.insert("end", "line %d\n" % line.n, "sub")
        t.insert("end", line.text + "\n\n", "code")
        if line.kind == "label":
            callers = callers_of(self.analysis, line.label)
            t.insert("end", "Label %s\n" % line.label, "titulo")
            t.insert(
                "end",
                "It is a name for this address. What leads here: %s.\n\n"
                % (", ".join(callers) if callers else "nothing in this file"),
            )
            if line.local_label:
                t.insert(
                    "end",
                    "It starts with a dot: it is a local label, it belongs to the "
                    "previous function and may repeat the name in other functions.\n",
                    "dim",
                )
        elif line.kind == "data":
            if line.reserve:
                t.insert("end", "Space reservation\n", "titulo")
                t.insert(
                    "end",
                    "%s reserves %s slot(s) of %d byte(s) with no initial value. "
                    "It lives in the .bss section and starts zeroed.\n"
                    % (
                        line.label or "this label",
                        line.args[0] if line.args else "?",
                        line.unit,
                    ),
                )
            elif line.directive == "equ":
                t.insert("end", "Assembler constant\n", "titulo")
                t.insert(
                    "end",
                    "It takes no memory: the value is substituted at assembly time.\n",
                )
            else:
                t.insert("end", "Initialized data\n", "titulo")
                t.insert(
                    "end",
                    "%s writes the values straight into the executable, %d byte(s) per item.\n"
                    % (line.directive.upper(), line.unit),
                )
        else:
            t.insert("end", "Assembler directive\n", "titulo")
            t.insert(
                "end",
                "It instructs the assembly tool; it does not become a CPU instruction.\n",
            )
        t.configure(state="disabled")

    def on_breakpoint(self, line: int, active: bool) -> None:
        """Store the breakpoints in the branch and report it in the status bar.

        Args:
            line: Breakpoint line.
            active: True when the breakpoint was set.
        """
        self.project.branch.breakpoints = sorted(self.editor.breakpoints)
        self.project.dirty = True
        self.set_status("breakpoint %s on line %d" % ("set" if active else "cleared", line))

    def _tag_line(self, tags: Union[Tuple[str, ...], str]) -> Optional[int]:
        """Extract the line number from a "line:N" tag of the tree.

        Args:
            tags: Tags of the selected item; Tk returns an empty string when the
                item has none.

        Returns:
            The line number, or None when the item does not point to a line.
        """
        for t in tags:
            if str(t).startswith("line:"):
                return int(str(t).split(":")[1])
        return None

    def on_tree_select(self, event: Optional[tk.Event[tk.Misc]] = None) -> None:
        """Jump to the line of the item selected in the structure."""
        sel = self.tree.selection()
        if not sel:
            return
        line = self._tag_line(self.tree.item(sel[0], "tags"))
        if line:
            self.editor.goto_line(line)

    def on_problem_select(self, event: Optional[tk.Event[tk.Misc]] = None) -> None:
        """Show the hint of the selected problem in the status bar."""
        sel = self.problem_tree.selection()
        if not sel:
            return
        line = self._tag_line(self.problem_tree.item(sel[0], "tags"))
        p = next((x for x in self.problems if x.line == line), None)
        if p:
            self.problem_hint.configure(text="%s — %s" % (p.code, p.hint or p.message))

    def on_problem_open(self, event: Optional[tk.Event[tk.Misc]] = None) -> None:
        """Jump to the line of the selected problem."""
        sel = self.problem_tree.selection()
        if not sel:
            return
        line = self._tag_line(self.problem_tree.item(sel[0], "tags"))
        if line:
            self.editor.goto_line(line)

    def on_reg_select(self, event: Optional[tk.Event[tk.Misc]] = None) -> None:
        """Show what the selected register does in the status bar."""
        sel = self.reg_tree.selection()
        if sel and sel[0] in REG_DOC:
            self.set_status("%s — %s" % (sel[0].upper(), REG_DOC[sel[0]]))

    # ========================================================= branches ===
    def refresh_branches(self) -> None:
        """Reload the branch list of the top bar."""
        names = list(self.project.branches)
        self.branch_box.configure(values=names)
        self.branch_var.set(self.project.active)

    def branch_new(self) -> None:
        """Ask for a name and create a branch from the current one."""
        name = TextPromptDialog(
            self,
            "New branch",
            "Name of the new branch",
            hint="The branch copies the current code. Use it to try an idea "
            "without touching the original — for example, replace a value "
            "with a huge number and see what breaks.",
        ).show()
        if not name:
            return
        try:
            self.project.set_code(self.editor.get_code())
            self.project.fork(name.strip())
            self.project.switch(name.strip())
        except (ValueError, KeyError) as exc:
            messagebox.showerror("New branch", str(exc), parent=self)
            return
        self.refresh_branches()
        self.load_branch_into_editor()
        self.set_status("branch %s created from %s" % (name.strip(), self.project.branch.parent))

    def branch_switch(self, name: str) -> None:
        """Switch the branch being edited.

        Args:
            name: Name of the chosen branch.
        """
        if name == self.project.active:
            return
        self.project.set_code(self.editor.get_code())
        self.project.switch(name)
        self.load_branch_into_editor()
        self.set_status("now editing branch %s" % name)

    def branch_rename(self) -> None:
        """Ask for a new name for the current branch."""
        new_name = TextPromptDialog(
            self, "Rename branch", "New name", value=self.project.active
        ).show()
        if not new_name:
            return
        try:
            self.project.rename_branch(self.project.active, new_name.strip())
        except (ValueError, KeyError) as exc:
            messagebox.showerror("Rename", str(exc), parent=self)
            return
        self.refresh_branches()

    def branch_delete(self) -> None:
        """Confirm and delete the current branch."""
        name = self.project.active
        if not messagebox.askyesno(
            "Delete branch",
            "Delete branch %s? This cannot be undone." % name,
            parent=self,
        ):
            return
        try:
            self.project.delete_branch(name)
        except ValueError as exc:
            messagebox.showerror("Delete branch", str(exc), parent=self)
            return
        self.refresh_branches()
        self.load_branch_into_editor()

    def branch_diff(self) -> None:
        """Ask for another branch and open the comparison window."""
        others = [b for b in self.project.branches if b != self.project.active]
        if not others:
            messagebox.showinfo("Compare", "There is only one branch in this project.", parent=self)
            return
        choice = TextPromptDialog(
            self,
            "Compare branches",
            "Compare %s with which branch?" % self.project.active,
            value=others[0],
            hint="available: " + ", ".join(others),
        ).show()
        if not choice or choice.strip() not in self.project.branches:
            return
        self.project.set_code(self.editor.get_code())
        diff = self.project.diff(self.project.active, choice.strip())
        DiffDialog(self, "%s ↔ %s" % (self.project.active, choice.strip()), diff)

    def load_branch_into_editor(self) -> None:
        """Put the active branch in the editor and redo the analysis and the machine."""
        self._suspend_change = True
        self.editor.set_code(self.project.code)
        self.editor.breakpoints = set(self.project.branch.breakpoints)
        self.editor.notes = dict(self.project.branch.notes)
        self._suspend_change = False
        self.editor.redraw_gutter()
        self.analyze_now()
        self.reset_machine()
        self.refresh_branches()

    # ============================================================ file ===
    def new_project(self) -> None:
        """Create an empty project after confirming the discard of the current one."""
        if not self.confirm_discard():
            return
        self.project = Project.new(
            code="; new program\n\nsection .text\n    global _start\n\n_start:\n    \n"
        )
        self.load_branch_into_editor()
        self.title("ASM X")

    def open_project(self) -> None:
        """Open a .asmproj file chosen by the user."""
        path = filedialog.askopenfilename(title="Open project", filetypes=PROJ_TYPES, parent=self)
        if not path:
            return
        try:
            self.project = Project.load(path)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Open project", "Could not read the file:\n%s" % exc, parent=self)
            return
        self.load_branch_into_editor()
        self.title("ASM X — %s" % os.path.basename(path))

    def save_project(self) -> bool:
        """Save the project; with no path set, ask for one.

        Returns:
            True when the project was saved.
        """
        self.project.set_code(self.editor.get_code())
        self.project.branch.breakpoints = sorted(self.editor.breakpoints)
        if not self.project.path:
            return self.save_project_as()
        self.project.save()
        self.set_status("project saved to %s" % self.project.path)
        return True

    def save_project_as(self) -> bool:
        """Ask for a path and save the project there.

        Returns:
            True when it saved, False when the user cancels.
        """
        path = filedialog.asksaveasfilename(
            title="Save project", defaultextension=".asmproj", filetypes=PROJ_TYPES, parent=self
        )
        if not path:
            return False
        self.project.set_code(self.editor.get_code())
        self.project.save(path)
        self.title("ASM X — %s" % os.path.basename(path))
        self.set_status("project saved to %s" % path)
        return True

    def import_asm(self) -> None:
        """Import an .asm file as a new project."""
        path = filedialog.askopenfilename(title="Import .asm", filetypes=ASM_TYPES, parent=self)
        if not path:
            return
        if not self.confirm_discard():
            return
        self.project = Project.from_asm_file(path)
        self.load_branch_into_editor()
        self.title("ASM X — %s" % os.path.basename(path))

    def export_asm(self) -> None:
        """Export the code of the current branch to an .asm file."""
        path = filedialog.asksaveasfilename(
            title="Export branch", defaultextension=".asm", filetypes=ASM_TYPES, parent=self
        )
        if not path:
            return
        self.project.set_code(self.editor.get_code())
        self.project.export_asm(path)
        self.set_status("branch %s exported to %s" % (self.project.active, path))

    def load_example(self, key: str) -> None:
        """Open one of the built-in samples.

        Args:
            key: Sample key in EXAMPLES.
        """
        if not self.confirm_discard():
            return
        self.project = Project.new(code=EXAMPLES[key]["code"], name=key)
        self.load_branch_into_editor()
        self.title("ASM X — %s" % EXAMPLES[key]["title"])

    def confirm_discard(self) -> bool:
        """Ask what to do with unsaved changes.

        Returns:
            True to go ahead and discard, False to cancel the operation.
        """
        if not self.project.dirty:
            return True
        answer = messagebox.askyesnocancel(
            "Unsaved changes",
            "The project has unsaved changes. Save them first?",
            parent=self,
        )
        if answer is None:
            return False
        if answer:
            return bool(self.save_project())
        return True

    def on_close(self) -> None:
        """Save whatever is pending and close the window."""
        self.project.set_code(self.editor.get_code())
        if self.confirm_discard():
            self.destroy()

    # ======================================================== execution ====
    def reset_machine(self) -> None:
        """Create a new machine from the current analysis."""
        if not self.analysis:
            return
        self.machine = Machine(self.analysis)
        self.last_regs = {}
        self.refresh_machine()
        self.set_status("machine reset")

    def _ensure_machine(self) -> Optional[Machine]:
        """Return the machine of the current analysis, resetting it if the code changed.

        Returns:
            The machine ready to run, or None when there is no analysis.
        """
        if self.machine is None or self.machine.analysis is not self.analysis:
            self.reset_machine()
        return self.machine

    def step(self) -> None:
        """Run one instruction and refresh the machine panel."""
        m = self._ensure_machine()
        if m.halted:
            self.set_status("the run already finished — use Reset (F10)")
            return
        self.last_regs = dict(m.regs)
        m.step()
        self.refresh_machine()

    def run(self) -> None:
        """Run to the end or to a breakpoint and refresh the panel."""
        m = self._ensure_machine()
        if m.halted:
            self.reset_machine()
            m = self.machine
        self.last_regs = dict(m.regs)
        m.run(breakpoints=set(self.editor.breakpoints))
        self.refresh_machine()
        if m.halted:
            self.set_status("run finished with code %s" % m.exit_code)
        else:
            self.set_status(
                "stopped at the breakpoint on line %s" % (m.current.n if m.current else "?")
            )

    def run_to_cursor(self) -> None:
        """Run to the instruction of the line where the cursor is."""
        m = self._ensure_machine()
        target = self.editor.cursor_line()
        indices = {i.idx for i in self.analysis.instrs if i.n == target}
        if not indices:
            self.set_status("there is no instruction on line %d" % target)
            return
        self.last_regs = dict(m.regs)
        m.run_until(indices)
        self.refresh_machine()

    def debug_function(self) -> None:
        """Ask for a label and run only that function, with a clean stack."""
        if not self.analysis:
            return
        functions = sorted(self.analysis.label_at)
        if not functions:
            messagebox.showinfo("Debug function", "This code has no labels.", parent=self)
            return
        choice = TextPromptDialog(
            self,
            "Debug single function",
            "Which label?",
            value=functions[0],
            hint="The run starts there with a clean stack. Set the input registers "
            "in a test scenario if the function depends on arguments.\n\navailable: "
            + ", ".join(functions[:20]),
        ).show()
        if not choice or choice.strip() not in self.analysis.label_at:
            return
        self.machine = Machine(self.analysis, entry=choice.strip())
        self.last_regs = {}
        self.refresh_machine()
        self.right.select(0)
        self.set_status("debugging %s in isolation — use Step (F8)" % choice.strip())

    def refresh_machine(self) -> None:
        """Redraw registers, flags, stack, variables, output and history."""
        m = self.machine
        if not m:
            return
        current = m.current
        if m.halted:
            text = "run finished"
            if m.exit_code is not None:
                text += " with code %d" % m.exit_code
            self.editor.set_exec_line(None)
        else:
            text = "next: line %d — %s" % (current.n, current.text) if current else "no instruction"
            self.editor.set_exec_line(current.n if current else None)
        text += " · %d steps" % m.steps
        if m.issues:
            text += "\n⚠ " + m.issues[-1]
        self.exec_label.configure(
            text=text, foreground=theme.SEV_COLOR["error"] if m.issues else theme.DIM
        )

        self.reg_tree.delete(*self.reg_tree.get_children())
        for r in REGS64:
            v = m.regs[r]
            tags = []
            if self.last_regs.get(r) is not None and self.last_regs.get(r) != v:
                tags.append("changed")
            elif v == 0:
                tags.append("zero")
            dec = to_signed(v)
            readable = "" if abs(dec) > 10**12 else str(dec)  # addresses do not help in decimal
            self.reg_tree.insert(
                "", "end", iid=r, text=r, values=(hexs(v), readable), tags=tuple(tags)
            )

        self.flags_label.configure(
            text="  ".join("%s=%d" % (f, m.flags[f]) for f in ("ZF", "SF", "CF", "OF", "PF", "DF")),
            foreground=theme.CMP,
        )

        self.mem_tree.delete(*self.mem_tree.get_children())
        stack_node = self.mem_tree.insert(
            "", "end", text="stack", values=("", "top first"), open=True
        )
        from ..emulator import RET_MAGIC, STACK_TOP

        address = m.regs["rsp"]
        for i in range(6):
            if address + i * 8 >= STACK_TOP:
                break
            addr = address + i * 8
            v = m.read_mem(addr, 8)
            note = "RSP" if i == 0 else ("RBP" if addr == m.regs["rbp"] else "")
            if RET_MAGIC <= v < RET_MAGIC + 1000000:
                note = (note + " " if note else "") + "return address"
            self.mem_tree.insert(stack_node, "end", text=hexs(addr), values=(hexs(v), note))
        if m.regs["rsp"] >= STACK_TOP:
            self.mem_tree.insert(stack_node, "end", text="—", values=("", "empty stack"))

        if m.symbols:
            data_node = self.mem_tree.insert(
                "", "end", text="variables", values=("", ""), open=True
            )
            for symbol_name, s in m.symbols.items():
                if s.addr is None:
                    self.mem_tree.insert(
                        data_node,
                        "end",
                        text=symbol_name,
                        values=(str(s.equ), "assembler constant"),
                    )
                    continue
                n = min(s.size or 8, 12)
                raw = " ".join("%02x" % m.rd8(s.addr + i) for i in range(n))
                ascii_text = "".join(
                    chr(b) if 32 <= b < 127 else "." for b in (m.rd8(s.addr + i) for i in range(n))
                )
                self.mem_tree.insert(data_node, "end", text=symbol_name, values=(raw, ascii_text))

        self.output_text.configure(state="normal")
        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", m.output or "")
        self.output_text.configure(state="disabled")

        self.trace_tree.delete(*self.trace_tree.get_children())
        for step in m.trace[-60:][::-1]:
            self.trace_tree.insert("", "end", values=(step.line, step.text, step.note))

    # ======================================================= validation ===
    def validate_now(self) -> None:
        """Validate the code, open the Problems tab and summarize the result in the status bar."""
        self.analyze_now()
        self.bottom.select(0)
        errors = [p for p in self.problems if p.severity == SEV_ERROR]
        if not self.problems:
            self.set_status("no problems found")
        else:
            self.set_status(
                summary(self.problems)
                + (" — start with the first error in the list" if errors else "")
            )

    # ======================================================== scenarios ===
    def refresh_scenarios(self) -> None:
        """Rebuild the scenario list with the result of the last run."""
        self.scenario_tree.delete(*self.scenario_tree.get_children())
        results = {r.scenario: r for r in self.results}
        for s in self.project.branch.scenarios:
            r = results.get(s.name)
            if r is None:
                result, tag = "not run", ()
            elif r.passed:
                result, tag = "passed", ("ok",)
            else:
                result, tag = "failed", ("failed",)
            regs = ", ".join("%s=%s" % (k, v) for k, v in (s.regs or {}).items())
            self.scenario_tree.insert(
                "",
                "end",
                iid=s.name,
                text=s.name,
                values=(s.entry or "program entry", regs, result),
                tags=tag,
            )
        idx = self.bottom.index(self.bottom.tabs()[2])
        self.bottom.tab(idx, text="Tests (%d)" % len(self.project.branch.scenarios))

    def on_scenario_select(self, event: Optional[tk.Event[tk.Misc]] = None) -> None:
        """Show the result of the selected scenario in the status area."""
        s = self._selected_scenario()
        if not s:
            return
        r = next((x for x in self.results if x.scenario == s.name), None)
        if r is None:
            self.scenario_detail.configure(
                text="%s — has not run yet. It starts at %s with %s."
                % (
                    s.name,
                    s.entry or "the entry point",
                    ", ".join("%s=%s" % kv for kv in (s.regs or {}).items())
                    or "the registers zeroed",
                ),
                foreground=theme.DIM,
            )
            return
        parts = [
            "%s: %s" % ("passed" if r.passed else "FAILED", r.reason),
            "%d instructions executed" % r.steps,
            "exit code: %s" % r.exit_code,
        ]
        if r.output:
            parts.append("output: %r" % r.output)
        if r.issues:
            parts.append("problems detected: " + "; ".join(r.issues[:3]))
        self.scenario_detail.configure(
            text="   ·   ".join(parts),
            foreground=theme.CALL if r.passed else theme.SEV_COLOR["error"],
        )

    def _selected_scenario(self) -> Optional[Scenario]:
        """Return the scenario selected in the list.

        Returns:
            The selected scenario, or None when nothing is selected.
        """
        sel = self.scenario_tree.selection()
        if not sel:
            return None
        return next((s for s in self.project.branch.scenarios if s.name == sel[0]), None)

    def scenario_new(self) -> None:
        """Ask for a new scenario and store it in the branch."""
        labels = sorted(self.analysis.label_at) if self.analysis else []
        s = ScenarioDialog(self, labels).show()
        if s:
            self.project.add_scenario(s)
            self.refresh_scenarios()
            self.bottom.select(2)

    def scenario_edit(self) -> None:
        """Edit the scenario selected in the list."""
        s = self._selected_scenario()
        if not s:
            self.set_status("select a scenario in the list")
            return
        labels = sorted(self.analysis.label_at) if self.analysis else []
        updated = ScenarioDialog(self, labels, s).show()
        if updated:
            if updated.name != s.name:
                self.project.remove_scenario(s.name)
            self.project.add_scenario(updated)
            self.refresh_scenarios()

    def scenario_delete(self) -> None:
        """Remove the selected scenario and its result."""
        s = self._selected_scenario()
        if not s:
            return
        self.project.remove_scenario(s.name)
        self.results = [r for r in self.results if r.scenario != s.name]
        self.refresh_scenarios()

    def run_selected_scenario(self) -> None:
        """Run the selected scenario and show the result."""
        s = self._selected_scenario()
        if not s:
            self.set_status("select a scenario in the list")
            return
        self.project.set_code(self.editor.get_code())
        r = run_scenario(self.project.code, s)
        self.results = [x for x in self.results if x.scenario != s.name] + [r]
        self.refresh_scenarios()
        self.set_status("%s: %s" % (s.name, "passed" if r.passed else r.reason))

    def run_all_scenarios(self) -> None:
        """Run every scenario of the branch and count how many passed."""
        scenarios = self.project.branch.scenarios
        if not scenarios:
            self.bottom.select(2)
            self.set_status("no scenarios in this branch — create one in Tests › New scenario")
            return
        self.project.set_code(self.editor.get_code())
        self.results = run_all_scenarios(self.project.code, scenarios)
        self.refresh_scenarios()
        self.bottom.select(2)
        passed = sum(1 for r in self.results if r.passed)
        self.set_status("%d of %d scenarios passed" % (passed, len(self.results)))

    # ============================================================ notes ===
    def refresh_notes(self) -> None:
        """Rebuild the note list and sync the editor gutter."""
        self.note_tree.delete(*self.note_tree.get_children())
        for line in sorted(self.project.branch.notes, key=lambda x: int(x)):
            self.note_tree.insert(
                "", "end", iid=line, text=line, values=(self.project.branch.notes[line],)
            )
        self.editor.notes = dict(self.project.branch.notes)
        self.editor.redraw_gutter()

    def edit_note(self) -> None:
        """Annotate the cursor line; with an empty field, remove its note."""
        line = self.editor.cursor_line()
        current = self.project.note(line)
        text = TextPromptDialog(
            self,
            "Note on line %d" % line,
            "What do you want to remember about this line?",
            value=current,
            multiline=True,
            hint="It is stored in the project, separate from the code.",
        ).show()
        if text is None:
            return
        self.project.set_note(line, text)
        self.refresh_notes()
        self.set_status("note %s on line %d" % ("saved" if text.strip() else "removed", line))

    def on_note_open(self, event: Optional[tk.Event[tk.Misc]] = None) -> None:
        """Jump to the line of the selected note."""
        sel = self.note_tree.selection()
        if sel:
            self.editor.goto_line(int(sel[0]))

    def delete_note(self) -> None:
        """Remove the note of the line selected in the list."""
        sel = self.note_tree.selection()
        if not sel:
            return
        self.project.set_note(int(sel[0]), "")
        self.refresh_notes()

    # ==================================================== documentation ===
    def refresh_doc_list(self) -> None:
        """Filter the mnemonic list by the text typed in the search field."""
        term = self.doc_query.get().strip().lower()
        self.doc_list.delete(0, "end")
        names = [k for k in sorted(ISA) if k.startswith(term)] if term else sorted(ISA)
        for n in names[:60]:
            self.doc_list.insert("end", n)

    def on_doc_select(self, event: Optional[tk.Event[tk.Misc]] = None) -> None:
        """Show the documentation of the mnemonic selected in the list."""
        sel = self.doc_list.curselection()
        if sel:
            self.show_doc(self.doc_list.get(sel[0]))

    def show_doc(self, mnemonic: Optional[str], ins: Optional[Line] = None) -> None:
        """Write the help of a mnemonic in the docs panel.

        Args:
            mnemonic: Mnemonic being looked up; with no documentation, warns in the panel.
            ins: Instruction from the code, when the lookup came from the editor.
        """
        info = ISA.get((mnemonic or "").lower())
        t = self.doc_text
        t.configure(state="normal")
        t.delete("1.0", "end")
        if ins is not None:
            t.insert("end", "line %d\n" % ins.n, "sub")
            t.insert("end", ins.text + "\n", "code")
            t.insert("end", "%s — %s\n\n" % (ins.sem.label, ins.sem.detail))
            regs = []
            for op in ins.operands:
                if op.type == "reg" and op.reg in REG_INFO:
                    regs.append(REG_INFO[op.reg]["base"])
                if op.type == "mem":
                    regs += [REG_INFO[r]["base"] for r in op.regs if r in REG_INFO]
            for r in dict.fromkeys(regs):
                if r in REG_DOC:
                    t.insert("end", "%s " % r.upper(), "code")
                    t.insert("end", REG_DOC[r] + "\n", "dim")
            t.insert("end", "\n")
        if not info:
            t.insert("end", "No documentation for %s.\n" % mnemonic, "dim")
        else:
            cat = CATEGORIES.get(info["cat"], {"label": info["cat"]})
            t.insert("end", (mnemonic or "").upper() + "\n", "titulo")
            t.insert("end", "%s · %s\n\n" % (info["name"], cat["label"]), "dim")
            t.insert("end", "Syntax\n", "sub")
            t.insert("end", info["syntax"] + "\n\n", "code")
            t.insert("end", "What it does\n", "sub")
            t.insert("end", info["desc"] + "\n\n")
            t.insert("end", "Example\n", "sub")
            t.insert("end", "\n".join(info["ex"]) + "\n\n", "code")
            t.insert("end", "Flags\n", "sub")
            t.insert("end", info["flags"] + "\n")
            if info.get("note"):
                t.insert("end", "\n" + info["note"] + "\n", "dim")
            t.insert("end", "\nProcessor flags\n", "sub")
            for f, d in FLAG_DOC.items():
                t.insert("end", "%s " % f, "code")
                t.insert("end", d + "\n", "dim")
        t.configure(state="disabled")

    def generate_report(self) -> None:
        """Generate the analysis report and open it in the browser.

        The file comes out self-contained (CSS, JavaScript and graphs embedded),
        so it opens offline and can be attached without depending on anything
        external.
        """
        from ..report import collect, write_report

        self.project.set_code(self.editor.get_code())
        base_name = os.path.splitext(os.path.basename(self.project.path or self.project.name))[0]
        path = filedialog.asksaveasfilename(
            title="Save report",
            defaultextension=".html",
            filetypes=REPORT_TYPES,
            initialfile="%s.report.html" % (base_name or "analysis"),
            parent=self,
        )
        if not path:
            return
        try:
            data = collect(
                self.project.code, emulate=True, command="asmx (interface) — %s" % self.project.name
            )
            written = write_report(data, path)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Report", "could not generate the report:\n%s" % exc, parent=self)
            return
        self.set_status(
            "report written to %s (%s, risk %s)"
            % (written, data.counts["instructions"], data.risk.get("level"))
        )
        webbrowser.open("file://" + os.path.abspath(written))

    # ============================================================ others ==
    def editor_toggle_comment(self) -> None:
        """Comment or uncomment the selection from the Edit menu."""
        self.editor.toggle_comment()

    def find(self) -> None:
        """Ask for a term and search for it in the editor."""
        term = TextPromptDialog(self, "Find", "Find what").show()
        if term:
            if not self.editor.find(term):
                self.set_status("could not find %r" % term)

    def goto_line(self) -> None:
        """Ask for a line number and jump to it."""
        value = TextPromptDialog(self, "Go to line", "Line number").show()
        if value and value.strip().isdigit():
            self.editor.goto_line(int(value.strip()))

    def show_about(self) -> None:
        """Open the window with the shortcuts and the version."""
        AboutDialog(self, __version__).show()

    def set_status(
        self, message: Optional[str] = None, cursor: Optional[Tuple[int, int]] = None
    ) -> None:
        """Write the status line with cursor, branch, statistics and warnings.

        Args:
            message: Extra note at the end of the line.
            cursor: Position (line, column) to show; without it the cursor one is used.
        """
        parts = []
        if cursor:
            parts.append("Ln %d, Col %d" % cursor)
        else:
            parts.append("Ln %d, Col %d" % (self.editor.cursor_line(), self.editor.cursor_col()))
        parts.append("branch: %s" % self.project.active)
        if self.analysis:
            s = self.analysis.stats
            parts.append("%d instructions in %d blocks" % (s["instructions"], s["blocks"]))
        if self.problems:
            parts.append(summary(self.problems))
        if self.project.dirty:
            parts.append("not saved")
        if message:
            parts.append(message)
        self.status.configure(text="   ·   ".join(parts))


def main() -> None:
    """Open the main window and enter the Tkinter event loop."""
    app = AsmXApp()
    app.mainloop()
