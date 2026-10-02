"""Colors and fonts of the interface."""

from __future__ import annotations

import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk

BG = "#FFFFFF"
PANEL = "#E8E8E8"
PANEL2 = "#D8D8D8"
LINE = "#A0A0A0"
FG = "#202020"
DIM = "#595959"
WHITE = "#111111"
SEL = "#316AC5"
CURSOR_LINE = "#F3F3F3"
EXEC_LINE = "#FFFFB0"
BREAK = "#B02020"

ACCENT = "#204A87"
DATA = "#003399"
STACK = "#333399"
ARITH = "#204A87"
LOGIC = "#7A3000"
CMP = "#A00000"
BRANCH = "#660099"
CALL = "#006000"
SYS = "#804000"
STRING = "#7A3000"
COMMENT = "#557755"
MISC = "#595959"

SEV_COLOR = {"error": "#A00000", "warning": "#204A87", "info": "#333399"}

TAG_COLOR = {
    "store": DATA,
    "load": "#003399",
    "set": DATA,
    "copy": DATA,
    "addr": DATA,
    "push": STACK,
    "pop": STACK,
    "frame": STACK,
    "arith": ARITH,
    "logic": LOGIC,
    "compare": CMP,
    "branch": BRANCH,
    "jump": BRANCH,
    "call": CALL,
    "return": CALL,
    "syscall": SYS,
    "string": "#660099",
    "misc": MISC,
    "unknown": "#A00000",
}


def mono(size: int = 11, weight: str = "normal") -> tkfont.Font:
    """Pick the first monospaced font available on the system.

    Args:
        size: Font size in points.
        weight: Font weight ("normal" or "bold").

    Returns:
        The created font; Courier is the last resort.
    """
    for family in (
        "DejaVu Sans Mono",
        "Consolas",
        "Liberation Mono",
        "Courier New",
        "TkFixedFont",
    ):
        try:
            f = tkfont.Font(family=family, size=size, weight=weight)
            if f.actual("family"):
                return f
        except Exception:  # noqa: BLE001
            continue
    return tkfont.Font(family="Courier", size=size, weight=weight)


def ui(size: int = 10, weight: str = "normal") -> tkfont.Font:
    """Pick the first interface font available on the system.

    Args:
        size: Font size in points.
        weight: Font weight ("normal" or "bold").

    Returns:
        The created font; the Tk default font is the last resort.
    """
    for family in ("Segoe UI", "DejaVu Sans", "Liberation Sans", "Helvetica", "TkDefaultFont"):
        try:
            f = tkfont.Font(family=family, size=size, weight=weight)
            if f.actual("family"):
                return f
        except Exception:  # noqa: BLE001
            continue
    return tkfont.Font(size=size, weight=weight)


def apply_ttk_theme(root: tk.Misc) -> ttk.Style:
    """Apply the classic light theme to the ttk widgets.

    Args:
        root: Window that owns the style, usually the main window.

    Returns:
        The configured style.
    """
    from tkinter import ttk

    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except Exception:  # noqa: BLE001
        pass
    base = ui(10)
    style.configure(".", background=PANEL, foreground=FG, fieldbackground=BG, font=base)
    style.configure("TFrame", background=PANEL)
    style.configure("TLabel", background=PANEL, foreground=FG)
    style.configure("Dim.TLabel", foreground=DIM)
    style.configure("Head.TLabel", foreground=WHITE, font=ui(10, "bold"))
    style.configure(
        "TButton", background=PANEL2, foreground=FG, borderwidth=2, relief="raised", padding=(7, 2)
    )
    style.map("TButton", background=[("active", LINE), ("pressed", LINE)])
    style.configure("Accent.TButton", background=PANEL2, foreground=FG, font=ui(10, "bold"))
    style.map("Accent.TButton", background=[("active", "#C8D7EB")])
    style.configure("TNotebook", background=PANEL, borderwidth=1)
    style.configure("TNotebook.Tab", background=PANEL, foreground=DIM, padding=(10, 5))
    style.map("TNotebook.Tab", background=[("selected", PANEL)], foreground=[("selected", FG)])
    style.configure(
        "Treeview",
        background=BG,
        fieldbackground=BG,
        foreground=FG,
        rowheight=20,
        borderwidth=1,
        relief="sunken",
        font=mono(9),
    )
    style.configure(
        "Treeview.Heading", background=PANEL2, foreground=FG, font=ui(9), relief="raised"
    )
    style.map("Treeview", background=[("selected", SEL)], foreground=[("selected", "#FFFFFF")])
    style.configure("TPanedwindow", background=LINE)
    style.configure("TEntry", fieldbackground=BG, foreground=FG, insertcolor=FG)
    style.configure("TCombobox", fieldbackground=BG, foreground=FG, background=PANEL2)
    style.map(
        "TCombobox",
        fieldbackground=[("readonly", BG)],
        foreground=[("readonly", FG)],
        selectbackground=[("readonly", PANEL2)],
        selectforeground=[("readonly", FG)],
        arrowcolor=[("readonly", FG)],
    )
    style.configure("TCheckbutton", background=PANEL, foreground=FG)
    style.configure("Status.TLabel", background=PANEL, foreground=FG, font=ui(9), relief="sunken")
    return style
