"""Colors and fonts of the interface."""

from __future__ import annotations

import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk

BG = "#0F1826"
PANEL = "#16202E"
PANEL2 = "#1C2A3A"
LINE = "#26394E"
FG = "#DCE6F2"
DIM = "#8AA0B8"
WHITE = "#F2F7FF"
SEL = "#27405C"
CURSOR_LINE = "#17253A"
EXEC_LINE = "#1E3A26"
BREAK = "#E05561"

ACCENT = "#E3A44B"
DATA = "#57C8D2"
STACK = "#79A6E8"
ARITH = "#E3A44B"
LOGIC = "#BFD46B"
CMP = "#EF7D9D"
BRANCH = "#9C8CF0"
CALL = "#5FD4A8"
SYS = "#F08A5D"
STRING = "#BFD46B"
COMMENT = "#5A748C"
MISC = "#8AA0B8"

SEV_COLOR = {"error": "#EF7D9D", "warning": "#E3A44B", "info": "#79A6E8"}

TAG_COLOR = {
    "store": DATA,
    "load": "#41A5AE",
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
    "string": "#B79AE8",
    "misc": MISC,
    "unknown": "#E08282",
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
        "JetBrains Mono",
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
    """Apply the ASM X dark theme to the ttk widgets.

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
    style.configure("TButton", background=PANEL2, foreground=FG, borderwidth=1, padding=(8, 3))
    style.map("TButton", background=[("active", LINE), ("pressed", LINE)])
    style.configure("Accent.TButton", background=ACCENT, foreground="#0F1826", font=ui(10, "bold"))
    style.map("Accent.TButton", background=[("active", "#F0B865")])
    style.configure("TNotebook", background=PANEL, borderwidth=0)
    style.configure("TNotebook.Tab", background=PANEL, foreground=DIM, padding=(10, 5))
    style.map("TNotebook.Tab", background=[("selected", PANEL2)], foreground=[("selected", WHITE)])
    style.configure(
        "Treeview",
        background=BG,
        fieldbackground=BG,
        foreground=FG,
        rowheight=20,
        borderwidth=0,
        font=ui(9),
    )
    style.configure(
        "Treeview.Heading", background=PANEL2, foreground=DIM, font=ui(9), relief="flat"
    )
    style.map("Treeview", background=[("selected", SEL)], foreground=[("selected", WHITE)])
    style.configure("TPanedwindow", background=LINE)
    style.configure("TEntry", fieldbackground=BG, foreground=FG, insertcolor=FG)
    style.configure("TCombobox", fieldbackground=BG, foreground=FG, background=PANEL2)
    # A read-only combobox draws its text through the "readonly" state map, not
    # through the base style: without this the branch name is invisible on the
    # dark field (and the selection would be dark on dark).
    style.map(
        "TCombobox",
        fieldbackground=[("readonly", BG)],
        foreground=[("readonly", FG)],
        selectbackground=[("readonly", PANEL2)],
        selectforeground=[("readonly", FG)],
        arrowcolor=[("readonly", FG)],
    )
    style.configure("TCheckbutton", background=PANEL, foreground=FG)
    style.configure("Status.TLabel", background=PANEL2, foreground=DIM, font=ui(9))
    return style
