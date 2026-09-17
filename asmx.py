#!/usr/bin/env python3
"""Atalho para abrir o ASM X: python3 asmx.py"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import tkinter  # noqa: F401
except ImportError:
    print("O ASM X usa Tkinter, que não está instalado.\n"
          "Debian/Ubuntu:  sudo apt install python3-tk\n"
          "Fedora:         sudo dnf install python3-tkinter\n"
          "Windows/macOS:  reinstale o Python marcando 'tcl/tk'")
    raise SystemExit(1)

from asmx.ui import main

if __name__ == "__main__":
    main()
