#!/usr/bin/env python3
"""Shortcut to ASM X straight from the source code.

``python3 asmx.py`` opens the graphical interface; ``python3 asmx.py check
prog.asm`` uses the command line — both paths enter through the same ``asmx``
package.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from asmx.cli import main  # noqa: E402  (sys.path has to come first)

if __name__ == "__main__":
    raise SystemExit(main())
