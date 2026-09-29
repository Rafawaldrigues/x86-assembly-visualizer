"""Entry point of the package.

``python3 -m asmx`` opens the graphical interface; any argument is handed to the
command line (``python3 -m asmx check prog.asm``). The import of the interface
is lazy on purpose: that way the command line keeps working on machines without
Tkinter, such as a minimal container.
"""

from __future__ import annotations

import sys


def main() -> int:
    """Dispatches between the graphical interface and the command line.

    Returns:
        Exit code of the process: the one from the command line when there are
        arguments, or ``0`` when the window closes normally.
    """
    from .cli import launch_gui, main as cli_main

    if len(sys.argv) > 1:
        return cli_main()
    return launch_gui()


if __name__ == "__main__":
    raise SystemExit(main())
