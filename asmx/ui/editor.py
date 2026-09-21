"""Editor de assembly: numeração de linhas, breakpoints, realce e anotações."""

from __future__ import annotations

import re
import tkinter as tk
from tkinter import ttk
from typing import Any, Callable, Dict, List, Optional, Set, Union

from ..isa import ISA
from . import theme

KEYWORDS = re.compile(
    r"\b(section|segment|global|globl|extern|db|dw|dd|dq|dt|resb|resw|"
    r"resd|resq|equ|times|bits|default|align|proc|endp|end|includelib|"
    r"byte|word|dword|qword|ptr)\b",
    re.I,
)
REGISTERS = re.compile(
    r"\b(r[abcd]x|r[sd]i|r[sb]p|r8|r9|r1[0-5]|e[abcd]x|e[sd]i|e[sb]p|"
    r"[abcd][lhx]|sil|dil|spl|bpl|r\d+[dwb]|xmm\d+|rip)\b",
    re.I,
)
NUMBERS = re.compile(r"\b(0x[0-9a-fA-F]+|\d+h|\d+b?|[01]+b)\b")
LABELDEF = re.compile(r"^\s*([A-Za-z_.$?@][\w.$@?]*)\s*:")


class CodeEditor(ttk.Frame):
    """Text widget com calha de linhas, breakpoints e realce de sintaxe."""

    def __init__(
        self,
        master: tk.Misc,
        on_change: Optional[Callable[..., Any]] = None,
        on_breakpoint: Optional[Callable[..., Any]] = None,
        on_cursor: Optional[Callable[..., Any]] = None,
    ) -> None:
        """Monta o texto, a calha, as barras de rolagem e os eventos.

        Args:
            master: widget pai.
            on_change: chamado quando o texto para de mudar.
            on_breakpoint: chamado com (linha, ativo) ao marcar um breakpoint.
            on_cursor: chamado com (linha, coluna) quando o cursor se move.
        """
        super().__init__(master)
        self.on_change = on_change
        self.on_breakpoint = on_breakpoint
        self.on_cursor = on_cursor
        self.breakpoints: Set[int] = set()
        self.notes: Dict[str, str] = {}
        self._destroyed = False
        self._highlight_job: Optional[str] = None
        self._change_job: Optional[str] = None

        self.gutter: tk.Canvas = tk.Canvas(
            self, width=58, bg=theme.PANEL, highlightthickness=0, bd=0, takefocus=0
        )
        self.gutter.pack(side="left", fill="y")

        self.scroll: ttk.Scrollbar = ttk.Scrollbar(self, orient="vertical", command=self._yview)
        self.scroll.pack(side="right", fill="y")

        self.font = theme.mono(11)
        self.text: tk.Text = tk.Text(
            self,
            wrap="none",
            undo=True,
            maxundo=-1,
            bg=theme.BG,
            fg=theme.FG,
            insertbackground=theme.ACCENT,
            selectbackground=theme.SEL,
            selectforeground=theme.WHITE,
            font=self.font,
            borderwidth=0,
            highlightthickness=0,
            tabs=("1c",),
            padx=8,
            pady=4,
            yscrollcommand=self._on_text_scroll,
        )
        self.hbar: ttk.Scrollbar = ttk.Scrollbar(self, orient="horizontal", command=self.text.xview)
        self.text.configure(xscrollcommand=self.hbar.set)
        self.hbar.pack(side="bottom", fill="x")
        self.text.pack(side="left", fill="both", expand=True)

        self._make_tags()
        self.text.bind("<KeyRelease>", self._changed)
        self.text.bind("<<Paste>>", lambda e: self.after(10, self._changed))
        self.text.bind("<ButtonRelease-1>", self._cursor_moved)
        self.text.bind("<KeyRelease-Up>", self._cursor_moved)
        self.text.bind("<KeyRelease-Down>", self._cursor_moved)
        self.text.bind("<Configure>", lambda e: self.redraw_gutter())
        self.text.bind("<MouseWheel>", self._wheel)
        self.text.bind("<Button-4>", self._wheel)
        self.text.bind("<Button-5>", self._wheel)
        self.text.bind("<Control-slash>", self.toggle_comment)
        self.text.bind("<Control-question>", self.toggle_comment)
        self.text.bind("<Tab>", self._tab)
        self.gutter.bind("<Button-1>", self._gutter_click)
        self.bind("<Destroy>", self._cleanup)

    def _cleanup(self, event: Optional[tk.Event[tk.Misc]] = None) -> None:
        """Cancela trabalhos agendados para a janela não reclamar ao fechar."""
        for job in (self._highlight_job, self._change_job):
            if job:
                try:
                    self.after_cancel(job)
                except Exception:  # noqa: BLE001
                    pass
        self._highlight_job = self._change_job = None
        self._destroyed = True

    # ------------------------------------------------------------- tags ---
    def _make_tags(self) -> None:
        """Cria as tags de realce usadas pelo widget de texto."""
        t = self.text
        t.tag_configure("mnemonic", foreground=theme.WHITE)
        t.tag_configure("register", foreground=theme.DATA)
        t.tag_configure("number", foreground=theme.ARITH)
        t.tag_configure("string", foreground=theme.STRING)
        t.tag_configure("comment", foreground=theme.COMMENT)
        t.tag_configure("label", foreground=theme.CALL)
        t.tag_configure("directive", foreground=theme.BRANCH)
        t.tag_configure("current", background=theme.CURSOR_LINE)
        t.tag_configure("exec", background=theme.EXEC_LINE)
        t.tag_configure("errorline", background="#3A1E26")
        t.tag_configure("found", background=theme.SEL)
        t.tag_raise("sel")

    # ------------------------------------------------------- conteúdo -----
    def get_code(self) -> str:
        """Devolve o texto do editor tal como está no widget.

        Returns:
            O conteúdo digitado, sem o newline final que o Tk mantém.
        """
        return self.text.get("1.0", "end-1c")

    def set_code(self, code: str, keep_view: bool = False) -> None:
        """Substitui todo o texto do editor e refaz o realce e a calha.

        Args:
            code: novo conteúdo do editor.
            keep_view: mantém a posição da rolagem quando verdadeiro.
        """
        pos = self.text.yview()[0] if keep_view else 0.0
        self.text.edit_separator()
        self.text.delete("1.0", "end")
        self.text.insert("1.0", code)
        if keep_view:
            self.text.yview_moveto(pos)
        self.highlight()
        self.redraw_gutter()

    def line_count(self) -> int:
        """Devolve o número de linhas do texto.

        Returns:
            A quantidade de linhas.
        """
        return int(self.text.index("end-1c").split(".")[0])

    def cursor_line(self) -> int:
        """Devolve a linha onde o cursor está.

        Returns:
            O número da linha, a partir de 1.
        """
        return int(self.text.index("insert").split(".")[0])

    def cursor_col(self) -> int:
        """Devolve a coluna onde o cursor está.

        Returns:
            O número da coluna, a partir de 1.
        """
        return int(self.text.index("insert").split(".")[1]) + 1

    def goto_line(self, line: int, focus: bool = True) -> None:
        """Põe o cursor na linha e rola até ela.

        Args:
            line: número da linha.
            focus: leva o foco do teclado para o editor quando verdadeiro.
        """
        self.text.mark_set("insert", "%d.0" % line)
        self.text.see("%d.0" % max(1, line - 2))
        self.mark_current_line()
        if focus:
            self.text.focus_set()
        self.redraw_gutter()

    # --------------------------------------------------------- eventos ----
    def _changed(self, event: Optional[tk.Event[tk.Misc]] = None) -> None:
        """Reage a uma edição: agenda o realce, redesenha a calha e avisa quem observa."""
        self.schedule_highlight()
        self.redraw_gutter()
        if self.on_change and not self._destroyed:
            if self._change_job:
                self.after_cancel(self._change_job)
            self._change_job = self.after(350, self.on_change)
        self._cursor_moved()

    def _cursor_moved(self, event: Optional[tk.Event[tk.Misc]] = None) -> None:
        """Atualiza a linha realçada e informa a posição do cursor."""
        self.mark_current_line()
        if self.on_cursor:
            self.on_cursor(self.cursor_line(), self.cursor_col())

    def _tab(self, event: tk.Event[tk.Misc]) -> str:
        """Insere quatro espaços no lugar da tecla Tab.

        Returns:
            "break", para o Tk não inserir a tabulação padrão.
        """
        self.text.insert("insert", "    ")
        return "break"

    def _wheel(self, event: tk.Event[tk.Misc]) -> str:
        """Rola o texto com a roda do mouse e redesenha a calha.

        Args:
            event: evento da roda; usa num no Linux e delta nos outros sistemas.

        Returns:
            "break", para o Tk não rolar o texto uma segunda vez.
        """
        if event.num == 4 or getattr(event, "delta", 0) > 0:
            self.text.yview_scroll(-3, "units")
        else:
            self.text.yview_scroll(3, "units")
        self.redraw_gutter()
        return "break"

    def _yview(self, *args: Any) -> None:
        """Repassa a rolagem para o texto e mantém a calha alinhada.

        Args:
            *args: argumentos de rolagem que o Tk entrega à barra.
        """
        self.text.yview(*args)
        self.redraw_gutter()

    def _on_text_scroll(self, first: Union[float, str], last: Union[float, str]) -> None:
        """Sincroniza a barra de rolagem vertical com o texto.

        Args:
            first: fração inicial visível, informada pelo Tk.
            last: fração final visível, informada pelo Tk.
        """
        self.scroll.set(first, last)
        self.redraw_gutter()

    def _gutter_click(self, event: tk.Event[tk.Misc]) -> None:
        """Liga ou desliga o breakpoint da linha clicada na calha.

        Args:
            event: clique na calha; a coordenada y indica a linha.
        """
        index = self.text.index("@0,%d" % event.y)
        line = int(index.split(".")[0])
        if line > self.line_count():
            return
        if line in self.breakpoints:
            self.breakpoints.discard(line)
        else:
            self.breakpoints.add(line)
        self.redraw_gutter()
        if self.on_breakpoint:
            self.on_breakpoint(line, line in self.breakpoints)

    # ---------------------------------------------------------- calha -----
    def redraw_gutter(self) -> None:
        """Redesenha a calha: números, breakpoints, anotação e linha em execução."""
        self.gutter.delete("all")
        try:
            first = self.text.index("@0,0")
        except tk.TclError:
            return
        line = int(first.split(".")[0])
        height = self.text.winfo_height()
        exec_line = getattr(self, "_exec_line", None)
        while True:
            dline = self.text.dlineinfo("%d.0" % line)
            if dline is None:
                break
            y = dline[1]
            if y > height:
                break
            color = theme.DIM if line != self.cursor_line() else theme.WHITE
            if line == exec_line:
                self.gutter.create_rectangle(
                    0, y - 1, 58, y + dline[3] + 1, fill=theme.EXEC_LINE, outline=""
                )
                color = theme.CALL
            if line in self.breakpoints:
                self.gutter.create_oval(6, y + 4, 15, y + 13, fill=theme.BREAK, outline="")
            if str(line) in self.notes:
                self.gutter.create_text(
                    54, y + 8, text="✎", fill=theme.ACCENT, font=theme.ui(9), anchor="e"
                )
            self.gutter.create_text(
                40, y + 8, text=str(line), anchor="e", fill=color, font=theme.mono(9)
            )
            line += 1

    def set_exec_line(self, line: Optional[int]) -> None:
        """Marca a linha que a máquina vai executar.

        Args:
            line: número da linha em execução; None limpa a marca.
        """
        self._exec_line = line
        self.text.tag_remove("exec", "1.0", "end")
        if line:
            self.text.tag_add("exec", "%d.0" % line, "%d.end+1c" % line)
            self.text.see("%d.0" % line)
        self.redraw_gutter()

    def mark_current_line(self) -> None:
        """Realça a linha onde o cursor está."""
        self.text.tag_remove("current", "1.0", "end")
        line = self.cursor_line()
        self.text.tag_add("current", "%d.0" % line, "%d.end+1c" % line)
        self.text.tag_lower("current")

    def mark_error_lines(self, lines: List[int]) -> None:
        """Pinta de erro as linhas indicadas.

        Args:
            lines: números das linhas com problema.
        """
        self.text.tag_remove("errorline", "1.0", "end")
        for line in lines:
            try:
                self.text.tag_add("errorline", "%d.0" % line, "%d.end+1c" % line)
            except tk.TclError:
                pass
        self.text.tag_lower("errorline")

    # --------------------------------------------------------- realce -----
    def schedule_highlight(self) -> None:
        """Agenda o realce para daqui a pouco, juntando várias edições seguidas."""
        if self._destroyed:
            return
        if self._highlight_job:
            self.after_cancel(self._highlight_job)
        self._highlight_job = self.after(120, self.highlight)

    def highlight(self) -> None:
        """Recolore o texto inteiro: comentários, strings, rótulos e mnemônicos.

        O trabalho é feito linha a linha, removendo as marcas antigas antes de
        aplicar as novas, para o realce não acumular. Um realce agendado que
        ainda não disparou é cancelado aqui: quem chamou o método já está
        pintando o texto agora, e um segundo trabalho pendente viraria um
        comando Tk órfão depois que a janela fecha.
        """
        if self._highlight_job:
            try:
                self.after_cancel(self._highlight_job)
            except tk.TclError:  # pragma: no cover - janela já destruída
                pass
        self._highlight_job = None
        t = self.text
        for tag in ("mnemonic", "register", "number", "string", "comment", "label", "directive"):
            t.tag_remove(tag, "1.0", "end")
        total = self.line_count()
        for i in range(1, total + 1):
            line = t.get("%d.0" % i, "%d.end" % i)
            if not line.strip():
                continue
            code = line
            cpos = None
            in_str = None
            for j, ch in enumerate(line):
                if in_str:
                    if ch == in_str:
                        in_str = None
                    continue
                if ch in "\"'":
                    in_str = ch
                    continue
                if ch == ";" or (ch == "#" and (j == 0 or not line[j - 1].isalnum())):
                    cpos = j
                    break
            if cpos is not None:
                t.tag_add("comment", "%d.%d" % (i, cpos), "%d.end" % i)
                code = line[:cpos]
            for m in re.finditer(r"(['\"]).*?\1", code):
                t.tag_add("string", "%d.%d" % (i, m.start()), "%d.%d" % (i, m.end()))
            m = LABELDEF.match(code)
            if m:
                t.tag_add("label", "%d.%d" % (i, m.start(1)), "%d.%d" % (i, m.end(1)))
            for m in KEYWORDS.finditer(code):
                t.tag_add("directive", "%d.%d" % (i, m.start()), "%d.%d" % (i, m.end()))
            for m in REGISTERS.finditer(code):
                t.tag_add("register", "%d.%d" % (i, m.start()), "%d.%d" % (i, m.end()))
            for m in NUMBERS.finditer(code):
                t.tag_add("number", "%d.%d" % (i, m.start()), "%d.%d" % (i, m.end()))
            for m in re.finditer(r"\b[a-zA-Z][a-zA-Z0-9]{1,8}\b", code):
                if m.group(0).lower() in ISA:
                    before = code[: m.start()].strip()
                    if not before or before.endswith(":"):
                        t.tag_add("mnemonic", "%d.%d" % (i, m.start()), "%d.%d" % (i, m.end()))
        self.text.tag_raise("string")
        self.text.tag_raise("comment")

    # ---------------------------------------------------- comentários -----
    def toggle_comment(self, event: Optional[tk.Event[tk.Misc]] = None) -> str:
        """Comenta ou descomenta a seleção; sem seleção, a linha do cursor.

        Returns:
            "break", para o Tk não processar a tecla de atalho.
        """
        try:
            start = int(self.text.index("sel.first").split(".")[0])
            end = int(self.text.index("sel.last").split(".")[0])
        except tk.TclError:
            start = end = self.cursor_line()
        linhas = [self.text.get("%d.0" % i, "%d.end" % i) for i in range(start, end + 1)]
        comentadas = all(linha.strip().startswith(";") or not linha.strip() for linha in linhas)
        self.text.edit_separator()
        for i, original in zip(range(start, end + 1), linhas):
            if not original.strip():
                continue
            if comentadas:
                nova = re.sub(r"^(\s*);\s?", r"\1", original)
            else:
                indent = len(original) - len(original.lstrip())
                nova = original[:indent] + "; " + original[indent:]
            self.text.delete("%d.0" % i, "%d.end" % i)
            self.text.insert("%d.0" % i, nova)
        self.highlight()
        self._changed()
        return "break"

    def insert_at_cursor(self, texto: str) -> None:
        """Insere texto na posição do cursor e avisa que o conteúdo mudou.

        Args:
            texto: o que será inserido.
        """
        self.text.insert("insert", texto)
        self._changed()

    # ------------------------------------------------------------ busca ---
    def find(self, termo: str, from_start: bool = False) -> bool:
        """Procura o termo no texto e seleciona a ocorrência encontrada.

        Args:
            termo: texto procurado, sem diferenciar maiúsculas de minúsculas.
            from_start: começa a busca no início do arquivo.

        Returns:
            True quando alguma ocorrência foi encontrada.
        """
        self.text.tag_remove("found", "1.0", "end")
        if not termo:
            return False
        inicio = "1.0" if from_start else "insert+1c"
        pos = self.text.search(termo, inicio, nocase=True, stopindex="end")
        if not pos:
            pos = self.text.search(termo, "1.0", nocase=True, stopindex="end")
        if not pos:
            return False
        fim = "%s+%dc" % (pos, len(termo))
        self.text.tag_add("found", pos, fim)
        self.text.mark_set("insert", fim)
        self.text.see(pos)
        return True
