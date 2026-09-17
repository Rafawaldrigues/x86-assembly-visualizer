"""Janelas auxiliares da interface."""

import tkinter as tk
from tkinter import ttk

from ..workspace import Scenario, parse_reg_values
from . import theme


class ModalDialog(tk.Toplevel):
    """Base das janelas modais, com resultado em self.result."""

    def __init__(self, master, title, width=520, height=420):
        super().__init__(master)
        self.result = None
        self.title(title)
        self.configure(bg=theme.PANEL)
        self.transient(master)
        self.resizable(True, True)
        self.geometry("%dx%d" % (width, height))
        self.body = ttk.Frame(self, padding=12)
        self.body.pack(fill="both", expand=True)
        self.buttons = ttk.Frame(self, padding=(12, 0, 12, 12))
        self.buttons.pack(fill="x")
        self.bind("<Escape>", lambda e: self.cancel())
        self.protocol("WM_DELETE_WINDOW", self.cancel)

    def add_buttons(self, ok_text="Salvar"):
        ttk.Button(self.buttons, text="Cancelar", command=self.cancel).pack(side="right")
        ttk.Button(self.buttons, text=ok_text, style="Accent.TButton",
                   command=self.confirm).pack(side="right", padx=(0, 8))

    def confirm(self):
        self.result = self.collect()
        if self.result is not None:
            self.destroy()

    def cancel(self):
        self.result = None
        self.destroy()

    def collect(self):
        return None

    def show(self):
        self.grab_set()
        self.wait_window()
        return self.result


class ScenarioDialog(ModalDialog):
    """Cria ou edita um cenário de teste."""

    def __init__(self, master, labels, scenario: Scenario = None):
        super().__init__(master, "Cenário de teste", 560, 470)
        s = scenario or Scenario(name="")
        self.error = ttk.Label(self.body, text="", foreground=theme.SEV_COLOR["erro"])

        campos = ttk.Frame(self.body)
        campos.pack(fill="both", expand=True)
        campos.columnconfigure(1, weight=1)
        linha = 0

        def add(label, widget, dica=""):
            nonlocal linha
            ttk.Label(campos, text=label).grid(row=linha, column=0, sticky="w", pady=(6, 0))
            widget.grid(row=linha, column=1, sticky="ew", pady=(6, 0))
            linha += 1
            if dica:
                ttk.Label(campos, text=dica, style="Dim.TLabel", wraplength=340,
                          justify="left").grid(row=linha, column=1, sticky="w")
                linha += 1

        self.nome = ttk.Entry(campos)
        self.nome.insert(0, s.name)
        add("Nome", self.nome)

        self.entrada = ttk.Combobox(campos, values=[""] + list(labels), state="normal")
        self.entrada.set(s.entry)
        add("Começar em", self.entrada,
            "vazio = ponto de entrada do programa; ou escolha uma função para testá-la sozinha")

        self.regs = ttk.Entry(campos)
        self.regs.insert(0, ", ".join("%s=%s" % (k, v) for k, v in (s.regs or {}).items()))
        add("Registradores iniciais", self.regs, "exemplo: rdi=1000000, rsi=0x20")

        self.stdin = ttk.Entry(campos)
        self.stdin.insert(0, s.stdin)
        add("Entrada simulada (syscall read)", self.stdin)

        self.saida = tk.Text(campos, height=4, bg=theme.BG, fg=theme.FG, font=theme.mono(10),
                             insertbackground=theme.ACCENT, borderwidth=0, highlightthickness=1,
                             highlightbackground=theme.LINE)
        if s.expect_output is not None:
            self.saida.insert("1.0", s.expect_output)
        add("Saída esperada", self.saida, "deixe vazio para não verificar a saída")

        self.exit_code = ttk.Entry(campos)
        if s.expect_exit is not None:
            self.exit_code.insert(0, str(s.expect_exit))
        add("Código de saída esperado", self.exit_code, "vazio = não verifica")

        self.espera_problema = tk.BooleanVar(value=s.expect_issue)
        ttk.Checkbutton(campos, text="O teste passa se a execução acusar algum problema "
                                     "(estouro, laço infinito, divisão por zero...)",
                        variable=self.espera_problema).grid(row=linha, column=1, sticky="w",
                                                            pady=(8, 0))
        linha += 1

        self.max_steps = ttk.Entry(campos)
        self.max_steps.insert(0, str(s.max_steps))
        add("Limite de instruções", self.max_steps,
            "protege contra laço infinito: ao estourar, a execução para e acusa o problema")

        self.error.pack(fill="x", pady=(8, 0))
        self.add_buttons("Salvar cenário")
        self.nome.focus_set()

    def collect(self):
        nome = self.nome.get().strip()
        if not nome:
            self.error.configure(text="dê um nome ao cenário")
            return None
        saida = self.saida.get("1.0", "end-1c")
        try:
            passos = int(self.max_steps.get() or 200000)
        except ValueError:
            self.error.configure(text="o limite de instruções precisa ser um número")
            return None
        exit_txt = self.exit_code.get().strip()
        try:
            exit_code = int(exit_txt) if exit_txt else None
        except ValueError:
            self.error.configure(text="o código de saída precisa ser um número")
            return None
        return Scenario(
            name=nome,
            entry=self.entrada.get().strip(),
            regs={k: str(v) for k, v in parse_reg_values(self.regs.get()).items()},
            stdin=self.stdin.get(),
            expect_output=saida if saida else None,
            expect_exit=exit_code,
            expect_issue=bool(self.espera_problema.get()),
            max_steps=passos,
        )


class TextPromptDialog(ModalDialog):
    """Pergunta um texto curto (nome de branch, anotação)."""

    def __init__(self, master, title, label, value="", multiline=False, hint=""):
        super().__init__(master, title, 460, 240 if multiline else 190)
        ttk.Label(self.body, text=label).pack(anchor="w")
        if hint:
            ttk.Label(self.body, text=hint, style="Dim.TLabel", wraplength=420,
                      justify="left").pack(anchor="w", pady=(2, 6))
        self.multiline = multiline
        if multiline:
            self.entry = tk.Text(self.body, height=5, bg=theme.BG, fg=theme.FG,
                                 font=theme.mono(10), insertbackground=theme.ACCENT,
                                 borderwidth=0, highlightthickness=1,
                                 highlightbackground=theme.LINE)
            self.entry.insert("1.0", value)
        else:
            self.entry = ttk.Entry(self.body)
            self.entry.insert(0, value)
            self.entry.bind("<Return>", lambda e: self.confirm())
        self.entry.pack(fill="both", expand=True, pady=(4, 0))
        self.error = ttk.Label(self.body, text="", foreground=theme.SEV_COLOR["erro"])
        self.error.pack(fill="x")
        self.add_buttons("Confirmar")
        self.entry.focus_set()

    def collect(self):
        value = (self.entry.get("1.0", "end-1c") if self.multiline else self.entry.get())
        return value


class DiffDialog(tk.Toplevel):
    """Mostra a diferença entre duas branches."""

    def __init__(self, master, titulo, diff_text):
        super().__init__(master)
        self.title(titulo)
        self.configure(bg=theme.PANEL)
        self.geometry("720x520")
        self.transient(master)
        txt = tk.Text(self, bg=theme.BG, fg=theme.FG, font=theme.mono(10),
                      borderwidth=0, highlightthickness=0, wrap="none")
        scroll = ttk.Scrollbar(self, orient="vertical", command=txt.yview)
        txt.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        txt.pack(fill="both", expand=True)
        txt.tag_configure("add", foreground=theme.CALL)
        txt.tag_configure("del", foreground=theme.CMP)
        txt.tag_configure("head", foreground=theme.ACCENT)
        if not diff_text.strip():
            txt.insert("1.0", "As duas branches têm exatamente o mesmo código.")
        else:
            for linha in diff_text.split("\n"):
                tag = ""
                if linha.startswith("+"):
                    tag = "add"
                elif linha.startswith("-"):
                    tag = "del"
                elif linha.startswith("@@") or linha.startswith("---") or linha.startswith("+++"):
                    tag = "head"
                txt.insert("end", linha + "\n", tag)
        txt.configure(state="disabled")
        ttk.Button(self, text="Fechar", command=self.destroy).pack(pady=8)


class AboutDialog(ModalDialog):
    def __init__(self, master, versao):
        super().__init__(master, "Sobre", 520, 360)
        ttk.Label(self.body, text="ASM X", style="Head.TLabel",
                  font=theme.ui(16, "bold")).pack(anchor="w")
        ttk.Label(self.body, text="Ambiente de estudo e depuração de assembly x86-64 — versão %s"
                  % versao, style="Dim.TLabel").pack(anchor="w", pady=(0, 10))
        texto = (
            "Atalhos principais\n"
            "  F5   validar o código\n"
            "  F8   executar um passo\n"
            "  F9   rodar até o fim ou até o breakpoint\n"
            "  F10  reiniciar a máquina\n"
            "  F11  rodar todos os cenários de teste\n"
            "  Ctrl+/   comentar ou descomentar a seleção\n"
            "  Ctrl+S   salvar o projeto\n"
            "  Ctrl+B   nova branch a partir da atual\n"
            "  Ctrl+F   procurar\n"
            "  Ctrl+G   ir para a linha\n\n"
            "Clique na calha de números para marcar um breakpoint.\n"
            "Clique duas vezes num problema ou num item da estrutura para pular até a linha."
        )
        box = tk.Text(self.body, bg=theme.BG, fg=theme.FG, font=theme.mono(10),
                      borderwidth=0, highlightthickness=0, height=14)
        box.insert("1.0", texto)
        box.configure(state="disabled")
        box.pack(fill="both", expand=True)
        ttk.Button(self.buttons, text="Fechar", command=self.cancel).pack(side="right")
