"""Janela principal do ASM X."""

import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .. import __version__
from ..analyzer import analyze, callers_of
from ..emulator import Machine, hexs, to_signed
from ..examples import EXAMPLES
from ..isa import (CATEGORIES, FLAG_DOC, ISA, REGS64, REG_DOC, REG_INFO)
from ..linter import ERRO, summary, validate
from ..workspace import Project, run_all_scenarios, run_scenario
from . import theme
from .dialogs import AboutDialog, DiffDialog, ScenarioDialog, TextPromptDialog
from .editor import CodeEditor

PROJ_TYPES = [("Projeto ASM X", "*.asmproj"), ("Todos os arquivos", "*.*")]
ASM_TYPES = [("Assembly", "*.asm *.s *.S *.nasm"), ("Todos os arquivos", "*.*")]


class AsmXApp(tk.Tk):

    def __init__(self, project: Project = None):
        super().__init__()
        self.title("ASM X")
        self.geometry("1360x820")
        self.minsize(900, 600)
        self.configure(bg=theme.PANEL)
        theme.apply_ttk_theme(self)

        self.project = project or Project.new(code=EXAMPLES["linux-hello"]["code"])
        self.analysis = None
        self.machine = None
        self.problems = []
        self.results = []
        self.last_regs = {}
        self._suspend_change = False

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

    # ===================================================== construção =====
    def _build_menu(self):
        menubar = tk.Menu(self, bg=theme.PANEL, fg=theme.FG, activebackground=theme.SEL,
                          activeforeground=theme.WHITE, borderwidth=0)

        def menu():
            return tk.Menu(menubar, tearoff=0, bg=theme.PANEL, fg=theme.FG,
                           activebackground=theme.SEL, activeforeground=theme.WHITE)

        arquivo = menu()
        arquivo.add_command(label="Novo projeto", accelerator="Ctrl+N", command=self.new_project)
        arquivo.add_command(label="Abrir projeto...", accelerator="Ctrl+O", command=self.open_project)
        arquivo.add_command(label="Salvar projeto", accelerator="Ctrl+S", command=self.save_project)
        arquivo.add_command(label="Salvar projeto como...", command=self.save_project_as)
        arquivo.add_separator()
        arquivo.add_command(label="Importar arquivo .asm...", command=self.import_asm)
        arquivo.add_command(label="Exportar branch como .asm...", command=self.export_asm)
        exemplos = menu()
        for key, ex in EXAMPLES.items():
            exemplos.add_command(label=ex["title"],
                                 command=lambda k=key: self.load_example(k))
        arquivo.add_cascade(label="Abrir exemplo", menu=exemplos)
        arquivo.add_separator()
        arquivo.add_command(label="Sair", command=self.on_close)
        menubar.add_cascade(label="Arquivo", menu=arquivo)

        editar = menu()
        editar.add_command(label="Desfazer", accelerator="Ctrl+Z",
                           command=lambda: self.editor.text.edit_undo())
        editar.add_command(label="Refazer", accelerator="Ctrl+Y",
                           command=lambda: self.editor.text.edit_redo())
        editar.add_separator()
        editar.add_command(label="Comentar/descomentar", accelerator="Ctrl+/",
                           command=self.editor_toggle_comment)
        editar.add_command(label="Anotar esta linha", accelerator="Ctrl+E", command=self.edit_note)
        editar.add_separator()
        editar.add_command(label="Procurar...", accelerator="Ctrl+F", command=self.find)
        editar.add_command(label="Ir para a linha...", accelerator="Ctrl+G", command=self.goto_line)
        menubar.add_cascade(label="Editar", menu=editar)

        branch = menu()
        branch.add_command(label="Nova branch a partir desta", accelerator="Ctrl+B",
                           command=self.branch_new)
        branch.add_command(label="Renomear branch atual", command=self.branch_rename)
        branch.add_command(label="Excluir branch atual", command=self.branch_delete)
        branch.add_separator()
        branch.add_command(label="Comparar com outra branch...", command=self.branch_diff)
        menubar.add_cascade(label="Branch", menu=branch)

        executar = menu()
        executar.add_command(label="Validar código", accelerator="F5", command=self.validate_now)
        executar.add_separator()
        executar.add_command(label="Passo", accelerator="F8", command=self.step)
        executar.add_command(label="Rodar", accelerator="F9", command=self.run)
        executar.add_command(label="Rodar até o cursor", accelerator="F7", command=self.run_to_cursor)
        executar.add_command(label="Reiniciar", accelerator="F10", command=self.reset_machine)
        executar.add_separator()
        executar.add_command(label="Depurar função isolada...", command=self.debug_function)
        executar.add_command(label="Rodar todos os cenários", accelerator="F11",
                             command=self.run_all_scenarios)
        menubar.add_cascade(label="Executar", menu=executar)

        ajuda = menu()
        ajuda.add_command(label="Atalhos e sobre", command=self.show_about)
        menubar.add_cascade(label="Ajuda", menu=ajuda)

        self.configure(menu=menubar)

    def _build_layout(self):
        barra = ttk.Frame(self, padding=(8, 5))
        barra.pack(fill="x")
        self.branch_var = tk.StringVar(value=self.project.active)
        ttk.Label(barra, text="branch").pack(side="left")
        self.branch_box = ttk.Combobox(barra, textvariable=self.branch_var, width=22,
                                       state="readonly")
        self.branch_box.pack(side="left", padx=(6, 10))
        self.branch_box.bind("<<ComboboxSelected>>", lambda e: self.branch_switch(self.branch_var.get()))
        ttk.Button(barra, text="Nova branch", command=self.branch_new).pack(side="left")
        ttk.Button(barra, text="Validar", command=self.validate_now).pack(side="left", padx=6)
        ttk.Button(barra, text="Passo", command=self.step).pack(side="left")
        ttk.Button(barra, text="Rodar", style="Accent.TButton", command=self.run).pack(side="left", padx=6)
        ttk.Button(barra, text="Reiniciar", command=self.reset_machine).pack(side="left")
        self.platform_label = ttk.Label(barra, text="—", style="Head.TLabel")
        self.platform_label.pack(side="right")

        self.status = ttk.Label(self, text="", style="Status.TLabel", padding=(8, 3))
        self.status.pack(side="bottom", fill="x")

        principal = ttk.PanedWindow(self, orient="horizontal")
        principal.pack(fill="both", expand=True)

        # ---------------------------------------------------- coluna 1 ----
        esquerda = ttk.Frame(principal, width=330)
        esquerda.pack_propagate(False)
        principal.add(esquerda, weight=0)
        ttk.Label(esquerda, text="Estrutura do código", style="Head.TLabel",
                  padding=(8, 6)).pack(fill="x")
        self.tree = ttk.Treeview(esquerda, columns=("info",), show="tree headings", height=20)
        self.tree.heading("#0", text="programa")
        self.tree.heading("info", text="o que faz")
        self.tree.column("#0", width=140, stretch=True, minwidth=90)
        self.tree.column("info", width=175, stretch=True, minwidth=90)
        vs = ttk.Scrollbar(esquerda, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vs.set)
        vs.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)
        self.tree.bind("<Double-1>", self.on_tree_select)

        # ---------------------------------------------------- coluna 2 ----
        centro = ttk.PanedWindow(principal, orient="vertical")
        principal.add(centro, weight=3)

        editor_frame = ttk.Frame(centro)
        centro.add(editor_frame, weight=3)
        self.editor = CodeEditor(editor_frame, on_change=self.on_code_change,
                                 on_breakpoint=self.on_breakpoint,
                                 on_cursor=self.on_cursor)
        self.editor.pack(fill="both", expand=True)

        inferior = ttk.Notebook(centro)
        centro.add(inferior, weight=1)
        self.bottom = inferior

        # problemas
        aba_problemas = ttk.Frame(inferior)
        inferior.add(aba_problemas, text="Problemas")
        self.problem_tree = ttk.Treeview(aba_problemas, columns=("linha", "codigo", "msg"),
                                         show="headings", height=7)
        for col, txt, w in (("linha", "linha", 55), ("codigo", "código", 70), ("msg", "problema", 700)):
            self.problem_tree.heading(col, text=txt)
            self.problem_tree.column(col, width=w, anchor="w")
        self.problem_tree.tag_configure("erro", foreground=theme.SEV_COLOR["erro"])
        self.problem_tree.tag_configure("alerta", foreground=theme.SEV_COLOR["alerta"])
        self.problem_tree.tag_configure("info", foreground=theme.SEV_COLOR["info"])
        ps = ttk.Scrollbar(aba_problemas, orient="vertical", command=self.problem_tree.yview)
        self.problem_tree.configure(yscrollcommand=ps.set)
        ps.pack(side="right", fill="y")
        self.problem_tree.pack(side="top", fill="both", expand=True)
        self.problem_hint = ttk.Label(aba_problemas, text="", style="Dim.TLabel",
                                      wraplength=900, justify="left", padding=(8, 4))
        self.problem_hint.pack(fill="x")
        self.problem_tree.bind("<<TreeviewSelect>>", self.on_problem_select)
        self.problem_tree.bind("<Double-1>", self.on_problem_open)

        # saída
        aba_saida = ttk.Frame(inferior)
        inferior.add(aba_saida, text="Saída")
        self.output_text = tk.Text(aba_saida, bg=theme.BG, fg=theme.LOGIC, height=7,
                                   font=theme.mono(10), borderwidth=0, highlightthickness=0)
        self.output_text.pack(fill="both", expand=True)
        self.output_text.configure(state="disabled")

        # cenários de teste
        aba_testes = ttk.Frame(inferior)
        inferior.add(aba_testes, text="Testes")
        acoes = ttk.Frame(aba_testes, padding=(4, 4))
        acoes.pack(fill="x")
        ttk.Button(acoes, text="Novo", command=self.scenario_new).pack(side="left")
        ttk.Button(acoes, text="Editar", command=self.scenario_edit).pack(side="left", padx=4)
        ttk.Button(acoes, text="Excluir", command=self.scenario_delete).pack(side="left")
        ttk.Button(acoes, text="Rodar", command=self.run_selected_scenario).pack(side="left", padx=4)
        ttk.Button(acoes, text="Rodar todos", style="Accent.TButton",
                   command=self.run_all_scenarios).pack(side="left")

        self.scenario_tree = ttk.Treeview(aba_testes, columns=("entrada", "estado", "resultado"),
                                          show="tree headings", height=6)
        self.scenario_tree.heading("#0", text="cenário")
        self.scenario_tree.heading("entrada", text="começa em")
        self.scenario_tree.heading("estado", text="registradores")
        self.scenario_tree.heading("resultado", text="resultado")
        self.scenario_tree.column("#0", width=140, minwidth=80)
        self.scenario_tree.column("entrada", width=100, minwidth=70)
        self.scenario_tree.column("estado", width=120, minwidth=70)
        self.scenario_tree.column("resultado", width=110, minwidth=70)
        self.scenario_tree.tag_configure("ok", foreground=theme.CALL)
        self.scenario_tree.tag_configure("falhou", foreground=theme.SEV_COLOR["erro"])
        self.scenario_tree.pack(fill="both", expand=True)
        self.scenario_detail = ttk.Label(aba_testes, text="Um cenário guarda o estado inicial "
                                         "(onde começar, quais registradores) e o que você espera "
                                         "que aconteça. Selecione um para ver o resultado completo.",
                                         style="Dim.TLabel", wraplength=900, justify="left",
                                         padding=(8, 4))
        self.scenario_detail.pack(fill="x")
        self.scenario_tree.bind("<Double-1>", lambda e: self.scenario_edit())
        self.scenario_tree.bind("<<TreeviewSelect>>", self.on_scenario_select)

        # histórico
        aba_hist = ttk.Frame(inferior)
        inferior.add(aba_hist, text="Histórico da execução")
        self.trace_tree = ttk.Treeview(aba_hist, columns=("linha", "instr", "efeito"),
                                       show="headings", height=7)
        for col, txt, w in (("linha", "linha", 55), ("instr", "instrução", 220),
                            ("efeito", "o que aconteceu", 700)):
            self.trace_tree.heading(col, text=txt)
            self.trace_tree.column(col, width=w, anchor="w")
        ts = ttk.Scrollbar(aba_hist, orient="vertical", command=self.trace_tree.yview)
        self.trace_tree.configure(yscrollcommand=ts.set)
        ts.pack(side="right", fill="y")
        self.trace_tree.pack(fill="both", expand=True)

        # ---------------------------------------------------- coluna 3 ----
        caixa_direita = ttk.Frame(principal, width=430)
        caixa_direita.pack_propagate(False)
        principal.add(caixa_direita, weight=0)
        direita = ttk.Notebook(caixa_direita)
        direita.pack(fill="both", expand=True)
        self.right = direita

        aba_insp = ttk.Frame(direita)
        direita.add(aba_insp, text="Máquina")
        self._build_inspector(aba_insp)

        aba_doc = ttk.Frame(direita)
        direita.add(aba_doc, text="Docs")
        self._build_docs(aba_doc)

        aba_notas = ttk.Frame(direita)
        direita.add(aba_notas, text="Notas")
        self._build_notes(aba_notas)

    def _build_inspector(self, parent):
        topo = ttk.Frame(parent, padding=(6, 6))
        topo.pack(fill="x")
        self.exec_label = ttk.Label(topo, text="máquina parada", style="Dim.TLabel",
                                    wraplength=340, justify="left")
        self.exec_label.pack(fill="x")

        self.reg_tree = ttk.Treeview(parent, columns=("hex", "dec"), show="tree headings",
                                     height=16)
        self.reg_tree.heading("#0", text="reg")
        self.reg_tree.heading("hex", text="hexadecimal")
        self.reg_tree.heading("dec", text="decimal")
        self.reg_tree.column("#0", width=48)
        self.reg_tree.column("hex", width=150, anchor="e")
        self.reg_tree.column("dec", width=140, anchor="e")
        self.reg_tree.tag_configure("mudou", foreground=theme.ACCENT)
        self.reg_tree.tag_configure("zero", foreground=theme.DIM)
        self.reg_tree.pack(fill="x", padx=4)
        self.reg_tree.bind("<<TreeviewSelect>>", self.on_reg_select)

        self.flags_label = ttk.Label(parent, text="", font=theme.mono(10), padding=(8, 6))
        self.flags_label.pack(fill="x")

        ttk.Label(parent, text="Pilha e variáveis", style="Head.TLabel",
                  padding=(8, 2)).pack(fill="x")
        self.mem_tree = ttk.Treeview(parent, columns=("valor", "nota"), show="tree headings",
                                     height=10)
        self.mem_tree.heading("#0", text="onde")
        self.mem_tree.heading("valor", text="conteúdo")
        self.mem_tree.heading("nota", text="observação")
        self.mem_tree.column("#0", width=95)
        self.mem_tree.column("valor", width=180)
        self.mem_tree.column("nota", width=120)
        self.mem_tree.pack(fill="both", expand=True, padx=4, pady=(0, 6))

    def _build_docs(self, parent):
        busca = ttk.Frame(parent, padding=(6, 6))
        busca.pack(fill="x")
        self.doc_query = ttk.Entry(busca)
        self.doc_query.pack(fill="x")
        self.doc_query.bind("<KeyRelease>", lambda e: self.refresh_doc_list())
        self.doc_list = tk.Listbox(parent, bg=theme.BG, fg=theme.FG, height=6,
                                   font=theme.mono(10), borderwidth=0, highlightthickness=0,
                                   selectbackground=theme.SEL)
        self.doc_list.pack(fill="x", padx=6)
        self.doc_list.bind("<<ListboxSelect>>", self.on_doc_select)
        self.doc_text = tk.Text(parent, bg=theme.BG, fg=theme.FG, font=theme.ui(10),
                                borderwidth=0, highlightthickness=0, wrap="word", padx=8, pady=6)
        self.doc_text.pack(fill="both", expand=True, padx=6, pady=6)
        self.doc_text.tag_configure("titulo", foreground=theme.WHITE, font=theme.ui(12, "bold"))
        self.doc_text.tag_configure("sub", foreground=theme.ACCENT, font=theme.ui(10, "bold"))
        self.doc_text.tag_configure("code", foreground=theme.DATA, font=theme.mono(10))
        self.doc_text.tag_configure("dim", foreground=theme.DIM)
        self.doc_text.configure(state="disabled")
        self.refresh_doc_list()
        self.show_doc("mov")

    def _build_notes(self, parent):
        topo = ttk.Frame(parent, padding=(6, 6))
        topo.pack(fill="x")
        ttk.Label(topo, text="Anotações desta branch", style="Head.TLabel").pack(anchor="w")
        ttk.Label(topo, text="Ctrl+E anota a linha onde o cursor está. As anotações ficam "
                            "salvas no projeto e não entram no arquivo .asm.",
                  style="Dim.TLabel", wraplength=340, justify="left").pack(anchor="w", pady=(2, 0))
        self.note_tree = ttk.Treeview(parent, columns=("texto",), show="tree headings", height=14)
        self.note_tree.heading("#0", text="linha")
        self.note_tree.heading("texto", text="anotação")
        self.note_tree.column("#0", width=60)
        self.note_tree.column("texto", width=300)
        self.note_tree.pack(fill="both", expand=True, padx=6)
        self.note_tree.bind("<Double-1>", self.on_note_open)
        botoes = ttk.Frame(parent, padding=(6, 6))
        botoes.pack(fill="x")
        ttk.Button(botoes, text="Anotar linha atual", command=self.edit_note).pack(side="left")
        ttk.Button(botoes, text="Remover", command=self.delete_note).pack(side="left", padx=4)

    def _bind_keys(self):
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

    # ======================================================== análise =====
    def on_code_change(self):
        if self._suspend_change:
            return
        self.project.set_code(self.editor.get_code())
        self.analyze_now()

    def analyze_now(self):
        code = self.editor.get_code()
        try:
            self.analysis = analyze(code)
        except Exception as exc:                       # noqa: BLE001
            self.set_status("falha ao analisar: %s" % exc)
            return
        self.problems = validate(self.analysis)
        self.refresh_platform()
        self.refresh_structure()
        self.refresh_problems()
        self.refresh_scenarios()
        self.refresh_notes()
        self.sync_machine_with_code()
        self.set_status()

    def sync_machine_with_code(self):
        """O painel da máquina não pode mostrar o estado de um código que mudou."""
        if self.machine is None or self.machine.analysis is self.analysis:
            return
        if self.machine.steps == 0:
            self.reset_machine()
        else:
            self.editor.set_exec_line(None)
            self.exec_label.configure(
                text="o código mudou depois que a execução começou — reinicie (F10) para "
                     "rodar a versão nova",
                foreground=theme.ACCENT)

    def refresh_platform(self):
        p = self.analysis.platform
        nome = {"linux": "Linux", "windows": "Windows",
                "ambíguo": "Ambíguo", "indefinido": "Sem pistas de sistema"}[p.os]
        cor = {"linux": theme.ACCENT, "windows": theme.STACK}.get(p.os, theme.DIM)
        texto = "%s · %d bits" % (nome, p.bits)
        if p.confidence:
            texto += " · %d%%" % p.confidence
        self.platform_label.configure(text=texto, foreground=cor)
        pistas = p.evidence["linux"] + p.evidence["windows"]
        self.platform_detail = ("%s — %s. %s%s" % (
            nome, p.abi["name"], p.abi["notes"],
            ("  Pistas: " + "; ".join(pistas) + ".") if pistas else
            "  Nenhuma pista de sistema operacional: este código roda igual nos dois."))
        self.platform_label.bind("<Enter>", lambda e: self.set_status(self.platform_detail))
        self.platform_label.bind("<Button-1>", lambda e: self.set_status(self.platform_detail))

    def refresh_structure(self):
        self.tree.delete(*self.tree.get_children())
        a = self.analysis
        if not a:
            return
        self.tree.tag_configure("sec", foreground=theme.DATA)
        self.tree.tag_configure("fn", foreground=theme.CALL)
        self.tree.tag_configure("blk", foreground=theme.WHITE)
        self.tree.tag_configure("flow", foreground=theme.BRANCH)
        for tag, cor in theme.TAG_COLOR.items():
            self.tree.tag_configure("sem_" + tag, foreground=cor)

        dados = [l for l in a.program.lines if l.kind == "data"]
        if dados:
            no = self.tree.insert("", "end", text="dados", values=("variáveis declaradas",),
                                  open=True, tags=("sec",))
            for l in dados:
                info = ("reserva %s" % (l.args[0] if l.args else "?")) if l.reserve \
                    else "%s" % (l.directive or "")
                self.tree.insert(no, "end", text=(l.label or l.directive or "?"),
                                 values=(info,), tags=("linha:%d" % l.n, "sec"))

        func_atual, no_func = None, None
        for b in a.blocks:
            if b.func != func_atual or no_func is None:
                func_atual = b.func
                chamadores = callers_of(a, func_atual) if func_atual else []
                resumo = ("chamada por %s" % ", ".join(chamadores)) if chamadores else \
                    ("ponto de entrada" if func_atual in ("_start", "main", "start", "WinMain")
                     else "ninguém chama neste arquivo")
                no_func = self.tree.insert("", "end", text=func_atual or "código",
                                           values=(resumo,), open=True, tags=("fn",))
            entradas = ", ".join("%s (%s)" % (a.blocks[e.target].name, e.why) for e in b.pred) \
                or ("início" if b.id == 0 else "nada leva até aqui")
            saidas = ", ".join("%s (%s)" % (a.blocks[e.target].name, e.why) for e in b.succ)
            if b.exit:
                saidas = (saidas + ", " if saidas else "") + b.exit
            no_b = self.tree.insert(no_func, "end", text=b.name,
                                    values=("%d instr · L%d-%d"
                                            % (len(b.instrs), b.instrs[0].n, b.instrs[-1].n),),
                                    tags=("blk", "linha:%d" % b.instrs[0].n))
            self.tree.insert(no_b, "end", text="vem de", values=(entradas,), tags=("flow",))
            self.tree.insert(no_b, "end", text="vai para", values=(saidas or "nada",),
                             tags=("flow",))
            for ins in b.instrs:
                self.tree.insert(no_b, "end", text="%d: %s" % (ins.n, ins.text[:34]),
                                 values=(ins.sem.label,),
                                 tags=("linha:%d" % ins.n, "sem_" + ins.sem.tag))

    def refresh_problems(self):
        self.problem_tree.delete(*self.problem_tree.get_children())
        for p in self.problems:
            self.problem_tree.insert("", "end", values=(p.line, p.code, p.message),
                                     tags=(p.severity, "linha:%d" % p.line))
        self.editor.mark_error_lines([p.line for p in self.problems if p.severity == ERRO])
        idx = self.bottom.index(self.bottom.tabs()[0])
        self.bottom.tab(idx, text="Problemas (%d)" % len(self.problems))

    # ====================================================== interações ====
    def on_cursor(self, line, col):
        self.set_status(cursor=(line, col))
        if not self.analysis:
            return
        ins = next((i for i in self.analysis.instrs if i.n == line), None)
        if ins:
            self.show_doc(ins.mnemonic, ins)
            return
        linha = next((l for l in self.analysis.program.lines if l.n == line), None)
        if linha is not None and linha.kind in ("label", "data", "directive"):
            self.describe_line(linha)

    def describe_line(self, linha):
        """Explica rótulos, dados e diretivas no painel de documentação."""
        t = self.doc_text
        t.configure(state="normal")
        t.delete("1.0", "end")
        t.insert("end", "linha %d\n" % linha.n, "sub")
        t.insert("end", linha.text + "\n\n", "code")
        if linha.kind == "label":
            chamadores = callers_of(self.analysis, linha.label)
            t.insert("end", "Rótulo %s\n" % linha.label, "titulo")
            t.insert("end", "É um nome para este endereço. O que leva até aqui: %s.\n\n"
                     % (", ".join(chamadores) if chamadores else "nada neste arquivo"))
            if linha.local_label:
                t.insert("end", "Começa com ponto: é um rótulo local, pertence à função "
                                "anterior e pode repetir o nome em outras funções.\n", "dim")
        elif linha.kind == "data":
            if linha.reserve:
                t.insert("end", "Reserva de espaço\n", "titulo")
                t.insert("end", "%s reserva %s espaço(s) de %d byte(s) sem valor inicial. "
                                "Fica na seção .bss e nasce zerado.\n"
                         % (linha.label or "este rótulo", linha.args[0] if linha.args else "?",
                            linha.unit))
            elif linha.directive == "equ":
                t.insert("end", "Constante do montador\n", "titulo")
                t.insert("end", "Não ocupa memória: o valor é substituído no momento da "
                                "montagem.\n")
            else:
                t.insert("end", "Dado inicializado\n", "titulo")
                t.insert("end", "%s grava os valores direto no executável, %d byte(s) por item.\n"
                         % (linha.directive.upper(), linha.unit))
        else:
            t.insert("end", "Diretiva do montador\n", "titulo")
            t.insert("end", "Instrui a ferramenta de montagem; não vira instrução de CPU.\n")
        t.configure(state="disabled")

    def on_breakpoint(self, line, active):
        self.project.branch.breakpoints = sorted(self.editor.breakpoints)
        self.project.dirty = True
        self.set_status("breakpoint %s na linha %d" % ("ligado" if active else "desligado", line))

    def _tag_line(self, tags):
        for t in tags:
            if str(t).startswith("linha:"):
                return int(str(t).split(":")[1])
        return None

    def on_tree_select(self, event=None):
        sel = self.tree.selection()
        if not sel:
            return
        linha = self._tag_line(self.tree.item(sel[0], "tags"))
        if linha:
            self.editor.goto_line(linha)

    def on_problem_select(self, event=None):
        sel = self.problem_tree.selection()
        if not sel:
            return
        linha = self._tag_line(self.problem_tree.item(sel[0], "tags"))
        p = next((x for x in self.problems if x.line == linha), None)
        if p:
            self.problem_hint.configure(text="%s — %s" % (p.code, p.hint or p.message))

    def on_problem_open(self, event=None):
        sel = self.problem_tree.selection()
        if not sel:
            return
        linha = self._tag_line(self.problem_tree.item(sel[0], "tags"))
        if linha:
            self.editor.goto_line(linha)

    def on_reg_select(self, event=None):
        sel = self.reg_tree.selection()
        if sel and sel[0] in REG_DOC:
            self.set_status("%s — %s" % (sel[0].upper(), REG_DOC[sel[0]]))

    # ========================================================= branches ===
    def refresh_branches(self):
        nomes = list(self.project.branches)
        self.branch_box.configure(values=nomes)
        self.branch_var.set(self.project.active)

    def branch_new(self):
        nome = TextPromptDialog(self, "Nova branch", "Nome da nova branch",
                                hint="A branch copia o código atual. Serve para testar uma ideia "
                                     "sem mexer no original — por exemplo, trocar um valor por um "
                                     "número gigante e ver o que quebra.").show()
        if not nome:
            return
        try:
            self.project.set_code(self.editor.get_code())
            self.project.fork(nome.strip())
            self.project.switch(nome.strip())
        except (ValueError, KeyError) as exc:
            messagebox.showerror("Nova branch", str(exc), parent=self)
            return
        self.refresh_branches()
        self.load_branch_into_editor()
        self.set_status("branch %s criada a partir de %s"
                        % (nome.strip(), self.project.branch.parent))

    def branch_switch(self, nome):
        if nome == self.project.active:
            return
        self.project.set_code(self.editor.get_code())
        self.project.switch(nome)
        self.load_branch_into_editor()
        self.set_status("agora editando a branch %s" % nome)

    def branch_rename(self):
        novo = TextPromptDialog(self, "Renomear branch", "Novo nome",
                                value=self.project.active).show()
        if not novo:
            return
        try:
            self.project.rename_branch(self.project.active, novo.strip())
        except (ValueError, KeyError) as exc:
            messagebox.showerror("Renomear", str(exc), parent=self)
            return
        self.refresh_branches()

    def branch_delete(self):
        nome = self.project.active
        if not messagebox.askyesno("Excluir branch",
                                   "Excluir a branch %s? Isso não pode ser desfeito." % nome,
                                   parent=self):
            return
        try:
            self.project.delete_branch(nome)
        except ValueError as exc:
            messagebox.showerror("Excluir branch", str(exc), parent=self)
            return
        self.refresh_branches()
        self.load_branch_into_editor()

    def branch_diff(self):
        outras = [b for b in self.project.branches if b != self.project.active]
        if not outras:
            messagebox.showinfo("Comparar", "Só existe uma branch neste projeto.", parent=self)
            return
        escolha = TextPromptDialog(self, "Comparar branches",
                                   "Comparar %s com qual branch?" % self.project.active,
                                   value=outras[0],
                                   hint="disponíveis: " + ", ".join(outras)).show()
        if not escolha or escolha.strip() not in self.project.branches:
            return
        self.project.set_code(self.editor.get_code())
        diff = self.project.diff(self.project.active, escolha.strip())
        DiffDialog(self, "%s ↔ %s" % (self.project.active, escolha.strip()), diff)

    def load_branch_into_editor(self):
        self._suspend_change = True
        self.editor.set_code(self.project.code)
        self.editor.breakpoints = set(self.project.branch.breakpoints)
        self.editor.notes = dict(self.project.branch.notes)
        self._suspend_change = False
        self.editor.redraw_gutter()
        self.analyze_now()
        self.reset_machine()
        self.refresh_branches()

    # ========================================================== arquivo ===
    def new_project(self):
        if not self.confirm_discard():
            return
        self.project = Project.new(code="; novo programa\n\nsection .text\n    global _start\n\n_start:\n    \n")
        self.load_branch_into_editor()
        self.title("ASM X")

    def open_project(self):
        caminho = filedialog.askopenfilename(title="Abrir projeto", filetypes=PROJ_TYPES, parent=self)
        if not caminho:
            return
        try:
            self.project = Project.load(caminho)
        except Exception as exc:                       # noqa: BLE001
            messagebox.showerror("Abrir projeto", "Não consegui ler o arquivo:\n%s" % exc, parent=self)
            return
        self.load_branch_into_editor()
        self.title("ASM X — %s" % os.path.basename(caminho))

    def save_project(self):
        self.project.set_code(self.editor.get_code())
        self.project.branch.breakpoints = sorted(self.editor.breakpoints)
        if not self.project.path:
            return self.save_project_as()
        self.project.save()
        self.set_status("projeto salvo em %s" % self.project.path)
        return True

    def save_project_as(self):
        caminho = filedialog.asksaveasfilename(title="Salvar projeto", defaultextension=".asmproj",
                                               filetypes=PROJ_TYPES, parent=self)
        if not caminho:
            return False
        self.project.set_code(self.editor.get_code())
        self.project.save(caminho)
        self.title("ASM X — %s" % os.path.basename(caminho))
        self.set_status("projeto salvo em %s" % caminho)
        return True

    def import_asm(self):
        caminho = filedialog.askopenfilename(title="Importar .asm", filetypes=ASM_TYPES, parent=self)
        if not caminho:
            return
        if not self.confirm_discard():
            return
        self.project = Project.from_asm_file(caminho)
        self.load_branch_into_editor()
        self.title("ASM X — %s" % os.path.basename(caminho))

    def export_asm(self):
        caminho = filedialog.asksaveasfilename(title="Exportar branch", defaultextension=".asm",
                                               filetypes=ASM_TYPES, parent=self)
        if not caminho:
            return
        self.project.set_code(self.editor.get_code())
        self.project.export_asm(caminho)
        self.set_status("branch %s exportada para %s" % (self.project.active, caminho))

    def load_example(self, key):
        if not self.confirm_discard():
            return
        self.project = Project.new(code=EXAMPLES[key]["code"], name=key)
        self.load_branch_into_editor()
        self.title("ASM X — %s" % EXAMPLES[key]["title"])

    def confirm_discard(self):
        if not self.project.dirty:
            return True
        resposta = messagebox.askyesnocancel(
            "Alterações não salvas",
            "O projeto tem alterações não salvas. Quer salvar antes?", parent=self)
        if resposta is None:
            return False
        if resposta:
            return bool(self.save_project())
        return True

    def on_close(self):
        self.project.set_code(self.editor.get_code())
        if self.confirm_discard():
            self.destroy()

    # ======================================================== execução ====
    def reset_machine(self):
        if not self.analysis:
            return
        self.machine = Machine(self.analysis)
        self.last_regs = {}
        self.refresh_machine()
        self.set_status("máquina reiniciada")

    def _ensure_machine(self):
        if self.machine is None or self.machine.analysis is not self.analysis:
            self.reset_machine()
        return self.machine

    def step(self):
        m = self._ensure_machine()
        if m.halted:
            self.set_status("a execução já terminou — use Reiniciar (F10)")
            return
        self.last_regs = dict(m.regs)
        m.step()
        self.refresh_machine()

    def run(self):
        m = self._ensure_machine()
        if m.halted:
            self.reset_machine()
            m = self.machine
        self.last_regs = dict(m.regs)
        m.run(breakpoints=set(self.editor.breakpoints))
        self.refresh_machine()
        if m.halted:
            self.set_status("execução encerrada com código %s" % m.exit_code)
        else:
            self.set_status("parou no breakpoint da linha %s"
                            % (m.current.n if m.current else "?"))

    def run_to_cursor(self):
        m = self._ensure_machine()
        alvo = self.editor.cursor_line()
        indices = {i.idx for i in self.analysis.instrs if i.n == alvo}
        if not indices:
            self.set_status("não há instrução na linha %d" % alvo)
            return
        self.last_regs = dict(m.regs)
        m.run_until(indices)
        self.refresh_machine()

    def debug_function(self):
        if not self.analysis:
            return
        funcoes = sorted(self.analysis.label_at)
        if not funcoes:
            messagebox.showinfo("Depurar função", "Este código não tem rótulos.", parent=self)
            return
        escolha = TextPromptDialog(
            self, "Depurar função isolada", "Qual rótulo?",
            value=funcoes[0],
            hint="A execução começa nele com a pilha limpa. Defina os registradores de entrada "
                 "em um cenário de teste se a função depender de argumentos.\n\ndisponíveis: "
                 + ", ".join(funcoes[:20])).show()
        if not escolha or escolha.strip() not in self.analysis.label_at:
            return
        self.machine = Machine(self.analysis, entry=escolha.strip())
        self.last_regs = {}
        self.refresh_machine()
        self.right.select(0)
        self.set_status("depurando %s isoladamente — use Passo (F8)" % escolha.strip())

    def refresh_machine(self):
        m = self.machine
        if not m:
            return
        atual = m.current
        if m.halted:
            texto = "execução encerrada"
            if m.exit_code is not None:
                texto += " com código %d" % m.exit_code
            self.editor.set_exec_line(None)
        else:
            texto = "próxima: linha %d — %s" % (atual.n, atual.text) if atual else "sem instrução"
            self.editor.set_exec_line(atual.n if atual else None)
        texto += " · %d passos" % m.steps
        if m.issues:
            texto += "\n⚠ " + m.issues[-1]
        self.exec_label.configure(text=texto,
                                  foreground=theme.SEV_COLOR["erro"] if m.issues else theme.DIM)

        self.reg_tree.delete(*self.reg_tree.get_children())
        for r in REGS64:
            v = m.regs[r]
            tags = []
            if self.last_regs.get(r) is not None and self.last_regs.get(r) != v:
                tags.append("mudou")
            elif v == 0:
                tags.append("zero")
            dec = to_signed(v)
            legivel = "" if abs(dec) > 10 ** 12 else str(dec)   # endereços não ajudam em decimal
            self.reg_tree.insert("", "end", iid=r, text=r, values=(hexs(v), legivel),
                                 tags=tuple(tags))

        self.flags_label.configure(
            text="  ".join("%s=%d" % (f, m.flags[f]) for f in ("ZF", "SF", "CF", "OF", "PF", "DF")),
            foreground=theme.CMP)

        self.mem_tree.delete(*self.mem_tree.get_children())
        pilha = self.mem_tree.insert("", "end", text="pilha", values=("", "topo primeiro"), open=True)
        from ..emulator import RET_MAGIC, STACK_TOP
        endereco = m.regs["rsp"]
        for i in range(6):
            if endereco + i * 8 >= STACK_TOP:
                break
            addr = endereco + i * 8
            v = m.read_mem(addr, 8)
            nota = "RSP" if i == 0 else ("RBP" if addr == m.regs["rbp"] else "")
            if RET_MAGIC <= v < RET_MAGIC + 1000000:
                nota = (nota + " " if nota else "") + "endereço de retorno"
            self.mem_tree.insert(pilha, "end", text=hexs(addr), values=(hexs(v), nota))
        if m.regs["rsp"] >= STACK_TOP:
            self.mem_tree.insert(pilha, "end", text="—", values=("", "pilha vazia"))

        if m.symbols:
            dados = self.mem_tree.insert("", "end", text="variáveis", values=("", ""), open=True)
            for nome, s in m.symbols.items():
                if s.addr is None:
                    self.mem_tree.insert(dados, "end", text=nome,
                                         values=(str(s.equ), "constante do montador"))
                    continue
                n = min(s.size or 8, 12)
                brutos = " ".join("%02x" % m.rd8(s.addr + i) for i in range(n))
                texto = "".join(chr(b) if 32 <= b < 127 else "."
                                for b in (m.rd8(s.addr + i) for i in range(n)))
                self.mem_tree.insert(dados, "end", text=nome, values=(brutos, texto))

        self.output_text.configure(state="normal")
        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", m.output or "")
        self.output_text.configure(state="disabled")

        self.trace_tree.delete(*self.trace_tree.get_children())
        for passo in m.trace[-60:][::-1]:
            self.trace_tree.insert("", "end", values=(passo.line, passo.text, passo.note))

    # ======================================================== validação ===
    def validate_now(self):
        self.analyze_now()
        self.bottom.select(0)
        erros = [p for p in self.problems if p.severity == ERRO]
        if not self.problems:
            self.set_status("nenhum problema encontrado")
        else:
            self.set_status(summary(self.problems) +
                            (" — comece pelo primeiro erro da lista" if erros else ""))

    # ========================================================= cenários ===
    def refresh_scenarios(self):
        self.scenario_tree.delete(*self.scenario_tree.get_children())
        resultados = {r.scenario: r for r in self.results}
        for s in self.project.branch.scenarios:
            r = resultados.get(s.name)
            if r is None:
                resultado, tag = "não rodou", ()
            elif r.passed:
                resultado, tag = "passou", ("ok",)
            else:
                resultado, tag = "falhou", ("falhou",)
            regs = ", ".join("%s=%s" % (k, v) for k, v in (s.regs or {}).items())
            self.scenario_tree.insert("", "end", iid=s.name, text=s.name,
                                      values=(s.entry or "entrada do programa", regs, resultado),
                                      tags=tag)
        idx = self.bottom.index(self.bottom.tabs()[2])
        self.bottom.tab(idx, text="Testes (%d)" % len(self.project.branch.scenarios))

    def on_scenario_select(self, event=None):
        s = self._selected_scenario()
        if not s:
            return
        r = next((x for x in self.results if x.scenario == s.name), None)
        if r is None:
            self.scenario_detail.configure(
                text="%s — ainda não rodou. Começa em %s com %s."
                     % (s.name, s.entry or "o ponto de entrada",
                        ", ".join("%s=%s" % kv for kv in (s.regs or {}).items()) or "os registradores zerados"),
                foreground=theme.DIM)
            return
        partes = ["%s: %s" % ("passou" if r.passed else "FALHOU", r.reason),
                  "%d instruções executadas" % r.steps,
                  "código de saída: %s" % r.exit_code]
        if r.output:
            partes.append("saída: %r" % r.output)
        if r.issues:
            partes.append("problemas detectados: " + "; ".join(r.issues[:3]))
        self.scenario_detail.configure(
            text="   ·   ".join(partes),
            foreground=theme.CALL if r.passed else theme.SEV_COLOR["erro"])

    def _selected_scenario(self):
        sel = self.scenario_tree.selection()
        if not sel:
            return None
        return next((s for s in self.project.branch.scenarios if s.name == sel[0]), None)

    def scenario_new(self):
        labels = sorted(self.analysis.label_at) if self.analysis else []
        s = ScenarioDialog(self, labels).show()
        if s:
            self.project.add_scenario(s)
            self.refresh_scenarios()
            self.bottom.select(2)

    def scenario_edit(self):
        s = self._selected_scenario()
        if not s:
            self.set_status("selecione um cenário na lista")
            return
        labels = sorted(self.analysis.label_at) if self.analysis else []
        novo = ScenarioDialog(self, labels, s).show()
        if novo:
            if novo.name != s.name:
                self.project.remove_scenario(s.name)
            self.project.add_scenario(novo)
            self.refresh_scenarios()

    def scenario_delete(self):
        s = self._selected_scenario()
        if not s:
            return
        self.project.remove_scenario(s.name)
        self.results = [r for r in self.results if r.scenario != s.name]
        self.refresh_scenarios()

    def run_selected_scenario(self):
        s = self._selected_scenario()
        if not s:
            self.set_status("selecione um cenário na lista")
            return
        self.project.set_code(self.editor.get_code())
        r = run_scenario(self.project.code, s)
        self.results = [x for x in self.results if x.scenario != s.name] + [r]
        self.refresh_scenarios()
        self.set_status("%s: %s" % (s.name, "passou" if r.passed else r.reason))

    def run_all_scenarios(self):
        cenarios = self.project.branch.scenarios
        if not cenarios:
            self.bottom.select(2)
            self.set_status("nenhum cenário nesta branch — crie um em Testes › Novo cenário")
            return
        self.project.set_code(self.editor.get_code())
        self.results = run_all_scenarios(self.project.code, cenarios)
        self.refresh_scenarios()
        self.bottom.select(2)
        passou = sum(1 for r in self.results if r.passed)
        self.set_status("%d de %d cenários passaram" % (passou, len(self.results)))

    # ======================================================== anotações ===
    def refresh_notes(self):
        self.note_tree.delete(*self.note_tree.get_children())
        for linha in sorted(self.project.branch.notes, key=lambda x: int(x)):
            self.note_tree.insert("", "end", iid=linha, text=linha,
                                  values=(self.project.branch.notes[linha],))
        self.editor.notes = dict(self.project.branch.notes)
        self.editor.redraw_gutter()

    def edit_note(self):
        linha = self.editor.cursor_line()
        atual = self.project.note(linha)
        texto = TextPromptDialog(self, "Anotação da linha %d" % linha,
                                 "O que você quer lembrar sobre esta linha?",
                                 value=atual, multiline=True,
                                 hint="Fica guardado no projeto, separado do código.").show()
        if texto is None:
            return
        self.project.set_note(linha, texto)
        self.refresh_notes()
        self.set_status("anotação %s na linha %d" % ("salva" if texto.strip() else "removida", linha))

    def on_note_open(self, event=None):
        sel = self.note_tree.selection()
        if sel:
            self.editor.goto_line(int(sel[0]))

    def delete_note(self):
        sel = self.note_tree.selection()
        if not sel:
            return
        self.project.set_note(int(sel[0]), "")
        self.refresh_notes()

    # ===================================================== documentação ===
    def refresh_doc_list(self):
        termo = self.doc_query.get().strip().lower()
        self.doc_list.delete(0, "end")
        nomes = [k for k in sorted(ISA) if k.startswith(termo)] if termo else sorted(ISA)
        for n in nomes[:60]:
            self.doc_list.insert("end", n)

    def on_doc_select(self, event=None):
        sel = self.doc_list.curselection()
        if sel:
            self.show_doc(self.doc_list.get(sel[0]))

    def show_doc(self, mnemonic, ins=None):
        info = ISA.get((mnemonic or "").lower())
        t = self.doc_text
        t.configure(state="normal")
        t.delete("1.0", "end")
        if ins is not None:
            t.insert("end", "linha %d\n" % ins.n, "sub")
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
            t.insert("end", "Sem documentação para %s.\n" % mnemonic, "dim")
        else:
            cat = CATEGORIES.get(info["cat"], {"label": info["cat"]})
            t.insert("end", (mnemonic or "").upper() + "\n", "titulo")
            t.insert("end", "%s · %s\n\n" % (info["name"], cat["label"]), "dim")
            t.insert("end", "Sintaxe\n", "sub")
            t.insert("end", info["syntax"] + "\n\n", "code")
            t.insert("end", "O que faz\n", "sub")
            t.insert("end", info["desc"] + "\n\n")
            t.insert("end", "Exemplo\n", "sub")
            t.insert("end", "\n".join(info["ex"]) + "\n\n", "code")
            t.insert("end", "Flags\n", "sub")
            t.insert("end", info["flags"] + "\n")
            if info.get("note"):
                t.insert("end", "\n" + info["note"] + "\n", "dim")
            t.insert("end", "\nFlags do processador\n", "sub")
            for f, d in FLAG_DOC.items():
                t.insert("end", "%s " % f, "code")
                t.insert("end", d + "\n", "dim")
        t.configure(state="disabled")

    # ============================================================ outros ==
    def editor_toggle_comment(self):
        self.editor.toggle_comment()

    def find(self):
        termo = TextPromptDialog(self, "Procurar", "Procurar por").show()
        if termo:
            if not self.editor.find(termo):
                self.set_status("não encontrei %r" % termo)

    def goto_line(self):
        valor = TextPromptDialog(self, "Ir para a linha", "Número da linha").show()
        if valor and valor.strip().isdigit():
            self.editor.goto_line(int(valor.strip()))

    def show_about(self):
        AboutDialog(self, __version__).show()

    def set_status(self, mensagem=None, cursor=None):
        partes = []
        if cursor:
            partes.append("Ln %d, Col %d" % cursor)
        else:
            partes.append("Ln %d, Col %d" % (self.editor.cursor_line(), self.editor.cursor_col()))
        partes.append("branch: %s" % self.project.active)
        if self.analysis:
            s = self.analysis.stats
            partes.append("%d instruções em %d blocos" % (s["instructions"], s["blocks"]))
        if self.problems:
            partes.append(summary(self.problems))
        if self.project.dirty:
            partes.append("não salvo")
        if mensagem:
            partes.append(mensagem)
        self.status.configure(text="   ·   ".join(partes))


def main():
    app = AsmXApp()
    app.mainloop()
