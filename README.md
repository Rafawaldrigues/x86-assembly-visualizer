# ASM X

Ambiente de desktop para estudar, validar, testar e depurar assembly x86-64.
Python + Tkinter, sem servidor, sem dependência externa.

```bash
python3 asmx.py          # Linux/macOS/Windows (precisa de python3-tk no Linux)
```

## O que ele faz

- **Lê o código e explica**: cada instrução ganha uma etiqueta ("Escreve na
  memória", "Desvia se for igual", "Chamada de sistema") e uma frase em
  português dizendo o efeito. Rótulos, dados e diretivas também.
- **Mapa de fluxo**: funções e blocos básicos com "vem de" e "vai para",
  incluindo o motivo de cada desvio.
- **Detecta a plataforma**: Linux ou Windows, com as pistas que levaram à
  conclusão e a ABI correspondente.
- **Valida** com 30 regras: string com acento, string sem terminador, `div` sem
  zerar RDX, `push` sem `pop`, `mov al, 300`, laço infinito, shadow space do
  Windows, rótulo inexistente, escrita em `.rodata` e por aí.
- **Executa passo a passo**: registradores, flags, pilha e memória à vista,
  breakpoints na calha, histórico do que cada instrução fez.
- **Branches**: variações do mesmo programa dentro de um projeto, com diff.
- **Cenários de teste**: estado inicial + expectativa, rodando uma função
  isolada ou o programa inteiro — é assim que se responde "o que acontece se
  esse número for gigante?".
- **Anotações por linha**, guardadas no projeto e fora do `.asm`.
- **Documentação** de 148 mnemônicos, 43 syscalls do Linux e as principais
  funções do kernel32/user32, em português.

## Estrutura

```
asmx.py               abre a interface
asmx/
  isa.py              base de instruções, registradores, flags, syscalls
  parser.py           NASM/Intel, MASM e GAS/AT&T
  analyzer.py         plataforma, semântica, blocos e fluxo
  emulator.py         máquina virtual + detecção de problemas em execução
  linter.py           validação estática (30 regras)
  workspace.py        projeto, branches, anotações, cenários
  examples.py         8 programas de exemplo
  ui/                 interface Tkinter (editor, diálogos, tema)
  data/isa.json       o acervo de documentação
docs/GUIA.md          manual de uso
docs/REFERENCIA.md    referência dos 148 mnemônicos
tests/                141 testes
```

## Testes

```bash
python3 -m unittest discover -s tests          # núcleo
xvfb-run -a python3 -m unittest discover -s tests   # inclui a GUI sem tela
```

Os testes de interface são pulados automaticamente quando não há display.

## Onde ele não vai

Não monta, não liga e não executa binário de verdade. A máquina virtual cobre o
essencial de inteiros; SSE, macros do NASM e a maior parte das syscalls ficam
de fora da simulação (a documentação continua lá). Passar aqui não substitui
`nasm` + `ld` + `gdb` — serve para entender o código e achar defeito antes.

Detalhes e limites completos em `docs/GUIA.md`.
