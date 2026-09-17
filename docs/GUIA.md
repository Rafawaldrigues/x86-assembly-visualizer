# Guia do ASM X

Ferramenta de desktop para ler, validar, testar e depurar assembly x86-64.
Escrita em Python com Tkinter — a mesma base gráfica do IDLE.

## Rodando

```bash
python3 asmx.py
```

Único requisito além do Python 3.8+: o Tkinter.

| Sistema | Como instalar |
|---|---|
| Debian/Ubuntu | `sudo apt install python3-tk` |
| Fedora | `sudo dnf install python3-tkinter` |
| Arch | `sudo pacman -S tk` |
| Windows/macOS | já vem com o instalador oficial do Python |

Nada é baixado, nada sai da máquina, não existe servidor.

## A tela

```
┌──────────────────────────────────────────────────────────────────────────┐
│ menu · branch atual · Validar · Passo · Rodar · Reiniciar · plataforma    │
├───────────────┬────────────────────────────────────┬─────────────────────┤
│ Estrutura     │ editor com números, breakpoints    │ Máquina             │
│ do código     │ e realce                           │ Docs                │
│               ├────────────────────────────────────┤ Notas               │
│ dados         │ Problemas · Saída · Testes ·       │                     │
│ funções       │ Histórico da execução              │                     │
│ blocos        │                                    │                     │
├───────────────┴────────────────────────────────────┴─────────────────────┤
│ Ln, Col · branch · contagem · resumo dos problemas · última ação         │
└──────────────────────────────────────────────────────────────────────────┘
```

**Estrutura do código** mostra dados, funções e blocos básicos. Cada bloco traz
"vem de" e "vai para" em português, com o motivo do desvio. Clique duas vezes
para pular até a linha.

**Editor**: realce de sintaxe, número de linha, ponto vermelho de breakpoint
(clique na calha), fundo verde na linha que vai executar, fundo vermelho nas
linhas com erro, ✎ nas linhas anotadas.

**Máquina**: os 16 registradores (o que mudou no último passo fica dourado),
flags, topo da pilha com marcação de endereço de retorno, e o conteúdo de cada
variável em bytes e em texto.

**Docs**: ao mover o cursor, mostra o que aquela linha faz — instrução, rótulo,
diretiva ou dado — junto com a ficha do mnemônico e a explicação dos
registradores envolvidos. Há busca por prefixo entre os 148 mnemônicos.

## Atalhos

| Tecla | O que faz |
|---|---|
| F5 | validar o código |
| F7 | rodar até a linha do cursor |
| F8 | executar um passo |
| F9 | rodar até o fim ou até o próximo breakpoint |
| F10 | reiniciar a máquina |
| F11 | rodar todos os cenários de teste |
| Ctrl+/ | comentar ou descomentar a seleção |
| Ctrl+E | anotar a linha atual |
| Ctrl+B | nova branch |
| Ctrl+S / Ctrl+O / Ctrl+N | salvar / abrir / novo projeto |
| Ctrl+F / Ctrl+G | procurar / ir para a linha |

## Projeto, branches e anotações

Tudo vive em um arquivo `.asmproj` (JSON legível). Dentro dele:

- **branches**: variações do mesmo programa. `Ctrl+B` copia o código atual para
  uma branch nova, com as anotações e os cenários juntos. Trocar de branch pela
  caixa na barra de cima. *Branch › Comparar* mostra o diff colorido.
- **anotações**: comentários que não sujam o `.asm`. `Ctrl+E` na linha, e ela
  ganha um ✎ na calha. Ficam listadas na aba Notas.
- **breakpoints**: gravados junto com a branch.
- **cenários de teste**: descritos abaixo.

Para levar o código para o NASM, use *Arquivo › Exportar branch como .asm*.

## Cenários de teste

Um cenário é um estado inicial mais uma expectativa:

| Campo | Para que serve |
|---|---|
| Começar em | rótulo onde a execução começa. Vazio = o programa todo. Escolher uma função executa **só ela**, com a pilha limpa |
| Registradores iniciais | `rdi=1000000, rsi=0x20` — é assim que se passa argumento para a função em teste |
| Entrada simulada | o que a syscall `read` vai devolver |
| Saída esperada | compara com o que o programa escreveu |
| Código de saída esperado | compara com o valor passado ao `exit` |
| Passa se acusar problema | inverte a lógica: o teste passa quando a execução detecta estouro, laço infinito, divisão por zero… |
| Limite de instruções | trava de segurança contra laço infinito |

O fluxo típico do "e se o número for muito alto":

1. `Ctrl+B` → branch `valor-alto`.
2. Aba **Testes** › **Novo** → começa em `soma_ate`, `rdi=0xFFFFFFFFFFFFFFFF`,
   limite 3000, marcar *passa se acusar problema*.
3. **Rodar todos** (F11). O detalhe embaixo mostra em que linha a soma estourou
   64 bits e quantas instruções rodaram até lá.
4. A branch `principal` continua intacta.

## O validador

F5 roda 30 regras sobre o código. Cada achado tem código, linha, explicação e
uma dica de correção (clique no item para ler a dica na barra abaixo da lista).

### Strings

| Código | O que pega |
|---|---|
| STR001 | caractere fora do ASCII na string (acento vira 2+ bytes; `$ - msg` não bate com o número de letras) |
| STR002 | aspas não fechadas |
| STR003 | string sem `0` no fim entregue a `printf`, `MessageBox` e parecidos |
| STR004 | caractere de controle literal dentro da string |
| STR005 | barra invertida que talvez não seja escape nessa sintaxe |
| STR006 | string sem terminador e sem `equ $ - rótulo`: ninguém sabe onde ela acaba |

### Aritmética e operandos

| Código | O que pega |
|---|---|
| DIV001 | `div`/`idiv` sem `xor rdx, rdx` ou `cqo` antes |
| DIV002 | divisão por zero literal |
| DIV003 | `div` com operando imediato (não existe) |
| IMM001 | o valor não cabe no destino — `mov al, 300` |
| IMM002 | imediato de 64 bits fora do `mov` |
| SHF001 | deslocamento maior que o tamanho do operando |
| MEM001 | `mov [x], 1` sem `byte`/`qword`: tamanho ambíguo |
| MEM002 | memória dos dois lados |
| UNK001 | mnemônico que a ferramenta não conhece |

### Pilha, funções e ABI

| Código | O que pega |
|---|---|
| STK001 | `push` sem `pop` antes do `ret` |
| STK002 | `pop` a mais: a função come a pilha de quem chamou |
| STK003 | função chamada com `call` que não tem `ret` |
| ABI001 | chamada no Windows sem os 32 bytes de shadow space |
| ABI002 | registrador callee-saved alterado sem salvar |
| REG001 | registrador lido antes de receber qualquer valor |

### Símbolos, fluxo e sistema

| Código | O que pega |
|---|---|
| SYM001 | `jmp`/`call` para rótulo inexistente |
| SYM002 | rótulo nunca usado |
| SYM003 | símbolo usado em operando de memória e nunca definido |
| ENT001 / ENT002 | sem ponto de entrada / `_start` sem `global` |
| EXIT001 | programa sem saída explícita |
| FLOW001 | bloco que nada alcança |
| FLOW002 | laço que não altera nada: infinito |
| SYS001 | `syscall` sem definir RAX no bloco |
| SYS002 | RCX ou R11 lidos depois do `syscall` (são destruídos) |
| SEC001 / SEC002 | código fora de `.text` / escrita em `.rodata` |

## Depurar uma função sozinha

*Executar › Depurar função isolada* começa a execução no rótulo escolhido com a
pilha limpa. O `ret` dela encerra a simulação em vez de acusar erro de pilha.
Combine com um cenário para preparar os registradores de entrada.

## Limites honestos

A máquina virtual é didática, não um emulador de CPU:

- não monta nem liga nada; não gera `.o` nem executável;
- executa o essencial de inteiros: SSE/ponto flutuante aparece na documentação
  mas não é simulado;
- macros do NASM (`%macro`, `%define`) e `struc` são lidos como diretivas, sem
  expansão;
- syscalls do Linux emuladas: `write`, `read`, `exit`, `exit_group`, `getpid`,
  `time`, `brk`, `getrandom`, `nanosleep`. As demais devolvem 0 e avisam;
- API do Windows: `ExitProcess`, `GetStdHandle`, `WriteConsoleA`, `WriteFile`,
  `MessageBoxA/W`, `Sleep`, `GetLastError`. As demais viram stub;
- memória é um dicionário de bytes: não há paginação, proteção real nem
  segmentação — o validador avisa sobre `.rodata`, a execução não;
- o resultado de uma execução aqui **não** garante que o binário real funcione.
  Serve para entender e para achar defeito cedo.
