"""Exemplos prontos para abrir na ferramenta.

São oito programas curtos, cada um mostrando uma ideia: o "olá mundo" com
syscall, laço com contador, função com pilha e argumentos, console do Windows
pela kernel32, saída típica do ``gcc -S`` em AT&T, ordenação bolha, um programa
com defeitos de propósito (para ver o validador trabalhando) e um somatório que
estoura com valor alto (para testar limite).

A chave é o nome curto usado na linha de comando (``asmx examples --show
linux-hello``) e cada entrada tem ``title`` (rótulo legível) e ``code`` (o
fonte). Os mesmos textos estão gravados em ``examples/*.asm`` por
``python -m asmx examples --dump examples``.

Example:
    >>> from asmx.examples import EXAMPLES, names
    >>> names()[0]
    'bubble'
    >>> "global _start" in EXAMPLES["linux-hello"]["code"]
    True
"""

from __future__ import annotations

from typing import Dict, List

#: Exemplos disponíveis: nome curto -> ``{"title": ..., "code": ...}``.
EXAMPLES: Dict[str, Dict[str, str]] = {
    "linux-hello": {
        "title": "Linux — olá mundo com syscall",
        "code": "; Olá mundo em NASM para Linux x86-64\n; montar:  nasm -f elf64 hello.asm && ld hello.o -o hello\n\nsection .data\n    msg     db  \"Ola, mundo!\", 10      ; 10 = '\\n'\n    msg_len equ $ - msg                ; tamanho calculado pelo montador\n\nsection .text\n    global _start\n\n_start:\n    mov rax, 1              ; syscall write\n    mov rdi, 1              ; descritor 1 = stdout\n    mov rsi, msg            ; endereco da string\n    mov rdx, msg_len        ; quantos bytes\n    syscall                 ; entrega ao kernel\n\n    mov rax, 60             ; syscall exit\n    xor rdi, rdi            ; codigo de saida 0\n    syscall",  # noqa: E501
    },
    "linux-loop": {
        "title": "Linux — laço, contador e desvio condicional",
        "code": '; Imprime cinco vezes a mesma linha, usando um contador em R12.\nsection .data\n    linha   db  "iteracao do laco", 10\n    tam     equ $ - linha\n\nsection .text\n    global _start\n\n_start:\n    mov r12, 5                  ; contador do laco\n\n.loop:\n    cmp r12, 0                  ; ainda sobra iteracao?\n    je  .fim                    ; se chegou a zero, sai\n\n    mov rax, 1\n    mov rdi, 1\n    mov rsi, linha\n    mov rdx, tam\n    syscall\n\n    dec r12                     ; contador = contador - 1\n    jmp .loop                   ; volta para o topo\n\n.fim:\n    mov rax, 60\n    mov rdi, 0\n    syscall',  # noqa: E501
    },
    "linux-funcao": {
        "title": "Linux — função com pilha, argumentos e retorno",
        "code": '; soma(a, b) chamada a partir de _start, no estilo System V.\nsection .bss\n    buffer  resb 32\n\nsection .data\n    prefixo db  "resultado: "\n    plen    equ $ - prefixo\n    nl      db  10\n\nsection .text\n    global _start\n\nsoma:\n    push rbp                 ; prologo: salva o quadro anterior\n    mov  rbp, rsp            ; RBP ancora este quadro\n    mov  rax, rdi            ; 1o argumento\n    add  rax, rsi            ; soma o 2o argumento\n    pop  rbp                 ; epilogo\n    ret                      ; devolve o valor em RAX\n\n; converte RAX em texto decimal dentro de buffer, devolve tamanho em RAX\nitoa:\n    push rbp\n    mov  rbp, rsp\n    lea  rdi, [buffer + 31]\n    mov  rcx, 0\n    mov  rbx, 10\n.digito:\n    xor  rdx, rdx\n    div  rbx                 ; RAX = RAX / 10, RDX = resto\n    add  rdx, 48             ; resto vira caractere ASCII\n    dec  rdi\n    mov  [rdi], dl\n    inc  rcx\n    test rax, rax\n    jnz  .digito\n    mov  rsi, rdi\n    mov  rax, rcx\n    pop  rbp\n    ret\n\n_start:\n    mov  rdi, 17             ; 1o argumento de soma\n    mov  rsi, 25             ; 2o argumento de soma\n    call soma                ; RAX = 42\n\n    call itoa                ; RSI = texto, RAX = tamanho\n\n    mov  rdx, rax\n    mov  rax, 1\n    mov  rdi, 1\n    syscall                  ; escreve o numero\n\n    mov  rax, 1\n    mov  rdi, 1\n    mov  rsi, nl\n    mov  rdx, 1\n    syscall                  ; quebra de linha\n\n    mov  rax, 60\n    xor  rdi, rdi\n    syscall',  # noqa: E501
    },
    "windows-hello": {
        "title": "Windows — console pela API do kernel32",
        "code": '; Ola mundo no Windows x64 (NASM + link com kernel32.lib)\n; A ABI da Microsoft passa argumentos em RCX, RDX, R8, R9\n; e exige 32 bytes de shadow space na pilha.\n\nextern GetStdHandle\nextern WriteConsoleA\nextern ExitProcess\n\nsection .data\n    msg     db  "Ola do Windows!", 13, 10\n    msg_len equ $ - msg\n\nsection .bss\n    escritos resq 1\n\nsection .text\n    global main\n\nmain:\n    sub  rsp, 40             ; 32 de shadow space + alinhamento\n\n    mov  rcx, -11            ; STD_OUTPUT_HANDLE\n    call GetStdHandle\n    mov  rbx, rax            ; guarda o handle\n\n    mov  rcx, rbx            ; handle\n    mov  rdx, msg            ; buffer\n    mov  r8,  msg_len        ; bytes a escrever\n    mov  r9,  escritos       ; onde guardar quantos sairam\n    call WriteConsoleA\n\n    xor  rcx, rcx            ; codigo de saida 0\n    call ExitProcess',  # noqa: E501
    },
    "gcc-att": {
        "title": "Sintaxe AT&T (saída típica do gcc -S)",
        "code": "\t.globl\tmain\n\t.type\tmain, @function\nmain:\n\tpushq\t%rbp\n\tmovq\t%rsp, %rbp\n\tsubq\t$16, %rsp\n\tmovl\t$0, -4(%rbp)\n\tmovl\t$10, -8(%rbp)\n\tmovl\t-8(%rbp), %eax\n\taddl\t%eax, -4(%rbp)\n\tmovl\t-4(%rbp), %eax\n\tleave\n\tret",  # noqa: E501
    },
    "bubble": {
        "title": "Ordenação bolha sobre um vetor na memória",
        "code": "; Ordena 8 bytes em ordem crescente e imprime o vetor.\nsection .data\n    vetor   db  9, 3, 7, 1, 8, 2, 5, 4\n    n       equ 8\n    nl      db  10\n\nsection .text\n    global _start\n\n_start:\n    mov  rcx, n\n    dec  rcx                 ; passes = n - 1\n\n.passe:\n    push rcx\n    mov  rsi, 0              ; indice interno\n\n.interno:\n    mov  al, [vetor + rsi]\n    mov  bl, [vetor + rsi + 1]\n    cmp  al, bl\n    jbe  .segue              ; ja esta em ordem\n    mov  [vetor + rsi], bl   ; troca os dois\n    mov  [vetor + rsi + 1], al\n\n.segue:\n    inc  rsi\n    cmp  rsi, rcx\n    jb   .interno\n\n    pop  rcx\n    dec  rcx\n    jnz  .passe\n\n    ; imprime os 8 bytes como numeros ASCII\n    mov  r12, 0\n.mostra:\n    mov  al, [vetor + r12]\n    add  al, 48\n    mov  [vetor + r12], al\n    inc  r12\n    cmp  r12, n\n    jb   .mostra\n\n    mov  rax, 1\n    mov  rdi, 1\n    mov  rsi, vetor\n    mov  rdx, n\n    syscall\n\n    mov  rax, 1\n    mov  rdi, 1\n    mov  rsi, nl\n    mov  rdx, 1\n    syscall\n\n    mov  rax, 60\n    xor  rdi, rdi\n    syscall",  # noqa: E501
    },
    "quebrado": {
        "title": "Código com defeitos (para ver o validador)",
        "code": '; Este exemplo é proposital: cada bloco tem um erro clássico.\nsection .data\n    msg     db  "Ação inválida", 10     ; acento = mais bytes do que letras\n    tam     equ $ - msg\n    nome    db  "rafael"                ; falta o terminador 0\n\nsection .text\n    global _start\n\ndivide:\n    push rbx\n    mov  rax, 100\n    mov  rbx, 7\n    div  rbx                 ; RDX não foi zerado\n    ret                      ; e o RBX empilhado nunca volta\n\n_start:\n    mov  al, 300             ; 300 não cabe em 8 bits\n    mov  [contador], 1       ; tamanho ambíguo e símbolo inexistente\n    call divide\n    jmp  .parado\n\n.parado:\n    jmp  .parado             ; laço infinito sem nada que mude\n',  # noqa: E501
    },
    "escala": {
        "title": "Somatório com risco de estouro (para testar valores altos)",
        "code": "; Soma os N primeiros inteiros em RAX. Bom para testar limites:\n; com N pequeno funciona; com N gigante o resultado estoura 64 bits.\nsection .text\n    global _start\n\nsoma_ate:                    ; entrada: RDI = N, saída: RAX = soma\n    xor  rax, rax\n    mov  rcx, rdi\n.laco:\n    test rcx, rcx\n    jz   .fim\n    add  rax, rcx\n    dec  rcx\n    jmp  .laco\n.fim:\n    ret\n\n_start:\n    mov  rdi, 10\n    call soma_ate            ; RAX = 55\n    mov  rdi, rax\n    mov  rax, 60\n    syscall\n",  # noqa: E501
    },
}


def names() -> List[str]:
    """Lista os nomes curtos dos exemplos, em ordem alfabética.

    Returns:
        Lista de chaves de :data:`EXAMPLES`.

    Example:
        >>> names()[:2]
        ['bubble', 'escala']
    """
    return sorted(EXAMPLES)


def title_of(name: str) -> str:
    """Devolve o título legível de um exemplo.

    Args:
        name: Nome curto do exemplo.

    Returns:
        O título; string vazia quando o nome não existe.
    """
    exemplo = EXAMPLES.get(name)
    return exemplo["title"] if exemplo else ""


def render(name: str) -> str:
    """Devolve o texto exato de um exemplo para gravar em disco.

    É o mesmo conteúdo de :data:`EXAMPLES`, apenas com uma única quebra de
    linha no fim. A linha de comando (``examples --dump``) e o utilitário
    ``tools/export_examples.py`` usam esta função, então o arquivo gravado e o
    exemplo embutido nunca divergem.

    Args:
        name: Nome curto do exemplo.

    Returns:
        O código pronto para gravar; string vazia quando o nome não existe.
    """
    exemplo = EXAMPLES.get(name)
    if not exemplo:
        return ""
    return exemplo["code"].rstrip("\n") + "\n"


def count_lines(name: str) -> int:
    """Conta as linhas do código de um exemplo.

    Args:
        name: Nome curto do exemplo.

    Returns:
        Quantidade de linhas (mínimo 1); ``0`` quando o nome não existe.
    """
    exemplo = EXAMPLES.get(name)
    if not exemplo:
        return 0
    return exemplo["code"].count("\n") + 1
