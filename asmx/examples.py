"""Ready-made examples to open in the tool.

They are nine short programs, each one showing an idea: the "hello world" with
syscall, a loop with a counter, a function with stack and arguments, the Windows
console through kernel32, the typical output of ``gcc -S`` in AT&T, a bubble
sort, a program with defects on purpose (to watch the validator working) and a
sum that overflows with a high value (to test limits).

The key is the short name used on the command line (``asmx examples --show
linux-hello``) and every entry has ``title`` (readable label) and ``code`` (the
source). The same texts are written to ``examples/*.asm`` by
``python -m asmx examples --dump examples``.

Example:
    >>> from asmx.examples import EXAMPLES, names
    >>> names()[0]
    'broken'
    >>> "global _start" in EXAMPLES["linux-hello"]["code"]
    True
"""

from __future__ import annotations

from typing import Dict, List

#: Available examples: short name -> ``{"title": ..., "code": ...}``.
EXAMPLES: Dict[str, Dict[str, str]] = {
    "linux-hello": {
        "title": "Linux — hello world with syscall",
        "code": "; Hello world in NASM for Linux x86-64\n; build:  nasm -f elf64 hello.asm && ld hello.o -o hello\n\nsection .data\n    msg     db  \"Hello, world!\", 10     ; 10 = '\\n'\n    msg_len equ $ - msg                ; size computed by the assembler\n\nsection .text\n    global _start\n\n_start:\n    mov rax, 1              ; syscall write\n    mov rdi, 1              ; descriptor 1 = stdout\n    mov rsi, msg            ; address of the string\n    mov rdx, msg_len        ; how many bytes\n    syscall                 ; hands it to the kernel\n\n    mov rax, 60             ; syscall exit\n    xor rdi, rdi            ; exit code 0\n    syscall",  # noqa: E501
    },
    "linux-loop": {
        "title": "Linux — loop, counter and conditional jump",
        "code": '; Prints the same line five times, using a counter in R12.\nsection .data\n    line    db  "loop iteration", 10\n    size    equ $ - line\n\nsection .text\n    global _start\n\n_start:\n    mov r12, 5                  ; loop counter\n\n.loop:\n    cmp r12, 0                  ; is there an iteration left?\n    je  .done                   ; if it reached zero, leave\n\n    mov rax, 1\n    mov rdi, 1\n    mov rsi, line\n    mov rdx, size\n    syscall\n\n    dec r12                     ; counter = counter - 1\n    jmp .loop                   ; back to the top\n\n.done:\n    mov rax, 60\n    mov rdi, 0\n    syscall',  # noqa: E501
    },
    "linux-function": {
        "title": "Linux — function with stack, arguments and return",
        "code": '; add_pair(a, b) called from _start, in the System V style.\nsection .bss\n    buffer  resb 32\n\nsection .data\n    prefix  db  "result: "\n    plen    equ $ - prefix\n    nl      db  10\n\nsection .text\n    global _start\n\nadd_pair:\n    push rbp                 ; prologue: saves the previous frame\n    mov  rbp, rsp            ; RBP anchors this frame\n    mov  rax, rdi            ; 1st argument\n    add  rax, rsi            ; adds the 2nd argument\n    pop  rbp                 ; epilogue\n    ret                      ; returns the value in RAX\n\n; converts RAX into decimal text inside buffer, returns the size in RAX\nitoa:\n    push rbp\n    mov  rbp, rsp\n    lea  rdi, [buffer + 31]\n    mov  rcx, 0\n    mov  rbx, 10\n.digit:\n    xor  rdx, rdx\n    div  rbx                 ; RAX = RAX / 10, RDX = remainder\n    add  rdx, 48             ; remainder becomes an ASCII character\n    dec  rdi\n    mov  [rdi], dl\n    inc  rcx\n    test rax, rax\n    jnz  .digit\n    mov  rsi, rdi\n    mov  rax, rcx\n    pop  rbp\n    ret\n\n_start:\n    mov  rdi, 17             ; 1st argument of add_pair\n    mov  rsi, 25             ; 2nd argument of add_pair\n    call add_pair            ; RAX = 42\n\n    call itoa                ; RSI = text, RAX = size\n\n    mov  rdx, rax\n    mov  rax, 1\n    mov  rdi, 1\n    syscall                  ; writes the number\n\n    mov  rax, 1\n    mov  rdi, 1\n    mov  rsi, nl\n    mov  rdx, 1\n    syscall                  ; line break\n\n    mov  rax, 60\n    xor  rdi, rdi\n    syscall',  # noqa: E501
    },
    "windows-hello": {
        "title": "Windows — console through the kernel32 API",
        "code": '; Hello world on Windows x64 (NASM + link with kernel32.lib)\n; The Microsoft ABI passes arguments in RCX, RDX, R8, R9\n; and requires 32 bytes of shadow space on the stack.\n\nextern GetStdHandle\nextern WriteConsoleA\nextern ExitProcess\n\nsection .data\n    msg     db  "Hello from Windows!", 13, 10\n    msg_len equ $ - msg\n\nsection .bss\n    written resq 1\n\nsection .text\n    global main\n\nmain:\n    sub  rsp, 40             ; 32 of shadow space + alignment\n\n    mov  rcx, -11            ; STD_OUTPUT_HANDLE\n    call GetStdHandle\n    mov  rbx, rax            ; keeps the handle\n\n    mov  rcx, rbx            ; handle\n    mov  rdx, msg            ; buffer\n    mov  r8,  msg_len        ; bytes to write\n    mov  r9,  written        ; where to store how many came out\n    call WriteConsoleA\n\n    xor  rcx, rcx            ; exit code 0\n    call ExitProcess',  # noqa: E501
    },
    "gcc-att": {
        "title": "AT&T syntax (typical output of gcc -S)",
        "code": "\t.globl\tmain\n\t.type\tmain, @function\nmain:\n\tpushq\t%rbp\n\tmovq\t%rsp, %rbp\n\tsubq\t$16, %rsp\n\tmovl\t$0, -4(%rbp)\n\tmovl\t$10, -8(%rbp)\n\tmovl\t-8(%rbp), %eax\n\taddl\t%eax, -4(%rbp)\n\tmovl\t-4(%rbp), %eax\n\tleave\n\tret",  # noqa: E501
    },
    "bubble": {
        "title": "Bubble sort over an array in memory",
        "code": "; Sorts 8 bytes in ascending order and prints the array.\nsection .data\n    array   db  9, 3, 7, 1, 8, 2, 5, 4\n    n       equ 8\n    nl      db  10\n\nsection .text\n    global _start\n\n_start:\n    mov  rcx, n\n    dec  rcx                 ; passes = n - 1\n\n.pass:\n    push rcx\n    mov  rsi, 0              ; inner index\n\n.inner:\n    mov  al, [array + rsi]\n    mov  bl, [array + rsi + 1]\n    cmp  al, bl\n    jbe  .next               ; already in order\n    mov  [array + rsi], bl   ; swaps the two\n    mov  [array + rsi + 1], al\n\n.next:\n    inc  rsi\n    cmp  rsi, rcx\n    jb   .inner\n\n    pop  rcx\n    dec  rcx\n    jnz  .pass\n\n    ; prints the 8 bytes as ASCII numbers\n    mov  r12, 0\n.show:\n    mov  al, [array + r12]\n    add  al, 48\n    mov  [array + r12], al\n    inc  r12\n    cmp  r12, n\n    jb   .show\n\n    mov  rax, 1\n    mov  rdi, 1\n    mov  rsi, array\n    mov  rdx, n\n    syscall\n\n    mov  rax, 1\n    mov  rdi, 1\n    mov  rsi, nl\n    mov  rdx, 1\n    syscall\n\n    mov  rax, 60\n    xor  rdi, rdi\n    syscall",  # noqa: E501
    },
    "broken": {
        "title": "Code with defects (to watch the validator)",
        "code": '; This example is on purpose: every block has a classic error.\nsection .data\n    msg     db  "Invalid action", 10    ; plain ASCII: one byte per letter\n    size    equ $ - msg\n    user    db  "rafael"                ; missing the 0 terminator\n\nsection .text\n    global _start\n\ndivide:\n    push rbx\n    mov  rax, 100\n    mov  rbx, 7\n    div  rbx                 ; RDX was not zeroed\n    ret                      ; and the pushed RBX never comes back\n\n_start:\n    mov  al, 300             ; 300 does not fit in 8 bits\n    mov  [counter], 1        ; ambiguous size and nonexistent symbol\n    call divide\n    jmp  .stuck\n\n.stuck:\n    jmp  .stuck              ; infinite loop with nothing that changes\n',  # noqa: E501
    },
    "suspicious": {
        "title": "Program that talks to the system (network, file, randomness)",
        "code": '; ---------------------------------------------------------------------------\n; Teaching example: a program that talks to the system.\n;\n; WARNING: this is NOT malware and it does not run anything for real. ASM X\n; only interprets these instructions in Python, inside the tool itself, without\n; touching the operating system. The goal is didactic: to see the analyzer\n; point out, line by line, the behaviors an analyst would look for in a real\n; binary (network, file, randomness, system information).\n;\n; build: nasm -f elf64 suspicious.asm && ld suspicious.o -o suspicious\n; ---------------------------------------------------------------------------\n\nsection .data\n    host        db  "collect.example.com", 0\n    url         db  "https://collect.example.com/beacon", 0\n    path        db  "/tmp/asmx-demo.txt", 0\n    message     db  "sample line", 10\n    size        equ $ - message\n    token       db  "session token sample", 0\n    user_agent  db  "Mozilla/5.0 (compatible; ASMX-Demo/1.0)", 0\n\nsection .bss\n    buffer      resb 64\n    seed        resq 1\n    descriptor  resq 1\n\nsection .text\n    global _start\n\n_start:\n    ; --- discovers information about the environment ----------------------\n    mov  rax, 39             ; getpid\n    syscall\n\n    mov  rax, 201            ; time\n    xor  rdi, rdi\n    syscall\n    mov  qword [seed], rax\n\n    ; --- asks for random bytes (key, nonce, identifier) -------------------\n    mov  rax, 318            ; getrandom\n    lea  rdi, [buffer]\n    mov  rsi, 32\n    xor  rdx, rdx\n    syscall\n\n    ; --- writes a file in /tmp --------------------------------------------\n    mov  rax, 2              ; open\n    lea  rdi, [path]\n    mov  rsi, 0x241          ; O_WRONLY | O_CREAT | O_TRUNC\n    mov  rdx, 0x1A4          ; mode 0644\n    syscall\n    mov  qword [descriptor], rax\n\n    mov  rax, 1              ; write\n    mov  rdi, [descriptor]\n    lea  rsi, [message]\n    mov  rdx, size\n    syscall\n\n    mov  rax, 3              ; close\n    mov  rdi, [descriptor]\n    syscall\n\n    ; --- opens a network socket -------------------------------------------\n    mov  rax, 41             ; socket\n    mov  rdi, 2              ; AF_INET\n    mov  rsi, 1              ; SOCK_STREAM\n    xor  rdx, rdx\n    syscall\n    mov  qword [descriptor], rax\n\n    mov  rax, 42             ; connect\n    mov  rdi, [descriptor]\n    lea  rsi, [host]\n    mov  rdx, 16\n    syscall\n\n    ; --- shows the destination on the screen ------------------------------\n    mov  rax, 1              ; write\n    mov  rdi, 1              ; stdout\n    lea  rsi, [url]\n    mov  rdx, 37\n    syscall\n\n    mov  rax, 60             ; exit\n    xor  rdi, rdi\n    syscall\n',  # noqa: E501
    },
    "overflow": {
        "title": "Sum with overflow risk (to test high values)",
        "code": "; Sums the first N integers in RAX. Good for testing limits:\n; with a small N it works; with a giant N the result overflows 64 bits.\nsection .text\n    global _start\n\nsum_until:                   ; input: RDI = N, output: RAX = sum\n    xor  rax, rax\n    mov  rcx, rdi\n.loop_body:\n    test rcx, rcx\n    jz   .done\n    add  rax, rcx\n    dec  rcx\n    jmp  .loop_body\n.done:\n    ret\n\n_start:\n    mov  rdi, 10\n    call sum_until           ; RAX = 55\n    mov  rdi, rax\n    mov  rax, 60\n    syscall\n",  # noqa: E501
    },
}


def names() -> List[str]:
    """Lists the short names of the examples, in alphabetical order.

    Returns:
        List of keys of :data:`EXAMPLES`.

    Example:
        >>> names()[:2]
        ['broken', 'bubble']
    """
    return sorted(EXAMPLES)


def title_of(name: str) -> str:
    """Returns the readable title of an example.

    Args:
        name: Short name of the example.

    Returns:
        The title; empty string when the name does not exist.
    """
    example = EXAMPLES.get(name)
    return example["title"] if example else ""


def render(name: str) -> str:
    """Returns the exact text of an example, ready to be written to disk.

    It is the same content of :data:`EXAMPLES`, only with a single line break
    at the end. The command line (``examples --dump``) and the utility
    ``tools/export_examples.py`` use this function, so the file on disk and the
    embedded example never diverge.

    Args:
        name: Short name of the example.

    Returns:
        The code ready to be written; empty string when the name does not exist.
    """
    example = EXAMPLES.get(name)
    if not example:
        return ""
    return example["code"].rstrip("\n") + "\n"


def count_lines(name: str) -> int:
    """Counts the lines of the code of an example.

    Args:
        name: Short name of the example.

    Returns:
        Number of lines (minimum 1); ``0`` when the name does not exist.
    """
    example = EXAMPLES.get(name)
    if not example:
        return 0
    return example["code"].count("\n") + 1
