; Ordena 8 bytes em ordem crescente e imprime o vetor.
section .data
    vetor   db  9, 3, 7, 1, 8, 2, 5, 4
    n       equ 8
    nl      db  10

section .text
    global _start

_start:
    mov  rcx, n
    dec  rcx                 ; passes = n - 1

.passe:
    push rcx
    mov  rsi, 0              ; indice interno

.interno:
    mov  al, [vetor + rsi]
    mov  bl, [vetor + rsi + 1]
    cmp  al, bl
    jbe  .segue              ; ja esta em ordem
    mov  [vetor + rsi], bl   ; troca os dois
    mov  [vetor + rsi + 1], al

.segue:
    inc  rsi
    cmp  rsi, rcx
    jb   .interno

    pop  rcx
    dec  rcx
    jnz  .passe

    ; imprime os 8 bytes como numeros ASCII
    mov  r12, 0
.mostra:
    mov  al, [vetor + r12]
    add  al, 48
    mov  [vetor + r12], al
    inc  r12
    cmp  r12, n
    jb   .mostra

    mov  rax, 1
    mov  rdi, 1
    mov  rsi, vetor
    mov  rdx, n
    syscall

    mov  rax, 1
    mov  rdi, 1
    mov  rsi, nl
    mov  rdx, 1
    syscall

    mov  rax, 60
    xor  rdi, rdi
    syscall
