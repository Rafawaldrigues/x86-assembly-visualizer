; Imprime cinco vezes a mesma linha, usando um contador em R12.
section .data
    linha   db  "iteracao do laco", 10
    tam     equ $ - linha

section .text
    global _start

_start:
    mov r12, 5                  ; contador do laco

.loop:
    cmp r12, 0                  ; ainda sobra iteracao?
    je  .fim                    ; se chegou a zero, sai

    mov rax, 1
    mov rdi, 1
    mov rsi, linha
    mov rdx, tam
    syscall

    dec r12                     ; contador = contador - 1
    jmp .loop                   ; volta para o topo

.fim:
    mov rax, 60
    mov rdi, 0
    syscall
