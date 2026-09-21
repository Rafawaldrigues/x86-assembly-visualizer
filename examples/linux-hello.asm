; Olá mundo em NASM para Linux x86-64
; montar:  nasm -f elf64 hello.asm && ld hello.o -o hello

section .data
    msg     db  "Ola, mundo!", 10      ; 10 = '\n'
    msg_len equ $ - msg                ; tamanho calculado pelo montador

section .text
    global _start

_start:
    mov rax, 1              ; syscall write
    mov rdi, 1              ; descritor 1 = stdout
    mov rsi, msg            ; endereco da string
    mov rdx, msg_len        ; quantos bytes
    syscall                 ; entrega ao kernel

    mov rax, 60             ; syscall exit
    xor rdi, rdi            ; codigo de saida 0
    syscall
