; Hello world in NASM for Linux x86-64
; build:  nasm -f elf64 hello.asm && ld hello.o -o hello

section .data
    msg     db  "Hello, world!", 10     ; 10 = '\n'
    msg_len equ $ - msg                ; size computed by the assembler

section .text
    global _start

_start:
    mov rax, 1              ; syscall write
    mov rdi, 1              ; descriptor 1 = stdout
    mov rsi, msg            ; address of the string
    mov rdx, msg_len        ; how many bytes
    syscall                 ; hands it to the kernel

    mov rax, 60             ; syscall exit
    xor rdi, rdi            ; exit code 0
    syscall
