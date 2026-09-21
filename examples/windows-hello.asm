; Ola mundo no Windows x64 (NASM + link com kernel32.lib)
; A ABI da Microsoft passa argumentos em RCX, RDX, R8, R9
; e exige 32 bytes de shadow space na pilha.

extern GetStdHandle
extern WriteConsoleA
extern ExitProcess

section .data
    msg     db  "Ola do Windows!", 13, 10
    msg_len equ $ - msg

section .bss
    escritos resq 1

section .text
    global main

main:
    sub  rsp, 40             ; 32 de shadow space + alinhamento

    mov  rcx, -11            ; STD_OUTPUT_HANDLE
    call GetStdHandle
    mov  rbx, rax            ; guarda o handle

    mov  rcx, rbx            ; handle
    mov  rdx, msg            ; buffer
    mov  r8,  msg_len        ; bytes a escrever
    mov  r9,  escritos       ; onde guardar quantos sairam
    call WriteConsoleA

    xor  rcx, rcx            ; codigo de saida 0
    call ExitProcess
