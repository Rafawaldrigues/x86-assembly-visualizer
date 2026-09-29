; Hello world on Windows x64 (NASM + link with kernel32.lib)
; The Microsoft ABI passes arguments in RCX, RDX, R8, R9
; and requires 32 bytes of shadow space on the stack.

extern GetStdHandle
extern WriteConsoleA
extern ExitProcess

section .data
    msg     db  "Hello from Windows!", 13, 10
    msg_len equ $ - msg

section .bss
    written resq 1

section .text
    global main

main:
    sub  rsp, 40             ; 32 of shadow space + alignment

    mov  rcx, -11            ; STD_OUTPUT_HANDLE
    call GetStdHandle
    mov  rbx, rax            ; keeps the handle

    mov  rcx, rbx            ; handle
    mov  rdx, msg            ; buffer
    mov  r8,  msg_len        ; bytes to write
    mov  r9,  written        ; where to store how many came out
    call WriteConsoleA

    xor  rcx, rcx            ; exit code 0
    call ExitProcess
