; ---------------------------------------------------------------------------
; Teaching example: a program that talks to the system.
;
; WARNING: this is NOT malware and it does not run anything for real. ASM X
; only interprets these instructions in Python, inside the tool itself, without
; touching the operating system. The goal is didactic: to see the analyzer
; point out, line by line, the behaviors an analyst would look for in a real
; binary (network, file, randomness, system information).
;
; build: nasm -f elf64 suspicious.asm && ld suspicious.o -o suspicious
; ---------------------------------------------------------------------------

section .data
    host        db  "collect.example.com", 0
    url         db  "https://collect.example.com/beacon", 0
    path        db  "/tmp/asmx-demo.txt", 0
    message     db  "sample line", 10
    size        equ $ - message
    token       db  "session token sample", 0
    user_agent  db  "Mozilla/5.0 (compatible; ASMX-Demo/1.0)", 0

section .bss
    buffer      resb 64
    seed        resq 1
    descriptor  resq 1

section .text
    global _start

_start:
    ; --- discovers information about the environment ----------------------
    mov  rax, 39             ; getpid
    syscall

    mov  rax, 201            ; time
    xor  rdi, rdi
    syscall
    mov  qword [seed], rax

    ; --- asks for random bytes (key, nonce, identifier) -------------------
    mov  rax, 318            ; getrandom
    lea  rdi, [buffer]
    mov  rsi, 32
    xor  rdx, rdx
    syscall

    ; --- writes a file in /tmp --------------------------------------------
    mov  rax, 2              ; open
    lea  rdi, [path]
    mov  rsi, 0x241          ; O_WRONLY | O_CREAT | O_TRUNC
    mov  rdx, 0x1A4          ; mode 0644
    syscall
    mov  qword [descriptor], rax

    mov  rax, 1              ; write
    mov  rdi, [descriptor]
    lea  rsi, [message]
    mov  rdx, size
    syscall

    mov  rax, 3              ; close
    mov  rdi, [descriptor]
    syscall

    ; --- opens a network socket -------------------------------------------
    mov  rax, 41             ; socket
    mov  rdi, 2              ; AF_INET
    mov  rsi, 1              ; SOCK_STREAM
    xor  rdx, rdx
    syscall
    mov  qword [descriptor], rax

    mov  rax, 42             ; connect
    mov  rdi, [descriptor]
    lea  rsi, [host]
    mov  rdx, 16
    syscall

    ; --- shows the destination on the screen ------------------------------
    mov  rax, 1              ; write
    mov  rdi, 1              ; stdout
    lea  rsi, [url]
    mov  rdx, 37
    syscall

    mov  rax, 60             ; exit
    xor  rdi, rdi
    syscall
