; ---------------------------------------------------------------------------
; Exemplo didatico: um programa que conversa com o sistema.
;
; ATENCAO: isto NAO e malware e nao executa nada de verdade. O ASM X apenas
; interpreta estas instrucoes em Python, dentro da propria ferramenta, sem
; tocar no sistema operacional. O objetivo e didatico: ver o analisador
; apontar, linha por linha, os comportamentos que um analista procuraria num
; binario real (rede, arquivo, aleatoriedade, informacao do sistema).
;
; montar: nasm -f elf64 suspeito.asm && ld suspeito.o -o suspeito
; ---------------------------------------------------------------------------

section .data
    host        db  "coleta.exemplo.com", 0
    url         db  "https://coleta.exemplo.com/beacon", 0
    caminho     db  "/tmp/asmx-demo.txt", 0
    mensagem    db  "linha de exemplo", 10
    tam         equ $ - mensagem
    rotulo      db  "session token de exemplo", 0
    user_agent  db  "Mozilla/5.0 (compatible; ASMX-Demo/1.0)", 0

section .bss
    buffer      resb 64
    semente     resq 1
    descritor   resq 1

section .text
    global _start

_start:
    ; --- descobre informacoes do ambiente --------------------------------
    mov  rax, 39             ; getpid
    syscall

    mov  rax, 201            ; time
    xor  rdi, rdi
    syscall
    mov  qword [semente], rax

    ; --- pede bytes aleatorios (chave, nonce, identificador) -------------
    mov  rax, 318            ; getrandom
    lea  rdi, [buffer]
    mov  rsi, 32
    xor  rdx, rdx
    syscall

    ; --- escreve um arquivo em /tmp --------------------------------------
    mov  rax, 2              ; open
    lea  rdi, [caminho]
    mov  rsi, 0x241          ; O_WRONLY | O_CREAT | O_TRUNC
    mov  rdx, 0x1A4          ; modo 0644
    syscall
    mov  qword [descritor], rax

    mov  rax, 1              ; write
    mov  rdi, [descritor]
    lea  rsi, [mensagem]
    mov  rdx, tam
    syscall

    mov  rax, 3              ; close
    mov  rdi, [descritor]
    syscall

    ; --- abre um soquete de rede -----------------------------------------
    mov  rax, 41             ; socket
    mov  rdi, 2              ; AF_INET
    mov  rsi, 1              ; SOCK_STREAM
    xor  rdx, rdx
    syscall
    mov  qword [descritor], rax

    mov  rax, 42             ; connect
    mov  rdi, [descritor]
    lea  rsi, [host]
    mov  rdx, 16
    syscall

    ; --- mostra o destino na tela ----------------------------------------
    mov  rax, 1              ; write
    mov  rdi, 1              ; stdout
    lea  rsi, [url]
    mov  rdx, 37
    syscall

    mov  rax, 60             ; exit
    xor  rdi, rdi
    syscall
