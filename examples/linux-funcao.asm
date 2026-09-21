; soma(a, b) chamada a partir de _start, no estilo System V.
section .bss
    buffer  resb 32

section .data
    prefixo db  "resultado: "
    plen    equ $ - prefixo
    nl      db  10

section .text
    global _start

soma:
    push rbp                 ; prologo: salva o quadro anterior
    mov  rbp, rsp            ; RBP ancora este quadro
    mov  rax, rdi            ; 1o argumento
    add  rax, rsi            ; soma o 2o argumento
    pop  rbp                 ; epilogo
    ret                      ; devolve o valor em RAX

; converte RAX em texto decimal dentro de buffer, devolve tamanho em RAX
itoa:
    push rbp
    mov  rbp, rsp
    lea  rdi, [buffer + 31]
    mov  rcx, 0
    mov  rbx, 10
.digito:
    xor  rdx, rdx
    div  rbx                 ; RAX = RAX / 10, RDX = resto
    add  rdx, 48             ; resto vira caractere ASCII
    dec  rdi
    mov  [rdi], dl
    inc  rcx
    test rax, rax
    jnz  .digito
    mov  rsi, rdi
    mov  rax, rcx
    pop  rbp
    ret

_start:
    mov  rdi, 17             ; 1o argumento de soma
    mov  rsi, 25             ; 2o argumento de soma
    call soma                ; RAX = 42

    call itoa                ; RSI = texto, RAX = tamanho

    mov  rdx, rax
    mov  rax, 1
    mov  rdi, 1
    syscall                  ; escreve o numero

    mov  rax, 1
    mov  rdi, 1
    mov  rsi, nl
    mov  rdx, 1
    syscall                  ; quebra de linha

    mov  rax, 60
    xor  rdi, rdi
    syscall
