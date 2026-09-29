; add_pair(a, b) called from _start, in the System V style.
section .bss
    buffer  resb 32

section .data
    prefix  db  "result: "
    plen    equ $ - prefix
    nl      db  10

section .text
    global _start

add_pair:
    push rbp                 ; prologue: saves the previous frame
    mov  rbp, rsp            ; RBP anchors this frame
    mov  rax, rdi            ; 1st argument
    add  rax, rsi            ; adds the 2nd argument
    pop  rbp                 ; epilogue
    ret                      ; returns the value in RAX

; converts RAX into decimal text inside buffer, returns the size in RAX
itoa:
    push rbp
    mov  rbp, rsp
    lea  rdi, [buffer + 31]
    mov  rcx, 0
    mov  rbx, 10
.digit:
    xor  rdx, rdx
    div  rbx                 ; RAX = RAX / 10, RDX = remainder
    add  rdx, 48             ; remainder becomes an ASCII character
    dec  rdi
    mov  [rdi], dl
    inc  rcx
    test rax, rax
    jnz  .digit
    mov  rsi, rdi
    mov  rax, rcx
    pop  rbp
    ret

_start:
    mov  rdi, 17             ; 1st argument of add_pair
    mov  rsi, 25             ; 2nd argument of add_pair
    call add_pair            ; RAX = 42

    call itoa                ; RSI = text, RAX = size

    mov  rdx, rax
    mov  rax, 1
    mov  rdi, 1
    syscall                  ; writes the number

    mov  rax, 1
    mov  rdi, 1
    mov  rsi, nl
    mov  rdx, 1
    syscall                  ; line break

    mov  rax, 60
    xor  rdi, rdi
    syscall
