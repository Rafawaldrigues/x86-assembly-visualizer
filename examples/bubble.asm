; Sorts 8 bytes in ascending order and prints the array.
section .data
    array   db  9, 3, 7, 1, 8, 2, 5, 4
    n       equ 8
    nl      db  10

section .text
    global _start

_start:
    mov  rcx, n
    dec  rcx                 ; passes = n - 1

.pass:
    push rcx
    mov  rsi, 0              ; inner index

.inner:
    mov  al, [array + rsi]
    mov  bl, [array + rsi + 1]
    cmp  al, bl
    jbe  .next               ; already in order
    mov  [array + rsi], bl   ; swaps the two
    mov  [array + rsi + 1], al

.next:
    inc  rsi
    cmp  rsi, rcx
    jb   .inner

    pop  rcx
    dec  rcx
    jnz  .pass

    ; prints the 8 bytes as ASCII numbers
    mov  r12, 0
.show:
    mov  al, [array + r12]
    add  al, 48
    mov  [array + r12], al
    inc  r12
    cmp  r12, n
    jb   .show

    mov  rax, 1
    mov  rdi, 1
    mov  rsi, array
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
