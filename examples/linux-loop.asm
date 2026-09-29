; Prints the same line five times, using a counter in R12.
section .data
    line    db  "loop iteration", 10
    size    equ $ - line

section .text
    global _start

_start:
    mov r12, 5                  ; loop counter

.loop:
    cmp r12, 0                  ; is there an iteration left?
    je  .done                   ; if it reached zero, leave

    mov rax, 1
    mov rdi, 1
    mov rsi, line
    mov rdx, size
    syscall

    dec r12                     ; counter = counter - 1
    jmp .loop                   ; back to the top

.done:
    mov rax, 60
    mov rdi, 0
    syscall
