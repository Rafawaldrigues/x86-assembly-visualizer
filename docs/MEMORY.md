# Memory model

ASM X uses a bounded simulated address space. Allocation is separate from
storage: a large zero-filled region occupies no backing pages until written.
Backing pages are 4096 bytes each. Data declarations, reserved BSS, heap growth
and stack usage all count toward the allocation budget.

The default is 512 MiB per machine. Set `--max-memory MIB`, `ASMX_MAX_MEMORY`,
or `max_memory` in the configuration file to change it. The CLI and
configuration require at least 16 MiB. The Python API accepts smaller budgets
for tests: `Machine(analyze(source), max_memory=1)`.

## Allocation failure

This program reserves 32 MiB. With a 16 MiB budget it fails while loading the
data, before any instruction executes:

```asm
section .bss
buffer resb 33554432
section .text
global _start
_start:
    mov rax, 60
    xor rdi, rdi
    syscall
```

Save it as `memory-limit.asm` and run:

```sh
python3 -m asmx run memory-limit.asm --max-memory 16 --json
```

The command exits with status 1. JSON contains `out_of_memory: true`,
`memory_fault.code: "MEM_LIMIT"`, the source line and requested size. Usage is
reported as `memory.allocated_bytes`, `peak_bytes`, `limit_bytes` and
`committed_bytes`. The last value counts backing pages only, excluding Python
objects and bookkeeping.

`resb`/`resw`/`resd`/`resq`, supported `times` initializers and MASM `dup`
initializers are checked before expanding their contents. Negative allocation
sizes are rejected. Simulated Linux `brk(0)` returns the current heap end;
requests at or above the heap base resize the heap. Shrinking it invalidates
the released range and clears stored bytes there.

## Invalid accesses

```asm
section .bss
buffer resb 4
section .text
global _start
_start:
    mov qword [buffer], 1     ; eight-byte write into a four-byte region
    mov rax, 60              ; not reached
    xor rdi, rdi
    syscall
```

The write produces `MEM_ACCESS`. The complete access is checked before any byte
is written. Checks also apply to string instructions, simulated syscall buffers
and supported Windows API buffers. `lea` only computes an address and does not
read memory.

Data in `.rodata` and `.const` is read-only. BSS starts at zero and is considered
initialized. Stack and newly grown heap bytes are uninitialized until written.
An access with even one uninitialized byte reports `MEM_UNINITIALIZED` and
returns the stored bytes, with zero for bytes that have no value yet.

## Stack

The stack has a one-MiB address range and grows downward from `STACK_TOP`.
Changing RSP to reserve stack space counts toward the budget. The simulator
allows accesses up to 128 bytes below RSP, modeling the System V red zone.
Stack accounting retains the lowest address reached until reset, so repeated
push/pop cycles at the same depth do not accumulate allocations.

Pushing or moving RSP past the stack boundary stops execution. Popping an empty
stack also stops. `main`, `WinMain` and an explicitly selected entry function
receive a synthetic return address; `_start` is treated as a process entry.

## Diagnostics

| Code | Meaning | Result |
| --- | --- | --- |
| `MEM_LIMIT` | Allocation would exceed the configured budget | Stops; `out_of_memory` is true |
| `MEM_HOST` | Python reports a host allocation failure | Stops when recoverable; `out_of_memory` is true |
| `MEM_ACCESS` | Unmapped access, boundary crossing, overlap or address wrap | Stops |
| `MEM_READONLY` | Write into a protected region | Stops |
| `MEM_STACK` | Stack overflow, underflow or access below the red zone | Stops |
| `MEM_SIZE` | Invalid allocation size or unsupported repeated initializer | Stops |
| `MEM_OUTPUT` | Retained console output would exceed one MiB | Stops |
| `MEM_UNINITIALIZED` | At least one byte was never initialized | Warns |

Runtime faults leave the instruction pointer on the failing instruction and
mark its history entry as fatal. Load-time errors use the declaration's source
line and execute zero instructions. Reset clears diagnostics and reloads the
source; a declaration that still exceeds the limit fails again.

The window displays usage above the memory table and the latest diagnostic
above the registers. Inspecting memory in the window does not count as a
program read. CLI JSON and report JSON include the structured fault and usage;
HTML and Markdown reports include usage and readable diagnostics.

Individual writes and REP operations have a one-MiB transfer limit. Retained
console output also has a one-MiB limit to bound repeated output. `getrandom`
returns at most 4096 bytes per call and reports the actual count in RAX.

## Scope

These are teaching checks, not x86 page tables or an OS memory manager:

- A single read or write must fit within one declared region. Crossing adjacent
  declarations is rejected even when a native process might allow it. A pointer
  landing entirely inside another valid region cannot be identified as a buffer
  overrun without pointer provenance.
- Heap support is limited to `brk`; `malloc`, `free`, `mmap` and Windows heap
  APIs are not implemented. There is no general use-after-free detector.
- Unlike native Linux `brk`, exhausting the simulated budget is a fatal
  diagnostic rather than an allocation failure returned to the program.
- Partial string-instruction progress can remain visible if a later byte faults.
- The stack and return-address model is 64-bit, including for source detected
  as 32-bit. The red-zone allowance is a simplified rule used on all platforms.
- The budget limits simulated allocations, not total host RAM. Source parsing,
  analysis, reports, Python objects and process overhead are outside it. The OS
  can terminate Python before it raises a catchable `MemoryError`.
- Timeouts are checked between instructions. They are not a hard wall-clock
  limit on parsing or on one expensive instruction.

An assembly program may pass these checks and still fail when assembled and
run on real hardware.
