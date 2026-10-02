# Examples

Run these commands from the repository root. The bundled sources are also
available through **File > Open sample** in the window.

## Print a string

```sh
python3 -m asmx check examples/linux-hello.asm
python3 -m asmx run examples/linux-hello.asm
```

`linux-hello.asm` writes `Hello, world!` and exits with code 0. Step through it
with F8 and inspect RAX: 1 selects `write`, then 60 selects `exit`.
RDI, RSI and RDX hold the descriptor, buffer address and byte count for `write`.

## Find common mistakes

```sh
python3 -m asmx check examples/broken.asm
```

The file intentionally contains an immediate that does not fit in AL, a write
to an undefined symbol, division without preparing RDX, an unbalanced stack and
an infinite loop. Check the source line and hint for each finding. Static
validation reports potential problems; execution stops at the first fatal
runtime fault, so it may not reach the other defects.

## Sort bytes in memory

```sh
python3 -m asmx run examples/bubble.asm
python3 -m asmx report examples/bubble.asm --format svg --out results/bubble.svg
```

The input is `9, 3, 7, 1, 8, 2, 5, 4`; the printed result is `12345789`.
Set a breakpoint in `.inner` to watch AL and BL compare adjacent bytes. The
control-flow graph shows the inner comparison loop and the outer pass loop.

## Call a function

```sh
python3 -m asmx run examples/linux-function.asm
python3 -m asmx run examples/linux-function.asm --entry add_pair --trace
```

The whole program passes 17 and 25 to `add_pair`, converts the result and
prints `42`. In the isolated run, argument registers start at zero, so it
returns zero. In the GUI, create a scenario starting at `add_pair` with
`rdi=17, rsi=25` and expected exit code 42. The synthetic return address makes
the function's return value the isolated run's exit code.

## Read static behavior findings

```sh
python3 -m asmx scan examples/suspicious.asm
python3 -m asmx report examples/suspicious.asm --out results/suspicious.html
```

`suspicious.asm` contains file, socket, randomness and environment-query
patterns. It is an analysis fixture, not a complete network client. Several
syscalls are not implemented by the simulator; the execution report lists
those stubs. A rule match identifies source patterns, not demonstrated native
behavior or malicious intent. Likewise, no validation findings does not prove
that this program works.

## Check memory errors

[MEMORY.md](MEMORY.md) contains small allocation-limit and out-of-bounds
examples. Try a four-byte buffer with an eight-byte write, then change it to a
four-byte write and reset. Compare the diagnostic and memory contents before
and after the change.

## Other bundled programs

| File | Demonstrates |
| --- | --- |
| `linux-loop.asm` | A counter and conditional branches |
| `windows-hello.asm` | Simplified Windows x64 calling convention and console output |
| `gcc-att.asm` | AT&T syntax and stack locals |
| `overflow.asm` | Summation and arithmetic overflow checks |
