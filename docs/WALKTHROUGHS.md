# Walkthroughs

Five guided readings of the programs that ship with the tool, using nothing but
the commands you already have. Each one shows the real output and then explains
what to look at — the point is not the sample, it is the habit: validate first,
run second, and only then decide what the program does.

To follow along:

```bash
git clone https://github.com/Rafawaldrigues/x86-assembly-visualizer
cd x86-assembly-visualizer
python3 -m asmx examples --list
```

Every output below is copied from a real run of the version in this repository.
The examples are **didactic programs written for this project**, not malware;
`suspicious.asm` is the one that behaves the way a small downloader would, and it
exists so the report has something to show.

## 1. `linux-hello.asm` — a clean baseline

```console
$ python3 -m asmx check examples/linux-hello.asm
linux-hello.asm (621 bytes · 20 lines · sha256 39fccdddcc6a…)
  platform  linux · 64 bits · 100% confidence  (System V AMD64)
  8 instructions · 1 blocks · 2 syscall(s) · 0 call(s) · 1 label(s)
  no problems found
```

Eight instructions, two syscalls, nothing wrong. This is what "clean" looks like,
and it is worth internalising before reading anything else: a program that writes
one string and exits has no behaviour worth a second look, and the tool says so
instead of inventing a finding.

```console
$ python3 -m asmx run examples/linux-hello.asm
linux-hello.asm · entry: program entry point
  output:
    Hello, world!
  8 instructions · exit code 0
  RAX=0x3c  RSP=0x7ffffffff000
  run with no problems
```

`RAX=0x3c` is 60, the `exit` syscall, left behind by the last instruction. If you
step through it (`F8` in the interface) you can watch `RAX` change from 1 (write)
to 60 (exit) — the same register carrying a different meaning three lines apart,
which is the first thing assembly teaches.

## 2. `broken.asm` — one classic mistake per block

```console
$ python3 -m asmx check examples/broken.asm
broken.asm (697 bytes · 24 lines · sha256 5f3c7117f63b…)
  platform  linux · 64 bits · 100% confidence  (System V AMD64)
  10 instructions · 3 blocks · 0 syscall(s) · 1 call(s) · 3 label(s)
  error   L14   DIV001  DIV without preparing RDX in this block
         → the CPU divides RDX:RAX; with garbage in RDX the quotient overflows and raises an exception. Put XOR RDX, RDX before it.
  error   L15   STK001  divide returns with 1 extra value(s) on the stack
         → every PUSH needs its matching POP before the RET, otherwise the RET takes the wrong value and jumps to an invalid address
  error   L18   IMM001  the value 300 does not fit in al (8 bits)
         → the assembler truncates or refuses it. Use a larger register or review the constant.
  error   L19   MEM001  ambiguous operand size
         → the assembler does not know whether to write 1, 2, 4 or 8 bytes. Write mov byte [..], 1
  error   L19   SYM003  counter is not defined anywhere
  6 error(s), 3 warning(s), 0 info(s)
```

Read the hints, not just the codes. `DIV001` and `STK001` are the two mistakes
that produce a crash at runtime instead of an error at assembly time: the first
one makes the CPU raise a divide exception, the second one sends `RET` to a
random address.

The same file in the interface is the fastest way to see the difference between
"error" and "warning": the Problems tab colours both and the hint bar under it
explains the selected item. `asmx check examples/broken.asm --json` gives the same
list as data, which is how you would fail a CI job on it.

## 3. `bubble.asm` — a real algorithm, and a graph worth looking at

```console
$ python3 -m asmx run examples/bubble.asm
bubble.asm · entry: program entry point
  output:
    12345789
  329 instructions · exit code 0
  RAX=0x3c  RSP=0x7fffffffeff8
  run with no problems
```

The result is the array printed digit by digit, already in order: the data
section declares `9, 3, 7, 1, 8, 2, 5, 4`, and the output is `1 2 3 4 5 7 8 9`
written without spaces — there is no `6` in the input, which is a good detail to
notice before wondering whether the sort dropped a value. The 329 instructions
are the whole program: bubble sort is not fast, and watching the counter in the
Machine panel is a good way to feel why.

```console
$ python3 -m asmx report examples/bubble.asm --format svg --out flow.svg
```

The control-flow graph is the reason this example exists: nine blocks, two nested
loops and a back edge you can see. Look for

- the block that ends with "returns to the caller" — the inner loop;
- the arrow labelled with the condition (`when above`, `when equal`), which is the
  comparison that decides whether the pass is over;
- the `continuation of .pass` blocks, which are the code the assembler puts after
  a conditional jump.

Reading that graph next to the source is the exercise: the structure of a bubble
sort in assembly is three blocks and two arrows, and the rest is bookkeeping.

## 4. `suspicious.asm` — what the analysis layers see

This one is deliberately closer to a small piece of malware than to a lesson: it
asks for random bytes, builds a path under `/tmp`, writes a file, resolves a host
and opens a socket.

```console
$ python3 -m asmx check examples/suspicious.asm
suspicious.asm (2659 bytes · 88 lines · sha256 3ef644093523…)
  platform  linux · 64 bits · 100% confidence  (System V AMD64)
  44 instructions · 1 blocks · 10 syscall(s) · 0 call(s) · 1 label(s)
  no problems found
```

"no problems found" is the first lesson: the validator looks for **defects**, not
for intent. A program can be perfectly well written and still do something you did
not want. That is why the other layers exist:

```console
$ python3 -m asmx analyze examples/ --out results | grep suspicious
  suspicious.asm               HIGH      42/100    44 instr   5 behav    6 IOC   0 prob  Network communication, Cryptography or obfuscation, File access
```

```console
$ python3 -m asmx scan examples/suspicious.asm
rules: 22 rule(s) from …/asmx/data/rules

  suspicious.asm 8 rule(s) matched: 4 high, 2 medium, 2 low
    IMP001  high     Recursive file walk with writes
            line 52: syscall open
            line 59: syscall write
            line 45: syscall getrandom
    NET001  high     Socket opened or connected
            line 70: syscall socket
            line 77: syscall connect
    NET002  high     Hardcoded host or URL
            line 4: `https?://[a-z0-9.-]+` -> … url db "https://collect.example.com/beacon"…
```

Four different answers to four different questions:

| Layer | Question | Answer here |
|---|---|---|
| validator | is the code correct? | yes, nothing to fix |
| behaviour | what does it do? | network, crypto, files, console, environment |
| indicators | what does it carry? | one URL, one domain, one path, keywords |
| rules | does it look like something known? | 8 signatures, 4 of them high |

The report puts all four in one page:

```bash
python3 -m asmx report examples/suspicious.asm --open
```

The Summary tab shows the risk (42/100, **high**) with the reasons that produced
it; Behaviors shows each category with the line that triggered it; Indicators
lists the URL and the path; Validation explains why the code itself is fine. Read
it as a set of indications to check, not as a verdict — the tool never claims to
know intent.

## 5. `linux-function.asm` — debugging a function in isolation

```console
$ python3 -m asmx run examples/linux-function.asm --entry add_pair
linux-function.asm · entry: add_pair
  output: (empty)
  6 instructions · exit code 0
  RAX=0x0  RSP=0x7ffffffff000
  run with no problems
```

`--entry add_pair` starts the machine inside the function with a synthetic return
address, so you can watch the arguments arrive in `RDI` and `RSI`, see the
prologue build the frame and stop at the `RET` without ever running `_start`.

With no arguments set, both registers hold zero, so the function returns zero —
which is exactly the kind of thing this mode is for: the whole program prints 42,
but the function in isolation shows you *why* it prints 42. Compare the two runs
(`--entry add_pair` and no `--entry`) side by side and the role of `_start`
becomes obvious.

In the interface the same thing is *Run › Debug single function…*, which asks for
the label, the register values and the instruction limit in one dialog.

## What to take from all this

1. **Validate before running.** The validator catches the crashes that cost the
   most time, and it never confuses "wrong" with "suspicious".
2. **Run to understand, not to test.** Stepping through eight instructions
   teaches more than reading the manual page for `mov`.
3. **Use the report to communicate.** The HTML is one file: attach it to an issue,
   paste the Markdown into a pull request, or pipe the JSON into whatever you
   already have.
4. **Treat every layer as evidence.** Behaviour, indicators and rules are
   indications with lines attached — they tell you where to look, not what to
   conclude.
