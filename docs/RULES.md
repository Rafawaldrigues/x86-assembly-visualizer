# Signature rules

`asmx scan` matches a sample against a set of rules and reports what fired, with
the line that made it fire. This is the same idea as a YARA rule or an antivirus
signature, but the input is assembly source instead of a compiled binary.

Two things to keep in mind before writing or trusting a rule:

1. **A match is an indicator, not a verdict.** `NET001` firing means "this
   program opens a socket", not "this program is malware". Read the evidence.
2. **Rules are data, not code.** A rule file cannot execute anything; it can only
   describe patterns. A broken rule fails loudly with the file and the field.

## Quick start

```bash
asmx rules                        # list the rules that ship with the tool
asmx rules --json                 # the same list, machine readable
asmx scan examples/suspicious.asm # run the rule set over one file
asmx scan samples/ --rules rules/ # run your own rule set over a folder
asmx scan sample.asm --fail-on high   # exit 1 when a high rule fires
```

## Where the rules live

The core rule set travels inside the package (`asmx/data/rules/*.json`), so a
`pip install` gets it with no extra step and no dependency. Point `--rules DIR`
at your own directory to use a different set — the two are never merged, which
keeps a scan reproducible.

Files are read as **JSON**, or as **YAML** when PyYAML happens to be installed
(`.yaml` / `.yml`). JSON is the default because it needs nothing.

## Anatomy of a rule

```json
{
  "id": "NET001",
  "name": "Socket opened or connected",
  "severity": "high",
  "description": "Why this matters, in one or two sentences.",
  "tags": ["network", "c2"],
  "mitre": ["T1095", "T1071"],
  "match": {
    "syscalls": ["socket", "connect"]
  }
}
```

| field | required | meaning |
|---|---|---|
| `id` | yes | stable identifier, shown in the report and used by `--fail-on` |
| `name` | yes | short human name |
| `severity` | no | `high`, `medium` or `low` (default `medium`) |
| `description` | no | what the rule looks for and what it means |
| `tags` | no | free labels for filtering |
| `mitre` | no | ATT&CK technique ids the rule hints at, like `T1071.001` |
| `match` | yes | the conditions; see below |

The file itself carries a schema marker and, optionally, a description:

```json
{
  "schema": "asmx-rules/1",
  "description": "Network and command-and-control indicators.",
  "rules": [ ... ]
}
```

## Conditions

Every key you put in `match` must hold (a logical **AND**). Inside one key, any
item matching is enough, unless you ask for all of them with `require_all`.

| key | matches on | example |
|---|---|---|
| `strings` | regular expressions over the source **with comments removed** | `["https?://", "CurrentVersion\\\\\\\\Run"]` |
| `syscalls` | syscalls the analyzer resolved (by name, from the syscall number) | `["socket", "connect"]` |
| `apis` | calls whose target is not a label declared in the file | `["CreateProcessA"]` |
| `behaviors` | behaviour categories from the classifier | `["network", "crypto"]` |
| `sections` | sections declared in the file, with or without the dot | `[".data", "text"]` |
| `mnemonics` | instructions that appear in the program | `["xor", "rol"]` |
| `problems` | validator codes | `["DIV001"]` |
| `min_instructions` | instruction count is at least N | `50` |
| `min_blocks` | basic block count is at least N | `4` |
| `min_syscalls` | distinct syscall count is at least N | `3` |
| `min_strings` | data declarations that are not reservations | `2` |

Switches:

| key | default | meaning |
|---|---|---|
| `require_all` | `false` | every listed item must be present, not just one |
| `case_sensitive` | `false` | make `strings` respect case |
| `strings_min` | `1` (or all, with `require_all`) | how many patterns must match |
| `any_of` | — | a list of condition objects; at least one of them must match |

`any_of` is how you write "either a Linux syscall or a Windows API":

```json
{
  "id": "FILE001",
  "name": "Writes a file",
  "severity": "medium",
  "match": {
    "any_of": [
      {"syscalls": ["open", "openat", "creat"]},
      {"apis": ["CreateFileA", "CreateFileW", "WriteFile"]}
    ]
  }
}
```

## What a match looks like

```console
$ asmx scan examples/suspicious.asm
suspicious.asm — 8 rule(s) matched: 4 high, 2 medium, 2 low
  NET001  high    Socket opened or connected
          line 70: syscall socket
          line 77: syscall connect
  IMG001  high    Recursive file walk with writes
          line 52: syscall open
          ...
```

Every match carries the rule, the severity, the tags, the ATT&CK techniques and
one evidence line per signal — always with the line number in the source. The
JSON output (`--json`) carries the same information for another tool to consume.

## The rules that ship with ASM X

| file | ids | theme |
|---|---|---|
| `anti-analysis.json` | `EVA00x` | debugger checks, timing, environment fingerprint, executable memory |
| `crypto-impact.json` | `CRY00x`, `IMP00x` | randomness, cipher loops, encryptor shape, locker strings |
| `evasion-pack.json` | `EXE00x` | spawning programs, shell strings, memory mapping, stream copies |
| `filesystem.json` | `FILE00x`, `PER00x` | file writes, sensitive paths, deletion, autostart, permissions |
| `network.json` | `NET00x` | sockets, embedded hosts, IPv4 literals, HTTP markers, DNS |

None of them fire on the nine example programs that ship with the tool except
`suspicious.asm` — a rule set that flags everything is a rule set nobody reads.
There is a test that enforces exactly that.

## Testing your rules

```bash
asmx scan samples/mine.asm --rules rules/ --json | jq '.matches[].id'
python3 -m unittest tests.test_rules        # the engine's own suite
```

When a rule is wrong, the engine says which rule and which field:

```console
$ asmx scan sample.asm --rules broken.json
[ERR_CONFIG] rule NET001 has unknown severity 'urgent' (use high, medium, low)
```

## Limits, stated plainly

- The engine reads the **source**, not a running program: a rule can be evaded by
  computing strings at runtime (which the emulator only partly follows).
- `strings` sees the code with comments blanked out, but it does see string data
  and labels — a rule can therefore fire on a comment-free literal that is never
  used.
- `apis` only knows calls whose target is not a label in the file; an indirect
  call (`call [rbx]`) has no name to match.
- There is no scoring across rules and no correlation: each rule is evaluated
  alone. The report shows the list; judging the combination is your job.
