# Signature rules

`asmx scan` matches patterns in assembly source. Each match includes a rule ID,
severity and source-line evidence. Matches are static indicators; they do not
establish what a compiled program will do or whether it is malicious.

```sh
python3 -m asmx rules
python3 -m asmx scan examples/suspicious.asm --json
python3 -m asmx scan samples/ --rules custom-rules/ --fail-on high
```

Without `--rules`, the command loads `asmx/data/rules/`. A custom directory
replaces the built-in set. Rule files can be JSON or, when PyYAML is installed,
YAML. The format is specific to ASM X; it is not compatible with YARA syntax.

## File format

```json
{
  "schema": "asmx-rules/1",
  "description": "Example network rule",
  "rules": [
    {
      "id": "NET001",
      "name": "Socket opened or connected",
      "severity": "high",
      "description": "Source contains a resolved socket or connect syscall.",
      "tags": ["network"],
      "mitre": ["T1095"],
      "match": {
        "syscalls": ["socket", "connect"]
      }
    }
  ]
}
```

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | Yes | Stable identifier |
| `name` | Yes | Short display name |
| `match` | Yes | Nonempty condition object |
| `severity` | No | `low`, `medium` or `high`; default `medium` |
| `description` | No | Explanation of the pattern |
| `tags` | No | Labels for grouping |
| `mitre` | No | ATT&CK technique identifiers |

A bare list of rule objects is also accepted. Use unique IDs; when files contain
duplicate IDs, the loader keeps the first rule and logs a warning.

## Conditions

Keys in a condition object are combined with AND. Within a list, one matching
item is normally sufficient. `require_all` requires every requested item.

| Key | Matches |
| --- | --- |
| `strings` | Regular expressions over source with comments removed |
| `syscalls` | Syscall names resolved from their numbers |
| `apis` | Named calls to targets not defined in the source |
| `behaviors` | Classifier category IDs, such as `network` |
| `sections` | Section names, with or without the leading dot |
| `mnemonics` | Instruction names |
| `problems` | Static validation codes, such as `DIV001` |
| `min_instructions` | Minimum instruction count |
| `min_blocks` | Minimum basic-block count |
| `min_syscalls` | Minimum distinct resolved syscall count |
| `min_strings` | Minimum data declarations excluding reservations |

Despite its name, `min_strings` counts data declarations; it does not require
that every declaration contain a string literal.

| Switch | Default | Meaning |
| --- | --- | --- |
| `require_all` | `false` | Require every requested item |
| `case_sensitive` | `false` | Case-sensitive string regex matching |
| `strings_min` | 1, or all with `require_all` | Minimum matching regex patterns |
| `any_of` | Absent | At least one nested condition must match |

For example, a rule can match either Linux or Windows file-opening calls:

```json
{
  "id": "CUSTOM001",
  "name": "File-opening call",
  "severity": "medium",
  "match": {
    "any_of": [
      {"syscalls": ["open", "openat", "creat"]},
      {"apis": ["CreateFileA", "CreateFileW"]}
    ]
  }
}
```

## Built-in files

| File | Patterns |
| --- | --- |
| `anti-analysis.json` | Debugger checks, timing and environment queries |
| `crypto-impact.json` | Randomness, bit operations and file-impact patterns |
| `evasion-pack.json` | Process execution, memory mapping and stream copies |
| `filesystem.json` | File writes, deletion, permissions and autostart paths |
| `network.json` | Sockets, host strings and protocol markers |

Use `python3 -m asmx rules --json` to inspect the current definitions. Test new
rules against both matching inputs and ordinary programs that should not match:

```sh
python3 -m asmx scan examples/ --rules custom-rules/ --json
python3 -m unittest discover -s tests -p 'test_rules.py'
```

## Limits

Rules operate on source patterns, without runtime data flow or general indirect
call resolution. They may miss computed strings or match unused literals.
Regular expressions come from the rule files and should be reviewed before
loading third-party rules. Each rule is evaluated separately; there is no
cross-file behavioral correlation. ATT&CK mappings are annotations to review,
not verified classifications of the program.
