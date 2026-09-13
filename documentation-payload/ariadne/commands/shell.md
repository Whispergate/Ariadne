+++
title = "shell"
chapter = false
weight = 10
+++

## shell

Execute a shell command on the target system.

### Usage

```
shell [command]
```

### MITRE ATT&CK

- T1059 — Command and Scripting Interpreter

### Notes

Uses the system's native shell:
- **Linux/macOS**: `/bin/sh -c`
- **Windows**: `cmd.exe /c`

Falls back through `proc_open` → `shell_exec` → `exec` → `system` → `passthru` (PHP) or equivalent in other languages.
