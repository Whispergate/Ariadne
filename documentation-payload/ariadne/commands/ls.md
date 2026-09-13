+++
title = "ls"
chapter = false
weight = 20
+++

## ls

List files and directories at a specified path.

### Usage

```
ls [path]
```

Default path is the current working directory (`.`).

### MITRE ATT&CK

- T1083 - File and Directory Discovery

### Output

Returns JSON with directory listing including file name, type, size, permissions, and modification time. Rendered in the Mythic file browser UI.
