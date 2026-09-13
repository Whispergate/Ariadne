+++
title = "ps"
chapter = false
weight = 86
+++

## ps

List running processes on the target.

### Usage

```
ps
```

### MITRE ATT&CK

- T1057 - Process Discovery

### Notes

On Windows (.NET), uses `Process.GetProcesses()` to enumerate processes with PID, name, and path. On Linux, runs `ps aux`. On Java, uses `ProcessHandle.allProcesses()` with a fallback to shell commands.
