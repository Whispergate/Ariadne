+++
title = "whoami"
chapter = false
weight = 84
+++

## whoami

Print current user information on the target.

### Usage

```
whoami
```

### MITRE ATT&CK

- T1033 — System Owner/User Discovery

### Notes

Returns the current user, group memberships, and privilege information. On Windows (.NET), uses `WindowsIdentity` to enumerate groups and SIDs. On Linux, runs `id` for full output.
