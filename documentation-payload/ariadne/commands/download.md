+++
title = "download"
chapter = false
weight = 50
+++

## download

Download a file from the target system to Mythic.

### Usage

```
download [file_path]
```

### MITRE ATT&CK

- T1005 - Data from Local System

### Notes

The file is read on the target, base64-encoded, and returned through the P2P delegate channel. File registration with Mythic is handled automatically.
