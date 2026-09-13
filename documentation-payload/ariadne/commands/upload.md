+++
title = "upload"
chapter = false
weight = 60
+++

## upload

Upload a file from Mythic to the target system.

### Usage

Select a file and specify the remote destination path.

### MITRE ATT&CK

- T1105 — Ingress Tool Transfer

### Notes

The file is base64-encoded, sent through the P2P delegate channel, and written to the specified path. Parent directories are created automatically if they don't exist.
