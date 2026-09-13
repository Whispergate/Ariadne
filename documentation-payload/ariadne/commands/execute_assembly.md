+++
title = "execute_assembly"
chapter = false
weight = 88
+++

## execute_assembly

Load and execute a .NET assembly in-memory on the target. Only available on ASPX and ASHX webshells running under .NET.

### Usage

Select a .NET assembly file and optionally provide command-line arguments.

### MITRE ATT&CK

- T1620 - Reflective Code Loading

### Notes

The assembly is base64-encoded and sent through the P2P delegate channel. On the target, it is loaded via `Assembly.Load()` and its entry point is invoked with the provided arguments. Console output is captured and returned.

Compatible with tools like Seatbelt, Rubeus, and SharpHound. No files are written to disk.

Only supported on Windows targets with ASPX or ASHX webshells.
