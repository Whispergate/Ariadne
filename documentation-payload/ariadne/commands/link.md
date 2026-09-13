+++
title = "link"
chapter = false
weight = 90
+++

## link

Manage P2P links to the webshell. Starburst uses `link_webshell` to connect; this command manages additional P2P listeners on the webshell itself.

### Usage

```
link start [http|smb|tcp] [address]
link stop [http|smb|tcp]
```

### MITRE ATT&CK

- T1572 — Protocol Tunneling

### Transport Types

- **HTTP**: P2P messages exchanged via the webshell's HTTP endpoint
- **SMB**: Named pipe listener (Windows ASPX/ASHX only)
- **TCP**: TCP socket listener on configurable port
