+++
title = "socks"
chapter = false
weight = 80
+++

## socks

Start or stop a SOCKS5 proxy that tunnels traffic through the webshell.

### Usage

```
socks start [port]
socks stop
```

Default port is 1080.

### MITRE ATT&CK

- T1572 - Protocol Tunneling

### Notes

SOCKS connections are proxied through the webshell using tunnel commands (CONNECT, FORWARD, READ, DISCONNECT). The webshell maintains socket sessions for each proxied connection.
