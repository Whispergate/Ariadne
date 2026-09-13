+++
title = "Ariadne"
chapter = false
weight = 5
+++

# Ariadne

Ariadne is a multi-language webshell agent for the Mythic C2 framework. It operates as a P2P payload linked through a Starburst callback via `link_webshell`. The webshell is stateless - it executes commands only when Starburst sends them through the P2P link.

## Supported Languages

- PHP
- ASPX (ASP.NET WebForms)
- ASHX (ASP.NET Generic Handler)
- JSP (Java Server Pages)
- JSPX (XML-format JSP)
- Go

## Features

- **Deformed base64** per-deployment encoding alphabet from a password via Fisher-Yates shuffle
- **AES-256-CBC** with HMAC-SHA256 integrity
- **Request templates** wrap payloads as form data, JSON, image data, or SOAP XML
- **Camouflage pages** returned for unauthenticated requests (fake 404, IIS default, blank)
- **Authentication** via cookie, header, or parameter
- **SOCKS5 proxy** tunneled through the webshell
- **P2P linking** over HTTP, SMB named pipes, or TCP sockets
- **Dynamic command loading** - select which commands to include at build time
- **In-memory .NET execution** - `execute_assembly` for ASPX/ASHX webshells

## How It Works

1. Build an Ariadne payload in Mythic to produce a webshell file
2. Deploy the webshell to the target web server
3. From a Starburst callback, run `link_webshell` with the webshell URL
4. Starburst sends a heartbeat to the webshell, which responds with host info
5. Mythic creates a callback with a P2P edge from Starburst to Ariadne
6. Tasks issued to the Ariadne callback are forwarded by Starburst to the webshell and responses are relayed back
