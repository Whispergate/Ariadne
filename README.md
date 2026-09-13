# Ariadne

A multi-language webshell agent for [Mythic](https://github.com/its-a-feature/Mythic), designed to operate as a P2P payload linked through [Starburst](https://github.com/Whispergate/Starburst).

Ariadne generates stateless webshells in 6 languages. The webshell is deployed to a target web server and linked from a Starburst callback via `link_webshell`. All tasking flows through Starburst as a delegate: Mythic sends tasks to Starburst, which forwards them to the webshell and relays responses back.

## Features

- **6 webshell languages** — PHP, ASPX, ASHX, JSP, JSPX, Go — with identical wire protocol
- **Deformed base64** — per-deployment encoding alphabet derived from a password via Fisher-Yates shuffle
- **AES-256-CBC + HMAC-SHA256** encryption
- **Request templates** — payloads wrapped as form posts, JSON, image data, or SOAP XML
- **Camouflage pages** — unauthenticated visitors see a fake 404, IIS default page, or blank page
- **Authentication** — cookie, header, or query parameter gating
- **SOCKS5 proxy** tunneled through the webshell
- **P2P linking** via HTTP, SMB named pipes, or TCP sockets
- **Dynamic command loading** — select which commands to include at build time for a minimal footprint
- **In-memory .NET execution** — `execute_assembly` loads and runs assemblies without touching disk (ASPX/ASHX)

## Architecture

```
Mythic <---> Starburst Agent <--- P2P link (HTTP) ---> Ariadne Webshell
              (delegate)                                (passive, stateless)
```

1. Build an Ariadne payload in Mythic — this produces a webshell file
2. Deploy the webshell to the target web server
3. From a Starburst callback, run `link_webshell` with the webshell URL
4. Starburst links to the webshell, and Mythic creates a new callback with a P2P edge
5. Tasks issued to the Ariadne callback flow through Starburst automatically

## Commands

Core commands are always included. Optional commands can be toggled on or off at build time.

| Command | Description | Builtin |
|---------|-------------|---------|
| `shell` | Execute a shell command | Yes |
| `ls` | List directory contents | Yes |
| `cd` | Change directory | Yes |
| `pwd` | Print working directory | Yes |
| `cat` | Read and display file contents | No |
| `download` | Download a file from the target | No |
| `upload` | Upload a file to the target | No |
| `rm` | Remove a file or directory | No |
| `mkdir` | Create a directory | No |
| `cp` | Copy a file or directory | No |
| `mv` | Move or rename a file or directory | No |
| `env` | List environment variables | No |
| `whoami` | Print current user and privileges | No |
| `ps` | List running processes | No |
| `execute_assembly` | Load and run a .NET assembly in-memory (ASPX/ASHX) | No |
| `socks` | Start/stop SOCKS5 proxy | No |
| `link` | Manage P2P agent links | No |
| `sleep` | Set beacon interval and jitter | No |

## Installation

```bash
sudo ./mythic-cli install github https://github.com/Whispergate/Ariadne
```

For local development:

```bash
cd Payload_Type/ariadne
python main.py
```

## C2 Profile

Ariadne uses the `ariadne_webshell` C2 profile, a P2P profile with these parameters:

| Parameter | Description |
|-----------|-------------|
| `webshell_url` | URL where the webshell is deployed |
| `auth_method` | Authentication method (cookie, header, or parameter) |
| `auth_name` | Name of the cookie, header, or parameter |
| `auth_value` | Authentication value to match |
| `aes_key` | Base64-encoded AES-256 key (empty for no encryption) |
| `param_name` | POST parameter name for form data |
