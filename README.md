# Python Messenger Client

## Overview

A cross-platform Messenger client supporting Python 3.6+.

## Capabilities

| Capability             | Status                                             |
|------------------------|----------------------------------------------------|
| Transports             | HTTP and WebSockets                                |
| Encryption             | AES-256-CBC with random IV prefix                  |
| Reconnection           | 5 attempts over 60 seconds (configurable)          |
| SOCKS5 TCP             | Supported                                          |
| SOCKS5 UDP             | Not Supported                                      |
| Remote Port Forwards   | Supported (server-initiated via `remote` command)  |

## Quick Start

```
operator~# python builder.py -e test
[+] Wrote Python client to 'client.py'

target~# python client.py
[+] Connected to ws://localhost:8080/
```

## Builder Options

Run `builder.py` directly or use `messenger-builder python` from the [Messenger repository](https://github.com/skylerknecht/messenger).

Options provided to the builder are hardcoded into the output script. The operator can override them at runtime with the same flags.

### Builder-Only Options

| Flag                  | Default    | Description                                                        |
|-----------------------|------------|--------------------------------------------------------------------|
| `--name`              | client.py  | Output filename                                                    |
| `--non-main-thread`   | off        | Build for non-main-thread execution (not CTRL+C-safe on WebSocket) |
| `--no-print`          | off        | Suppress all stdout/stderr at startup                              |

### Client Configuration

| Flag                    | Default        | Description                              |
|-------------------------|----------------|------------------------------------------|
| `--server-url`          | localhost:8080 | Server URL (protocol sets transport)     |
| `-e`, `--encryption-key`| (none)        | AES encryption key                       |
| `--user-agent`          | Chrome 141     | HTTP/WebSocket User-Agent string         |
| `--proxy`               | (none)         | HTTP proxy (`http://user:pass@host:port`)|

### Retry Behavior

| Flag                | Default | Description                           |
|---------------------|---------|---------------------------------------|
| `--retry-duration`  | 60      | Total seconds to keep retrying        |
| `--retry-attempts`  | 5       | Number of reconnection attempts       |

Set `--retry-attempts 0` to disable reconnection.

## Transport Selection

The protocol in `--server-url` determines the transport:

- `http://` or `https://` — HTTP polling
- `ws://` or `wss://` — WebSocket

## Remote Port Forwards

Remote port forwards are configured server-side with the `remote` command, not at build time. See the [operator guide](https://github.com/skylerknecht/messenger/blob/main/docs/remote-port-forwards.md).
