# Python Messenger Client

![CI](https://img.shields.io/github/actions/workflow/status/skylerknecht/messenger-client-python/python-version-tests.yml?branch=main&label=Python%20Version%20Tests)

## Overview

The Client is a cross-platform compatible Messenger Client supporting Python v3.6+.

## Quick Start

```
operator~# ./builder.py --encryption-key test
Wrote Python client to 'client.py'
operator~# ./client.py 
[+] Connected to http://localhost:8080/socketio/?EIO=4&transport=websocket
```

## Primary Capabilities

| Capability                 | Support Status                                         |
|----------------------------|--------------------------------------------------------|
| Transports                 | HTTP and WebSockets                                    |
| Encryption                 | AES-256-CBC with random IV prefix.                     |
| Reconnection procedure     | Defaults to five (5) attempts over sixty (60) seconds. |
| SOCKS5 TCP                 | Supported                                              |
| SOCKS5 UDP                 | Not Supported                                          |

## Client-Specific Capabilities

| Capability                    | Support Status                                                                                          |
|-------------------------------|---------------------------------------------------------------------------------------------------------|
| Multi-Threaded Deploy-ability | Provide `--non-main-thread` to the builder script if the client is not meant to run in the main thread. |

## Usage

To build the client, execute `builder.py` or `messenger-builder` from the [Messenger Repository](https://github.com/skylerknecht/messenger).

Both scripts accept the same options and will generate a Python Messenger Client. If provided options, the builder scripts
will hard-code the options into the script. Once built, the operator can specify command-line arguments that will override
the hardcoded options. Those options and their definitions are shown below. 

## Client Options

| Option                                        | Flag                      | Default Value          |
|-----------------------------------------------|---------------------------|------------------------|
| [Server URL](#server-url)                     | `--server-url`            | ws://localhost:8080    |
| [Encryption Key](#encryption-key)             | `--encryption-key`        | None                   |
| [User Agent](#user-agent)                     | `--user-agent`            | None                   |
| [Proxy](#proxy)                               | `--proxy`                 | None                   |
| [Remote Port Forwards](#remote-port-forwards) | `--remote-port-forwards`  | None                   |
| [Retry Duration](#retry-duration)             | `--retry-duration`        | One Minute             |
| [Retry Attempts](#retry-attempts)             | `--retry-attempts`        | Five                   |
| [Name](#name)                                 | `--name`                  | client.py              |

### Server URL

Once the Messenger Server is running, the operator will be provided a server URL that can be set with `--server-url`. 

```
builder.py --server-url http://localhost:8080
```

The client will attempt to establish a connection to the server based on the protocol specified in the server URL. For HTTP, leave the protocol as 
`http://`, for websockets use `ws://`. Given that the server is listening with SSL encryption, provide the SSL 
alternative to each protocol. 

#### Encryption Key

Messenger Server will also provide an encryption key upon startup that can be hardcoded.

```
builder.py --encryption-key SuP3rs_crEtk3y
```

Since the server expects encryption, the default will likely cause issues; therefore, the client outputs an 
error.

```
[!] No encryption key provided, please specify one with --encryption-key.
```

#### User Agent

For HTTP-based protocols, the operator can control the user-agent header. 

```
builder.py --user-agent "Test User Agent"
```

#### Proxy

Enterprise environments typically have outbound proxies. Operators can provide a proxy using the HTTP-proxy schema. 

```
builder.py --proxy http://user:password@localhost:8080
```

#### Remote Port Forwards



#### Retry Duration

#### Retry Attempts
