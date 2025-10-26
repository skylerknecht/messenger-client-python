# Python Messenger Client

![CI](https://img.shields.io/github/actions/workflow/status/skylerknecht/messenger-client-python/python-version-tests.yml?branch=main&label=Python%20Version%20Tests)

### Overview

The Client is a cross-platform compatible Messenger Client supporting Python v3.6+.

### Quick Start

```
operator~# ./builder.py --encryption-key test
Wrote Python client to 'client.py'
operator~# ./client.py 
[+] Connected to http://localhost:8080/socketio/?EIO=4&transport=websocket
```

### Primary Capabilities

| Capability                 | Support Status                                         |
|----------------------------|--------------------------------------------------------|
| Transports                 | HTTP and WebSockets                                    |
| Encryption                 | AES-256-CBC with random IV prefix.                     |
| Reconnection procedure     | Defaults to five (5) attempts over sixty (60) seconds. |
| SOCKS5 TCP                 | Supported                                              |
| SOCKS5 UDP                 | Not Supported                                          |

### Client-Specific Capabilities

| Capability                    | Support Status                                                                                          |
|-------------------------------|---------------------------------------------------------------------------------------------------------|
| Multi-Threaded Deploy-ability | Provide `--non-main-thread` to the builder script if the client is not meant to run in the main thread. | |

### Usage

To build the client execute `builder.py` or `messenger-builder` from the [Messenger Repository](https://github.com/skylerknecht/messenger).

Both scripts accept the same options and will generate a Python Messenger Client. If provided options, the builder scripts
will hardcode the options into the script. Once built, the operator can specify command line arguments that will override
the hardcoded options. Those options and their definitions can be seen below. 

### Client Options

#### Server URL 
*Default: ws://localhost:8080*

Once the Messenger Server is running the operator will be provided a sever url that can be provided here. 

```
builder.py --server-url http://localhost:8080
```

The client will attempt to establish a connection to the server based on the protocol specified in the server url. For http leave the protocol as 
`http://`, for websockets use `ws://`. Given the server is listening with SSL encryption provide the SSL 
alternative to each protocol. 

#### Encryption Key

Messenger Server will also provide an encryption key upon startup that can be hardcoded.

```
builder.py --encryption-key SuP3rs_crEtk3y
```

**Default:** None

Since the server excepts encryption the default will likely cause issues, therefore the client outputs an 
error.

```
[!] No encryption key provided, please specify one with --encryption-key.
```

#### User Agent

For http-based protocols the operator can control the user-agent header. 

```
builder.py --user-agent "Test User Agent"
```



#### Proxy

#### Remote Port Forwards

#### Retry Duration

#### Retry Attempts
