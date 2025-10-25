# Python Messenger Client

![CI](https://img.shields.io/github/actions/workflow/status/skylerknecht/messenger-client-python/python-version-tests.yml?branch=main&label=Python%20Version%20Tests)

### Overview

The Client is a cross-platform compatible Messenger Client supporting Python v3.6+.

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

### Building

To build the client execute `builder.py` or `messenger-builder` from the [Messenger Repository](https://github.com/skylerknecht/messenger).

Both scripts accept the same options, for more detail one each see below.

#### Server URL

Once the Messenger Server is running the operator will be provided a Server URL that can be provided here. 

```
builder.py --server-url http://localhost:8080
```

If not provided, the builder script will default to `http://localhost:8080`. The client will attempt to establish to the server based on the protocol specified in the Server URL. For http leave the protocol as `http://`, for websockets use `ws://`. 
Given the server is listening with SSL encryption provide the SSL alternative to each protocol. 

