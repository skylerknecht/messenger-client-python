#!/usr/bin/env python3
"""Tiny server shim: accepts one client check-in over WS, replies, sends checkout."""

import asyncio
import struct
import sys

try:
    import websockets
except ImportError:
    print("[!] pip install websockets", file=sys.stderr)
    sys.exit(1)


def build_string(s):
    encoded = s.encode("utf-8")
    return struct.pack("!I", len(encoded)) + encoded


def build_message(msg_type, payload):
    length = 8 + len(payload)
    return struct.pack("!II", msg_type, length) + payload


def parse_checkin(data):
    msg_type = struct.unpack("!I", data[:4])[0]
    if msg_type != 0x04:
        return None
    offset = 8  # skip type + length
    str_len = struct.unpack("!I", data[offset:offset+4])[0]
    client_id = data[offset+4:offset+4+str_len].decode("utf-8")
    return client_id


async def handle(ws, path=None):
    data = await ws.recv()
    if isinstance(data, str):
        data = data.encode()
    client_id = parse_checkin(data)
    if client_id is None:
        await ws.close()
        return

    assigned_id = client_id or "shim-test-id"
    reply = build_message(0x04, build_string(assigned_id))
    await ws.send(reply)

    await asyncio.sleep(0.3)

    checkout = build_message(0x07, b"")
    await ws.send(checkout)
    await ws.close()


async def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9999
    server = await websockets.serve(handle, "127.0.0.1", port)
    print(f"READY {port}", flush=True)
    await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
