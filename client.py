#!/usr/bin/env python3
try:
    import aiohttp
    no_ws = False
except ImportError:
    print('[!] Failed to import AIOHTTP, Websockets will not be supported.')
    no_ws = True

import asyncio
import argparse
import ssl
import struct
import socket
import time
import errno

from abc import ABC, abstractmethod
from urllib import request
from collections import namedtuple

from messenger.message import MessageParser, MessageBuilder
from messenger.generator import alphanumeric_identifier, generate_hash

from messenger.message import CheckInMessage, InitiateForwarderClientReq, InitiateForwarderClientRep, SendDataMessage

ForwarderClient = namedtuple('ForwarderClient', 'reader writer')

HTTP_ROUTE = 'socketio/?EIO=4&transport=polling'
WS_ROUTE = 'socketio/?EIO=4&transport=websocket'
USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0'


class MessengerClient(ABC):
    def __init__(self, encryption_key):
        self.encryption_key = encryption_key
        self.forwarder_clients = {}

        # Accept Self-Signed SSL Certs
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE

        # Change User Agent
        self.headers = {'User-Agent': USER_AGENT}
        self.identifier = None

    async def handle_initiate_forwarder_client_req(self, message):
        try:
            ip = message['IP Address']
            port = message['Port']
            client_id = message['Forwarder Client ID']

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=5
            )
            self.forwarder_clients[client_id] = ForwarderClient(reader, writer)

            bind_info = writer.get_extra_info("sockname")
            bind_addr = bind_info[0]
            bind_port = bind_info[1]

            sock = writer.get_extra_info("socket")
            family = sock.family
            atype = 1 if family == socket.AF_INET else 4

            downstream_message = InitiateForwarderClientRep(
                forwarder_client_id=client_id,
                bind_address=bind_addr,
                bind_port=bind_port,
                address_type=atype,
                reason=0
            )

            asyncio.create_task(self.stream(client_id))
        except socket.gaierror:
            reason = 4
        except socket.timeout:
            reason = 6
        except ConnectionRefusedError:
            reason = 5
        except OSError as e:
            reason = {
                errno.ENETUNREACH: 3,
                errno.EHOSTUNREACH: 4,
                errno.ECONNREFUSED: 5,
                errno.ENOPROTOOPT: 7,
                errno.EAFNOSUPPORT: 8
            }.get(e.errno, 1)
        except Exception:
            reason = 1
        else:
            await self.send_downstream_message(downstream_message)
            return

        downstream_message = InitiateForwarderClientRep(
            forwarder_client_id=message["Forwarder Client ID"],
            bind_address="0.0.0.0",
            bind_port=0,
            address_type=1,
            reason=reason
        )

        await self.send_downstream_message(downstream_message)
        return

    async def start_remote_port_forwards(self, remote_port_forwards):
        for remote_port_forward in remote_port_forwards:
            remote_forward = RemotePortForwarder(self, remote_port_forward)
            await remote_forward.start()

    def serialize_messages(self, messages):
        data = b''
        for message in messages:
            data += MessageBuilder.serialize_message(self.encryption_key, message)
        return data

    def deserialize_messages(self, data: bytes):
        """
        Parses ALL messages from 'data' until it's exhausted or insufficient
        for another header. Returns a list of (message_type, parsed_message).
        """
        messages = []
        while True:
            # If we don't have at least 8 bytes, we can't read another header
            if len(data) < 8:
                break

            # Peek at the length from the header to see if there's enough payload
            # to parse. We can do a quick check here or just rely on our single parse.
            potential_length = struct.unpack('!I', data[4:8])[0]

            # If the total needed is more than we have, we can't parse further
            if len(data) < potential_length:
                break  # or raise an error if you want strictness

            # Now parse one message
            remaining_data, message = MessageParser.deserialize_message(self.encryption_key, data)
            messages.append(message)
            data = remaining_data

        return messages

    async def handle_message(self, message):
        """
        Here, 'message' is a named tuple: InitiateForwarderClientReq,
        InitiateForwarderClientRep, or SendDataMessage.
        """
        if isinstance(message, InitiateForwarderClientReq):
            await self.handle_initiate_forwarder_client_req({
                "IP Address": message.ip_address,
                "Port": message.port,
                "Forwarder Client ID": message.forwarder_client_id
            })

        elif isinstance(message, InitiateForwarderClientRep):
            asyncio.create_task(self.stream(message.forwarder_client_id))

        elif isinstance(message, SendDataMessage):
            forwarder_client = self.forwarder_clients.get(message.forwarder_client_id)
            if not forwarder_client:
                return
            forwarder_client.writer.write(message.data)

        else:
            print(f"Received unknown message type: {type(message).__name__}")

    @abstractmethod
    async def stream(self, message_id):
        raise NotImplementedError

    @abstractmethod
    async def send_downstream_message(self, message_data):
        raise NotImplementedError


class WebSocketClient(MessengerClient):
    def __init__(self, server_url: str, encryption_key, remote_port_forwards: str, proxy: str = None):
        super().__init__(encryption_key)
        self.server_url = server_url
        self.remote_port_forwards = remote_port_forwards
        self.proxy = proxy
        self.ws = None

    async def connect(self) -> str:
        """
        1) Start remote port forwards
        2) Create a session
        3) Open a WebSocket to self.server_url
        4) Perform an initial handshake (send CheckInMessage, wait for the server's check-in response)
        5) Return the messenger_id once received
        """
        await self.start_remote_port_forwards(self.remote_port_forwards)

        # Create a persistent ClientSession
        self.session = aiohttp.ClientSession(headers=self.headers)

        # Connect the WebSocket
        self.ws = await self.session.ws_connect(
            self.server_url,
            ssl=self.ssl_context,
            proxy=self.proxy
        )

        # --- Perform a "check in" to get messenger_id from the server ---
        check_in_msg = self.serialize_messages([CheckInMessage(messenger_id='')])
        await self.ws.send_bytes(check_in_msg)

        # Now wait for the server’s response that includes our messenger_id
        while True:
            msg = await self.ws.receive()
            messages = self.deserialize_messages(msg.data)
            check_in_msg = messages[0]
            assert isinstance(check_in_msg, CheckInMessage), "Expected CheckInMessage, got something else"
            self.identifier = check_in_msg.messenger_id
            break

    async def start(self):
        async for msg in self.ws:
            messages = self.deserialize_messages(msg.data)
            for message in messages:
                try:
                    asyncio.create_task(self.handle_message(message))
                except:
                    continue

        print('[*] Disconnected from server attempt to reconnect')

        timeout = 1800  # 30 minutes
        deadline = time.time() + timeout

        while time.time() < deadline:
            try:
                await asyncio.sleep(15)
                self.ws = await self.session.ws_connect(self.server_url)
                downstream_messages = [CheckInMessage(messenger_id=self.identifier)]
                await self.ws.send_bytes(self.serialize_messages(downstream_messages))
                print("[+] Reconnected and check-in sent.")
                return await self.start()  # restart loop cleanly
            except Exception as e:
                print(f"[!] Reconnect failed: {type(e).__name__}")

        print("[-] Reconnect timeout after 30 minutes. Giving up.")

    async def stop(self):
        if self.ws is not None and not self.ws.closed:
            await self.ws.close()

        if self.session is not None and not self.session.closed:
            await self.session.close()

    async def send_downstream_message(self, downstream_message):
        downstream_messages = [CheckInMessage(messenger_id=self.identifier), downstream_message]
        await self.ws.send_bytes(self.serialize_messages(downstream_messages))

    async def stream(self, forwarder_client_identifier):
        forwarder_client = self.forwarder_clients[forwarder_client_identifier]
        while True:
            try:
                msg = await forwarder_client.reader.read(4096)
                if not msg:
                    break

                downstream_message = SendDataMessage(
                    forwarder_client_id=forwarder_client_identifier,
                    data=msg
                )
                await self.send_downstream_message(downstream_message)
            except (EOFError, ConnectionResetError):
                break

        downstream_message = SendDataMessage(
            forwarder_client_id=forwarder_client_identifier,
            data=b''
        )
        await self.send_downstream_message(downstream_message)
        del self.forwarder_clients[forwarder_client_identifier]


class HTTPClient(MessengerClient):
    def __init__(self, server_url, encryption_key, remote_port_forwards: str, proxy: str = None):
        super().__init__(encryption_key)
        self.server_url = server_url
        self.remote_port_forwards = remote_port_forwards
        self.downstream_messages = asyncio.Queue()
        self.ssl_context = ssl.create_default_context()

        proxy_handler = request.ProxyHandler({
            'http': proxy,
            'https': proxy
        } if proxy else {})

        https_handler = request.HTTPSHandler(context=self.ssl_context)
        self.opener = request.build_opener(proxy_handler, https_handler)

    async def connect(self):
        await self.start_remote_port_forwards(self.remote_port_forwards)

        downstream_messages = [CheckInMessage(messenger_id='')]
        check_in_request = request.Request(
            self.server_url,
            headers=self.headers,
            data=self.serialize_messages(downstream_messages)
        )

        with self.opener.open(check_in_request) as response:
            if response.status != 200:
                return
            messages = self.deserialize_messages(response.read())
            check_in_msg = messages[0]
            assert isinstance(check_in_msg, CheckInMessage), "Expected CheckInMessage, got something else"
            self.identifier = check_in_msg.messenger_id

    async def start(self):
        timeout = 1800  # 30 minutes
        retry_interval = 15
        deadline = time.time() + timeout

        while True:
            try:
                to_send = [CheckInMessage(messenger_id=self.identifier)]
                while not self.downstream_messages.empty():
                    to_send.append(await self.downstream_messages.get())

                check_in_req = request.Request(
                    self.server_url,
                    headers=self.headers,
                    data=self.serialize_messages(to_send)
                )

                with self.opener.open(check_in_req) as response:
                    if response.status != 200:
                        raise ConnectionError(f"Bad status: {response.status}")

                    raw_data = response.read()
                    messages = self.deserialize_messages(raw_data)
                    for message in messages:
                        asyncio.create_task(self.handle_message(message))

                await asyncio.sleep(1.0)

            except Exception as e:
                print(f"[!] HTTPClient error: {type(e).__name__}, attempting to reconnect...")
                while time.time() < deadline:
                    await asyncio.sleep(retry_interval)
                    try:
                        # Try a basic check-in
                        check_req = request.Request(
                            self.server_url,
                            headers=self.headers,
                            data=self.serialize_messages([CheckInMessage(messenger_id=self.identifier)])
                        )
                        with self.opener.open(check_req) as response:
                            if response.status == 200:
                                print("[+] Reconnected and check-in successful.")
                                break
                    except Exception as retry_err:
                        print(f"[!] Retry failed: {type(retry_err).__name__}")
                else:
                    print("[-] Failed to reconnect after 30 minutes. Exiting.")
                    return

    async def send_downstream_message(self, downstream_message):
        """
        Enqueue the named tuple to send on the next poll.
        """
        await self.downstream_messages.put(downstream_message)

    async def stream(self, forwarder_client_identifier):
        forwarder_client = self.forwarder_clients[forwarder_client_identifier]
        while True:
            try:
                msg = await forwarder_client.reader.read(4096)
                if not msg:
                    break

                # Build a SendDataMessage
                downstream_message = SendDataMessage(
                    forwarder_client_id=forwarder_client_identifier,
                    data=msg
                )
                await self.send_downstream_message(downstream_message)
            except (EOFError, ConnectionResetError):
                break

        # Send one final empty
        empty_message = SendDataMessage(
            forwarder_client_id=forwarder_client_identifier,
            data=b''
        )
        await self.send_downstream_message(empty_message)
        del self.forwarder_clients[forwarder_client_identifier]


class RemotePortForwarder:
    def __init__(self, messenger, config):
        self.messenger = messenger
        self.listening_host, self.listening_port, self.destination_host, self.destination_port = self.parse_config(
            config)
        self.name = 'Remote Port Forwarder'
        self.identifier = alphanumeric_identifier()

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        forwarder_client = ForwarderClient(reader, writer)
        forwarder_client_id = alphanumeric_identifier()

        downstream_message = InitiateForwarderClientReq(
            forwarder_client_id=forwarder_client_id,
            ip_address=self.destination_host,
            port=int(self.destination_port)
        )
        await self.messenger.send_downstream_message(downstream_message)

        self.messenger.forwarder_clients[forwarder_client_id] = forwarder_client

    def parse_config(self, config):
        parts = config.split(':')
        return parts

    async def start(self):
        try:
            await asyncio.start_server(self.handle_client, self.listening_host, int(self.listening_port))
        except OSError:
            print(f'{self.listening_host}:{self.listening_port} is already in use.')
            return
        print(f'{self.name} {self.identifier} is listening on {self.listening_host}:{self.listening_port}')


class Messenger:
    def __init__(self, server_url, encryption_key, remote_port_forwards, proxy, continue_after_success):
        self.server_url = server_url
        self.encryption_key = encryption_key
        self.remote_port_forwards = remote_port_forwards
        self.proxy = proxy
        self.continue_after_success = continue_after_success
        self.connected_successfully = False

    async def start(self):
        # If user gave e.g. "ws+http://example.com", attempts = ["ws", "http"]
        # Otherwise default to ["ws", "http", "wss", "https"]
        remainder = self.server_url
        if "://" in self.server_url:
            scheme, remainder = self.server_url.split("://", 1)
            attempts = scheme.split('+')
        else:
            attempts = ["ws", "http", "wss", "https"]

        for attempt in attempts:
            if self.connected_successfully and not self.continue_after_success:
                return
            candidate_url = f"{attempt}://{remainder}/"
            if "http" in attempt:
                print('[*] Attempting to connect to Messenger Server over HTTP')
                await self.try_http(candidate_url, self.encryption_key, self.remote_port_forwards, self.proxy)
            if "ws" in attempt and not no_ws:
                print('[*] Attempting to connect to Messenger Server over WebSockets')
                if attempt == "wss":
                    candidate_url = f"https://{remainder}/"
                else:
                    candidate_url = f"http://{remainder}/"
                await self.try_ws(candidate_url, self.encryption_key, self.remote_port_forwards, self.proxy)
        print('Messenger Client stopped.')

    async def try_http(self, candidate_url, encryption_key, remote_port_forwards, proxy):
        try:
            messenger_client = HTTPClient(f'{candidate_url}{HTTP_ROUTE}', encryption_key, remote_port_forwards, proxy)
            await messenger_client.connect()
            if not messenger_client.identifier:
                print('[!] Failed to connect to Messenger Server over HTTP')
                return
            print(f'[+] Successfully connected to {candidate_url}{HTTP_ROUTE}')
            self.connected_successfully = True
            await messenger_client.start()
        except Exception:
            print('[!] Failed to connect to Messenger Server over HTTP')
            return

    async def try_ws(self, candidate_url, encryption_key, remote_port_forwards, proxy):
        messenger_client = WebSocketClient(f'{candidate_url}{WS_ROUTE}', encryption_key, remote_port_forwards, proxy)
        try:
            await messenger_client.connect()
            if not messenger_client.identifier:
                print('[!] Failed to connect to Messenger Server over WebSockets')
                return
            print(f'[+] Successfully connected to {candidate_url}{WS_ROUTE}')
            self.connected_successfully = True
            await messenger_client.start()
            await messenger_client.stop()
        except Exception:
            await messenger_client.stop()
            print('[!] Failed to connect to Messenger Server over WS')
            return


async def main(args):
    server_url = args.server_url.strip('/')
    encryption_key = generate_hash(args.encryption_key)
    remote_port_forwards = args.remote_port_forwards
    proxy = args.proxy
    continue_after_success = args.continue_after_success

    messenger = Messenger(server_url, encryption_key, remote_port_forwards, proxy, continue_after_success)

    await messenger.start()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Messenger Client for establishing HTTP or WebSocket connections with remote port forwarding."
    )

    parser.add_argument(
        'server_url',
        type=str,
        help="The URL of the server to connect to. This should include the scheme (e.g. ws://, wss://, http://, https://) "
             "and the domain or IP address. For example: 'ws://example.com' or 'https://example.com'. "
             "If no scheme is provided, it will try 'ws', 'wss', 'http', and 'https'."
    )

    parser.add_argument(
        'encryption_key',
        type=str,
        help="The AES encryption key to use for encryption."
    )

    parser.add_argument(
        'remote_port_forwards',
        type=str,
        nargs='*',
        help="A list of remote port forwarding configurations. Each configuration should be in the format "
             "'listening_host:listening_port:destination_host:destination_port'. "
             "For example: '127.0.0.1:8080:example.com:80'. This sets up port forwarding from a local listening address "
             "and port to a remote destination address and port."
    )

    parser.add_argument(
        '--proxy',
        type=str,
        help="Optional proxy server URL."
    )

    parser.add_argument(
        '--continue-after-success',
        action='store_true',
        default=False,
        help='If a attempt were to fail after being successfully connected, continue trying other schemas.'
    )

    args = parser.parse_args()
    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        print('\rMessenger Client stopped.')
