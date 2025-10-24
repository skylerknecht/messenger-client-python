import argparse
import aiohttp
import asyncio
import base64
import errno
import hashlib
import random
import ssl
import sys
import struct
import socket
import string

from collections import namedtuple
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def generate_hash(hash_input: str) -> bytes:
    hasher = hashlib.sha256()
    hash_input = hash_input.encode('utf-8')
    hasher.update(hash_input)
    return hasher.digest()

ForwarderClient = namedtuple('ForwarderClient', 'reader writer')
alphanumeric = list(string.ascii_letters + string.digits)
alphabet = list(string.ascii_letters)

def alphanumeric_identifier(length: int = 10) -> str:
    _identifier = [alphanumeric[random.randint(0, len(alphabet) - 1)] for _ in range(0, length)]
    _identifier = ''.join(_identifier)
    return _identifier


### AES ###

def decrypt(key: bytes, ciphertext: bytes) -> bytes:
    # Note that the first AES.block_size bytes of the ciphertext
    # contain the IV
    iv = ciphertext[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    msg = unpad(cipher.decrypt(ciphertext[16:]), AES.block_size)
    return msg

def encrypt(key: bytes, plaintext: bytes) -> bytes:
    # Encrypt the plaintext bytes with a provided key.
    # Generate a new 16 byte IV and include that
    # at the begining of the ciphertext
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    msg = cipher.encrypt(pad(plaintext, AES.block_size))
    return iv + msg


### Message Structures ###

CheckInMessage = namedtuple('CheckInMessage', ['messenger_id'])
InitiateForwarderClientReq = namedtuple('InitiateForwarderClientReq', ['forwarder_client_id', 'ip_address', 'port'])
InitiateForwarderClientRep = namedtuple('InitiateForwarderClientRep', ['forwarder_client_id', 'bind_address', 'bind_port', 'address_type', 'reason'])
SendDataMessage = namedtuple('SendDataMessage', ['forwarder_client_id', 'data'])

class MessageParser:
    @staticmethod
    def read_uint32(data: bytes) -> (int, bytes):
        unsigned_32bit = data[:4]               # The 4-byte integer
        remaining_data = data[4:]               # Everything after the 4 bytes
        (value,) = struct.unpack('!I', unsigned_32bit)
        return value, remaining_data

    @staticmethod
    def read_string(data: bytes) -> (str, bytes):
        length, data = MessageParser.read_uint32(data)
        s = data[:length].decode('utf-8')
        return s, data[length:]

    @staticmethod
    def parse_check_in(value: bytes) -> CheckInMessage:
        messenger_id, _ = MessageParser.read_string(value)
        return CheckInMessage(messenger_id=messenger_id)

    @staticmethod
    def parse_initiate_forwarder_client_req(value: bytes) -> InitiateForwarderClientReq:
        forwarder_client_id, value = MessageParser.read_string(value)
        ip_address, value = MessageParser.read_string(value)
        port, value = MessageParser.read_uint32(value)
        return InitiateForwarderClientReq(
            forwarder_client_id=forwarder_client_id,
            ip_address=ip_address,
            port=port
        )

    @staticmethod
    def parse_initiate_forwarder_client_rep(value: bytes) -> InitiateForwarderClientRep:
        forwarder_client_id, value = MessageParser.read_string(value)
        bind_address, value = MessageParser.read_string(value)
        bind_port, value = MessageParser.read_uint32(value)
        address_type, value = MessageParser.read_uint32(value)
        reason, value = MessageParser.read_uint32(value)
        return InitiateForwarderClientRep(
            forwarder_client_id=forwarder_client_id,
            bind_address=bind_address,
            bind_port=bind_port,
            address_type=address_type,
            reason=reason
        )

    @staticmethod
    def parse_send_data(value: bytes) -> SendDataMessage:
        forwarder_client_id, value = MessageParser.read_string(value)
        encoded_data, value = MessageParser.read_string(value)
        raw_data = base64.b64decode(encoded_data)
        return SendDataMessage(
            forwarder_client_id=forwarder_client_id,
            data=raw_data
        )

    @staticmethod
    def deserialize_message(encryption_key: bytes, raw_data: bytes):
        message_type, data = MessageParser.read_uint32(raw_data)
        message_length, data = MessageParser.read_uint32(data)
        payload_len = message_length - 8
        if len(data) < payload_len:
            raise ValueError("Not enough bytes in data for the payload")
        payload = data[:payload_len]
        leftover = data[payload_len:]
        if message_type == 0x01:
            decrypted = decrypt(encryption_key, payload)
            parsed_msg = MessageParser.parse_initiate_forwarder_client_req(decrypted)
        elif message_type == 0x02:
            decrypted = decrypt(encryption_key, payload)
            parsed_msg = MessageParser.parse_initiate_forwarder_client_rep(decrypted)
        elif message_type == 0x03:
            decrypted = decrypt(encryption_key, payload)
            parsed_msg = MessageParser.parse_send_data(decrypted)
        elif message_type == 0x04:
            parsed_msg = MessageParser.parse_check_in(payload)
        else:
            raise ValueError(f"Unknown message type: {hex(message_type)}")

        return leftover, parsed_msg

class MessageBuilder:
    @staticmethod
    def serialize_message(encryption_key: bytes, msg) -> bytes:
        if isinstance(msg, InitiateForwarderClientReq):
            message_type = 0x01
            value = encrypt(encryption_key, MessageBuilder.build_initiate_forwarder_client_req(
                msg.forwarder_client_id,
                msg.ip_address,
                msg.port
            ))
        elif isinstance(msg, InitiateForwarderClientRep):
            message_type = 0x02
            value = encrypt(encryption_key, MessageBuilder.build_initiate_forwarder_client_rep(
                msg.forwarder_client_id,
                msg.bind_address,
                msg.bind_port,
                msg.address_type,
                msg.reason
            ))
        elif isinstance(msg, SendDataMessage):
            message_type = 0x03
            value = encrypt(encryption_key, MessageBuilder.build_send_data(
                msg.forwarder_client_id,
                msg.data
            ))
        elif isinstance(msg, CheckInMessage):
            message_type = 0x04
            value = MessageBuilder.build_check_in_message(
                msg.messenger_id
            )
        else:
            raise ValueError(f"Unknown message tuple type: {type(msg)}")

        return MessageBuilder.build_message(message_type, value)

    @staticmethod
    def build_message(message_type: int, value: bytes) -> bytes:
        message_length = 8 + len(value)
        header = struct.pack('!II', message_type, message_length)
        return header + value

    @staticmethod
    def build_string(value: str) -> bytes:

        encoded = value.encode('utf-8')
        return struct.pack('!I', len(encoded)) + encoded

    @staticmethod
    def build_check_in_message(messenger_id: str) -> bytes:
        return MessageBuilder.build_string(messenger_id)

    @staticmethod
    def build_initiate_forwarder_client_req(forwarder_client_id: str,
                                            ip_address: str, port: int) -> bytes:
        return (
            MessageBuilder.build_string(forwarder_client_id) +
            MessageBuilder.build_string(ip_address) +
            struct.pack('!I', port)
        )

    @staticmethod
    def build_initiate_forwarder_client_rep(forwarder_client_id: str,
                                            bind_address: str, bind_port: int,
                                            address_type: int, reason: int) -> bytes:
        return (
            MessageBuilder.build_string(forwarder_client_id) +
            MessageBuilder.build_string(bind_address) +
            struct.pack('!III', bind_port, address_type, reason)
        )

    @staticmethod
    def build_send_data(forwarder_client_id: str, data: bytes) -> bytes:
        encoded_data = base64.b64encode(data).decode('utf-8')
        return (
            MessageBuilder.build_string(forwarder_client_id) +
            MessageBuilder.build_string(encoded_data)
        )


class Client:
    def __init__(self, server_endpoint, encryption_key, user_agent, proxy, remote_port_forwards):
        self.server_endpoint = server_endpoint
        self.encryption_key = encryption_key
        self.headers = {'User-Agent': user_agent}
        self.proxy = proxy
        self.session = aiohttp.ClientSession(headers=self.headers)
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        self.identifier = ''
        self.forwarder_clients = {}
        self.remote_port_forwards = remote_port_forwards

    def deserialize_messages(self, data: bytes):
        messages = []
        while True:
            if len(data) < 8:
                break

            potential_length = struct.unpack('!I', data[4:8])[0]

            if len(data) < potential_length:
                break

            remaining_data, message = MessageParser.deserialize_message(self.encryption_key, data)
            messages.append(message)
            data = remaining_data

        return messages

    async def start_remote_port_forwards(self, remote_port_forwards):
        for remote_port_forward in remote_port_forwards:
            remote_forward = RemotePortForwarder(self, remote_port_forward)
            await remote_forward.start()

    async def connect(self):
        await self.start_remote_port_forwards(self.remote_port_forwards)
        self.ws = await self.session.ws_connect(
            self.server_endpoint,
            ssl=self.ssl_context,
            proxy=self.proxy
        )

        check_in_msg = self.serialize_messages([CheckInMessage(messenger_id='')])
        await self.ws.send_bytes(check_in_msg)

        msg = await self.ws.receive()
        messages = self.deserialize_messages(msg.data)
        check_in_msg = messages[0]
        assert isinstance(check_in_msg, CheckInMessage), f"Expected CheckInMessage, got {type(check_in_msg)}"
        self.identifier = check_in_msg.messenger_id
        print(f'Connected to {self.server_endpoint}')

    async def start(self):
        async for msg in self.ws:
            messages = self.deserialize_messages(msg.data)
            for message in messages:
                asyncio.create_task(self.handle_message(message))

    async def handle_message(self, message):
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

    def serialize_messages(self, messages):
        data = b''
        for message in messages:
            data += MessageBuilder.serialize_message(self.encryption_key, message)
        return data

    async def send_downstream_message(self, downstream_message):
        downstream_messages = [CheckInMessage(messenger_id=self.identifier), downstream_message]
        await self.ws.send_bytes(self.serialize_messages(downstream_messages))
        await asyncio.sleep(0.1)

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

def parse_args():
    parser = argparse.ArgumentParser(description="Messenger Client Runner")

    parser.add_argument("--server", default=None)
    parser.add_argument("--encryption-key", default=None)
    parser.add_argument("--user-agent", default=None)
    parser.add_argument("--proxy", default=None)
    parser.add_argument("--remote-port-forwards", nargs="*", default=None)

    return parser.parse_args()

DEFAULT_SERVER = "http://127.0.0.1:9090"
DEFAULT_ENCRYPTION_KEY = "lol"
DEFAULT_USER_AGENT = "help"
DEFAULT_PROXY = ""
DEFAULT_REMOTE_PORT_FORWARDS = []

async def main():
    args = parse_args()

    server = args.server or DEFAULT_SERVER
    server = server.strip('/') + '/socketio/?EIO=4&transport=websocket'
    encryption_key = generate_hash(args.encryption_key or DEFAULT_ENCRYPTION_KEY)
    user_agent = args.user_agent or DEFAULT_USER_AGENT
    proxy = args.proxy or DEFAULT_PROXY
    remote_port_forwards = args.remote_port_forwards or DEFAULT_REMOTE_PORT_FORWARDS

    client = Client(server, encryption_key, user_agent, proxy, remote_port_forwards)

    await client.connect()
    await client.start()

def run_coro_in_thread(coro):
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(coro)
    finally:
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()


#run_coro_in_thread(main())
loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)
try:
    loop.run_until_complete(main())
except KeyboardInterrupt:
    print('\rShutdown')