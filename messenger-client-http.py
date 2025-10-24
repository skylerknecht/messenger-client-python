import asyncio
import argparse
import base64
import errno
import hashlib
import os
import random
import ssl
import sys
import struct
import socket
import string

from collections import namedtuple
from urllib import request
from urllib.error import HTTPError, URLError

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
import os

s_box = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

inv_s_box = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)


def sub_bytes(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = s_box[s[i][j]]


def inv_sub_bytes(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = inv_s_box[s[i][j]]


def shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]


def inv_shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]


def add_round_key(s, k):
    for i in range(4):
        for j in range(4):
            s[i][j] ^= k[i][j]


xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


def mix_single_column(a):
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)


def mix_columns(s):
    for i in range(4): mix_single_column(s[i])


def inv_mix_columns(s):
    for i in range(4):
        u = xtime(xtime(s[i][0] ^ s[i][2]))
        v = xtime(xtime(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v

    mix_columns(s)


r_con = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)


def bytes2matrix(text):
    return [list(text[i:i + 4]) for i in range(0, len(text), 4)]


def matrix2bytes(matrix):
    return bytes(sum(matrix, []))


def xor_bytes(a, b):
    return bytes(i ^ j for i, j in zip(a, b))


def inc_bytes(a):
    out = list(a)
    for i in reversed(range(len(out))):
        if out[i] == 0xFF:
            out[i] = 0
        else:
            out[i] += 1
            break
    return bytes(out)


def pad(plaintext):
    padding_len = 16 - (len(plaintext) % 16)
    padding = bytes([padding_len] * padding_len)
    return plaintext + padding


def unpad(plaintext):
    padding_len = plaintext[-1]
    assert padding_len > 0
    message, padding = plaintext[:-padding_len], plaintext[-padding_len:]
    assert all(p == padding_len for p in padding)
    return message


def split_blocks(message, block_size=16, require_padding=True):
    assert len(message) % block_size == 0 or not require_padding
    return [message[i:i + 16] for i in range(0, len(message), block_size)]


class AES:
    rounds_by_key_size = {16: 10, 24: 12, 32: 14}

    def __init__(self, master_key):
        assert len(master_key) in AES.rounds_by_key_size
        self.n_rounds = AES.rounds_by_key_size[len(master_key)]
        self._key_matrices = self._expand_key(master_key)

    def _expand_key(self, master_key):
        key_columns = bytes2matrix(master_key)
        iteration_size = len(master_key) // 4
        columns_per_iteration = len(key_columns)
        i = 1
        while len(key_columns) < (self.n_rounds + 1) * 4:
            word = list(key_columns[-1])
            if len(key_columns) % iteration_size == 0:
                word.append(word.pop(0))
                word = [s_box[b] for b in word]
                word[0] ^= r_con[i]
                i += 1
            elif len(master_key) == 32 and len(key_columns) % iteration_size == 4:
                word = [s_box[b] for b in word]

            word = xor_bytes(word, key_columns[-iteration_size])
            key_columns.append(word)
        return [key_columns[4 * i: 4 * (i + 1)] for i in range(len(key_columns) // 4)]

    def encrypt_block(self, plaintext):
        assert len(plaintext) == 16
        plain_state = bytes2matrix(plaintext)
        add_round_key(plain_state, self._key_matrices[0])
        for i in range(1, self.n_rounds):
            sub_bytes(plain_state)
            shift_rows(plain_state)
            mix_columns(plain_state)
            add_round_key(plain_state, self._key_matrices[i])
        sub_bytes(plain_state)
        shift_rows(plain_state)
        add_round_key(plain_state, self._key_matrices[-1])

        return matrix2bytes(plain_state)

    def decrypt_block(self, ciphertext):
        assert len(ciphertext) == 16
        cipher_state = bytes2matrix(ciphertext)
        add_round_key(cipher_state, self._key_matrices[-1])
        inv_shift_rows(cipher_state)
        inv_sub_bytes(cipher_state)

        for i in range(self.n_rounds - 1, 0, -1):
            add_round_key(cipher_state, self._key_matrices[i])
            inv_mix_columns(cipher_state)
            inv_shift_rows(cipher_state)
            inv_sub_bytes(cipher_state)
        add_round_key(cipher_state, self._key_matrices[0])
        return matrix2bytes(cipher_state)

    def encrypt_cbc(self, plaintext, iv):
        assert len(iv) == 16
        plaintext = pad(plaintext)
        blocks = []
        previous = iv
        for plaintext_block in split_blocks(plaintext):
            block = self.encrypt_block(xor_bytes(plaintext_block, previous))
            blocks.append(block)
            previous = block
        return b''.join(blocks)

    def decrypt_cbc(self, ciphertext, iv):
        assert len(iv) == 16
        blocks = []
        previous = iv
        for ciphertext_block in split_blocks(ciphertext):
            blocks.append(xor_bytes(previous, self.decrypt_block(ciphertext_block)))
            previous = ciphertext_block
        return unpad(b''.join(blocks))

try:
    from Crypto import Random
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad

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
except:
    def encrypt(key: bytes, plaintext: bytes) -> bytes:
        # Encrypt the plaintext bytes with a provided key.
        # Generate a new 16-byte IV and include that at the beginning of the ciphertext
        iv = os.urandom(16)
        aes = AES(key)
        ciphertext = aes.encrypt_cbc(plaintext, iv)
        return iv + ciphertext

    def decrypt(key: bytes, ciphertext: bytes) -> bytes:
        # Note that the first 16 bytes of the ciphertext contain the IV
        iv = ciphertext[:16]
        aes = AES(key)
        ciphertext = ciphertext[16:]
        return aes.decrypt_cbc(ciphertext, iv)

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
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        self.identifier = ''
        self.forwarder_clients = {}
        self.downstream_messages = asyncio.Queue()
        self.remote_port_forwards = remote_port_forwards
        proxy_handler = request.ProxyHandler({
            'http': proxy,
            'https': proxy
        } if proxy else {})

        https_handler = request.HTTPSHandler(context=self.ssl_context)
        self.opener = request.build_opener(proxy_handler, https_handler)

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

    def _blocking_http_req(self, req, timeout = 10.0):
        with self.opener.open(req, timeout=timeout) as resp:
            assert getattr(resp, "status", None) == 200, "[*] Non-200 response during initial connection, exiting"
            return resp.read()

    async def connect(self):
        await self.start_remote_port_forwards(self.remote_port_forwards)
        downstream_messages = [CheckInMessage(messenger_id='')]
        req = request.Request(
            self.server_endpoint,
            headers=self.headers,
            data=self.serialize_messages(downstream_messages)
        )
        loop = asyncio.get_event_loop()
        resp = await loop.run_in_executor(None, self._blocking_http_req, req, 10.0)
        messages = self.deserialize_messages(resp)
        check_in_msg = messages[0]
        assert isinstance(check_in_msg, CheckInMessage), "[*] Expected CheckInMessage, got something else"
        self.identifier = check_in_msg.messenger_id
        print(f'[+] Connected to {self.server_endpoint}')

    async def start(self):
        while True:
            to_send = [CheckInMessage(messenger_id=self.identifier)]
            for _ in range(5):
                 if self.downstream_messages.empty():
                     break
                 to_send.append(await self.downstream_messages.get())

            req = request.Request(
                self.server_endpoint,
                headers=self.headers,
                data=self.serialize_messages(to_send)
            )

            loop = asyncio.get_event_loop()
            resp = await loop.run_in_executor(None, self._blocking_http_req, req, 10.0)
            messages = self.deserialize_messages(resp)
            for message in messages:
                asyncio.create_task(self.handle_message(message))
            await asyncio.sleep(0.1)

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
        await self.downstream_messages.put(downstream_message)


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
    server = server.strip('/') + '/socketio/?EIO=4&transport=polling'
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