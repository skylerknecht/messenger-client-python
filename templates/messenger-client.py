import argparse
import asyncio
import base64
import errno
import hashlib
import os
import secrets
import ssl
import struct
import socket
import string
import sys

from collections import namedtuple
from urllib import request

pycrypto = False
try:
    from Crypto import Random
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    pycrypto = True
except ImportError:
    print('[!] Failed to import pycryptodome, performance will be impacted.')

ws = False
try:
    import aiohttp
    ws = True
except ImportError:
    print('[!] Failed to import aiohttp, websockets will not be supported.')

SERVER_URL = "{{ server_url }}"
ENCRYPTION_KEY = "{{ encryption_key }}"
USER_AGENT = "{{ user_agent }}"
PROXY = "{{ proxy }}"
RETRY_DURATION = {{ retry_duration }}
RETRY_ATTEMPTS = {{ retry_attempts }}

TcpClient = namedtuple('TcpClient', 'reader writer bind_id')
alphanumeric = list(string.ascii_letters + string.digits)

def alphanumeric_identifier(length: int = 10) -> str:
    _identifier = [secrets.choice(alphanumeric) for _ in range(0, length)]
    _identifier = ''.join(_identifier)
    return _identifier

class DecryptionError(Exception):
    # Raised when an encrypted payload cannot be decrypted/unpadded -- almost
    # always a wrong encryption key. Treated as fatal: the messenger can never
    # decrypt server traffic, so main() logs once and stops instead of looping.
    pass

if pycrypto:
    def decrypt(key: bytes, ciphertext: bytes) -> bytes:
        iv = ciphertext[:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        msg = unpad(cipher.decrypt(ciphertext[16:]), AES.block_size)
        return msg

    def encrypt(key: bytes, plaintext: bytes) -> bytes:
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        msg = cipher.encrypt(pad(plaintext, AES.block_size))
        return iv + msg
else:
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

    def encrypt(key: bytes, plaintext: bytes) -> bytes:
        iv = os.urandom(16)
        aes = AES(key)
        ciphertext = aes.encrypt_cbc(plaintext, iv)
        return iv + ciphertext

    def decrypt(key: bytes, ciphertext: bytes) -> bytes:
        iv = ciphertext[:16]
        aes = AES(key)
        ciphertext = ciphertext[16:]
        return aes.decrypt_cbc(ciphertext, iv)

### Message Structures ###

CheckInMessage = namedtuple('CheckInMessage', ['messenger_id'])
InitiateTCPClientReq = namedtuple('InitiateTCPClientReq', ['client_id', 'destination_host', 'destination_port', 'listening_host', 'listening_port'])
InitiateTCPClientRep = namedtuple('InitiateTCPClientRep', ['client_id', 'bind_address', 'bind_port', 'address_type', 'reason', 'remote_addr', 'remote_port'])
SendDataMessage = namedtuple('SendDataMessage', ['client_id', 'data'])
InitiateBINDReq = namedtuple('InitiateBINDReq', ['bind_id', 'listening_host', 'listening_port', 'destination_host', 'destination_port'])
InitiateBINDRep = namedtuple('InitiateBINDRep', ['bind_id', 'listening_host', 'listening_port', 'reason'])
CheckOutMessage = namedtuple('CheckOutMessage', [])

class MessageParser:
    @staticmethod
    def read_uint32(data: bytes) -> (int, bytes):
        unsigned_32bit = data[:4]
        remaining_data = data[4:]
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
    def parse_initiate_tcp_client_req(value: bytes) -> InitiateTCPClientReq:
        client_id, value = MessageParser.read_string(value)
        destination_host, value = MessageParser.read_string(value)
        destination_port, value = MessageParser.read_uint32(value)
        # Optional listening endpoint appended by a remote port forwarder.
        listening_host = ''
        listening_port = 0
        if len(value) > 0:
            listening_host, value = MessageParser.read_string(value)
            listening_port, value = MessageParser.read_uint32(value)
        return InitiateTCPClientReq(client_id=client_id, destination_host=destination_host, destination_port=destination_port,
                                    listening_host=listening_host, listening_port=listening_port)

    @staticmethod
    def parse_initiate_tcp_client_rep(value: bytes) -> InitiateTCPClientRep:
        client_id, value = MessageParser.read_string(value)
        bind_address, value = MessageParser.read_string(value)
        bind_port, value = MessageParser.read_uint32(value)
        address_type, value = MessageParser.read_uint32(value)
        reason, value = MessageParser.read_uint32(value)
        # remote_addr / remote_port are optional -- the server omits them when it
        # has no remote info (e.g. a reason!=0 denial). Only read them if bytes
        # remain, otherwise a Rep without them overruns the buffer.
        remote_addr = ''
        remote_port = 0
        if len(value) > 0:
            remote_addr, value = MessageParser.read_string(value)
            remote_port, value = MessageParser.read_uint32(value)
        return InitiateTCPClientRep(
            client_id=client_id, bind_address=bind_address, bind_port=bind_port,
            address_type=address_type, reason=reason, remote_addr=remote_addr, remote_port=remote_port
        )

    @staticmethod
    def parse_send_data(value: bytes) -> SendDataMessage:
        client_id, value = MessageParser.read_string(value)
        encoded_data, value = MessageParser.read_string(value)
        raw_data = base64.b64decode(encoded_data)
        return SendDataMessage(client_id=client_id, data=raw_data)

    @staticmethod
    def parse_initiate_bind_req(value: bytes) -> InitiateBINDReq:
        bind_id, value = MessageParser.read_string(value)
        listening_host, value = MessageParser.read_string(value)
        listening_port, value = MessageParser.read_uint32(value)
        destination_host, value = MessageParser.read_string(value)
        destination_port, value = MessageParser.read_uint32(value)
        return InitiateBINDReq(
            bind_id=bind_id, listening_host=listening_host, listening_port=listening_port,
            destination_host=destination_host, destination_port=destination_port
        )

    @staticmethod
    def parse_initiate_bind_rep(value: bytes) -> InitiateBINDRep:
        bind_id, value = MessageParser.read_string(value)
        listening_host, value = MessageParser.read_string(value)
        listening_port, value = MessageParser.read_uint32(value)
        reason, value = MessageParser.read_uint32(value)
        return InitiateBINDRep(
            bind_id=bind_id, listening_host=listening_host,
            listening_port=listening_port, reason=reason
        )

    @staticmethod
    def _decrypt(encryption_key: bytes, payload: bytes) -> bytes:
        try:
            return decrypt(encryption_key, payload)
        except DecryptionError:
            raise
        except Exception as e:
            raise DecryptionError(str(e))

    @staticmethod
    def deserialize_message(encryption_key: bytes, raw_data: bytes):
        message_type, data = MessageParser.read_uint32(raw_data)
        message_length, data = MessageParser.read_uint32(data)
        if message_length < 8:
            raise ValueError("Invalid message: length field too small")
        payload_len = message_length - 8
        if len(data) < payload_len:
            raise ValueError("Not enough bytes in data for the payload")
        payload = data[:payload_len]
        leftover = data[payload_len:]
        if message_type == 0x01:
            decrypted = MessageParser._decrypt(encryption_key, payload)
            parsed_msg = MessageParser.parse_initiate_tcp_client_req(decrypted)
        elif message_type == 0x02:
            decrypted = MessageParser._decrypt(encryption_key, payload)
            parsed_msg = MessageParser.parse_initiate_tcp_client_rep(decrypted)
        elif message_type == 0x03:
            decrypted = MessageParser._decrypt(encryption_key, payload)
            parsed_msg = MessageParser.parse_send_data(decrypted)
        elif message_type == 0x04:
            parsed_msg = MessageParser.parse_check_in(payload)
        elif message_type == 0x05:
            decrypted = MessageParser._decrypt(encryption_key, payload)
            parsed_msg = MessageParser.parse_initiate_bind_req(decrypted)
        elif message_type == 0x06:
            decrypted = MessageParser._decrypt(encryption_key, payload)
            parsed_msg = MessageParser.parse_initiate_bind_rep(decrypted)
        elif message_type == 0x07:
            parsed_msg = CheckOutMessage()
        else:
            raise ValueError(f"Unknown message type: {hex(message_type)}")

        return leftover, parsed_msg

class MessageBuilder:
    @staticmethod
    def serialize_message(encryption_key: bytes, msg) -> bytes:
        if isinstance(msg, InitiateTCPClientReq):
            message_type = 0x01
            value = encrypt(encryption_key, MessageBuilder.build_initiate_tcp_client_req(
                msg.client_id, msg.destination_host, msg.destination_port, msg.listening_host, msg.listening_port
            ))
        elif isinstance(msg, InitiateTCPClientRep):
            message_type = 0x02
            value = encrypt(encryption_key, MessageBuilder.build_initiate_tcp_client_rep(
                msg.client_id, msg.bind_address, msg.bind_port,
                msg.address_type, msg.reason, msg.remote_addr, msg.remote_port
            ))
        elif isinstance(msg, SendDataMessage):
            message_type = 0x03
            value = encrypt(encryption_key, MessageBuilder.build_send_data(
                msg.client_id, msg.data
            ))
        elif isinstance(msg, CheckInMessage):
            message_type = 0x04
            value = MessageBuilder.build_check_in_message(msg.messenger_id)
        elif isinstance(msg, InitiateBINDReq):
            message_type = 0x05
            value = encrypt(encryption_key, MessageBuilder.build_initiate_bind_req(
                msg.bind_id, msg.listening_host, msg.listening_port,
                msg.destination_host, msg.destination_port
            ))
        elif isinstance(msg, InitiateBINDRep):
            message_type = 0x06
            value = encrypt(encryption_key, MessageBuilder.build_initiate_bind_rep(
                msg.bind_id, msg.listening_host, msg.listening_port, msg.reason
            ))
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
    def build_initiate_tcp_client_req(client_id: str, destination_host: str, destination_port: int,
                                      listening_host: str = '', listening_port: int = 0) -> bytes:
        result = (
            MessageBuilder.build_string(client_id) +
            MessageBuilder.build_string(destination_host) +
            struct.pack('!I', destination_port)
        )
        if listening_host:
            result += MessageBuilder.build_string(listening_host) + struct.pack('!I', listening_port)
        return result

    @staticmethod
    def build_initiate_tcp_client_rep(client_id: str, bind_address: str, bind_port: int,
                                     address_type: int, reason: int, remote_addr: str, remote_port: int) -> bytes:
        result = (
            MessageBuilder.build_string(client_id) +
            MessageBuilder.build_string(bind_address) +
            struct.pack('!III', bind_port, address_type, reason)
        )
        if remote_addr:
            result += MessageBuilder.build_string(remote_addr) + struct.pack('!I', remote_port)
        return result

    @staticmethod
    def build_send_data(client_id: str, data: bytes) -> bytes:
        encoded_data = base64.b64encode(data).decode('utf-8')
        return (
            MessageBuilder.build_string(client_id) +
            MessageBuilder.build_string(encoded_data)
        )

    @staticmethod
    def build_initiate_bind_req(bind_id: str, listening_host: str, listening_port: int,
                                destination_host: str, destination_port: int) -> bytes:
        return (
            MessageBuilder.build_string(bind_id) +
            MessageBuilder.build_string(listening_host) +
            struct.pack('!I', listening_port) +
            MessageBuilder.build_string(destination_host) +
            struct.pack('!I', destination_port)
        )

    @staticmethod
    def build_initiate_bind_rep(bind_id: str, listening_host: str, listening_port: int, reason: int) -> bytes:
        return (
            MessageBuilder.build_string(bind_id) +
            MessageBuilder.build_string(listening_host) +
            struct.pack('!II', listening_port, reason)
        )


## Clients

class Client:
    def __init__(self, encryption_key):
        self.encryption_key = encryption_key
        self.identifier = ''
        self.tcp_clients = {}
        self.remote_port_forwarders = []
        self.killed = False

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

    def serialize_messages(self, messages):
        data = b''
        for message in messages:
            data += MessageBuilder.serialize_message(self.encryption_key, message)
        return data

    async def handle_bind(self, message):
        if self.killed:
            return

        # Empty listening host = STOP: tear down the forwarder immediately.
        # The accept loop cleanup owns list removal and client teardown.
        if message.listening_host == '':
            existing = next((f for f in self.remote_port_forwarders if f.identifier == message.bind_id), None)
            if existing is not None:
                existing.stop()
            return

        # Real listening host = bind request. Idempotent if we already hold it.
        if any(f.identifier == message.bind_id for f in self.remote_port_forwarders):
            await self.send_upstream_message(InitiateBINDRep(
                bind_id=message.bind_id, listening_host=message.listening_host,
                listening_port=message.listening_port, reason=0
            ))
            return

        try:
            forwarder = RemotePortForwarder(
                self, message.bind_id, message.listening_host, message.listening_port,
                message.destination_host, message.destination_port
            )
            reason = await forwarder.start()
            if reason != 0:
                if not self.killed:
                    await self.send_upstream_message(InitiateBINDRep(
                        bind_id=message.bind_id, listening_host=message.listening_host, listening_port=message.listening_port, reason=reason
                    ))
                return
            if self.killed:
                forwarder.stop()
                return
            await self.send_upstream_message(InitiateBINDRep(
                bind_id=message.bind_id, listening_host=message.listening_host,
                listening_port=message.listening_port, reason=0
            ))
        except Exception:
            if not self.killed:
                await self.send_upstream_message(InitiateBINDRep(
                    bind_id=message.bind_id, listening_host=message.listening_host, listening_port=message.listening_port, reason=1
                ))

    async def handle_initiate_tcp_client_req(self, client_id, ip, port):
        if self.killed:
            return
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=5
            )
            if self.killed:
                writer.close()
                return
            tcp_client = TcpClient(reader, writer, None)
            self.tcp_clients[client_id] = tcp_client

            bind_info = writer.get_extra_info("sockname")
            bind_addr = bind_info[0]
            bind_port = bind_info[1]

            peer_info = writer.get_extra_info("peername")
            remote_addr = peer_info[0]
            remote_port = peer_info[1]

            sock = writer.get_extra_info("socket")
            family = sock.family
            atype = 1 if family == socket.AF_INET else 4

            upstream_message = InitiateTCPClientRep(
                client_id=client_id, bind_address=bind_addr, bind_port=bind_port,
                address_type=atype, reason=0, remote_addr=remote_addr, remote_port=remote_port
            )
            await self.send_upstream_message(upstream_message)
            asyncio.create_task(self.stream(client_id))

        except socket.gaierror:
            reason = 4
        except asyncio.TimeoutError:
            reason = 6
        except ConnectionRefusedError:
            reason = 5
        except OSError as e:
            reason = {
                errno.ENETUNREACH: 3,
                errno.EHOSTUNREACH: 4,
                errno.ECONNREFUSED: 5,
                errno.EPROTONOSUPPORT: 7,
                errno.EAFNOSUPPORT: 8
            }.get(e.errno, 1)
        except Exception:
            reason = 1
        else:
            return

        if not self.killed:
            upstream_message = InitiateTCPClientRep(
                client_id=client_id, bind_address="0.0.0.0", bind_port=0,
                address_type=1, reason=reason, remote_addr="0.0.0.0", remote_port=0
            )
            await self.send_upstream_message(upstream_message)

    async def stream(self, client_identifier):
        tcp_client = self.tcp_clients.get(client_identifier)
        if tcp_client is None:
            return
        try:
            while True:
                msg = await tcp_client.reader.read(4096)
                if not msg:
                    break
                upstream_message = SendDataMessage(client_id=client_identifier, data=msg)
                await self.send_upstream_message(upstream_message)
        except (EOFError, ConnectionResetError, ConnectionAbortedError):
            pass
        except Exception:
            pass
        finally:
            removed = self.tcp_clients.pop(client_identifier, None)
            if removed is not None:
                removed.writer.close()
                if not self.killed:
                    upstream_message = SendDataMessage(client_id=client_identifier, data=b'')
                    await self.send_upstream_message(upstream_message)

    async def dispatch_message(self, message):
        if isinstance(message, InitiateTCPClientReq):
            asyncio.create_task(self.handle_initiate_tcp_client_req(
                message.client_id, message.destination_host, message.destination_port))
        elif isinstance(message, InitiateTCPClientRep):
            tcp_client = self.tcp_clients.get(message.client_id)
            if not tcp_client:
                return
            if message.reason != 0:
                tcp_client.writer.close()
                self.tcp_clients.pop(message.client_id, None)
                return
            tcp_client.writer.transport.resume_reading()
            asyncio.create_task(self.stream(message.client_id))
        elif isinstance(message, SendDataMessage):
            tcp_client = self.tcp_clients.get(message.client_id)
            if not tcp_client:
                return
            if not message.data:
                removed = self.tcp_clients.pop(message.client_id, None)
                if removed:
                    removed.writer.close()
                return
            tcp_client.writer.write(message.data)
        elif isinstance(message, InitiateBINDReq):
            asyncio.create_task(self.handle_bind(message))
        elif isinstance(message, CheckInMessage):
            self.identifier = message.messenger_id
        elif isinstance(message, CheckOutMessage):
            self.handle_checkout()

    def handle_checkout(self):
        print('[!] Kill signal received')
        self.killed = True
        for forwarder in list(self.remote_port_forwarders):
            forwarder.stop()
        for client_id, tcp_client in list(self.tcp_clients.items()):
            self.tcp_clients.pop(client_id, None)
            try:
                tcp_client.writer.close()
            except Exception:
                pass

    def close_connections_for_bind(self, bind_id):
        for client_id, tcp_client in list(self.tcp_clients.items()):
            if getattr(tcp_client, 'bind_id', None) == bind_id:
                self.tcp_clients.pop(client_id, None)
                try:
                    tcp_client.writer.close()
                except Exception:
                    pass

    async def cleanup(self):
        for forwarder in list(self.remote_port_forwarders):
            forwarder.stop()
        for tcp_client in list(self.tcp_clients.values()):
            tcp_client.writer.close()
        await self.close_transport()

    async def close_transport(self):
        raise NotImplementedError

    async def connect(self):
        raise NotImplementedError

    async def start(self):
        raise NotImplementedError

    async def send_upstream_message(self, upstream_message):
        raise NotImplementedError

    async def readvertise_forwarders(self):
        # On every (re)connect, tell the server which remote port forwards we're
        # actually listening on (a real-host BindRep per RPF). A server that lost
        # its state -- e.g. after a restart -- re-learns them (as orphans awaiting
        # a destination); a server that already knows them just re-confirms.
        for forwarder in list(self.remote_port_forwarders):
            await self.send_upstream_message(InitiateBINDRep(
                bind_id=forwarder.identifier,
                listening_host=forwarder.listening_host,
                listening_port=forwarder.listening_port,
                reason=0
            ))

class WSClient(Client):
    def __init__(self, server_url, encryption_key, user_agent, proxy):
        super().__init__(encryption_key)
        self.server_url = server_url.strip('/')
        self.headers = {'User-Agent': user_agent}
        self.proxy = proxy
        self.ws = None
        self.session = None
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        self.upstream_messages = asyncio.Queue()
        self._pending = []

    async def close_transport(self):
        if self.ws and not self.ws.closed:
            await self.ws.close()
        if self.session and not self.session.closed:
            await self.session.close()

    async def connect(self):
        await self.close_transport()
        self.session = aiohttp.ClientSession(headers=self.headers)
        self.ws = await self.session.ws_connect(
            self.server_url,
            ssl=self.ssl_context,
            proxy=self.proxy
        )
        check_in_msg = self.serialize_messages([CheckInMessage(messenger_id=self.identifier)])
        await self.ws.send_bytes(check_in_msg)
        if self.identifier:
            return
        msg = await self.ws.receive()
        messages = self.deserialize_messages(msg.data)
        assert len(messages) > 0, f"[!] Invalid response from server:\n{msg.data}"
        check_in_msg = messages[0]
        assert isinstance(check_in_msg, CheckInMessage), f"[!] Expected CheckInMessage, got {type(check_in_msg)}"
        self.identifier = check_in_msg.messenger_id

    async def start(self):
        await self.readvertise_forwarders()
        recv_task = asyncio.create_task(self._receive_loop())
        send_task = asyncio.create_task(self._send_loop())
        try:
            done, _ = await asyncio.wait(
                {recv_task, send_task}, return_when=asyncio.FIRST_COMPLETED
            )
        finally:
            for task in (recv_task, send_task):
                if not task.done():
                    task.cancel()
            await asyncio.gather(recv_task, send_task, return_exceptions=True)

        for task in done:
            exc = task.exception()
            if exc is not None:
                raise exc

    async def _receive_loop(self):
        async for msg in self.ws:
            messages = self.deserialize_messages(msg.data)
            if any(isinstance(m, CheckOutMessage) for m in messages):
                self.handle_checkout()
                break
            for message in messages:
                await self.dispatch_message(message)
            if self.killed:
                break

    async def _send_loop(self):
        while True:
            if not self._pending:
                self._pending.append(await self.upstream_messages.get())
                while not self.upstream_messages.empty():
                    self._pending.append(self.upstream_messages.get_nowait())
            try:
                batch = [CheckInMessage(messenger_id=self.identifier)]
                batch.extend(self._pending)
                await self.ws.send_bytes(self.serialize_messages(batch))
                self._pending.clear()
            except Exception:
                break

    async def send_upstream_message(self, upstream_message):
        # Producer: just enqueue. The single send loop serializes the socket.
        await self.upstream_messages.put(upstream_message)

class HTTPClient(Client):
    def __init__(self, server_url, encryption_key, user_agent, proxy):
        super().__init__(encryption_key)
        self.server_url = server_url.strip('/')
        self.encryption_key = encryption_key
        self.headers = {'User-Agent': user_agent}
        self.proxy = proxy
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        self.upstream_messages = asyncio.Queue()
        self._pending = []
        proxy_handler = request.ProxyHandler({
            'http': proxy,
            'https': proxy
        } if proxy else {})

        https_handler = request.HTTPSHandler(context=self.ssl_context)
        self.opener = request.build_opener(proxy_handler, https_handler)

    async def close_transport(self):
        pass

    def _blocking_http_req(self, req, timeout = 10.0):
        with self.opener.open(req, timeout=timeout) as resp:
            assert getattr(resp, "status", None) == 200, "[*] Non-200 response during initial connection, exiting"
            return resp.read()

    async def connect(self):
        upstream_messages = [CheckInMessage(messenger_id=self.identifier)]
        req = request.Request(
            self.server_url,
            headers=self.headers,
            data=self.serialize_messages(upstream_messages)
        )
        loop = asyncio.get_event_loop()
        resp = await loop.run_in_executor(None, self._blocking_http_req, req, 10.0)
        if self.identifier:
            if resp:
                messages = self.deserialize_messages(resp)
                if any(isinstance(m, CheckOutMessage) for m in messages):
                    self.handle_checkout()
                    return
                for msg in messages:
                    await self.dispatch_message(msg)
            return
        messages = self.deserialize_messages(resp)
        assert len(messages) > 0, f"[*] Invalid response from server:\n{resp}"
        check_in_msg = messages[0]
        assert isinstance(check_in_msg, CheckInMessage), "[*] Expected CheckInMessage, got something else"
        self.identifier = check_in_msg.messenger_id

    async def start(self):
        await self.readvertise_forwarders()
        while not self.killed:
            if not self._pending:
                while not self.upstream_messages.empty():
                    self._pending.append(self.upstream_messages.get_nowait())

            to_send = [CheckInMessage(messenger_id=self.identifier)]
            to_send.extend(self._pending)

            req = request.Request(
                self.server_url,
                headers=self.headers,
                data=self.serialize_messages(to_send)
            )

            loop = asyncio.get_event_loop()
            resp = await loop.run_in_executor(None, self._blocking_http_req, req, 15.0)
            if not resp:
                self._pending.clear()
                await asyncio.sleep(0.1)
                continue

            self._pending.clear()
            messages = self.deserialize_messages(resp)
            if any(isinstance(m, CheckOutMessage) for m in messages):
                self.handle_checkout()
                break
            for message in messages:
                await self.dispatch_message(message)
            await asyncio.sleep(0.1)

    async def send_upstream_message(self, upstream_message):
        await self.upstream_messages.put(upstream_message)

class RemotePortForwarder:
    def __init__(self, messenger, bind_id, listening_host, listening_port, destination_host, destination_port):
        self.messenger = messenger
        self.identifier = bind_id
        self.listening_host = listening_host
        self.listening_port = int(listening_port)
        self.destination_host = destination_host
        self.destination_port = int(destination_port)
        self.server = None

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self.messenger.killed or self not in self.messenger.remote_port_forwarders:
            writer.close()
            return
        tcp_client = TcpClient(reader, writer, self.identifier)
        client_id = alphanumeric_identifier()

        writer.transport.pause_reading()

        self.messenger.tcp_clients[client_id] = tcp_client

        if self not in self.messenger.remote_port_forwarders:
            self.messenger.tcp_clients.pop(client_id, None)
            writer.close()
            return

        upstream_message = InitiateTCPClientReq(
            client_id=client_id,
            destination_host=self.destination_host,
            destination_port=self.destination_port,
            listening_host=self.listening_host,
            listening_port=self.listening_port
        )
        await self.messenger.send_upstream_message(upstream_message)

    async def start(self):
        try:
            self.server = await asyncio.start_server(
                self.handle_client, self.listening_host, self.listening_port
            )
        except OSError as e:
            reason = {
                errno.EADDRINUSE: 2,
                errno.EACCES: 3,
            }.get(e.errno, 1)
            print(f'[!] {self.listening_host}:{self.listening_port} is already in use or encountered an error')
            return reason
        if self.messenger.killed:
            self.server.close()
            return 1
        print(f'[+] Remote Port Forwarder listening on {self.listening_host}:{self.listening_port}')
        self.messenger.remote_port_forwarders.append(self)
        asyncio.create_task(self._serve_forever())
        return 0

    async def _serve_forever(self):
        try:
            await self.server.serve_forever()
        except Exception:
            pass
        finally:
            await self.cleanup()

    async def cleanup(self):
        if self not in self.messenger.remote_port_forwarders:
            return
        self.messenger.remote_port_forwarders.remove(self)
        self.messenger.close_connections_for_bind(self.identifier)
        if not self.messenger.killed:
            try:
                await self.messenger.send_upstream_message(InitiateBINDRep(
                    bind_id=self.identifier, listening_host=self.listening_host,
                    listening_port=self.listening_port, reason=5))
            except Exception:
                pass

    def stop(self):
        if self.server is not None:
            self.server.close()

## Arg Parsing

def generate_hash(hash_input: str) -> bytes:
    hasher = hashlib.sha256()
    hash_input = hash_input.encode('utf-8')
    hasher.update(hash_input)
    return hasher.digest()

def parse_args():
    parser = argparse.ArgumentParser(description="Messenger Client Runner")

    parser.add_argument("--server-url")
    parser.add_argument("--encryption-key")
    parser.add_argument("--user-agent")
    parser.add_argument("--proxy")
    parser.add_argument("--retry-duration", type=float)
    parser.add_argument("--retry-attempts", type=int)

    args, unknown = parser.parse_known_args()
    for arg in unknown:
        print(f'[!] Could not find argument `{arg}`.')
    return args


async def main():
    args = parse_args()

    server_url = args.server_url or SERVER_URL
    encryption_key = args.encryption_key or ENCRYPTION_KEY
    if not encryption_key:
        print('[!] No encryption key provided, please specify `--encryption-key`')
        return
    encryption_key = generate_hash(encryption_key)
    user_agent = args.user_agent or USER_AGENT
    proxy = args.proxy or PROXY
    retry_duration = (
        args.retry_duration
        if args.retry_duration is not None
        else RETRY_DURATION
    )
    retry_attempts = (
        args.retry_attempts
        if args.retry_attempts is not None
        else RETRY_ATTEMPTS
    )

    if proxy and not proxy.startswith('http'):
        proxy = f'http://{proxy}'

    remainder = server_url
    if "://" in server_url:
        scheme, remainder = server_url.split("://", 1)
        attempts = scheme.split('+')
    else:
        attempts = ["ws", "wss", "http", "https"]

    client = None
    for attempt in attempts:
        candidate_url = f"{attempt}://{remainder}"
        if "ws" in attempt and ws:
            print(f'[*] Attempting to connect over {attempt.upper()}')
            client = WSClient(candidate_url, encryption_key, user_agent, proxy)
        elif "http" in attempt:
            print(f'[*] Attempting to connect over {attempt.upper()}')
            client = HTTPClient(candidate_url, encryption_key, user_agent, proxy)
        else:
            print(f"[!] Unsupported scheme: {attempt}")
            continue
        try:
            await client.connect()
            print(f'[+] Connected to {candidate_url}')
            break
        except DecryptionError:
            print('[!] Decryption failed -- the encryption key is likely incorrect. The messenger cannot decrypt server traffic and is stopping.')
            if hasattr(client, 'close'):
                await client.close()
            return
        except Exception as e:
            print(f'[!] Connection failed: {e}')
            client = None
            continue

    if client is None:
        print('[!] All connection attempts failed.')
        return

    try:
        try:
            await client.start()
        except DecryptionError:
            print('[!] Decryption failed -- the encryption key is likely incorrect. The messenger cannot decrypt server traffic and is stopping.')
            return
        except Exception as e:
            print(f'[!] Disconnected: {e}')

        if client.killed:
            return

        if retry_attempts <= 0:
            return

        sleep_time = retry_duration / retry_attempts
        consecutive_failures = 0
        while consecutive_failures < retry_attempts:
            consecutive_failures += 1
            print(f'[*] Attempting to reconnect (attempt {consecutive_failures}/{retry_attempts})')
            await asyncio.sleep(sleep_time)
            try:
                await client.connect()
                if client.killed:
                    break
                print(f'[+] Reconnected')
                consecutive_failures = 0
                await client.start()
            except DecryptionError:
                print('[!] Decryption failed -- the encryption key is likely incorrect. The messenger cannot decrypt server traffic and is stopping.')
                break
            except Exception as e:
                print(f'[!] Reconnection failed: {e}')

            if client.killed:
                break
    finally:
        await client.cleanup()

{% if non_main_thread %}
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
{% endif %}

{% if non_main_thread %}

try:
    run_coro_in_thread(main())
except KeyboardInterrupt:
    print('\rShutdown')
{% else %}
loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)
try:
    loop.run_until_complete(main())
except KeyboardInterrupt:
    print('\rShutdown')
{% endif %}
