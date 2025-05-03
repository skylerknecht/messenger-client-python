#!/usr/bin/env python3
import aiohttp
import asyncio
import argparse
import ssl
import struct
import urllib
import base64
import struct

from abc import ABC, abstractmethod
from urllib import request
from collections import namedtuple

import random
import string
import hashlib

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

# Populate alphabet with uppercase, lowercase characters, and digits
alphanumeric = list(string.ascii_letters + string.digits)  # 'a-z', 'A-Z', and '0-9'
alphabet = list(string.ascii_letters)


def digit_identifier(length: int = 10) -> str:
    """
    Generate random integers from 1 to 9 and concatenate the digits
    together for a length of zero to *length*.

    :param: int length: The amount of random digits to concatenate.
    :return: The generated digit identifier.
    :rtype: str
    """
    _identifier = [str(random.randint(1, 9)) for _ in range(0, length)]
    _identifier = ''.join(_identifier)
    return _identifier


def string_identifier(length: int = 10) -> str:
    """
    Generate random alphanumeric characters and concatenate
    them for a length of zero to *length*.
    :param: int length: The amount of random characters to concatenate.
    :return: The generated string identifier.
    :rtype: str
    """
    _identifier = [alphabet[random.randint(0, len(alphabet) - 1)] for _ in range(0, length)]
    _identifier = ''.join(_identifier)
    return _identifier


def alphanumeric_identifier(length: int = 10) -> str:
    """
    Generate random alphanumeric characters and concatenate
    them for a length of zero to *length*.
    :param: int length: The amount of random characters to concatenate.
    :return: The generated string identifier.
    :rtype: str
    """
    _identifier = [alphanumeric[random.randint(0, len(alphabet) - 1)] for _ in range(0, length)]
    _identifier = ''.join(_identifier)
    return _identifier


def generate_encryption_key(min_len=10, max_len=20):
    length = random.randint(min_len, max_len)  # Random length between min_length and max_length
    letters = string.ascii_letters   # Contains both uppercase and lowercase letters
    return ''.join(random.choice(letters) for _ in range(length))


def generate_hash(hash_input: str) -> bytes:
    hasher = hashlib.sha256()
    hash_input = hash_input.encode('utf-8')
    hasher.update(hash_input)
    return hasher.digest()



# ---------------------------
# 1. Named Tuple Definitions
# ---------------------------

CheckInMessage = namedtuple('CheckInMessage', ['messenger_id'])
InitiateForwarderClientReq = namedtuple('InitiateForwarderClientReq', ['forwarder_client_id', 'ip_address', 'port'])
InitiateForwarderClientRep = namedtuple('InitiateForwarderClientRep', ['forwarder_client_id', 'bind_address', 'bind_port', 'address_type', 'reason'])
SendDataMessage = namedtuple('SendDataMessage', ['forwarder_client_id', 'data'])

# You could also store message_type inside each namedtuple, or convert them to @dataclass if you prefer.


# --------------------------------
# 2. MessageParser: Reading Bytes
# --------------------------------

class MessageParser:
    @staticmethod
    def read_uint32(data: bytes) -> (int, bytes):
        """
        Reads the first 4 bytes as an unsigned 32-bit integer (big-endian),
        returns (the_integer, remaining_bytes).
        """
        unsigned_32bit = data[:4]               # The 4-byte integer
        remaining_data = data[4:]               # Everything after the 4 bytes
        (value,) = struct.unpack('!I', unsigned_32bit)
        return value, remaining_data

    @staticmethod
    def read_string(data: bytes) -> (str, bytes):
        """
        Reads a length-prefixed UTF-8 string from data:
          1) read an unsigned 32-bit length
          2) read 'length' bytes as the string
        returns (string, remaining_bytes).
        """
        length, data = MessageParser.read_uint32(data)
        s = data[:length].decode('utf-8')
        return s, data[length:]

    @staticmethod
    def parse_check_in(value: bytes) -> CheckInMessage:
        """
        Given decrypted bytes for a 0x04 message,
        read the messenger_id string into a CheckInMessage.
        """
        messenger_id, _ = MessageParser.read_string(value)
        return CheckInMessage(messenger_id=messenger_id)

    @staticmethod
    def parse_initiate_forwarder_client_req(value: bytes) -> InitiateForwarderClientReq:
        """
        For message type 0x01, parse out:
          - forwarder_client_id (str)
          - ip_address (str)
          - port (uint32)
        """
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
        """
        For message type 0x02, parse out:
          - forwarder_client_id (str)
          - bind_address (str)
          - bind_port (uint32)
          - address_type (uint32)
          - reason (uint32)
        """
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
        """
        For message type 0x03, parse out:
          - forwarder_client_id (str)
          - data (bytes) [ base64-decoded from the stored string ]
        """
        forwarder_client_id, value = MessageParser.read_string(value)
        encoded_data, value = MessageParser.read_string(value)
        raw_data = base64.b64decode(encoded_data)
        return SendDataMessage(
            forwarder_client_id=forwarder_client_id,
            data=raw_data
        )

    @staticmethod
    def deserialize_message(encryption_key: bytes, raw_data: bytes):
        """
        High-level parse entrypoint:
          1) read the message_type (uint32)
          2) read the message_length (uint32)
          3) slice out the encrypted payload
          4) decrypt and parse into an appropriate namedtuple
        Returns (leftover_bytes, parsed_message).
        """
        # 1) Read the message type
        message_type, data = MessageParser.read_uint32(raw_data)

        # 2) Read the message length (which includes header + payload)
        message_length, data = MessageParser.read_uint32(data)

        # 3) The payload is (message_length - 8) bytes (subtracting the 8-byte header)
        payload_len = message_length - 8
        if len(data) < payload_len:
            raise ValueError("Not enough bytes in data for the payload")

        # Extract the encrypted payload + leftover
        payload = data[:payload_len]
        leftover = data[payload_len:]

        # 5) Dispatch to parse the now-decrypted payload
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


# --------------------------------
# 3. MessageBuilder: Creating Bytes
# --------------------------------

class MessageBuilder:
    @staticmethod
    def serialize_message(encryption_key: bytes, msg) -> bytes:
        """
        High-level build entrypoint: accept one of our named tuples and return
        the fully built+encrypted bytes (including message type, length, etc.).
        """
        value = b''
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
        """
        Common routine to build the 8-byte header and append encrypted payload:
          1) 4 bytes: message_type
          2) 4 bytes: total_length (header + payload)
          3) remainder: encrypt(encryption_key, plaintext_value)
        """
        message_length = 8 + len(value)
        header = struct.pack('!II', message_type, message_length)
        return header + value

    @staticmethod
    def build_string(value: str) -> bytes:
        """
        Encodes a string with a 4-byte length prefix, plus the UTF-8 data.
        """
        encoded = value.encode('utf-8')
        return struct.pack('!I', len(encoded)) + encoded

    @staticmethod
    def build_check_in_message(messenger_id: str) -> bytes:
        return MessageBuilder.build_string(messenger_id)

    @staticmethod
    def build_initiate_forwarder_client_req(forwarder_client_id: str,
                                            ip_address: str, port: int) -> bytes:
        """
        Build a 0x01 request with:
         - forwarder_client_id
         - ip_address
         - port
        """
        return (
            MessageBuilder.build_string(forwarder_client_id) +
            MessageBuilder.build_string(ip_address) +
            struct.pack('!I', port)
        )

    @staticmethod
    def build_initiate_forwarder_client_rep(forwarder_client_id: str,
                                            bind_address: str, bind_port: int,
                                            address_type: int, reason: int) -> bytes:
        """
        Build a 0x02 'response' with:
         - forwarder_client_id
         - bind_address
         - bind_port
         - address_type
         - reason
        """
        return (
            MessageBuilder.build_string(forwarder_client_id) +
            MessageBuilder.build_string(bind_address) +
            struct.pack('!III', bind_port, address_type, reason)
        )

    @staticmethod
    def build_send_data(forwarder_client_id: str, data: bytes) -> bytes:
        """
        Build a 0x03 'send_data' message with:
         - forwarder_client_id
         - data (base64-encoded)
        """
        encoded_data = base64.b64encode(data).decode('utf-8')
        return (
            MessageBuilder.build_string(forwarder_client_id) +
            MessageBuilder.build_string(encoded_data)
        )


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
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(message['IP Address'], message['Port']),
                timeout=5  # Timeout after 5 seconds
            )
            self.forwarder_clients[message['Forwarder Client ID']] = ForwarderClient(reader, writer)
            bind_addr, bind_port = writer.get_extra_info('sockname')

            downstream_message = InitiateForwarderClientRep(
                forwarder_client_id=message['Forwarder Client ID'],
                bind_address=bind_addr,
                bind_port=bind_port,
                address_type=0,
                reason=0
            )
            asyncio.create_task(self.stream(message['Forwarder Client ID']))
        except Exception:
            downstream_message = InitiateForwarderClientRep(
                forwarder_client_id=message['Forwarder Client ID'],
                bind_address='',
                bind_port=0,
                address_type=0,
                reason=1
            )
        await self.send_downstream_message(downstream_message)

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
        """
        Continuously read messages from self.ws until closed or error.
        """
        async for msg in self.ws:
            messages = self.deserialize_messages(msg.data)
            for message in messages:
                try:
                    await self.handle_message(message)
                except:
                    continue

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
        proxies = {
            'http': '' if proxy is None else proxy,
            'https': '' if proxy is None else proxy
        }

        # ToDo: Support Proxies with HTTPClient
        self.downstream_messages = asyncio.Queue()

    async def connect(self):
        await self.start_remote_port_forwards(self.remote_port_forwards)
        # Start by sending a CheckInMessage
        downstream_messages = [CheckInMessage(messenger_id='')]
        check_in_request = request.Request(
            self.server_url,
            headers=self.headers,
            data=self.serialize_messages(downstream_messages)
        )
        with request.urlopen(check_in_request, context=self.ssl_context) as response:
            if response.status != 200:
                return
            messages = self.deserialize_messages(response.read())
            check_in_msg = messages[0]
            assert isinstance(check_in_msg, CheckInMessage), "Expected CheckInMessage, got something else"
            self.identifier = check_in_msg.messenger_id

    async def start(self):
        """
        Main loop of polling: we repeatedly send check_in + any queued messages,
        then read the server's response.
        """
        while True:
            # Always start with a CheckInMessage
            to_send = [CheckInMessage(messenger_id=self.identifier)]

            # Drain the queue and serialize each message
            while not self.downstream_messages.empty():
                to_send.append(await self.downstream_messages.get())

            check_in_req = request.Request(self.server_url, headers=self.headers, data=self.serialize_messages(to_send))
            with request.urlopen(check_in_req, context=self.ssl_context) as response:
                if response.status != 200:
                    break
                raw_data = response.read()
                messages = self.deserialize_messages(raw_data)
                for message in messages:
                    try:
                        await self.handle_message(message)
                    except:
                        continue
            await asyncio.sleep(1.0)

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
            except (EOFError, ConnectionResetError) as e:
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
            if "ws" in attempt:
                print('[*] Attempting to connect to Messenger Server over WebSockets')
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
