"""Minimum code needed to connect to a OpenSSH Server."""

import math
import os
import select
import socket
import struct
import sys
from binascii import hexlify
from hashlib import sha256
from hmac import HMAC
from io import BytesIO
from pathlib import Path
from typing import Any, Callable, Optional, Tuple, cast

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    CipherContext,
    algorithms,
    modes,
)

_Hash = Callable[[], Any]

VERSION = b"SSH-2.0-BRS-0.0.1"

MSG_SERVICE_REQUEST = b"\05"
MSG_SERVICE_ACCEPT = b"\06"
MSG_KEXINIT = b"\x14"
MSG_NEWKEYS = b"\x15"
MSG_KEXDH_GEX_GROUP = b"\x1f"
MSG_KEXDH_GEX_INIT = b"\x20"
MSG_KEXDH_GEX_REPLY = b"\x21"
MSG_KEXDH_GEX_REQUEST = b"\x22"
MSG_USERAUTH_REQUEST = b"\x32"
MSG_USERAUTH_SUCCESS = b"\x34"
MSG_GLOBAL_REQUEST = b"\x50"
MSG_CHANNEL_OPEN = b"\x5a"
MSG_CHANNEL_OPEN_SUCCESS = b"\x5b"
MSG_CHANNEL_WINDOW_ADJUST = b"\x5d"
MSG_CHANNEL_DATA = b"\x5e"
MSG_CHANNEL_EOF = b"\x60"
MSG_CHANNEL_REQUEST = b"\x62"
MSG_CHANNEL_SUCCESS = b"\x63"

DEFAULT_WINDOW_SIZE = 64 * 2 ** 15
DEFAULT_MAX_PACKET_SIZE = 2 ** 15


def compute_key(id: bytes, nbytes: int, k: int, h: bytes, session_id: bytes) -> bytes:
    """Serialise key to bytes."""
    m = Message()
    m.add_mpint(k)
    m.write(h)
    m.write(id)
    m.write(session_id)
    buf = sha256(m.getvalue()).digest()
    while len(buf) < nbytes:
        m = Message()
        m.add_mpint(k)
        m.write(h)
        m.write(buf)
        digest = sha256(m.getvalue()).digest()
        buf += digest
    return buf[:nbytes]


class Message(BytesIO):
    """Message in protocol."""

    seqno: int = 0

    def get_remainder(self) -> bytes:
        """Get bytes after position."""
        position = self.tell()
        remainder = self.read()
        self.seek(position)
        return remainder

    def get_so_far(self) -> bytes:
        """Get bytes before position."""
        position = self.tell()
        self.seek(0)
        return self.read(position)

    def get_bytes(self, n: int) -> bytes:
        """Read bytes."""
        b = self.read(n)
        if len(b) < n < 1 << 20:
            return b + b"\x00" * (n - len(b))
        return b

    def get_boolean(self) -> bool:
        """Read a bool."""
        b = self.get_bytes(1)
        return b != b"\x00"

    def get_int(self) -> int:
        """Read a int."""
        return int(struct.unpack(">I", self.get_bytes(4))[0])

    def get_mpint(self) -> int:
        """Read a mpint."""
        s = self.get_binary()
        buf = 0
        negative = (len(s) > 0) and (s[0] >= 0x80)
        if len(s) % 4:
            filler = b"\x00"
            if negative:
                filler = b"\xFF"
            s = filler * (4 - len(s) % 4) + s
        for i in range(0, len(s), 4):
            buf = (buf << 32) + struct.unpack(">I", s[i : i + 4])[0]
        if negative:
            buf -= 1 << (8 * len(s))
        return buf

    def get_binary(self) -> bytes:
        """Read a len then that many bytes."""
        return self.get_bytes(self.get_int())

    def add_int(self, n: int) -> None:
        """Write a int."""
        self.write(struct.pack(">I", n))

    def add_mpint(self, n: int) -> None:
        """Write a mpint."""
        buf = bytes()
        while (n != 0) and (n != -1):
            buf = struct.pack(">I", n & 0xFFFFFFFF) + buf
            n >>= 32
        for i in enumerate(buf):
            if (n == 0) and (i[1] != 0):
                break
            if (n == -1) and (i[1] != 0xFF):
                break
        else:
            i = (0, 0)
            if n == 0:
                buf = b"\x00"
            else:
                buf = b"\xFF"
        buf = buf[i[0] :]
        if (n == 0) and (buf[0] >= 0x80):  # pragma: no cover
            buf = b"\x00" + buf
        if (n == -1) and (buf[0] < 0x80):  # pragma: no cover
            buf = b"\xFF" + buf
        self.add_binary(buf)

    def add_binary(self, s: bytes) -> None:
        """Write the len then the data."""
        self.add_int(len(s))
        self.write(s)


class Packetizer:
    """Implement protocol packetizing."""

    def __init__(self, socket: socket.socket) -> None:
        """Init."""
        self.__socket = socket
        self.__block_size_out = 8
        self.__block_size_in = 8
        self.__mac_size_out = 0
        self.__mac_size_in = 0
        self.__block_engine_out: Optional[CipherContext] = None
        self.__block_engine_in: Optional[CipherContext] = None
        self.__sdctr_out = False
        self.__mac_engine_out: Optional[_Hash] = None
        self.__mac_engine_in: Optional[_Hash] = None
        self.__mac_key_out = bytes()
        self.__mac_key_in = bytes()
        self.__sequence_number_out = 0
        self.__sequence_number_in = 0

    def set_outbound_cipher(
        self,
        block_engine: CipherContext,
        block_size: int,
        mac_engine: _Hash,
        mac_size: int,
        mac_key: bytes,
        sdctr: bool = False,
    ) -> None:
        """Set the outbound Cipher (must be called)."""
        self.__block_engine_out = block_engine
        self.__sdctr_out = sdctr
        self.__block_size_out = block_size
        self.__mac_engine_out = mac_engine
        self.__mac_size_out = mac_size
        self.__mac_key_out = mac_key

    def set_inbound_cipher(
        self,
        block_engine: CipherContext,
        block_size: int,
        mac_engine: _Hash,
        mac_size: int,
        mac_key: bytes,
    ) -> None:
        """Set the inbound Cipher (must be called)."""
        self.__block_engine_in = block_engine
        self.__block_size_in = block_size
        self.__mac_engine_in = mac_engine
        self.__mac_size_in = mac_size
        self.__mac_key_in = mac_key

    def send_message(self, data: bytes) -> None:
        """Send a message."""
        padding = 3 + self.__block_size_out - ((len(data) + 8) % self.__block_size_out)
        packet = struct.pack(">IB", len(data) + padding + 1, padding)
        packet += data
        packet += os.urandom(padding)

        if self.__block_engine_out is not None:
            buf = self.__block_engine_out.update(packet)
            payload = struct.pack(">I", self.__sequence_number_out) + packet
            assert self.__mac_engine_out
            buf += HMAC(self.__mac_key_out, payload, self.__mac_engine_out).digest()[
                : self.__mac_size_out
            ]
        else:
            buf = packet
        self.__sequence_number_out = (self.__sequence_number_out + 1) & 0xFFFFFFFF
        self.__socket.send(buf)

    def read_message(self) -> Tuple[bytes, Message]:
        """Read a message."""
        header = self.__socket.recv(self.__block_size_in)
        if self.__block_engine_in is not None:
            header = self.__block_engine_in.update(header)
        packet_size = struct.unpack(">I", header[:4])[0]
        leftover = header[4:]
        if (packet_size - len(leftover)) % self.__block_size_in != 0:
            raise Exception("Invalid packet blocking")
        buf = self.__socket.recv(packet_size + self.__mac_size_in - len(leftover))
        packet = buf[: packet_size - len(leftover)]
        post_packet = buf[packet_size - len(leftover) :]
        if self.__block_engine_in is not None:
            packet = self.__block_engine_in.update(packet)
        packet = leftover + packet

        if self.__mac_size_in > 0:
            mac = post_packet[: self.__mac_size_in]
            mac_payload = (
                struct.pack(">II", self.__sequence_number_in, packet_size) + packet
            )
            assert self.__mac_engine_in
            my_mac = HMAC(
                self.__mac_key_in, mac_payload, self.__mac_engine_in
            ).digest()[: self.__mac_size_in]
            if my_mac != mac:  # should be constant time
                raise Exception("Mismatched MAC")
        padding = packet[0]
        payload = packet[1 : packet_size - padding]

        msg = Message(payload[1:])
        msg.seqno = self.__sequence_number_in
        self.__sequence_number_in = (self.__sequence_number_in + 1) & 0xFFFFFFFF

        return payload[0:1], msg


def connect(  # noqa: C901
    username: str,
    private_key_file: str = "~/.ssh/id_rsa",
    host: str = "localhost",
    port: int = 22,
) -> None:  # pragma: no cover
    """Connect to server."""

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))

    packetizer = Packetizer(sock)

    # Banner
    sock.send(VERSION + b"\r\n")
    while True:
        buf = b""
        while True:
            buf += sock.recv(1)
            if buf[-1] == 10:
                break
        if buf[:4] == b"SSH-":
            break
    transport_remote_version = buf[:-2]  # Drop \r\n
    print(transport_remote_version.decode("utf-8"))

    # Initiate Key Exchange
    m = Message()
    m.write(MSG_KEXINIT)
    m.write(os.urandom(16))
    m.add_binary(b"diffie-hellman-group-exchange-sha256")
    m.add_binary(b"ssh-rsa")
    m.add_binary(b"aes128-ctr")
    m.add_binary(b"aes128-ctr")
    m.add_binary(b"hmac-sha2-256")
    m.add_binary(b"hmac-sha2-256")
    m.add_binary(b"none")
    m.add_binary(b"none")
    m.add_binary(bytes())
    m.add_binary(bytes())
    m.write(b"\x00")  # False
    m.add_int(0)
    transport_local_kex_init = m.getvalue()
    packetizer.send_message(m.getvalue())
    # ><
    ptype, m = packetizer.read_message()
    if ptype != MSG_KEXINIT:
        raise Exception("No MSG_KEXINIT", ptype)
    # Read records to find the end of the remote_kex_init
    m.get_bytes(16)  # cookie
    for _ in range(10):
        m.get_binary()  # client, server: key,encrupt, mac, compress, lang
    m.get_boolean()  # kex_follows
    m.get_int()  # unused
    transport_remote_kex_init = b"\x14" + m.get_so_far()

    # Request Group Exchange
    m = Message()
    m.write(MSG_KEXDH_GEX_REQUEST)
    m.add_int(2048)
    m.add_int(2048)
    m.add_int(2048)
    packetizer.send_message(m.getvalue())
    # ><
    ptype, m = packetizer.read_message()
    if ptype != MSG_KEXDH_GEX_GROUP:
        raise Exception("No MSG_KEXDH_GEX_GROUP", ptype)
    transport_p = m.get_mpint()
    transport_g = m.get_mpint()
    # Generate randome 1 < x < (transport_p - 1) / 2
    q = (transport_p - 1) // 2
    byte_count = int(math.log(q, 256)) + 1
    transport_x = q + 1
    while transport_x >= q:
        transport_x = int.from_bytes(os.urandom(byte_count), byteorder="big")
    transport_e = pow(transport_g, transport_x, transport_p)

    # Initalise Group Exchange
    m = Message()
    m.write(MSG_KEXDH_GEX_INIT)
    m.add_mpint(transport_e)
    packetizer.send_message(m.getvalue())
    # ><
    ptype, m = packetizer.read_message()
    if ptype != MSG_KEXDH_GEX_REPLY:
        raise Exception("No MSG_KEXDH_GEX_REPLY", ptype)
    host_key = m.get_binary()
    transport_f = m.get_mpint()
    if (transport_f < 1) or (transport_f > transport_p - 1):
        raise Exception('Server kex "f" is out of range')
    raw_sig = m.get_binary()
    transport_k = pow(transport_f, transport_x, transport_p)
    hm = Message()
    hm.add_binary(VERSION)
    hm.add_binary(transport_remote_version)
    hm.add_binary(transport_local_kex_init)
    hm.add_binary(transport_remote_kex_init)
    hm.add_binary(host_key)
    hm.add_int(2048)  # min
    hm.add_int(2048)  # prefered
    hm.add_int(2048)  # max
    hm.add_mpint(transport_p)
    hm.add_mpint(transport_g)
    hm.add_mpint(transport_e)
    hm.add_mpint(transport_f)
    hm.add_mpint(transport_k)
    transport_h = sha256(hm.getvalue()).digest()
    transport_session_id = transport_h
    key = Message(host_key)
    sig = Message(raw_sig)
    if key.get_binary() != b"ssh-rsa":
        raise Exception("Invalid key")
    if sig.get_binary() != b"ssh-rsa":
        raise Exception("Invalid sig")
    transport_host_key = rsa.RSAPublicNumbers(
        e=key.get_mpint(), n=key.get_mpint()
    ).public_key()
    transport_host_key.verify(
        signature=sig.get_binary(),
        data=transport_h,
        padding=padding.PKCS1v15(),
        algorithm=hashes.SHA1(),
    )
    print(hexlify(sha256(key.getvalue()).digest()).decode())

    # New Keys
    m = Message()
    m.write(MSG_NEWKEYS)
    packetizer.send_message(m.getvalue())
    # ><
    ptype, m = packetizer.read_message()
    if ptype != MSG_NEWKEYS:
        raise Exception("No MSG_NEWKEYS", ptype)
    aes = algorithms.AES(
        compute_key(b"C", 16, transport_k, transport_h, transport_session_id)
    )
    ctr = modes.CTR(
        compute_key(b"A", 16, transport_k, transport_h, transport_session_id)
    )
    encryptor = Cipher(aes, ctr).encryptor()  # type: ignore
    packetizer.set_outbound_cipher(
        encryptor,
        16,
        sha256,
        32,
        compute_key(
            b"E", sha256().digest_size, transport_k, transport_h, transport_session_id
        ),
        True,
    )
    aes = algorithms.AES(
        compute_key(b"D", 16, transport_k, transport_h, transport_session_id)
    )
    crt = modes.CTR(
        compute_key(b"B", 16, transport_k, transport_h, transport_session_id)
    )
    decryptor = Cipher(aes, crt).decryptor()  # type: ignore
    packetizer.set_inbound_cipher(
        decryptor,
        16,
        sha256,
        32,
        compute_key(
            b"F", sha256().digest_size, transport_k, transport_h, transport_session_id
        ),
    )

    # Request userauth Service
    m = Message()
    m.write(MSG_SERVICE_REQUEST)
    m.add_binary(b"ssh-userauth")
    packetizer.send_message(m.getvalue())
    # <>
    ptype, m = packetizer.read_message()
    if ptype != MSG_SERVICE_ACCEPT:
        raise Exception("Not MSG_SERVICE_ACCEPT", ptype)
    service = m.get_binary()
    if service != b"ssh-userauth":
        raise Exception("Not ssh-userauth", service)

    # Publickey Auth
    with Path(private_key_file).expanduser().open("rb") as id_rsa:
        private_key = cast(
            rsa.RSAPrivateKey,
            serialization.load_ssh_private_key(id_rsa.read(), password=None),
        )
    m = Message()
    m.add_binary(transport_session_id)
    m.write(MSG_USERAUTH_REQUEST)
    m.add_binary(username.encode())
    m.add_binary(b"ssh-connection")
    m.add_binary(b"publickey")
    m.write(b"\x01")  # True
    m.add_binary(b"ssh-rsa")
    pk = Message()
    pk.add_binary(b"ssh-rsa")
    pk.add_mpint(private_key.private_numbers().public_numbers.e)
    pk.add_mpint(private_key.private_numbers().public_numbers.n)
    m.add_binary(pk.getvalue())
    sig = Message()
    sig.add_binary(b"ssh-rsa")
    sig.add_binary(
        private_key.sign(
            m.getvalue(), padding=padding.PKCS1v15(), algorithm=hashes.SHA1()
        )
    )
    m.add_binary(sig.getvalue())
    del private_key
    m.seek(0)
    m.get_binary()  # strip session_id
    packetizer.send_message(m.get_remainder())
    # <>
    ptype, m = packetizer.read_message()
    if ptype != MSG_USERAUTH_SUCCESS:
        raise Exception("Not MSG_USERAUTH_SUCCESS", ptype)
    print("\\ o /")

    # Open channel
    m = Message()
    m.write(MSG_CHANNEL_OPEN)
    m.add_binary(b"session")
    m.add_int(0)
    m.add_int(DEFAULT_WINDOW_SIZE)
    m.add_int(DEFAULT_MAX_PACKET_SIZE)
    packetizer.send_message(m.getvalue())
    # <>
    # Ignore global request
    ptype, m = packetizer.read_message()
    if ptype != MSG_GLOBAL_REQUEST:
        raise Exception("Open not MSG_GLOBAL_REQUEST", ptype)
    print("GLOBAL:", m.get_binary().decode(), m.get_boolean())

    # Channel success
    ptype, m = packetizer.read_message()
    if ptype != MSG_CHANNEL_OPEN_SUCCESS:
        raise Exception("Open not MSG_CHANNEL_OPEN_SUCCESS", ptype)

    m.get_int()  # client chan
    transport_server_chan = m.get_int()
    print("Open channel 0:", transport_server_chan)
    # window_size = m.get_int()
    # max_packet_size = m.get_int()

    # Request PTY (skip for exec instaid of shell)
    m = Message()
    m.write(MSG_CHANNEL_REQUEST)
    m.add_int(transport_server_chan)
    m.add_binary(b"pty-req")
    m.write(b"\x01")  # Req-reply
    m.add_binary(b"xterm-256color")
    m.add_int(80)
    m.add_int(24)
    m.add_int(0)
    m.add_int(0)
    m.add_binary(bytes())
    packetizer.send_message(m.getvalue())
    # <>
    ptype, m = packetizer.read_message()
    if ptype != MSG_CHANNEL_SUCCESS:
        raise Exception("PTY not MSG_CHANNEL_SUCCESS", ptype)

    # Request Shell
    m = Message()
    m.write(MSG_CHANNEL_REQUEST)
    m.add_int(transport_server_chan)
    m.add_binary(b"shell")
    m.write(b"\x01")  # Req-reply
    packetizer.send_message(m.getvalue())
    # <>
    # Ignore MSG_CHANNEL_WINDOW_ADJUST
    ptype, m = packetizer.read_message()
    if ptype != MSG_CHANNEL_WINDOW_ADJUST:
        raise Exception("Open not MSG_CHANNEL_WINDOW_ADJUST", ptype)

    ptype, m = packetizer.read_message()
    if ptype != MSG_CHANNEL_SUCCESS:
        raise Exception("Shell not MSG_CHANNEL_SUCCESS", ptype)

    # Interactive
    while True:
        while select.select([sock], [], [], 0.1) == ([sock], [], []):
            ptype, m = packetizer.read_message()
            if ptype == MSG_CHANNEL_EOF:
                exit()
            if ptype == MSG_CHANNEL_REQUEST:
                if m.get_int() != 0:
                    raise Exception("Unknown Channel")
                if m.get_binary() != b"exit-status":
                    raise Exception("Unkown Request")
                m.get_boolean()
                exit(m.get_int())
            if ptype != MSG_CHANNEL_DATA:
                raise Exception("Open not MSG_CHANNEL_DATA", ptype)
            if m.get_int() != 0:
                raise Exception("Unknown Channel")
            print(m.get_binary().decode("utf-8"), end="", flush=True)
        m = Message()
        m.write(MSG_CHANNEL_DATA)
        m.add_int(transport_server_chan)
        m.add_binary(sys.stdin.readline().encode("utf-8"))
        packetizer.send_message(m.getvalue())
