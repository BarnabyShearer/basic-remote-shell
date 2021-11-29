"""Tests."""
import socket
from hashlib import sha256
from unittest.mock import Mock, patch

import pytest
from cryptography.hazmat.primitives.ciphers import CipherContext

import basic_remote_shell


def test_compute_key() -> None:
    """Test we can compute key."""
    assert (
        basic_remote_shell.compute_key(b"", 64, 0, b"", b"")[:8]
        == b"\x06\r\xc6>U\x95\xdf\xfb"
    )


def test_message_decoding() -> None:
    """Test message decoding."""
    msg = basic_remote_shell.Message(("\x01" * 16).encode())
    assert msg.get_so_far() == b""
    assert msg.get_bytes(0) == b""
    assert msg.get_boolean()
    assert msg.get_int() == 16843009
    assert msg.get_mpint() == 282578800148737
    msg = basic_remote_shell.Message(("\x01" * 8).encode())
    assert msg.get_binary() == b"\x01\x01\x01\x01"
    msg = basic_remote_shell.Message(("\x01" * 8).encode())
    assert msg.get_boolean()
    assert msg.get_remainder() == b"\x01\x01\x01\x01\x01\x01\x01"
    assert msg.get_bytes(10) == b"\x01\x01\x01\x01\x01\x01\x01\x00\x00\x00"
    msg = basic_remote_shell.Message(("\x04").encode())
    assert msg.get_mpint() == 0
    msg = basic_remote_shell.Message(("\x02\x80\x80").encode())
    assert msg.get_mpint() == -128


def test_message_encoding() -> None:
    """Test message encoding."""
    msg = basic_remote_shell.Message()
    msg.add_int(0)
    assert msg.get_so_far() == b"\x00\x00\x00\x00"
    msg = basic_remote_shell.Message()
    msg.add_mpint(1)
    assert msg.get_so_far() == b"\x00\x00\x00\x01\x01"
    msg = basic_remote_shell.Message()
    msg.add_mpint(-200000000)
    assert msg.get_so_far() == b"\x00\x00\x00\x04\xf4\x14>\x00"
    msg = basic_remote_shell.Message()
    msg.add_mpint(-1)
    assert msg.get_so_far() == b"\x00\x00\x00\x01\xff"
    msg = basic_remote_shell.Message()
    msg.add_binary(b"")
    assert msg.get_so_far() == b"\x00\x00\x00\x00"


@patch("basic_remote_shell.os.urandom", side_effect=lambda x: ("\x01" * x).encode())
def test_packetizer_send(_: Mock) -> None:
    """Test high level protocol Packetizer."""
    soc = Mock(spec=socket.socket)
    pack = basic_remote_shell.Packetizer(soc)
    pack.send_message(b"")
    soc.send.assert_called_with(
        b"\x00\x00\x00\x0c\x0b\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
    )
    cypher = Mock(spec=CipherContext)
    cypher.update.side_effect = lambda x: x
    pack.set_outbound_cipher(cypher, 16, sha256, 32, ("\x00" * 16).encode())
    pack.send_message(b"")
    soc.send.assert_called_with(
        b"\x00\x00\x00\x0c\x0b\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\xe3-=\xb3"
        b"\x95\x1d\x13\xf3\xd2Q[\xc3Fe9\x1c\x12\xac}\x9f\xc7!*\x14\x81\xdaN\xcf*|?\x9a"
    )


def test_packetizer_read() -> None:
    """Test high level protocol Packetizer."""
    soc = Mock(spec=socket.socket)
    pack = basic_remote_shell.Packetizer(soc)
    with pytest.raises(Exception) as e:
        soc.recv.return_value = b"\x00\x00\x00\x01"
        t, m = pack.read_message()
        assert str(e) == "Invalid packet blocking"
    soc.recv.return_value = (
        b"\x00\x00\x00\x0c\x0b\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
    )
    t, m = pack.read_message()
    assert t == b""
    assert m.get_remainder() == b""
    cypher = Mock(spec=CipherContext)
    cypher.update.side_effect = lambda x: x
    pack.set_inbound_cipher(cypher, 16, sha256, 32, ("\x00" * 16).encode())

    soc.recv.side_effect = [
        b"\x00\x00\x00\x0c\x0b\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01",
        b"\xe3-=\xb3\x95\x1d\x13\xf3\xd2Q[\xc3Fe9\x1c\x12\xac}\x9f\xc7!*\x14\x81"
        b"\xdaN\xcf*|?\x9a",
    ]
    t, m = pack.read_message()
    with pytest.raises(Exception) as e:
        soc.recv.side_effect = [
            b"\x00\x00\x00\x0c\x0b\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01",
            b"\x00",
        ]
        t, m = pack.read_message()
        assert str(e) == "Mismatched MAC"
